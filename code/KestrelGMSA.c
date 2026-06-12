/*
 * KestrelGMSA.c  —  v0.7  Group Managed Service Account (gMSA) enumeration
 *
 * Enumerates all gMSA objects (objectClass=msDS-Group-Managed-Service-Account)
 * and identifies which principals are permitted to retrieve the managed password
 * by parsing msDS-GroupMSAMembership — a raw NT security descriptor stored on
 * each gMSA object whose DACL contains exactly the principals allowed to call
 * GetPassword on a DC.
 *
 * Attributes read per object:
 *   sAMAccountName, distinguishedName, objectSid,
 *   msDS-GroupMSAMembership, servicePrincipalName, dNSHostName
 *
 * Network profile: one paged LDAP subtree search, authenticated domain user.
 * No elevated privileges required; no write operations.
 *
 * Output:
 *   Per gMSA: list of principals in the membership DACL, annotated as
 *   ALLOW / DENY / (inherited), plus a REVIEW flag for non-SYSTEM trustees.
 *
 * Note: resolving SID → sAMAccountName requires an additional LDAP query per
 * SID; that is intentionally deferred — the caller can pipe SIDs through
 * Get-ADObject or incorporate a future SID-cache module.
 */

#include "../include/Kestrel.h"

/* ════════════════════════════════════════════════════════════════════════════
 * Internal helpers
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * Grow rgReaders by 2x.
 */
_Must_inspect_result_
static HRESULT
_GmsaResultAppend(
    _Inout_     KESTREL_GMSA_SCAN_RESULT *pResult,
    _In_  const KESTREL_GMSA_READER      *pReader)
{
    if (pResult->cReaders == pResult->cCapacity) {
        DWORD cNew = pResult->cCapacity ? pResult->cCapacity * 2 : 64;
        KESTREL_GMSA_READER *pNew = (KESTREL_GMSA_READER *)HeapReAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY,
            pResult->rgReaders, cNew * sizeof(KESTREL_GMSA_READER));
        if (!pNew) return E_OUTOFMEMORY;
        pResult->rgReaders = pNew;
        pResult->cCapacity = cNew;
    }
    pResult->rgReaders[pResult->cReaders++] = *pReader;
    return S_OK;
}

/*
 * Decode a simple or object ACE into its components.
 * Returns FALSE for ACE types we do not handle (SYSTEM_AUDIT_*, etc.).
 * Returned PSID points into the ACE — valid while the parent ACL is alive.
 */
static BOOL
_GmsaAceDecode(
    _In_     LPVOID  pAce,
    _Out_    DWORD  *pdwMask,
    _Outptr_ PSID   *ppSid,
    _Out_    BOOL   *pbDeny)
{
    ACE_HEADER *pHdr = (ACE_HEADER *)pAce;

    *pdwMask = 0;
    *ppSid   = NULL;
    *pbDeny  = FALSE;

    switch (pHdr->AceType) {
    case ACCESS_ALLOWED_ACE_TYPE:
    case ACCESS_DENIED_ACE_TYPE: {
        ACCESS_ALLOWED_ACE *p = (ACCESS_ALLOWED_ACE *)pAce;
        *pdwMask = p->Mask;
        *ppSid   = (PSID)&p->SidStart;
        *pbDeny  = (pHdr->AceType == ACCESS_DENIED_ACE_TYPE);
        return TRUE;
    }
    case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
    case ACCESS_DENIED_OBJECT_ACE_TYPE: {
        ACCESS_ALLOWED_OBJECT_ACE *p = (ACCESS_ALLOWED_OBJECT_ACE *)pAce;
        *pdwMask = p->Mask;
        *pbDeny  = (pHdr->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE);
        /* SID offset depends on which optional GUID fields are present */
        *ppSid   = (PSID)((BYTE *)p + sizeof(ACCESS_ALLOWED_OBJECT_ACE) -
            sizeof(GUID) *
            (2 - !!(p->Flags & ACE_OBJECT_TYPE_PRESENT)
               - !!(p->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)));
        return TRUE;
    }
    default:
        return FALSE;
    }
}

/*
 * Walk the DACL from msDS-GroupMSAMembership and emit one finding per
 * allow/deny ACE. Every trustee in an allow ACE can retrieve the password.
 */
_Must_inspect_result_
static HRESULT
_GmsaEmitReadersFromSd(
    _In_    PSECURITY_DESCRIPTOR      pSD,
    _In_z_  LPCWSTR                   pwszGmsaDN,
    _In_z_  LPCWSTR                   pwszGmsaSam,
    _Inout_ KESTREL_GMSA_SCAN_RESULT *pResult)
{
    PACL pDacl    = NULL;
    BOOL bPresent = FALSE;
    BOOL bDefault = FALSE;

    if (!IsValidSecurityDescriptor(pSD))                                return S_OK;
    if (!GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefault)) return S_OK;
    if (!bPresent || !pDacl)                                            return S_OK;

    ACL_SIZE_INFORMATION aclInfo = { 0 };
    if (!GetAclInformation(pDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation))
        return S_OK;

    for (DWORD i = 0; i < aclInfo.AceCount; i++) {
        LPVOID pAce = NULL;
        if (!GetAce(pDacl, i, &pAce)) continue;

        ACE_HEADER *pHdr = (ACE_HEADER *)pAce;

        /* Skip pure inherit-only ACEs — they do not apply to the object itself */
        if ((pHdr->AceFlags & INHERIT_ONLY_ACE) &&
            !(pHdr->AceFlags & OBJECT_INHERIT_ACE))
            continue;

        DWORD dwMask = 0;
        PSID  pSid   = NULL;
        BOOL  bDeny  = FALSE;

        if (!_GmsaAceDecode(pAce, &dwMask, &pSid, &bDeny)) continue;
        if (!pSid) continue;

        LPWSTR pwszSidStr = NULL;
        if (!ConvertSidToStringSidW(pSid, &pwszSidStr) || !pwszSidStr)
            continue;

        KESTREL_GMSA_READER r = { 0 };
        StringCchCopyW(r.wszGmsaDN,     ARRAYSIZE(r.wszGmsaDN),     pwszGmsaDN);
        StringCchCopyW(r.wszGmsaSam,    ARRAYSIZE(r.wszGmsaSam),    pwszGmsaSam);
        StringCchCopyW(r.wszTrusteeSid, ARRAYSIZE(r.wszTrusteeSid), pwszSidStr);
        r.bDeny      = bDeny;
        r.bInherited = !!(pHdr->AceFlags & INHERITED_ACE);

        LocalFree(pwszSidStr);

        HRESULT hr = _GmsaResultAppend(pResult, &r);
        if (FAILED(hr)) return hr;
    }
    return S_OK;
}

/*
 * Extract PSECURITY_DESCRIPTOR from an ADSI column.
 * The attribute msDS-GroupMSAMembership is an NT security descriptor
 * and returns as ADSTYPE_PROV_SPECIFIC (same as RBCD / nTSecurityDescriptor).
 * As a safety net we also handle ADSTYPE_OCTET_STRING.
 *
 * Returns a pointer into the ADSI column buffer — valid until FreeColumn.
 * Does NOT allocate; caller must NOT HeapFree the result.
 */
static PSECURITY_DESCRIPTOR
_GmsaExtractSdFromColumn(_In_ const ADS_SEARCH_COLUMN *pCol)
{
    if (!pCol || pCol->dwNumValues == 0 || !pCol->pADsValues)
        return NULL;

    if (pCol->pADsValues[0].dwType == ADSTYPE_PROV_SPECIFIC &&
        pCol->pADsValues[0].ProviderSpecific.lpValue &&
        pCol->pADsValues[0].ProviderSpecific.dwLength >= sizeof(SECURITY_DESCRIPTOR))
        return (PSECURITY_DESCRIPTOR)pCol->pADsValues[0].ProviderSpecific.lpValue;

    if (pCol->pADsValues[0].dwType == ADSTYPE_OCTET_STRING &&
        pCol->pADsValues[0].OctetString.lpValue &&
        pCol->pADsValues[0].OctetString.dwLength >= sizeof(SECURITY_DESCRIPTOR))
        return (PSECURITY_DESCRIPTOR)pCol->pADsValues[0].OctetString.lpValue;

    return NULL;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Public API — KestrelRunGMSAScan
 * ════════════════════════════════════════════════════════════════════════════ */

_Must_inspect_result_
HRESULT KestrelRunGMSAScan(
    _In_z_   LPCWSTR                    pwszDomainNC,
    _Outptr_ KESTREL_GMSA_SCAN_RESULT **ppResult)
{
    if (!pwszDomainNC || !ppResult) return E_INVALIDARG;
    *ppResult = NULL;

    HRESULT                   hr      = S_OK;
    IDirectorySearch         *pSearch = NULL;
    ADS_SEARCH_HANDLE         hSearch = NULL;
    KESTREL_GMSA_SCAN_RESULT *pResult = NULL;
    WCHAR                     wszPath[512] = { 0 };

    /* ── Allocate result ────────────────────────────────────────────── */
    pResult = (KESTREL_GMSA_SCAN_RESULT *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(KESTREL_GMSA_SCAN_RESULT));
    if (!pResult) return E_OUTOFMEMORY;

    pResult->rgReaders = (KESTREL_GMSA_READER *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, 64 * sizeof(KESTREL_GMSA_READER));
    if (!pResult->rgReaders) {
        HeapFree(GetProcessHeap(), 0, pResult);
        return E_OUTOFMEMORY;
    }
    pResult->cCapacity = 64;

    /* ── Bind IDirectorySearch ──────────────────────────────────────── */
    hr = StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszDomainNC);
    if (FAILED(hr)) goto Cleanup;

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pSearch);
    if (FAILED(hr)) {
        wprintf(L"  [!] KestrelRunGMSAScan: ADsGetObject failed 0x%08X\n", hr);
        goto Cleanup;
    }

    /* ── Search preferences ─────────────────────────────────────────── */
    ADS_SEARCHPREF_INFO prefs[2];

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;

    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;

    /* Note: ADS_SEARCHPREF_SECURITY_MASK is not set here.
     * That preference controls reading nTSecurityDescriptor.
     * msDS-GroupMSAMembership is a regular attribute whose value happens
     * to be a security descriptor — it is returned as ADSTYPE_PROV_SPECIFIC
     * regardless of SECURITY_MASK, same as msDS-AllowedToActOnBehalfOf...  */

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);
    if (FAILED(hr)) goto Cleanup;

    /* ── Execute search ─────────────────────────────────────────────── */
    LPWSTR rgAttrs[] = {
        L"sAMAccountName",
        L"distinguishedName",
        L"objectSid",
        L"msDS-GroupMSAMembership",
        L"servicePrincipalName",
        L"dNSHostName"
    };

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
        L"(objectClass=msDS-Group-Managed-Service-Account)",
        rgAttrs, ARRAYSIZE(rgAttrs),
        &hSearch);
    if (FAILED(hr)) {
        wprintf(L"  [!] KestrelRunGMSAScan: ExecuteSearch failed 0x%08X\n", hr);
        goto Cleanup;
    }

    wprintf(L"  [*] Enumerating gMSA objects and password readers...\n\n");
    wprintf(L"  %-32s  %-30s  %-28s  %s\n",
            L"gMSA Account", L"DNS Host", L"Reader SID", L"Status");
    wprintf(L"  ─────────────────────────────────────────────────────────────────"
            L"──────────────────────────────────────────────────\n");

    /* ── Row loop ───────────────────────────────────────────────────── */
    for (;;) {
        hr = pSearch->lpVtbl->GetNextRow(pSearch, hSearch);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr))              {              break; }

        ADS_SEARCH_COLUMN colDN  = { 0 };
        ADS_SEARCH_COLUMN colSam = { 0 };
        ADS_SEARCH_COLUMN colSid = { 0 };
        ADS_SEARCH_COLUMN colMSD = { 0 };
        ADS_SEARCH_COLUMN colSpn = { 0 };
        ADS_SEARCH_COLUMN colDns = { 0 };

        WCHAR wszDN[512]  = { 0 };
        WCHAR wszSam[128] = { 0 };
        WCHAR wszDns[256] = { 0 };
        BOOL  bGotDN  = FALSE;
        BOOL  bGotMSD = FALSE;

        /* distinguishedName — mandatory */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"distinguishedName", &colDN)) &&
            colDN.dwNumValues > 0 &&
            colDN.pADsValues[0].dwType == ADSTYPE_DN_STRING) {
            StringCchCopyW(wszDN, ARRAYSIZE(wszDN),
                           colDN.pADsValues[0].DNString);
            bGotDN = TRUE;
            pSearch->lpVtbl->FreeColumn(pSearch, &colDN);
        }
        if (!bGotDN) { pResult->cErrors++; continue; }

        /* sAMAccountName */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"sAMAccountName", &colSam)) &&
            colSam.dwNumValues > 0 &&
            colSam.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING) {
            StringCchCopyW(wszSam, ARRAYSIZE(wszSam),
                           colSam.pADsValues[0].CaseIgnoreString);
            pSearch->lpVtbl->FreeColumn(pSearch, &colSam);
        }

        /* objectSid — store on pResult for future graph integration */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"objectSid", &colSid))) {
            pSearch->lpVtbl->FreeColumn(pSearch, &colSid);
        }

        /* dNSHostName — informational */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"dNSHostName", &colDns)) &&
            colDns.dwNumValues > 0 &&
            colDns.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING) {
            StringCchCopyW(wszDns, ARRAYSIZE(wszDns),
                           colDns.pADsValues[0].CaseIgnoreString);
            pSearch->lpVtbl->FreeColumn(pSearch, &colDns);
        }

        /* servicePrincipalName — consumed but not printed (future use) */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"servicePrincipalName", &colSpn)))
            pSearch->lpVtbl->FreeColumn(pSearch, &colSpn);

        pResult->cGmsaScanned++;
        KTRACE(L"gMSA: %s  dns: %s", wszSam, wszDns);

        /* msDS-GroupMSAMembership — NT security descriptor */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"msDS-GroupMSAMembership", &colMSD))) {
            PSECURITY_DESCRIPTOR pSD = _GmsaExtractSdFromColumn(&colMSD);
            if (pSD && IsValidSecurityDescriptor(pSD)) {
                bGotMSD = TRUE;
                DWORD cBefore = pResult->cReaders;
                hr = _GmsaEmitReadersFromSd(pSD, wszDN, wszSam, pResult);
                if (FAILED(hr)) {
                    pSearch->lpVtbl->FreeColumn(pSearch, &colMSD);
                    goto Cleanup;
                }
                /* If no ACEs found, still print the gMSA as having empty DACL */
                if (pResult->cReaders == cBefore) {
                    wprintf(L"  %-32s  %-30s  %-28s  %s\n",
                            wszSam, wszDns, L"(empty DACL)", L"");
                }
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &colMSD);
        }

        if (!bGotMSD) {
            wprintf(L"  %-32s  %-30s  %-28s  %s\n",
                    wszSam, wszDns, L"(no membership SD)", L"[not set]");
        }
    }

    /* ── Print reader table ─────────────────────────────────────────── */
    DWORD cUnexpected = 0;
    DWORD cDeny       = 0;

    for (DWORD i = 0; i < pResult->cReaders; i++) {
        const KESTREL_GMSA_READER *pR = &pResult->rgReaders[i];

        LPCWSTR pwszStatus;
        if (pR->bDeny) {
            pwszStatus = L"DENY";
            cDeny++;
        } else if (_wcsicmp(pR->wszTrusteeSid, L"S-1-5-18") == 0) {
            pwszStatus = L"[SYSTEM]";
        } else {
            pwszStatus = L"** REVIEW **";
            cUnexpected++;
        }

        wprintf(L"  %-32s  %-30s  %-28s  %s%s\n",
                pR->wszGmsaSam,
                pR->wszGmsaDN,
                pR->wszTrusteeSid,
                pwszStatus,
                pR->bInherited ? L" (inherited)" : L"");
    }

    /* ── Summary ────────────────────────────────────────────────────── */
    wprintf(L"\n  gMSA objects: %lu  |  Reader ACEs: %lu  "
            L"|  Deny ACEs: %lu  |  Review: %lu  |  Errors: %lu\n",
            pResult->cGmsaScanned,
            pResult->cReaders,
            cDeny,
            cUnexpected,
            pResult->cErrors);

    if (pResult->cGmsaScanned == 0) {
        wprintf(L"\n  [*] No gMSA objects found in domain.\n");
    } else if (cUnexpected > 0) {
        wprintf(L"\n  [!] %lu principal(s) marked REVIEW can retrieve gMSA password(s).\n"
                L"      Resolve SIDs: Get-ADObject -Filter {objectSID -eq '<SID>'} | Select Name,ObjectClass\n",
                cUnexpected);
    } else {
        wprintf(L"\n  [+] No unexpected password readers detected.\n");
    }

    wprintf(L"\n");

    *ppResult = pResult;
    pResult   = NULL;

Cleanup:
    if (hSearch && pSearch)
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    if (pResult)
        KestrelFreeGMSAScanResult(pResult);
    return hr;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Public API — KestrelFreeGMSAScanResult
 * ════════════════════════════════════════════════════════════════════════════ */

VOID KestrelFreeGMSAScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GMSA_SCAN_RESULT *pResult)
{
    if (!pResult) return;
    if (pResult->rgReaders)
        HeapFree(GetProcessHeap(), 0, pResult->rgReaders);
    HeapFree(GetProcessHeap(), 0, pResult);
}