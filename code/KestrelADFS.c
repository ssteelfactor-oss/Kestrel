/*
 * KestrelADFS.c — AD FS DKM key ACL audit (v0.17)
 *
 * AD FS encrypts its token-signing certificate with a DKM (Distributed Key
 * Manager) master key stored in AD as the `thumbnailPhoto` attribute of an
 * object under CN=<group>,CN=Microsoft,CN=Program Data,<domainDN>. Anyone who
 * can READ that attribute can decrypt the token-signing key and forge SAML
 * tokens for any user — "Golden SAML". Whoever holds read on the DKM object is
 * therefore a Golden SAML precondition.
 *
 * This is a passive, best-effort check: it reads the DACL (no SeSecurityPrivilege,
 * DACL-only security mask) of each DKM key object and reports every non-default
 * trustee with read access. If AD FS is not deployed, or an ordinary user cannot
 * read the container / object SD, the scan simply reports nothing and returns —
 * it never errors out on a missing or inaccessible container.
 *
 * On-prem only: this audits the footprint AD FS leaves *in AD*. It makes no cloud
 * / Entra / Graph calls.
 */

#include "../include/Kestrel.h"
#include <sddl.h>

/* Read rights that expose the DKM key value. */
#define KESTREL_ADFS_READ_MASK \
    (READ_CONTROL | ADS_RIGHT_DS_READ_PROP | ADS_RIGHT_GENERIC_READ | ADS_RIGHT_GENERIC_ALL)

/* Default/privileged holders we do NOT flag (SYSTEM, admins, DCs). */
static BOOL
_AdfsDefaultHolder(_In_z_ LPCWSTR sid)
{
    LPCWSTR r;
    if (_wcsicmp(sid, L"S-1-5-18")     == 0) return TRUE;  /* SYSTEM         */
    if (_wcsicmp(sid, L"S-1-5-32-544") == 0) return TRUE;  /* Administrators */
    if (_wcsicmp(sid, L"S-1-5-9")      == 0) return TRUE;  /* Enterprise DCs */
    r = wcsrchr(sid, L'-');
    if (r) {
        r++;
        if (!wcscmp(r, L"512") || !wcscmp(r, L"519") ||    /* Domain / Enterprise Admins */
            !wcscmp(r, L"518") || !wcscmp(r, L"516") ||    /* Schema Admins / Domain Controllers */
            !wcscmp(r, L"500"))                            /* Administrator */
            return TRUE;
    }
    return FALSE;
}

/* Trustee SID of an allow / allow-object ACE. */
static PSID
_AdfsAceSid(_In_ ACE_HEADER *pAce)
{
    switch (pAce->AceType) {
    case ACCESS_ALLOWED_ACE_TYPE:
        return (PSID)&((ACCESS_ALLOWED_ACE *)pAce)->SidStart;
    case ACCESS_ALLOWED_OBJECT_ACE_TYPE: {
        ACCESS_ALLOWED_OBJECT_ACE *p = (ACCESS_ALLOWED_OBJECT_ACE *)pAce;
        return (PSID)((BYTE *)p + sizeof(ACCESS_ALLOWED_OBJECT_ACE) -
            (2 - !!(p->Flags & ACE_OBJECT_TYPE_PRESENT)
               - !!(p->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)) * sizeof(GUID));
    }
    default:
        return NULL;
    }
}

/* Walk one DKM object's DACL; report non-default trustees with read. */
static DWORD
_AdfsReportDkmDacl(_In_z_ LPCWSTR pwszDN, _In_ PSECURITY_DESCRIPTOR pSD)
{
    PACL  pDacl = NULL;
    BOOL  bPresent = FALSE, bDefault = FALSE;
    WORD  i;
    DWORD cHit = 0;

    if (!pSD || !IsValidSecurityDescriptor(pSD)) return 0;
    if (!GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefault) || !bPresent || !pDacl)
        return 0;

    for (i = 0; i < pDacl->AceCount; i++) {
        ACE_HEADER *pAce = NULL;
        ACCESS_MASK mask;
        PSID        pSid;
        LPWSTR      s = NULL;

        if (!GetAce(pDacl, i, (LPVOID *)&pAce) || !pAce) continue;
        if (pAce->AceType != ACCESS_ALLOWED_ACE_TYPE &&
            pAce->AceType != ACCESS_ALLOWED_OBJECT_ACE_TYPE) continue;

        mask = ((ACCESS_ALLOWED_ACE *)pAce)->Mask;   /* Mask offset is common */
        if (!(mask & KESTREL_ADFS_READ_MASK)) continue;

        pSid = _AdfsAceSid(pAce);
        if (!pSid || !IsValidSid(pSid) || !ConvertSidToStringSidW(pSid, &s) || !s) continue;

        if (!_AdfsDefaultHolder(s)) {
            WCHAR        nm[256] = L"", dm[256] = L"";
            DWORD        cn = ARRAYSIZE(nm), cd = ARRAYSIZE(dm);
            SID_NAME_USE use;
            if (LookupAccountSidW(NULL, pSid, nm, &cn, dm, &cd, &use))
                wprintf(L"  [ADFS-DKM] %s: %s\\%s (%s) has read access to the DKM key "
                        L"(Golden SAML precondition)\n", pwszDN, dm, nm, s);
            else
                wprintf(L"  [ADFS-DKM] %s: %s has read access to the DKM key "
                        L"(Golden SAML precondition)\n", pwszDN, s);
            cHit++;
        }
        LocalFree(s);
    }
    return cHit;
}

_Must_inspect_result_
HRESULT
KestrelRunADFSDkmScan(_In_z_ LPCWSTR pwszDomainNC)
{
    WCHAR               wszPath[700];
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h = NULL;
    ADS_SEARCHPREF_INFO prefs[3];
    HRESULT             hr;
    DWORD               cKeys = 0, cExposed = 0;
    LPWSTR rgAttrs[] = {
        (LPWSTR)L"distinguishedName",
        (LPWSTR)L"nTSecurityDescriptor"
    };

    wprintf(L"\n[*] AD FS DKM key ACL audit (Golden SAML precondition)\n");

    /* AD FS stores its config (incl. the DKM key) under Program Data\Microsoft. */
    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath),
            L"LDAP://CN=Microsoft,CN=Program Data,%s", pwszDomainNC)))
        return E_FAIL;

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pS);
    if (FAILED(hr)) {
        wprintf(L"  [=] No readable Program Data container — AD FS not deployed here, "
                L"or not readable as this user (skipping)\n");
        return S_OK;   /* best-effort: absence is not an error */
    }

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_SECURITY_MASK;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = ADS_SECURITY_INFO_DACL;   /* DACL only — no SeSecurityPrivilege */
    prefs[2].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[2].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[2].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pS->lpVtbl->SetSearchPreference(pS, prefs, ARRAYSIZE(prefs));

    /* The DKM master key lives in thumbnailPhoto on the key object(s). */
    hr = pS->lpVtbl->ExecuteSearch(pS, (LPWSTR)L"(thumbnailPhoto=*)",
            rgAttrs, ARRAYSIZE(rgAttrs), &h);
    if (FAILED(hr)) {
        wprintf(L"  [=] Container present but not searchable as this user (skipping)\n");
        pS->lpVtbl->Release(pS);
        return S_OK;
    }

    for (;;) {
        ADS_SEARCH_COLUMN col;
        WCHAR wszDN[700] = L"";

        hr = pS->lpVtbl->GetNextRow(pS, h);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr)) break;

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"distinguishedName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszDN, ARRAYSIZE(wszDN), col.pADsValues[0].CaseIgnoreString);
            else if (col.dwADsType == ADSTYPE_DN_STRING && col.dwNumValues)
                StringCchCopyW(wszDN, ARRAYSIZE(wszDN), col.pADsValues[0].DNString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        cKeys++;

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"nTSecurityDescriptor", &col))) {
            if (col.dwADsType == ADSTYPE_NT_SECURITY_DESCRIPTOR && col.dwNumValues)
                cExposed += _AdfsReportDkmDacl(wszDN[0] ? wszDN : L"<DKM key>",
                    (PSECURITY_DESCRIPTOR)col.pADsValues[0].SecurityDescriptor.lpValue);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
    }

    if (cKeys == 0)
        wprintf(L"  [=] No AD FS DKM key found (AD FS not deployed, or not readable)\n");
    else
        wprintf(L"\n  [=] %lu DKM key object(s), %lu non-default read grant(s) "
                L"(review — the AD FS service account is expected)\n", cKeys, cExposed);

    if (h) pS->lpVtbl->CloseSearchHandle(pS, h);
    pS->lpVtbl->Release(pS);
    return hr;
}
