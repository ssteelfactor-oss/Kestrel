/*
 * KestrelBaseline.c — v0.8  default-ACL baseline for delegation noise suppression
 *
 * The ACL scanner emits an edge for every non-trivial ACE on every object. Most
 * of those ACEs are not delegations — they are the default rights every object
 * of a given class is born with (stamped from the schema), plus the AdminSDHolder
 * template re-applied to every adminCount=1 object. Reporting them buries the
 * handful of ACEs an admin actually delegated.
 *
 * This module builds a baseline of "expected" ACEs from two authoritative,
 * read-only, ordinary-user sources, both pure LDAP:
 *
 *   1. defaultSecurityDescriptor on each classSchema (Schema NC) — the DACL
 *      stamped onto new objects of that class. Keyed by lDAPDisplayName.
 *   2. The DACL of CN=AdminSDHolder,CN=System,<domainNC> — what SDProp stamps
 *      onto protected (adminCount=1) objects, overriding inheritance.
 *
 * KestrelAceIsBaseline() returns TRUE when an object's ACE matches the default
 * for its class (or AdminSDHolder, for protected objects). The ACL scanner skips
 * those, so only genuine, admin-introduced delegations remain.
 *
 * Why defaultSecurityDescriptor and not a hardcoded list: it is schema-driven
 * (version- and locale-independent), and ConvertStringSecurityDescriptorToSecurity
 * DescriptorW resolves the SDDL aliases (DA/EA/AU/SY/CO/…) to the SAME concrete
 * domain SIDs that appear on real objects — so the comparison is exact.
 */

#include "../include/Kestrel.h"

/* ════════════════════════════════════════════════════════════════════════════
 * ACE signature extraction
 * ════════════════════════════════════════════════════════════════════════════ */

/* Reduce one ACE to its identity (allow/deny, mask, object-type, trustee SID). */
static BOOL _SigFromAce(_In_ PVOID pAce, _Out_ KESTREL_ACE_SIG *pSig)
{
    ACE_HEADER *pHdr = (ACE_HEADER *)pAce;
    PSID        pSid = NULL;
    LPWSTR      pwszSid = NULL;

    ZeroMemory(pSig, sizeof(*pSig));

    switch (pHdr->AceType) {
    case ACCESS_ALLOWED_ACE_TYPE:
    case ACCESS_DENIED_ACE_TYPE: {
        ACCESS_ALLOWED_ACE *p = (ACCESS_ALLOWED_ACE *)pAce;
        pSig->bAllow = (pHdr->AceType == ACCESS_ALLOWED_ACE_TYPE);
        pSig->dwMask = p->Mask;
        pSid = (PSID)&p->SidStart;
        break;
    }
    case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
    case ACCESS_DENIED_OBJECT_ACE_TYPE: {
        ACCESS_ALLOWED_OBJECT_ACE *p = (ACCESS_ALLOWED_OBJECT_ACE *)pAce;
        pSig->bAllow = (pHdr->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE);
        pSig->dwMask = p->Mask;
        if (p->Flags & ACE_OBJECT_TYPE_PRESENT) {
            pSig->bHasObjType = TRUE;
            pSig->objType     = p->ObjectType;
        }
        pSid = (PSID)((BYTE *)p + sizeof(ACCESS_ALLOWED_OBJECT_ACE) -
            sizeof(GUID) *
            (2 - !!(p->Flags & ACE_OBJECT_TYPE_PRESENT)
               - !!(p->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)));
        break;
    }
    default:
        return FALSE;   /* audit/alarm — not a grant */
    }

    if (!pSid || !IsValidSid(pSid))
        return FALSE;
    if (ConvertSidToStringSidW(pSid, &pwszSid) && pwszSid) {
        StringCchCopyW(pSig->wszSid, ARRAYSIZE(pSig->wszSid), pwszSid);
        LocalFree(pwszSid);
        return TRUE;
    }
    return FALSE;
}

static BOOL _SigEqual(_In_ const KESTREL_ACE_SIG *a, _In_ const KESTREL_ACE_SIG *b)
{
    if (a->bAllow != b->bAllow)         return FALSE;
    if (a->dwMask != b->dwMask)         return FALSE;
    if (a->bHasObjType != b->bHasObjType) return FALSE;
    if (a->bHasObjType && !IsEqualGUID(&a->objType, &b->objType)) return FALSE;
    return _wcsicmp(a->wszSid, b->wszSid) == 0;
}

/* Walk a DACL, appending each ACE's signature to a growable array. */
static HRESULT _SigSetFromDacl(_In_ PACL pDacl,
                               _Inout_ KESTREL_ACE_SIG **prgSig, _Inout_ DWORD *pcSig)
{
    ACL_SIZE_INFORMATION info = { 0 };
    if (!GetAclInformation(pDacl, &info, sizeof(info), AclSizeInformation))
        return HRESULT_FROM_WIN32(GetLastError());

    for (DWORD i = 0; i < info.AceCount; i++) {
        PVOID           pAce = NULL;
        KESTREL_ACE_SIG sig;
        KESTREL_ACE_SIG *p;

        if (!GetAce(pDacl, i, &pAce))
            continue;
        if (!_SigFromAce(pAce, &sig))
            continue;

        p = (KESTREL_ACE_SIG *)(*prgSig
            ? HeapReAlloc(GetProcessHeap(), 0, *prgSig, (SIZE_T)(*pcSig + 1) * sizeof(sig))
            : HeapAlloc(GetProcessHeap(), 0, sizeof(sig)));
        if (!p)
            return E_OUTOFMEMORY;
        *prgSig = p;
        (*prgSig)[(*pcSig)++] = sig;
    }
    return S_OK;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Baseline construction
 * ════════════════════════════════════════════════════════════════════════════ */

/* Read a single object's nTSecurityDescriptor DACL into a signature set. */
static HRESULT _LoadObjectDaclSigs(_In_z_ LPCWSTR pwszPath,
                                   _Inout_ KESTREL_ACE_SIG **prgSig, _Inout_ DWORD *pcSig)
{
    HRESULT          hr;
    IDirectoryObject *pObj = NULL;
    PADS_ATTR_INFO   pAttr = NULL;
    DWORD            cRet  = 0;
    LPWSTR           rgAttr[1] = { (LPWSTR)L"nTSecurityDescriptor" };

    hr = ADsGetObject(pwszPath, &IID_IDirectoryObject, (void **)&pObj);
    if (FAILED(hr))
        return hr;

    hr = pObj->lpVtbl->GetObjectAttributes(pObj, rgAttr, 1, &pAttr, &cRet);
    if (SUCCEEDED(hr) && pAttr && cRet > 0 &&
        pAttr[0].dwADsType == ADSTYPE_NT_SECURITY_DESCRIPTOR &&
        pAttr[0].pADsValues) {
        PSECURITY_DESCRIPTOR pSD =
            (PSECURITY_DESCRIPTOR)pAttr[0].pADsValues[0].SecurityDescriptor.lpValue;
        PACL pDacl = NULL;
        BOOL bPresent = FALSE, bDef = FALSE;
        if (pSD && IsValidSecurityDescriptor(pSD) &&
            GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDef) &&
            bPresent && pDacl)
            hr = _SigSetFromDacl(pDacl, prgSig, pcSig);
    }

    if (pAttr)
        FreeADsMem(pAttr);
    pObj->lpVtbl->Release(pObj);
    return hr;
}

VOID KestrelFreeACLBaseline(_In_opt_ KESTREL_ACL_BASELINE *pBaseline)
{
    if (!pBaseline)
        return;
    if (pBaseline->rgClass) {
        for (DWORD i = 0; i < pBaseline->cClass; i++)
            if (pBaseline->rgClass[i].rgSig)
                HeapFree(GetProcessHeap(), 0, pBaseline->rgClass[i].rgSig);
        HeapFree(GetProcessHeap(), 0, pBaseline->rgClass);
    }
    if (pBaseline->rgAdminSD)
        HeapFree(GetProcessHeap(), 0, pBaseline->rgAdminSD);
    HeapFree(GetProcessHeap(), 0, pBaseline);
}

_Must_inspect_result_
HRESULT KestrelBuildACLBaseline(_Outptr_ KESTREL_ACL_BASELINE **ppBaseline)
{
    HRESULT               hr;
    KESTREL_ACL_BASELINE *pB        = NULL;
    IADs                 *pRootDSE  = NULL;
    IDirectorySearch     *pSchema   = NULL;
    ADS_SEARCH_HANDLE     hSearch   = NULL;
    WCHAR                 wszSchemaNC[512] = { 0 };
    WCHAR                 wszDomainNC[512] = { 0 };
    WCHAR                 wszPath[600];
    VARIANT               varSchema, varDomain;
    LPWSTR                rgAttrs[2] = { (LPWSTR)L"lDAPDisplayName",
                                        (LPWSTR)L"defaultSecurityDescriptor" };
    ADS_SEARCHPREF_INFO   prefs[2];

    if (!ppBaseline)
        return E_INVALIDARG;
    *ppBaseline = NULL;

    VariantInit(&varSchema);
    VariantInit(&varDomain);

    pB = (KESTREL_ACL_BASELINE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*pB));
    if (!pB)
        return E_OUTOFMEMORY;

    /* ── rootDSE: schema + domain naming contexts ─────────────────────── */
    hr = ADsGetObject(L"LDAP://rootDSE", &IID_IADs, (void **)&pRootDSE);
    if (FAILED(hr))
        goto Cleanup;
    if (SUCCEEDED(pRootDSE->lpVtbl->Get(pRootDSE, L"schemaNamingContext", &varSchema)) &&
        varSchema.vt == VT_BSTR)
        StringCchCopyW(wszSchemaNC, ARRAYSIZE(wszSchemaNC), varSchema.bstrVal);
    if (SUCCEEDED(pRootDSE->lpVtbl->Get(pRootDSE, L"defaultNamingContext", &varDomain)) &&
        varDomain.vt == VT_BSTR)
        StringCchCopyW(wszDomainNC, ARRAYSIZE(wszDomainNC), varDomain.bstrVal);
    pRootDSE->lpVtbl->Release(pRootDSE);
    pRootDSE = NULL;

    if (wszSchemaNC[0] == L'\0') {
        hr = E_FAIL;
        goto Cleanup;
    }

    /* ── Pass 1: per-class defaultSecurityDescriptor ──────────────────── */
    hr = StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", wszSchemaNC);
    if (FAILED(hr)) goto Cleanup;

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pSchema);
    if (FAILED(hr)) goto Cleanup;

    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = 256;
    pSchema->lpVtbl->SetSearchPreference(pSchema, prefs, 2);

    hr = pSchema->lpVtbl->ExecuteSearch(pSchema,
            (LPWSTR)L"(objectClass=classSchema)", rgAttrs, 2, &hSearch);
    if (FAILED(hr)) goto Cleanup;

    while (pSchema->lpVtbl->GetNextRow(pSchema, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN col;
        WCHAR  wszClass[64] = { 0 };
        WCHAR  wszSddl[2048] = { 0 };

        if (SUCCEEDED(pSchema->lpVtbl->GetColumn(pSchema, hSearch,
                (LPWSTR)L"lDAPDisplayName", &col))) {
            if (col.dwNumValues > 0 && col.pADsValues[0].CaseIgnoreString)
                StringCchCopyW(wszClass, ARRAYSIZE(wszClass), col.pADsValues[0].CaseIgnoreString);
            pSchema->lpVtbl->FreeColumn(pSchema, &col);
        }
        if (SUCCEEDED(pSchema->lpVtbl->GetColumn(pSchema, hSearch,
                (LPWSTR)L"defaultSecurityDescriptor", &col))) {
            if (col.dwNumValues > 0 && col.pADsValues[0].CaseIgnoreString)
                StringCchCopyW(wszSddl, ARRAYSIZE(wszSddl), col.pADsValues[0].CaseIgnoreString);
            pSchema->lpVtbl->FreeColumn(pSchema, &col);
        }
        if (wszClass[0] == L'\0' || wszSddl[0] == L'\0')
            continue;

        /* SDDL → SD → DACL → signatures */
        PSECURITY_DESCRIPTOR pSD = NULL;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wszSddl, SDDL_REVISION_1, &pSD, NULL) && pSD) {
            PACL pDacl = NULL;
            BOOL bPresent = FALSE, bDef = FALSE;
            KESTREL_ACE_SIG *rgSig = NULL;
            DWORD            cSig  = 0;

            if (GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDef) &&
                bPresent && pDacl)
                _SigSetFromDacl(pDacl, &rgSig, &cSig);

            if (cSig > 0) {
                KESTREL_CLASS_BASELINE *pNew = (KESTREL_CLASS_BASELINE *)(pB->rgClass
                    ? HeapReAlloc(GetProcessHeap(), 0, pB->rgClass,
                          (SIZE_T)(pB->cClass + 1) * sizeof(KESTREL_CLASS_BASELINE))
                    : HeapAlloc(GetProcessHeap(), 0, sizeof(KESTREL_CLASS_BASELINE)));
                if (pNew) {
                    pB->rgClass = pNew;
                    StringCchCopyW(pB->rgClass[pB->cClass].wszClass,
                        ARRAYSIZE(pB->rgClass[pB->cClass].wszClass), wszClass);
                    pB->rgClass[pB->cClass].rgSig = rgSig;
                    pB->rgClass[pB->cClass].cSig  = cSig;
                    pB->cClass++;
                } else if (rgSig) {
                    HeapFree(GetProcessHeap(), 0, rgSig);
                }
            } else if (rgSig) {
                HeapFree(GetProcessHeap(), 0, rgSig);
            }
            LocalFree(pSD);
        }
    }

    /* ── Pass 2: AdminSDHolder DACL (protected-object baseline) ────────── */
    if (wszDomainNC[0] != L'\0') {
        WCHAR wszAdmin[700];
        if (SUCCEEDED(StringCchPrintfW(wszAdmin, ARRAYSIZE(wszAdmin),
                L"LDAP://CN=AdminSDHolder,CN=System,%s", wszDomainNC)))
            _LoadObjectDaclSigs(wszAdmin, &pB->rgAdminSD, &pB->cAdminSD);
    }

    KTRACE(L"baseline: %lu classes, %lu AdminSDHolder ACEs",
        pB->cClass, pB->cAdminSD);
    hr = S_OK;

Cleanup:
    VariantClear(&varSchema);
    VariantClear(&varDomain);
    if (hSearch && pSchema)
        pSchema->lpVtbl->CloseSearchHandle(pSchema, hSearch);
    if (pSchema)
        pSchema->lpVtbl->Release(pSchema);
    if (pRootDSE)
        pRootDSE->lpVtbl->Release(pRootDSE);
    if (SUCCEEDED(hr)) {
        *ppBaseline = pB;
    } else {
        KestrelFreeACLBaseline(pB);
    }
    return hr;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Lookup
 * ════════════════════════════════════════════════════════════════════════════ */

static BOOL _SigInSet(_In_ const KESTREL_ACE_SIG *pSig,
                      _In_reads_(cSet) const KESTREL_ACE_SIG *rgSet, _In_ DWORD cSet)
{
    for (DWORD i = 0; i < cSet; i++)
        if (_SigEqual(pSig, &rgSet[i]))
            return TRUE;
    return FALSE;
}

BOOL KestrelAceIsBaseline(
    _In_     const KESTREL_ACL_BASELINE *pBaseline,
    _In_z_   LPCWSTR                     pwszLeafClass,
    _In_     BOOL                        bAdminCount,
    _In_     BOOL                        bAllow,
    _In_     DWORD                       dwMask,
    _In_opt_ const GUID                 *pObjType,
    _In_     PSID                        pTrusteeSid)
{
    KESTREL_ACE_SIG sig;
    LPWSTR          pwszSid = NULL;

    if (!pBaseline || !pTrusteeSid || !IsValidSid(pTrusteeSid))
        return FALSE;

    ZeroMemory(&sig, sizeof(sig));
    sig.bAllow = bAllow ? 1 : 0;
    sig.dwMask = dwMask;
    if (pObjType) {
        sig.bHasObjType = TRUE;
        sig.objType     = *pObjType;
    }
    if (!ConvertSidToStringSidW(pTrusteeSid, &pwszSid) || !pwszSid)
        return FALSE;
    StringCchCopyW(sig.wszSid, ARRAYSIZE(sig.wszSid), pwszSid);
    LocalFree(pwszSid);

    /* Protected objects carry the AdminSDHolder ACL, not the class default. */
    if (bAdminCount && _SigInSet(&sig, pBaseline->rgAdminSD, pBaseline->cAdminSD))
        return TRUE;

    /* Class default. */
    for (DWORD i = 0; i < pBaseline->cClass; i++)
        if (_wcsicmp(pBaseline->rgClass[i].wszClass, pwszLeafClass) == 0)
            return _SigInSet(&sig, pBaseline->rgClass[i].rgSig,
                             pBaseline->rgClass[i].cSig);

    return FALSE;
}
