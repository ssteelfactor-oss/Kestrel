/*
 * Kestrel_ACL.c — v0.2
 * ACL edge extraction via IDirectoryObject / SECURITY_DESCRIPTOR
 *
 * Three phases:
 *   1. Build Extended Rights GUID→name table from CN=Extended-Rights,CN=Configuration
 *   2. Enumerate all relevant AD objects, retrieve raw nTSecurityDescriptor
 *   3. Walk DACL per object, classify ACEs into typed edges
 *
 * All queries run through ADSI COM interfaces (IDirectorySearch, IDirectoryObject).
 * No .NET, no PowerShell, no managed runtime.
 * SAL 2.0 annotations validated by /analyze (PREfast).
 *
 * rootDSE (defaultNamingContext, configurationNamingContext) is resolved once
 * by the caller and passed as parameters — never re-queried inside this module.
 */

#include "../include/Kestrel.h"
 /* ─────────────────────────────────────────────────────────────────────────── */
 /*  Constants                                                                  */
 /* ─────────────────────────────────────────────────────────────────────────── */

 /* Full-scope object filter — all types that carry meaningful ACL edges */
#define KESTREL_ACL_FILTER \
    L"(|(objectClass=user)(objectClass=group)(objectClass=computer)" \
    L"(objectClass=organizationalUnit)(objectClass=domainDNS)"       \
    L"(objectClass=container)(objectClass=groupPolicyContainer)"      \
    L"(objectClass=builtinDomain))"

/* Attributes fetched per object via IDirectorySearch */
static LPWSTR g_rgszObjectAttrs[] = {
    L"distinguishedName",
    L"objectClass",
    L"objectSid",
    L"nTSecurityDescriptor",
    L"adminCount"
};
#define KESTREL_OBJECT_ATTR_COUNT \
    (sizeof(g_rgszObjectAttrs) / sizeof(g_rgszObjectAttrs[0]))

/* Attributes fetched per Extended Right entry */
static LPWSTR g_rgszRightAttrs[] = {
    L"rightsGuid",
    L"displayName",
    L"appliesTo"
};
#define KESTREL_RIGHT_ATTR_COUNT \
    (sizeof(g_rgszRightAttrs) / sizeof(g_rgszRightAttrs[0]))

/* Well-known GUID strings used in ACE ObjectType comparison */
/* DS-Replication-Get-Changes  — DCSync component                          */
#define GUID_DS_REPL_GET_CHANGES        L"{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"
/* DS-Replication-Get-Changes-All — DCSync component                       */
#define GUID_DS_REPL_GET_CHANGES_ALL    L"{1131f6ab-9c07-11d1-f79f-00c04fc2dcd2}"
/* User-Force-Change-Password                                               */
#define GUID_FORCE_CHANGE_PASSWORD      L"{00299570-246d-11d0-a768-00aa006e0529}"
/* Self-Membership (write to member attr on groups)                         */
#define GUID_SELF_MEMBERSHIP            L"{bf9679c0-0de6-11d0-a285-00aa003049e2}"
/* ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity (RBCD write)           */
#define GUID_ALLOWED_TO_ACT_ON_BEHALF  L"{3f78c3e5-f79a-46bd-a0b8-9d18116ddc79}"


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Data structures                                                            */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * KESTREL_EXTENDED_RIGHT
 * One entry in the Extended Rights table.
 * appliesTo is a NULL-terminated array of class GUIDs (schema objects
 * this right is defined on — e.g. user, group, computer).
 */
typedef struct _KESTREL_EXTENDED_RIGHT {
    WCHAR    wszGuid[64];        /* rightsGuid canonical form, e.g. {xxxxxxxx-...} */
    WCHAR    wszDisplayName[128];/* human-readable name, e.g. "User-Force-Change-Password" */
    WCHAR** rgwszAppliesTo;     /* NULL-terminated array of schema class GUIDs   */
    DWORD    cAppliesTo;
    struct _KESTREL_EXTENDED_RIGHT* pNext;
} KESTREL_EXTENDED_RIGHT;





/* ─────────────────────────────────────────────────────────────────────────── */
/*  Forward declarations (SAL 2.0 annotated)                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * Phase 1 — Build Extended Rights lookup table.
 *
 * Queries CN=Extended-Rights,CN=Configuration,<configNC> via IDirectorySearch.
 * Allocates a singly-linked list of KESTREL_EXTENDED_RIGHT entries on the heap.
 * Caller must free via KestrelFreeExtendedRightsTable.
 *
 * Parameters:
 *   pwszConfigNC    — configurationNamingContext from rootDSE (caller-owned)
 *   ppRightsHead    — receives pointer to head of list; NULL on failure
 *
 * Returns:
 *   S_OK            — table built successfully (list may still be empty if
 *                     CN=Extended-Rights is empty or inaccessible)
 *   HRESULT error   — LDAP bind failed, ADsGetObject error, or allocation failure
 */
_Must_inspect_result_
HRESULT
KestrelBuildExtendedRightsTable(
    _In_z_  LPCWSTR                 pwszConfigNC,
    _Outptr_result_maybenull_
    KESTREL_EXTENDED_RIGHT** ppRightsHead
);

/*
 * Resolve an Extended Right GUID to its displayName.
 * Linear scan — table is small enough (~200 entries) that hashing is unnecessary.
 *
 * Returns pointer to entry if found, NULL if GUID is not in the table.
 * Returned pointer is valid for the lifetime of pRightsHead.
 */
_Ret_maybenull_
const KESTREL_EXTENDED_RIGHT*
KestrelLookupExtendedRight(
    _In_   const KESTREL_EXTENDED_RIGHT* pRightsHead,
    _In_z_ LPCWSTR                       pwszGuid
);

/*
 * Phase 2 — Retrieve raw nTSecurityDescriptor for one AD object.
 *
 * Uses IDirectoryObject::GetObjectAttributes with attribute "nTSecurityDescriptor".
 * The returned SECURITY_DESCRIPTOR is allocated by ADSI; caller must call
 * FreeADsMem on *ppSD when done.
 *
 * Parameters:
 *   pDirObj     — bound IDirectoryObject for the target object
 *   ppSD        — receives pointer to SECURITY_DESCRIPTOR; NULL on failure
 *   pcbSD       — receives byte length of the returned SD
 */
_Must_inspect_result_
HRESULT
KestrelGetObjectSecurityDescriptor(
    _In_            IDirectoryObject* pDirObj,
    _Outptr_        PSECURITY_DESCRIPTOR* ppSD,
    _Out_           DWORD* pcbSD
);

/*
 * Phase 3 — Walk DACL and emit edges into result buffer.
 *
 * Iterates every ACE in pDacl.  Filters out INHERIT_ONLY ACEs that do not
 * apply to the object itself.  Classifies each ACE and appends one
 * KESTREL_ACL_EDGE to pResult per significant right found.
 *
 * Significant = GenericAll / WriteDacl / WriteOwner / GenericWrite /
 *               ExtendedRight (DS_CONTROL_ACCESS) / WriteProperty (DS_WRITE_PROP)
 *               on a named attribute GUID / CreateChild / DeleteChild.
 *
 * Parameters:
 *   pDacl       — pointer to DACL extracted from object's SD
 *   pwszTargetDN    — DN of the object (for edge annotation)
 *   pwszObjectClass — objectClass of the object (for edge annotation)
 *   pRightsHead — Extended Rights table (may be NULL; GUIDs emitted raw)
 *   pResult     — output buffer; KestrelACLResultAppend reallocates as needed
 */
_Must_inspect_result_
HRESULT
KestrelWalkDacl(
    _In_     PACL                          pDacl,
    _In_z_   LPCWSTR                       pwszTargetDN,
    _In_z_   LPCWSTR                       pwszObjectClass,
    _In_opt_ const KESTREL_EXTENDED_RIGHT* pRightsHead,
    _In_opt_ const KESTREL_ACL_BASELINE*   pBaseline,
    _In_     BOOL                          bAdminCount,
    _Inout_  KESTREL_ACL_SCAN_RESULT*      pResult
);

/*
 * KestrelScanACLEdges — rewrite with Plan A / Plan B fallback.
 *
 * Replace the entire KestrelScanACLEdges function body in KestrelACL.C.
 *
 * Plan A: per-object ADsGetObject bind → IDirectoryObject::GetObjectAttributes
 *         Requires elevated rights in some environments.
 *         SD is HeapAlloc'd copy — caller frees with HeapFree.
 *
 * Plan B: read nTSecurityDescriptor directly from IDirectorySearch column.
 *         Works for any authenticated domain user.
 *         SD pointer lives inside ADSI column buffer — freed with FreeColumn.
 *
 * On first 0x80004005 / E_ACCESSDENIED from Plan A, switches to Plan B
 * for all remaining objects (including the one that triggered the switch).
 */

_Must_inspect_result_
HRESULT
KestrelScanACLEdges(
    _In_z_  LPCWSTR                  pwszDomainNC,
    _In_z_  LPCWSTR                  pwszConfigNC,
    _Outptr_ KESTREL_ACL_SCAN_RESULT** ppResult
);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Internal helpers (not exported)                                            */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * Grow pResult->rgEdges if needed and append one edge.
 * Initial capacity: 4096 edges; grows by doubling.
 */
_Must_inspect_result_
static HRESULT
KestrelACLResultAppend(
    _Inout_        KESTREL_ACL_SCAN_RESULT* pResult,
    _In_     const KESTREL_ACL_EDGE* pEdge
);

/*
 * Translate ACCESS_MASK bits to KESTREL_ACL_EDGE_TYPE.
 * Returns EDGE_UNKNOWN if the mask carries no significant right.
 * For DS_CONTROL_ACCESS / DS_WRITE_PROP, also emits GUID if pObjectTypeGuid != NULL.
 */
static KESTREL_ACL_EDGE_TYPE
KestrelClassifyAccessMask(
    _In_     DWORD   dwAccessMask,
    _In_opt_ GUID* pObjectTypeGuid
);

/*
 * Format a GUID struct to the canonical string form {xxxxxxxx-xxxx-...}.
 * pwszBuf must be at least 40 characters.
 */
static VOID
KestrelGuidToString(
    _In_    const GUID* pGuid,
    _Out_writes_z_(cchBuf) LPWSTR pwszBuf,
    _In_    SIZE_T     cchBuf
);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Cleanup                                                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * Free the singly-linked Extended Rights list built by
 * KestrelBuildExtendedRightsTable.  Safe to call with NULL.
 */
VOID
KestrelFreeExtendedRightsTable(
    _In_opt_ _Post_ptr_invalid_ KESTREL_EXTENDED_RIGHT* pRightsHead
);

/*
 * Free scan result and all contained edge data.
 * Safe to call with NULL.
 */
VOID
KestrelFreeACLScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_ACL_SCAN_RESULT* pResult
);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Implementation stubs                                                       */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * KestrelBuildExtendedRightsTable — Phase 1 implementation.
 */

_Must_inspect_result_
HRESULT
KestrelBuildExtendedRightsTable(
    _In_z_  LPCWSTR                 pwszConfigNC,
    _Outptr_result_maybenull_
    KESTREL_EXTENDED_RIGHT** ppRightsHead)
{
    HRESULT                  hr = S_OK;
    IDirectorySearch* pSearch = NULL;
    ADS_SEARCH_HANDLE        hSearch = NULL;
    KESTREL_EXTENDED_RIGHT* pHead = NULL;
    KESTREL_EXTENDED_RIGHT** ppTail = &pHead; /* build list in order */
    WCHAR                    wszPath[512];
    DWORD                    cTotal = 0;

    if (!pwszConfigNC || !ppRightsHead) return E_INVALIDARG;
    *ppRightsHead = NULL;

    /* ── 1. Bind IDirectorySearch to CN=Extended-Rights ─────────────── */
    hr = StringCchPrintfW(wszPath, ARRAYSIZE(wszPath),
        L"LDAP://CN=Extended-Rights,%s", pwszConfigNC);
    if (FAILED(hr)) return hr;

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void**)&pSearch);
    if (FAILED(hr)) {
        wprintf(L"  [!] KestrelBuildExtendedRightsTable: ADsGetObject failed 0x%08X\n", hr);
        return hr;
    }

    /* ── 2. Set preferences: ONELEVEL scope, paged ───────────────────── */
    ADS_SEARCHPREF_INFO prefs[2];

    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_ONELEVEL; /* direct children only */

    prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = 200;

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);
    if (FAILED(hr)) goto Cleanup;

    /* ── 3. Execute search ───────────────────────────────────────────── */
    LPWSTR attrs[] = { L"rightsGuid", L"displayName", L"appliesTo" };

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
        L"(objectClass=controlAccessRight)",
        attrs, ARRAYSIZE(attrs),
        &hSearch);
    if (FAILED(hr)) goto Cleanup;

    /* ── 4. Walk rows, build linked list ─────────────────────────────── */
    while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {

        ADS_SEARCH_COLUMN colGuid = { 0 };
        ADS_SEARCH_COLUMN colName = { 0 };
        ADS_SEARCH_COLUMN colApplies = { 0 };

        BOOL bGotGuid = FALSE;
        BOOL bGotName = FALSE;
        BOOL bGotAppl = FALSE;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
            L"rightsGuid", &colGuid)) &&
            colGuid.dwNumValues > 0 &&
            colGuid.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING)
            bGotGuid = TRUE;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
            L"displayName", &colName)) &&
            colName.dwNumValues > 0 &&
            colName.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING)
            bGotName = TRUE;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
            L"appliesTo", &colApplies)) &&
            colApplies.dwNumValues > 0)
            bGotAppl = TRUE;

        /* rightsGuid is mandatory — skip entries without it */
        if (!bGotGuid) goto NextRow;

        /* ── Allocate entry ─────────────────────────────────────────── */
        KESTREL_EXTENDED_RIGHT* pEntry = (KESTREL_EXTENDED_RIGHT*)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(KESTREL_EXTENDED_RIGHT));
        if (!pEntry) { hr = E_OUTOFMEMORY; goto NextRow; }

        /*
         * rightsGuid comes from LDAP as bare UUID string without braces:
         * "ab721a52-1e2f-11d0-9819-00aa0040529b"
         *
         * KestrelGuidToString produces {XXXXXXXX-...} form.
         * Store WITH braces so KestrelLookupExtendedRight can match directly.
         * _wcsicmp handles case difference.
         */
        StringCchPrintfW(pEntry->wszGuid, ARRAYSIZE(pEntry->wszGuid),
            L"{%s}", colGuid.pADsValues[0].CaseIgnoreString);

        if (bGotName)
            StringCchCopyW(pEntry->wszDisplayName, ARRAYSIZE(pEntry->wszDisplayName),
                colName.pADsValues[0].CaseIgnoreString);

        /* ── appliesTo: multi-valued schema class GUIDs ─────────────── */
        if (bGotAppl) {
            pEntry->cAppliesTo = colApplies.dwNumValues;
            pEntry->rgwszAppliesTo = (LPWSTR*)HeapAlloc(GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                colApplies.dwNumValues * sizeof(LPWSTR));

            if (pEntry->rgwszAppliesTo) {
                for (DWORD i = 0; i < colApplies.dwNumValues; i++) {
                    if (colApplies.pADsValues[i].dwType != ADSTYPE_CASE_IGNORE_STRING)
                        continue;

                    LPCWSTR pwszVal = colApplies.pADsValues[i].CaseIgnoreString;
                    SIZE_T  cch = wcslen(pwszVal) + 1;

                    pEntry->rgwszAppliesTo[i] = (LPWSTR)HeapAlloc(
                        GetProcessHeap(), 0, cch * sizeof(WCHAR));

                    if (pEntry->rgwszAppliesTo[i])
                        StringCchCopyW(pEntry->rgwszAppliesTo[i], cch, pwszVal);
                }
            }
        }

        /* ── Append to tail (preserves LDAP order) ──────────────────── */
        *ppTail = pEntry;
        ppTail = &pEntry->pNext;
        cTotal++;

    NextRow:
        if (bGotGuid)  pSearch->lpVtbl->FreeColumn(pSearch, &colGuid);
        if (bGotName)  pSearch->lpVtbl->FreeColumn(pSearch, &colName);
        if (bGotAppl)  pSearch->lpVtbl->FreeColumn(pSearch, &colApplies);
    }

    wprintf(L"  [*] Extended Rights table: %lu entries\n", cTotal);

    *ppRightsHead = pHead;
    pHead = NULL;   /* ownership transferred to caller */

Cleanup:
    if (hSearch && pSearch)
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    /* pHead != NULL only if we hit E_OUTOFMEMORY mid-loop */
    if (pHead)
        KestrelFreeExtendedRightsTable(pHead);

    return hr;
}

_Ret_maybenull_
const KESTREL_EXTENDED_RIGHT*
KestrelLookupExtendedRight(
    _In_   const KESTREL_EXTENDED_RIGHT* pRightsHead,
    _In_z_ LPCWSTR                       pwszGuid)
{
    for (const KESTREL_EXTENDED_RIGHT* p = pRightsHead; p; p = p->pNext) {
        if (_wcsicmp(p->wszGuid, pwszGuid) == 0)
            return p;
    }
    return NULL;
}
/*
 * KestrelGetObjectSecurityDescriptor — Phase 2 implementation.
 *
 * Design note:
 *   IDirectoryObject::GetObjectAttributes allocates pAttrInfo via ADSI.
 *   The raw SD lives inside pAttrInfo->pADsValues[0].ProviderSpecific.lpValue.
 *   We copy it into a HeapAlloc'd buffer and free pAttrInfo before returning.
 *   Caller owns *ppSD and must HeapFree it when done.
 */

_Must_inspect_result_
HRESULT
KestrelGetObjectSecurityDescriptor(
    _In_        IDirectoryObject* pDirObj,
    _Outptr_    PSECURITY_DESCRIPTOR* ppSD,
    _Out_       DWORD* pcbSD)
{
    HRESULT         hr = S_OK;
    ADS_ATTR_INFO* pAttrInfo = NULL;
    DWORD           cAttrs = 0;
    PSECURITY_DESCRIPTOR pSdCopy = NULL;

    if (!pDirObj || !ppSD || !pcbSD) return E_INVALIDARG;
    *ppSD = NULL;
    *pcbSD = 0;

    LPWSTR rgszAttrs[] = { L"nTSecurityDescriptor" };

    /* ── 1. Retrieve nTSecurityDescriptor via IDirectoryObject ────────── */
    hr = pDirObj->lpVtbl->GetObjectAttributes(pDirObj,
        rgszAttrs, 1,
        &pAttrInfo, &cAttrs);

    if (FAILED(hr)) goto Cleanup;

    if (cAttrs == 0 || !pAttrInfo) {
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        goto Cleanup;
    }

    /* ── 2. Locate the nTSecurityDescriptor attribute ─────────────────── */
    ADS_ATTR_INFO* pSD_Attr = NULL;

    for (DWORD i = 0; i < cAttrs; i++) {
        if (_wcsicmp(pAttrInfo[i].pszAttrName, L"nTSecurityDescriptor") == 0) {
            pSD_Attr = &pAttrInfo[i];
            break;
        }
    }

    if (!pSD_Attr || pSD_Attr->dwNumValues == 0) {
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        goto Cleanup;
    }

    /* ── 3. Verify type and extract raw SD bytes ──────────────────────── */
    ADS_PROV_SPECIFIC* pProvSpec = &pSD_Attr->pADsValues[0].ProviderSpecific;

    if (pSD_Attr->pADsValues[0].dwType != ADSTYPE_PROV_SPECIFIC ||
        !pProvSpec->lpValue || pProvSpec->dwLength == 0) {
        hr = E_UNEXPECTED;
        goto Cleanup;
    }

    /* ── 4. Copy SD into HeapAlloc buffer — caller owns this memory ───── */
    pSdCopy = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), 0,
        pProvSpec->dwLength);
    if (!pSdCopy) {
        hr = E_OUTOFMEMORY;
        goto Cleanup;
    }

    CopyMemory(pSdCopy, pProvSpec->lpValue, pProvSpec->dwLength);

    /* ── 5. Quick sanity check before handing off ─────────────────────── */
    if (!IsValidSecurityDescriptor(pSdCopy)) {
        HeapFree(GetProcessHeap(), 0, pSdCopy);
        pSdCopy = NULL;
        hr = E_UNEXPECTED;
        goto Cleanup;
    }

    *ppSD = pSdCopy;
    *pcbSD = pProvSpec->dwLength;
    pSdCopy = NULL;  /* ownership transferred */

Cleanup:
    /* pAttrInfo allocated by ADSI — must use FreeADsMem, not HeapFree */
    if (pAttrInfo) FreeADsMem(pAttrInfo);
    /* pSdCopy != NULL only if we hit an error after HeapAlloc */
    if (pSdCopy)   HeapFree(GetProcessHeap(), 0, pSdCopy);

    return hr;
}

_Must_inspect_result_
HRESULT
KestrelWalkDacl(
    _In_     PACL                          pDacl,
    _In_z_   LPCWSTR                       pwszTargetDN,
    _In_z_   LPCWSTR                       pwszObjectClass,
    _In_opt_ const KESTREL_EXTENDED_RIGHT* pRightsHead,
    _In_opt_ const KESTREL_ACL_BASELINE* pBaseline,
    _In_     BOOL                          bAdminCount,
    _Inout_  KESTREL_ACL_SCAN_RESULT* pResult)
{
    if (!pDacl || !pwszTargetDN || !pwszObjectClass || !pResult)
        return E_INVALIDARG;

    ACL_SIZE_INFORMATION aclInfo = { 0 };
    if (!GetAclInformation(pDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation))
        return HRESULT_FROM_WIN32(GetLastError());

    for (DWORD i = 0; i < aclInfo.AceCount; i++) {
        LPVOID pAce = NULL;
        if (!GetAce(pDacl, i, &pAce)) continue;

        ACE_HEADER* pHeader = (ACE_HEADER*)pAce;
        BOOL        bDeny = (pHeader->AceType == ACCESS_DENIED_ACE_TYPE ||
            pHeader->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE);

        /* Skip pure inherit-only ACEs — they do not apply to the object itself */
        if ((pHeader->AceFlags & INHERIT_ONLY_ACE) &&
            !(pHeader->AceFlags & OBJECT_INHERIT_ACE))
            continue;

        DWORD  dwMask = 0;
        PSID   pTrusteeSid = NULL;
        GUID* pObjectType = NULL;

        switch (pHeader->AceType) {
        case ACCESS_ALLOWED_ACE_TYPE:
        case ACCESS_DENIED_ACE_TYPE: {
            ACCESS_ALLOWED_ACE* p = (ACCESS_ALLOWED_ACE*)pAce;
            dwMask = p->Mask;
            pTrusteeSid = (PSID)&p->SidStart;
            break;
        }
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case ACCESS_DENIED_OBJECT_ACE_TYPE: {
            ACCESS_ALLOWED_OBJECT_ACE* p = (ACCESS_ALLOWED_OBJECT_ACE*)pAce;
            dwMask = p->Mask;
            if (p->Flags & ACE_OBJECT_TYPE_PRESENT)
                pObjectType = &p->ObjectType;
            /* SidStart offset depends on which GUIDs are present */
            pTrusteeSid = (PSID)((BYTE*)p + sizeof(ACCESS_ALLOWED_OBJECT_ACE) -
                sizeof(GUID) *
                (2 - !!(p->Flags & ACE_OBJECT_TYPE_PRESENT)
                    - !!(p->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)));
            break;
        }
        default:
            continue; /* SYSTEM_AUDIT_*, etc. — not relevant here */
        }

        KESTREL_ACL_EDGE_TYPE edgeType = KestrelClassifyAccessMask(dwMask, pObjectType);
        if (edgeType == EDGE_UNKNOWN) continue;

        /* Drop ACEs that match the schema / AdminSDHolder default — not a delegation */
        if (!g_bAclRaw && pBaseline &&
            KestrelAceIsBaseline(pBaseline, pwszObjectClass, bAdminCount,
                !bDeny, dwMask, pObjectType, pTrusteeSid)) {
            pResult->cSuppressed++;
            continue;
        }

        /* Build the edge record */
        KESTREL_ACL_EDGE edge = { 0 };
        edge.EdgeType = edgeType;
        edge.bDeny = bDeny;
        edge.bInherited = !!(pHeader->AceFlags & INHERITED_ACE);

        StringCchCopyW(edge.wszTargetDN, ARRAYSIZE(edge.wszTargetDN), pwszTargetDN);
        StringCchCopyW(edge.wszObjectClass, ARRAYSIZE(edge.wszObjectClass), pwszObjectClass);

        LPWSTR pwszSid = NULL;
        if (ConvertSidToStringSidW(pTrusteeSid, &pwszSid) && pwszSid) {
            StringCchCopyW(edge.wszTrusteeSid, ARRAYSIZE(edge.wszTrusteeSid), pwszSid);
            LocalFree(pwszSid);
        }
        else {
            StringCchCopyW(edge.wszTrusteeSid, ARRAYSIZE(edge.wszTrusteeSid), L"(invalid SID)");
        }

        if (pObjectType && (edgeType == EDGE_EXTENDED_RIGHT || edgeType == EDGE_WRITE_PROPERTY)) {
            KestrelGuidToString(pObjectType, edge.wszRightGuid, ARRAYSIZE(edge.wszRightGuid));
            const KESTREL_EXTENDED_RIGHT* pRight = KestrelLookupExtendedRight(pRightsHead, edge.wszRightGuid);
            if (pRight)
                StringCchCopyW(edge.wszRightName, ARRAYSIZE(edge.wszRightName), pRight->wszDisplayName);
        }

        HRESULT hr = KestrelACLResultAppend( pResult, & edge );
        if ( FAILED(hr) ) return hr;
    }

    return S_OK;
}
_Must_inspect_result_
static HRESULT
KestrelGetConfigNC(
    _Out_writes_z_(cchBuf) LPWSTR pwszBuf,
    _In_                   SIZE_T cchBuf)
{
    HRESULT  hr = S_OK;
    IADs* pRootDSE = 0;
    VARIANT  var = { 0 };

    VariantInit( & var );

    hr = ADsGetObject(L"LDAP://rootDSE", &IID_IADs, (void**)&pRootDSE);
    if (FAILED(hr)) goto Cleanup;

    hr = pRootDSE->lpVtbl->Get(pRootDSE, L"configurationNamingContext", &var);
    if (FAILED(hr)) goto Cleanup;

    if (var.vt != VT_BSTR || !var.bstrVal) {
        hr = E_UNEXPECTED;
        goto Cleanup;
    }

    hr = StringCchCopyW(pwszBuf, cchBuf, var.bstrVal);

Cleanup:
    VariantClear(&var);
    if (pRootDSE) pRootDSE->lpVtbl->Release(pRootDSE);
    return hr;
}


/* ═════════════════════════════════════════════════════════════════════════
 * PART B — KestrelScanACLEdges
 * ═════════════════════════════════════════════════════════════════════════ */

 /*
  * KestrelScanACLEdges — rewrite with Plan A / Plan B fallback.
  *
  * Replace the entire KestrelScanACLEdges function body in KestrelACL.C.
  *
  * Plan A: per-object ADsGetObject bind → IDirectoryObject::GetObjectAttributes
  *         Requires elevated rights in some environments.
  *         SD is HeapAlloc'd copy — caller frees with HeapFree.
  *
  * Plan B: read nTSecurityDescriptor directly from IDirectorySearch column.
  *         Works for any authenticated domain user.
  *         SD pointer lives inside ADSI column buffer — freed with FreeColumn.
  *
  * On first 0x80004005 / E_ACCESSDENIED from Plan A, switches to Plan B
  * for all remaining objects (including the one that triggered the switch).
  */

_Must_inspect_result_
HRESULT
KestrelScanACLEdges(
    _In_z_   LPCWSTR                  pwszDomainNC,
    _In_z_   LPCWSTR                  pwszConfigNC,
    _Outptr_ KESTREL_ACL_SCAN_RESULT** ppResult)
{
    HRESULT                  hr = S_OK;
    KESTREL_EXTENDED_RIGHT* pRights = 0;
    KESTREL_ACL_SCAN_RESULT* pResult = 0;
    IDirectorySearch* pSearch = 0;
    ADS_SEARCH_HANDLE        hSearch = 0;
    WCHAR                    wszPath[512];
    WCHAR                    wszConfigNC[512];
    BOOL                     bUsePlanB = FALSE;
    KESTREL_ACL_BASELINE*    pBaseline = 0;

    if (!pwszDomainNC || !ppResult) return E_INVALIDARG;
    *ppResult = 0;

    /* ── 1. Allocate result container ────────────────────────────────── */
    pResult = (KESTREL_ACL_SCAN_RESULT*)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(*pResult));
    if (!pResult) return E_OUTOFMEMORY;

    /* ── 2. Resolve configNC ──────────────────────────────────────────── */
    if (pwszConfigNC && *pwszConfigNC != L'\0') {
        StringCchCopyW(wszConfigNC, ARRAYSIZE(wszConfigNC), pwszConfigNC);
    }
    else {
        hr = KestrelGetConfigNC(wszConfigNC, ARRAYSIZE(wszConfigNC));
        if (FAILED(hr)) {
            wprintf(L"  [!] Failed to resolve configNC: 0x%08X\n", hr);
            goto Cleanup;
        }
    }

    /* ── 3. Phase 1: Extended Rights table ───────────────────────────── */
    wprintf(L"  [*] Building Extended Rights table...\n");
    hr = KestrelBuildExtendedRightsTable(wszConfigNC, &pRights);
    if (FAILED(hr)) {
        wprintf(L"  [!] KestrelBuildExtendedRightsTable: 0x%08X\n", hr);
        goto Cleanup;
    }
    if (!g_bAclRaw) {
        wprintf(L"  [*] Building default-ACL baseline...\n");
        HRESULT hrBase = KestrelBuildACLBaseline(&pBaseline);
        if (FAILED(hrBase)) {
            wprintf(L"  [!] Baseline build failed (0x%08X) — continuing raw\n", hrBase);
            pBaseline = NULL;
        }
    }

    /* ── 4. Bind IDirectorySearch ─────────────────────────────────────── */
    hr = StringCchPrintfW(wszPath, ARRAYSIZE(wszPath),
        L"LDAP://%s", pwszDomainNC);
    if (FAILED(hr)) goto Cleanup;

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void**)&pSearch);
    if (FAILED(hr)) {
        wprintf(L"  [!] ADsGetObject root failed: 0x%08X\n", hr);
        goto Cleanup;
    }

    /* ── 5. Search preferences ────────────────────────────────────────── */
    ADS_SEARCHPREF_INFO prefs[3];

    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;

    prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;

    prefs[2].dwSearchPref = ADS_SEARCHPREF_SECURITY_MASK;
    prefs[2].vValue.dwType = ADSTYPE_INTEGER;
    prefs[2].vValue.Integer = 0x4; /* DACL_SECURITY_INFORMATION only —
                                      readable by any authenticated user */

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 3);
    if (FAILED(hr)) goto Cleanup;

    /* ── 6. Execute search ────────────────────────────────────────────── */
    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
        KESTREL_ACL_FILTER,
        (LPWSTR*)g_rgszObjectAttrs,
        KESTREL_OBJECT_ATTR_COUNT,
        &hSearch);
    if (FAILED(hr)) goto Cleanup;

    wprintf(L"  [*] Scanning ACL edges...\n\n");
    wprintf(L"  %-50s %-20s %-18s %s\n",
        L"Target DN", L"Trustee SID", L"Edge Type", L"Right");
    wprintf(L"  %s\n",
        L"--------------------------------------------------------------------------------"
        L"--------------------");

    /* ── 7. Main loop ─────────────────────────────────────────────────── */
    while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {

        ADS_SEARCH_COLUMN colDN = { 0 };
        ADS_SEARCH_COLUMN colClass = { 0 };
        ADS_SEARCH_COLUMN colSD = { 0 };

        WCHAR   wszDN[512] = { 0 };
        WCHAR   wszClass[64] = { 0 };
        WCHAR   wszObjPath[600] = { 0 };
        BOOL    bGotDN = FALSE;
        BOOL    bGotClass = FALSE;
        BOOL    bGotSD = FALSE;

        /* ── Get DN ───────────────────────────────────────────────────── */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
            L"distinguishedName", &colDN)) &&
            colDN.dwNumValues > 0 &&
            colDN.pADsValues[0].dwType == ADSTYPE_DN_STRING) {
            StringCchCopyW(wszDN, ARRAYSIZE(wszDN),
                colDN.pADsValues[0].DNString);
            bGotDN = TRUE;
            pSearch->lpVtbl->FreeColumn(pSearch, &colDN);
        }

        if (!bGotDN) { pResult->cObjectsErrored++; continue; }

        /* ── Get objectClass ──────────────────────────────────────────── */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
            L"objectClass", &colClass)) &&
            colClass.dwNumValues > 0) {
            DWORD iLast = colClass.dwNumValues - 1;
            if (colClass.pADsValues[iLast].dwType == ADSTYPE_CASE_IGNORE_STRING)
                StringCchCopyW(wszClass, ARRAYSIZE(wszClass),
                    colClass.pADsValues[iLast].CaseIgnoreString);
            bGotClass = TRUE;
            pSearch->lpVtbl->FreeColumn(pSearch, &colClass);
        }

        if (!bGotClass)
            StringCchCopyW(wszClass, ARRAYSIZE(wszClass), L"unknown");

        /* ── Get adminCount (protected-object flag) ───────────────────── */
        BOOL bAdminCount = FALSE;
        ADS_SEARCH_COLUMN colAdmin = { 0 };
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
            L"adminCount", &colAdmin)) && colAdmin.dwNumValues > 0) {
            if (colAdmin.pADsValues[0].dwType == ADSTYPE_INTEGER &&
                colAdmin.pADsValues[0].Integer == 1)
                bAdminCount = TRUE;
            pSearch->lpVtbl->FreeColumn(pSearch, &colAdmin);
        }

        /* ── Obtain SECURITY_DESCRIPTOR ──────────────────────────────── */
        PSECURITY_DESCRIPTOR pSD = NULL;
        BOOL                 bOwnsSD = FALSE; /* TRUE = HeapAlloc, must HeapFree
                                                 FALSE = ADSI owns, FreeColumn */

        if (!bUsePlanB) {
            /* ── Plan A: per-object IDirectoryObject bind ─────────────── */
            StringCchPrintfW(wszObjPath, ARRAYSIZE(wszObjPath),
                L"LDAP://%s", wszDN);

            IDirectoryObject* pDirObj = 0;
            DWORD             cbSD = 0;

            HRESULT hrA = ADsGetObject(wszObjPath,
                &IID_IDirectoryObject, (void**)&pDirObj);
            //wprintf(L"[*** ? ***] hrA = 0x%08X", hrA);
            //if (hrA == E_FAIL || hrA == E_ACCESSDENIED ||
            //    hrA == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) 
            
            if( FAILED ( hrA ) ){
                /*
                 * Plan A denied — switch to Plan B for this and all
                 * subsequent objects. Re-read SD from column below.
                 */
                bUsePlanB = TRUE;
                wprintf(L"  [*] Plan A denied (0x%08X) — "
                    L"switching to direct LDAP read mode\n\n", hrA);
            }
            else if (SUCCEEDED(hrA) && pDirObj) {
                hrA = KestrelGetObjectSecurityDescriptor(pDirObj, &pSD, &cbSD);
                pDirObj->lpVtbl->Release(pDirObj);
                if (SUCCEEDED(hrA) && pSD)
                    bOwnsSD = TRUE;
                else
                    pResult->cObjectsErrored++;
            }
        }

        if (bUsePlanB && !pSD) {
            /* ── Plan B: read SD directly from search column ──────────── */
            if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"nTSecurityDescriptor", &colSD)) &&
                colSD.dwNumValues > 0 &&
                colSD.pADsValues[0].dwType == ADSTYPE_PROV_SPECIFIC &&
                colSD.pADsValues[0].ProviderSpecific.lpValue) {
                pSD = (PSECURITY_DESCRIPTOR)
                    colSD.pADsValues[0].ProviderSpecific.lpValue;
                bGotSD = TRUE;
                /* bOwnsSD stays FALSE — ADSI owns this memory */
            }
        }

        /* ── Walk DACL ────────────────────────────────────────────────── */
        if (pSD && IsValidSecurityDescriptor(pSD)) {
            PACL pDacl = NULL;
            BOOL bPresent = FALSE;
            BOOL bDefault = FALSE;

            if (GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefault) &&
                bPresent && pDacl) {
                HRESULT hrW = KestrelWalkDacl(pDacl, wszDN, wszClass,
                    pRights, pBaseline, bAdminCount, pResult);
                if (FAILED(hrW))
                    pResult->cObjectsErrored++;
            }
            pResult->cObjectsScanned++;
        }
        else if (!bOwnsSD && !bGotSD) {
            pResult->cObjectsErrored++;
        }

        /* ── Cleanup per-object resources ─────────────────────────────── */
        if (bOwnsSD && pSD)
            HeapFree(GetProcessHeap(), 0, pSD);

        if (bGotSD)
            pSearch->lpVtbl->FreeColumn(pSearch, &colSD);
    }

    /* ── 8. Print results ─────────────────────────────────────────────── */
    static const LPCWSTR rgszEdgeNames[] = {
        L"UNKNOWN",   L"GenericAll",    L"WriteDACL",
        L"WriteOwner", L"GenericWrite",  L"ExtendedRight",
        L"WriteProperty", L"CreateChild", L"DeleteChild", L"Self"
    };

    for (DWORD i = 0; i < pResult->cEdges; i++) {
        KESTREL_ACL_EDGE* pE = &pResult->rgEdges[i];

        LPCWSTR pwszType = (pE->EdgeType < ARRAYSIZE(rgszEdgeNames))
            ? rgszEdgeNames[pE->EdgeType] : L"?";

        LPCWSTR pwszRight = pE->wszRightName[0]
            ? pE->wszRightName : pE->wszRightGuid;

        wprintf(L"  %-50s %-20s %-18s %s%s\n",
            pE->wszTargetDN,
            pE->wszTrusteeSid,
            pwszType,
            pwszRight,
            pE->bDeny ? L" [DENY]" : L"");
    }

    wprintf(L"\n  [*] Mode: %s\n", bUsePlanB ? L"Plan B (LDAP column)" : L"Plan A (per-object bind)");
    wprintf(L"  [*] Objects scanned: %lu  |  Delegations: %lu  |  Default ACEs suppressed: %lu  |  Errors: %lu\n",
        pResult->cObjectsScanned,
        pResult->cEdges,
        pResult->cSuppressed,
        pResult->cObjectsErrored);  

    *ppResult = pResult;
    pResult = 0;

Cleanup:
    if ( hSearch && pSearch )
        pSearch->lpVtbl->CloseSearchHandle( pSearch, hSearch );
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    if (pRights != 0) KestrelFreeExtendedRightsTable( pRights );
    //KestrelFreeExtendedRightsTable( pRights );
    if (pBaseline) KestrelFreeACLBaseline(pBaseline);
    if (pResult) KestrelFreeACLScanResult(pResult);
    return hr;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Internal helper implementations                                            */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
KestrelACLResultAppend(
    _Inout_        KESTREL_ACL_SCAN_RESULT* pResult,
    _In_     const KESTREL_ACL_EDGE* pEdge)
{
    /* Initial allocation: 4096 edges; double on each growth */
    if (pResult->cEdges == pResult->cCapacity) {
        DWORD             cNew = pResult->cCapacity ? pResult->cCapacity * 2 : 4096;
        KESTREL_ACL_EDGE* pNew = (KESTREL_ACL_EDGE*)HeapReAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY,
            pResult->rgEdges,
            cNew * sizeof(KESTREL_ACL_EDGE));
        if (!pNew) return E_OUTOFMEMORY;
        pResult->rgEdges = pNew;
        pResult->cCapacity = cNew;
    }

    pResult->rgEdges[pResult->cEdges++] = *pEdge;
    return S_OK;
}

static KESTREL_ACL_EDGE_TYPE
KestrelClassifyAccessMask(
    _In_     DWORD  dwAccessMask,
    _In_opt_ GUID* pObjectTypeGuid)
{
    /* Order matters: check broadest rights first */
    if (dwAccessMask & GENERIC_ALL)                  return EDGE_GENERIC_ALL;
    if (dwAccessMask & WRITE_DAC)                    return EDGE_WRITE_DACL;
    if (dwAccessMask & WRITE_OWNER)                  return EDGE_WRITE_OWNER;
    if (dwAccessMask & GENERIC_WRITE)                return EDGE_GENERIC_WRITE;
    if (dwAccessMask & ADS_RIGHT_DS_CONTROL_ACCESS)  return EDGE_EXTENDED_RIGHT;
    if (dwAccessMask & ADS_RIGHT_DS_WRITE_PROP)      return EDGE_WRITE_PROPERTY;
    if (dwAccessMask & ADS_RIGHT_DS_CREATE_CHILD)    return EDGE_CREATE_CHILD;
    if (dwAccessMask & ADS_RIGHT_DS_DELETE_CHILD)    return EDGE_DELETE_CHILD;
    if (dwAccessMask & ADS_RIGHT_DS_SELF)            return EDGE_SELF;
    return EDGE_UNKNOWN;
}

static VOID
KestrelGuidToString(
    _In_    const GUID* pGuid,
    _Out_writes_z_(cchBuf) LPWSTR pwszBuf,
    _In_    SIZE_T     cchBuf)
{
    StringCchPrintfW(pwszBuf, cchBuf,
        L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        pGuid->Data1, pGuid->Data2, pGuid->Data3,
        pGuid->Data4[0], pGuid->Data4[1], pGuid->Data4[2], pGuid->Data4[3],
        pGuid->Data4[4], pGuid->Data4[5], pGuid->Data4[6], pGuid->Data4[7]);
}

VOID
KestrelFreeExtendedRightsTable(
    _In_opt_ _Post_ptr_invalid_ KESTREL_EXTENDED_RIGHT* pRightsHead)
{
    while (pRightsHead) {
        KESTREL_EXTENDED_RIGHT* pNext = pRightsHead->pNext;
        if (pRightsHead->rgwszAppliesTo) {
            for (DWORD i = 0; i < pRightsHead->cAppliesTo; i++)
                HeapFree(GetProcessHeap(), 0, pRightsHead->rgwszAppliesTo[i]);
            HeapFree(GetProcessHeap(), 0, pRightsHead->rgwszAppliesTo);
        }
        HeapFree(GetProcessHeap(), 0, pRightsHead);
        pRightsHead = pNext;
    }
}

VOID
KestrelFreeACLScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_ACL_SCAN_RESULT* pResult)
{
    if (!pResult) return;
    if (pResult->rgEdges)
        HeapFree(GetProcessHeap(), 0, pResult->rgEdges);
    HeapFree(GetProcessHeap(), 0, pResult);
}

/* ═════════════════════════════════════════════════════════════════════════
 * PART C — Kerberos delegation surface (unconstrained / constrained / RBCD)
 *
 * Passive, attribute/DACL-derived, DC-only, ordinary domain-user rights —
 * the same invariant as the ACL scan. This enumerates the delegation
 * *surface*; nothing here requests tickets or exercises S4U2Self/S4U2Proxy.
 *
 * One LDAP search with a server-side filter that returns only objects that
 * carry a delegation property:
 *   - userAccountControl bits via LDAP_MATCHING_RULE_BIT_AND
 *     (1.2.840.113556.1.4.803): 0x80000 unconstrained, 0x1000000 protocol
 *     transition;
 *   - presence of msDS-AllowedToDelegateTo (constrained, Kerberos-only);
 *   - presence of msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD).
 * Classification and RBCD-SD parsing are done per row.
 *
 * NOTE on detectability: the bitwise matching-rule filter and the SD reads
 * below are themselves distinctive query patterns. This is low-touch, not
 * stealthy — consistent with the tool's defensive/audit positioning.
 * ═════════════════════════════════════════════════════════════════════════ */

/* userAccountControl flags relevant to delegation */
#define KESTREL_UAC_TRUSTED_FOR_DELEGATION         0x00080000UL /* unconstrained        */
#define KESTREL_UAC_TRUSTED_TO_AUTH_FOR_DELEGATION 0x01000000UL /* protocol transition  */

/* Server-side filter: any object with a delegation property set. */
#define KESTREL_DELEG_FILTER \
    L"(|(userAccountControl:1.2.840.113556.1.4.803:=524288)"    \
    L"(userAccountControl:1.2.840.113556.1.4.803:=16777216)"    \
    L"(msDS-AllowedToDelegateTo=*)"                              \
    L"(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"

static LPWSTR g_rgszDelegAttrs[] = {
    L"distinguishedName",
    L"sAMAccountName",
    L"objectClass",
    L"userAccountControl",
    L"msDS-AllowedToDelegateTo",
    L"msDS-AllowedToActOnBehalfOfOtherIdentity"
};
#define KESTREL_DELEG_ATTR_COUNT \
    (sizeof(g_rgszDelegAttrs) / sizeof(g_rgszDelegAttrs[0]))

/* ─────────────────────────────────────────────────────────────────────────── */
/*  PART C/D internal helpers                                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * Decode a single ACE into (mask, trustee SID, object type, deny) for the
 * ACE types Kestrel cares about. Returns FALSE for ACE types we do not
 * classify (SYSTEM_AUDIT_*, etc.). The returned PSID / GUID* point into the
 * ACE itself — valid only while the parent ACL (and its SD) stays alive.
 *
 * Mirrors the switch inside KestrelWalkDacl, kept as a separate helper so the
 * new collectors do not edit the already-tested Phase-3 code.
 */
static BOOL
KestrelAceDecode(
    _In_     LPVOID  pAce,
    _Out_    DWORD  *pdwMask,
    _Outptr_ PSID   *ppTrusteeSid,
    _Outptr_result_maybenull_ GUID **ppObjectType,
    _Out_    BOOL   *pbDeny)
{
    ACE_HEADER *pHeader = (ACE_HEADER *)pAce;

    *pdwMask      = 0;
    *ppTrusteeSid = 0;
    *ppObjectType = 0;
    *pbDeny       = FALSE;

    switch (pHeader->AceType) {
    case ACCESS_ALLOWED_ACE_TYPE:
    case ACCESS_DENIED_ACE_TYPE: {
        ACCESS_ALLOWED_ACE *p = (ACCESS_ALLOWED_ACE *)pAce;
        *pdwMask      = p->Mask;
        *ppTrusteeSid = ( PSID ) & p->SidStart;
        *pbDeny       = (pHeader->AceType == ACCESS_DENIED_ACE_TYPE);
        return TRUE;
    }
    case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
    case ACCESS_DENIED_OBJECT_ACE_TYPE: {
        ACCESS_ALLOWED_OBJECT_ACE *p = (ACCESS_ALLOWED_OBJECT_ACE *)pAce;
        *pdwMask = p->Mask;
        if (p->Flags & ACE_OBJECT_TYPE_PRESENT)
            *ppObjectType = &p->ObjectType;
        /* SidStart offset depends on which of the two optional GUIDs are present */
        *ppTrusteeSid = (PSID)((BYTE *)p + sizeof(ACCESS_ALLOWED_OBJECT_ACE) -
            sizeof(GUID) *
            (2 - !!(p->Flags & ACE_OBJECT_TYPE_PRESENT)
               - !!(p->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)));
        *pbDeny = (pHeader->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE);
        return TRUE;
    }
    default:
        return FALSE;
    }
}

_Must_inspect_result_
static HRESULT
KestrelDelegResultAppend(
    _Inout_     KESTREL_DELEG_SCAN_RESULT *pResult,
    _In_  const KESTREL_DELEG_FINDING     *pFinding)
{
    if (pResult->cFindings == pResult->cCapacity) {
        DWORD cNew = pResult->cCapacity ? pResult->cCapacity * 2 : 256;
        KESTREL_DELEG_FINDING *pNew = (KESTREL_DELEG_FINDING *)HeapReAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY,
            pResult->rgFindings, cNew * sizeof(KESTREL_DELEG_FINDING));
        if (!pNew) return E_OUTOFMEMORY;
        pResult->rgFindings = pNew;
        pResult->cCapacity  = cNew;
    }
    pResult->rgFindings[pResult->cFindings++] = *pFinding;
    return S_OK;
}

/*
 * Walk the DACL inside an RBCD security descriptor
 * (msDS-AllowedToActOnBehalfOfOtherIdentity) and emit one RBCD finding per
 * allowed trustee. The principals in this DACL are exactly those permitted
 * to impersonate to the owning computer.
 */
_Must_inspect_result_
static HRESULT
KestrelEmitRbcdFromSd(
    _In_     PSECURITY_DESCRIPTOR       pSD,
    _In_z_   LPCWSTR                    pwszDN,
    _In_z_   LPCWSTR                    pwszSam,
    _In_z_   LPCWSTR                    pwszClass,
    _Inout_  KESTREL_DELEG_SCAN_RESULT *pResult)
{
    PACL pDacl = NULL;
    BOOL bPresent = FALSE, bDefault = FALSE;

    if (!IsValidSecurityDescriptor(pSD))                                 return S_OK;
    if (!GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefault))   return S_OK;
    if (!bPresent || !pDacl)                                             return S_OK;

    ACL_SIZE_INFORMATION aclInfo = { 0 };
    if (!GetAclInformation(pDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation))
        return S_OK;

    for (DWORD i = 0; i < aclInfo.AceCount; i++) {
        LPVOID pAce = NULL;
        if (!GetAce(pDacl, i, &pAce)) continue;

        DWORD  dwMask   = 0;
        PSID   pSid     = NULL;
        GUID  *pObjType = NULL;
        BOOL   bDeny    = FALSE;

        if (!KestrelAceDecode(pAce, &dwMask, &pSid, &pObjType, &bDeny)) continue;
        if (bDeny || !pSid) continue;   /* RBCD is expressed as allow ACEs */

        KESTREL_DELEG_FINDING f = { 0 };
        f.Kind = DELEG_RBCD;
        StringCchCopyW(f.wszDN,          ARRAYSIZE(f.wszDN),          pwszDN);
        StringCchCopyW(f.wszSam,         ARRAYSIZE(f.wszSam),         pwszSam);
        StringCchCopyW(f.wszObjectClass, ARRAYSIZE(f.wszObjectClass), pwszClass);

        LPWSTR pwszSidStr = NULL;
        if (ConvertSidToStringSidW(pSid, &pwszSidStr) && pwszSidStr) {
            StringCchCopyW(f.wszDetail, ARRAYSIZE(f.wszDetail), pwszSidStr);
            LocalFree(pwszSidStr);
        } else {
            StringCchCopyW(f.wszDetail, ARRAYSIZE(f.wszDetail), L"(invalid SID)");
        }

        HRESULT hr = KestrelDelegResultAppend(pResult, &f);
        if (FAILED(hr)) return hr;
    }
    return S_OK;
}

/*
 * KestrelScanDelegation — PART C implementation.
 */
_Must_inspect_result_
HRESULT
KestrelScanDelegation(
    _In_z_   LPCWSTR                     pwszDomainNC,
    _Outptr_ KESTREL_DELEG_SCAN_RESULT **ppResult)
{
    HRESULT                    hr      = S_OK;
    IDirectorySearch          *pSearch = NULL;
    ADS_SEARCH_HANDLE          hSearch = NULL;
    KESTREL_DELEG_SCAN_RESULT *pResult = NULL;
    WCHAR                      wszPath[512];

    if (!pwszDomainNC || !ppResult) return E_INVALIDARG;
    *ppResult = NULL;

    pResult = (KESTREL_DELEG_SCAN_RESULT *)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, sizeof(*pResult));
    if (!pResult) return E_OUTOFMEMORY;

    hr = StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszDomainNC);
    if (FAILED(hr)) goto Cleanup;

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pSearch);
    if (FAILED(hr)) {
        wprintf(L"  [!] KestrelScanDelegation: ADsGetObject failed 0x%08X\n", hr);
        goto Cleanup;
    }

    ADS_SEARCHPREF_INFO prefs[2];
    prefs[0].dwSearchPref  = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref  = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);
    if (FAILED(hr)) goto Cleanup;

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
        KESTREL_DELEG_FILTER,
        (LPWSTR *)g_rgszDelegAttrs, KESTREL_DELEG_ATTR_COUNT,
        &hSearch);
    if (FAILED(hr)) goto Cleanup;

    wprintf(L"  [*] Scanning Kerberos delegation surface...\n\n");
    wprintf(L"  %-52s %-22s %-26s %s\n",
        L"Object", L"sAMAccountName", L"Kind", L"Detail");
    wprintf(L"  %s\n",
        L"--------------------------------------------------------------------------------"
        L"--------------------------------------------------");

    while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {

        ADS_SEARCH_COLUMN colDN    = { 0 };
        ADS_SEARCH_COLUMN colSam   = { 0 };
        ADS_SEARCH_COLUMN colClass = { 0 };
        ADS_SEARCH_COLUMN colUac   = { 0 };
        ADS_SEARCH_COLUMN colA2D   = { 0 };  /* msDS-AllowedToDelegateTo            */
        ADS_SEARCH_COLUMN colRbcd  = { 0 };  /* msDS-AllowedToActOnBehalfOfOtherId. */

        WCHAR wszDN[512]   = { 0 };
        WCHAR wszSam[64]   = L"-";
        WCHAR wszClass[64] = L"unknown";
        DWORD dwUac        = 0;

        BOOL bGotDN   = FALSE, bGotSam = FALSE, bGotClass = FALSE;
        BOOL bGotUac  = FALSE, bGotA2D = FALSE, bGotRbcd  = FALSE;

        /* distinguishedName (mandatory) */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"distinguishedName", &colDN)) &&
            colDN.dwNumValues > 0 &&
            colDN.pADsValues[0].dwType == ADSTYPE_DN_STRING) {
            StringCchCopyW(wszDN, ARRAYSIZE(wszDN), colDN.pADsValues[0].DNString);
            bGotDN = TRUE;
            pSearch->lpVtbl->FreeColumn(pSearch, &colDN);
        }
        if (!bGotDN) { pResult->cObjectsErrored++; continue; }

        /* sAMAccountName */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"sAMAccountName", &colSam)) &&
            colSam.dwNumValues > 0 &&
            colSam.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING) {
            StringCchCopyW(wszSam, ARRAYSIZE(wszSam),
                colSam.pADsValues[0].CaseIgnoreString);
            bGotSam = TRUE;
        }
        if (bGotSam) pSearch->lpVtbl->FreeColumn(pSearch, &colSam);

        /* objectClass — take most specific (last) */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"objectClass", &colClass)) &&
            colClass.dwNumValues > 0) {
            DWORD iLast = colClass.dwNumValues - 1;
            if (colClass.pADsValues[iLast].dwType == ADSTYPE_CASE_IGNORE_STRING)
                StringCchCopyW(wszClass, ARRAYSIZE(wszClass),
                    colClass.pADsValues[iLast].CaseIgnoreString);
            bGotClass = TRUE;
            pSearch->lpVtbl->FreeColumn(pSearch, &colClass);
        }

        /* userAccountControl */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"userAccountControl", &colUac)) &&
            colUac.dwNumValues > 0 &&
            colUac.pADsValues[0].dwType == ADSTYPE_INTEGER) {
            dwUac = (DWORD)colUac.pADsValues[0].Integer;
            bGotUac = TRUE;
        }
        if (bGotUac) pSearch->lpVtbl->FreeColumn(pSearch, &colUac);

        /* ── Classify ───────────────────────────────────────────────── */

        /* 1) Unconstrained — TGT forwarded to any service this host runs */
        if (dwUac & KESTREL_UAC_TRUSTED_FOR_DELEGATION) {
            KESTREL_DELEG_FINDING f = { 0 };
            f.Kind = DELEG_UNCONSTRAINED;
            StringCchCopyW(f.wszDN,          ARRAYSIZE(f.wszDN),          wszDN);
            StringCchCopyW(f.wszSam,         ARRAYSIZE(f.wszSam),         wszSam);
            StringCchCopyW(f.wszObjectClass, ARRAYSIZE(f.wszObjectClass), wszClass);
            StringCchCopyW(f.wszDetail,      ARRAYSIZE(f.wszDetail),
                L"(forwards TGT to any service)");
            hr = KestrelDelegResultAppend(pResult, &f);
            if (FAILED(hr)) goto RowCleanup;
        }

        /* 2) Constrained — one finding per target SPN; protocol transition
              (S4U2Self) distinguished by the TRUSTED_TO_AUTH bit. */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"msDS-AllowedToDelegateTo", &colA2D)) &&
            colA2D.dwNumValues > 0) {
            bGotA2D = TRUE;
            BOOL bProtoTrans = !!(dwUac & KESTREL_UAC_TRUSTED_TO_AUTH_FOR_DELEGATION);

            for (DWORD i = 0; i < colA2D.dwNumValues; i++) {
                if (colA2D.pADsValues[i].dwType != ADSTYPE_CASE_IGNORE_STRING)
                    continue;

                KESTREL_DELEG_FINDING f = { 0 };
                f.Kind = bProtoTrans ? DELEG_CONSTRAINED_PROTOTRANS
                                     : DELEG_CONSTRAINED;
                StringCchCopyW(f.wszDN,          ARRAYSIZE(f.wszDN),          wszDN);
                StringCchCopyW(f.wszSam,         ARRAYSIZE(f.wszSam),         wszSam);
                StringCchCopyW(f.wszObjectClass, ARRAYSIZE(f.wszObjectClass), wszClass);
                StringCchCopyW(f.wszDetail,      ARRAYSIZE(f.wszDetail),
                    colA2D.pADsValues[i].CaseIgnoreString);

                hr = KestrelDelegResultAppend(pResult, &f);
                if (FAILED(hr)) { pSearch->lpVtbl->FreeColumn(pSearch, &colA2D);
                                  goto RowCleanup; }
            }
        }
        if (bGotA2D) pSearch->lpVtbl->FreeColumn(pSearch, &colA2D);

        /* 3) RBCD — parse the SD blob, one finding per allowed principal */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"msDS-AllowedToActOnBehalfOfOtherIdentity", &colRbcd)) &&
            colRbcd.dwNumValues > 0 &&
            colRbcd.pADsValues[0].dwType == ADSTYPE_PROV_SPECIFIC &&
            colRbcd.pADsValues[0].ProviderSpecific.lpValue) {
            bGotRbcd = TRUE;
            PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)
                colRbcd.pADsValues[0].ProviderSpecific.lpValue;
            hr = KestrelEmitRbcdFromSd(pSD, wszDN, wszSam, wszClass, pResult);
            if (FAILED(hr)) { pSearch->lpVtbl->FreeColumn(pSearch, &colRbcd);
                              goto RowCleanup; }
        }
        if (bGotRbcd) pSearch->lpVtbl->FreeColumn(pSearch, &colRbcd);

        pResult->cObjectsScanned++;
        continue;

    RowCleanup:
        /* hr already set to a failure; columns for this row freed above as
           reached. Bail out of the loop on hard allocation failure. */
        goto Cleanup;
    }

    /* ── Print findings ───────────────────────────────────────────────── */
    {
        static const LPCWSTR rgszKind[] = {
            L"Unconstrained",
            L"Constrained (Kerberos)",
            L"Constrained + S4U2Self",
            L"RBCD (allowed principal)"
        };
        for (DWORD i = 0; i < pResult->cFindings; i++) {
            KESTREL_DELEG_FINDING *pF = &pResult->rgFindings[i];
            LPCWSTR pwszKind = (pF->Kind < ARRAYSIZE(rgszKind))
                ? rgszKind[pF->Kind] : L"?";
            wprintf(L"  %-52s %-22s %-26s %s\n",
                pF->wszDN, pF->wszSam, pwszKind, pF->wszDetail);
        }
    }

    wprintf(L"\n  [*] Objects with delegation set: %lu  |  Findings: %lu  |  Errors: %lu\n",
        pResult->cObjectsScanned, pResult->cFindings, pResult->cObjectsErrored);

    *ppResult = pResult;
    pResult   = NULL;

Cleanup:
    if (hSearch && pSearch)
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    if (pResult) KestrelFreeDelegScanResult(pResult);
    return hr;
}

VOID
KestrelFreeDelegScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_DELEG_SCAN_RESULT *pResult)
{
    if (!pResult) return;
    if (pResult->rgFindings)
        HeapFree(GetProcessHeap(), 0, pResult->rgFindings);
    HeapFree(GetProcessHeap(), 0, pResult);
}


/* ═════════════════════════════════════════════════════════════════════════
 * PART D — LAPS readability (who can read the local-admin password)
 *
 * Passive, DC-only, ordinary domain-user rights. We answer the audit
 * question "which principals are permitted to read the LAPS attribute" — we
 * never read the secret itself (it is ACL-protected and confidential).
 *
 * Method:
 *   1. Resolve the schemaIDGUID of the LAPS attributes from CN=Schema. Their
 *      presence also tells us which LAPS generation is deployed:
 *        legacy  : ms-Mcs-AdmPwd
 *        Windows : msLAPS-Password, msLAPS-EncryptedPassword
 *   2. Enumerate computer objects with DACL_SECURITY_INFORMATION and, for
 *      each, find ACEs that grant a read of the LAPS attribute:
 *        - an object ACE whose ObjectType == a LAPS schemaIDGUID with
 *          ReadProperty or Control-Access (confidential attrs need CR too); or
 *        - an all-properties ACE (no ObjectType) with ReadProperty/GenericRead; or
 *        - GenericAll.
 *
 * Domain Admins / SYSTEM reading LAPS is expected by design; the audit signal
 * is *delegated* or unexpected readers. SYSTEM (S-1-5-18) is filtered out as
 * pure noise; everything else is reported.
 * ═════════════════════════════════════════════════════════════════════════ */

#define KESTREL_LAPS_MAX_ATTRS 3

static LPWSTR g_rgszLapsObjAttrs[] = {
    L"distinguishedName",
    L"nTSecurityDescriptor"
};
#define KESTREL_LAPS_OBJ_ATTR_COUNT \
    (sizeof(g_rgszLapsObjAttrs) / sizeof(g_rgszLapsObjAttrs[0]))

typedef struct _KESTREL_LAPS_ATTR {
    GUID    guid;
    WCHAR   wszName[64];
    BOOL    bValid;
} KESTREL_LAPS_ATTR;

/*
 * Resolve schemaIDGUID for one attribute lDAPDisplayName under CN=Schema.
 * schemaIDGUID is the raw 16-byte GUID in the same layout as a GUID struct,
 * so it is memcpy-comparable against an ACE ObjectType. Sets *pbFound=FALSE
 * (and returns S_OK) when the attribute is not in the schema.
 */
_Must_inspect_result_
static HRESULT
KestrelResolveSchemaGuid(
    _In_z_ LPCWSTR pwszSchemaNC,
    _In_z_ LPCWSTR pwszLdapName,
    _Out_  GUID   *pGuid,
    _Out_  BOOL   *pbFound)
{
    HRESULT           hr      = S_OK;
    IDirectorySearch *pSearch = NULL;
    ADS_SEARCH_HANDLE hSearch = NULL;
    WCHAR             wszPath[600];
    WCHAR             wszFilter[256];
    LPWSTR            attrs[] = { L"schemaIDGUID" };

    ZeroMemory(pGuid, sizeof(*pGuid));
    *pbFound = FALSE;

    hr = StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszSchemaNC);
    if (FAILED(hr)) return hr;

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pSearch);
    if (FAILED(hr)) return hr;

    ADS_SEARCHPREF_INFO prefs[2];
    prefs[0].dwSearchPref  = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_ONELEVEL;
    prefs[1].dwSearchPref  = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = 50;

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);
    if (FAILED(hr)) goto Cleanup;

    hr = StringCchPrintfW(wszFilter, ARRAYSIZE(wszFilter),
        L"(lDAPDisplayName=%s)", pwszLdapName);
    if (FAILED(hr)) goto Cleanup;

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch, wszFilter, attrs, 1, &hSearch);
    if (FAILED(hr)) goto Cleanup;

    if (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN col = { 0 };
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"schemaIDGUID", &col)) &&
            col.dwNumValues > 0 &&
            col.pADsValues[0].dwType == ADSTYPE_OCTET_STRING &&
            col.pADsValues[0].OctetString.lpValue &&
            col.pADsValues[0].OctetString.dwLength >= sizeof(GUID)) {
            CopyMemory(pGuid, col.pADsValues[0].OctetString.lpValue, sizeof(GUID));
            *pbFound = TRUE;
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }
    }

Cleanup:
    if (hSearch && pSearch)
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    return hr;
}

_Must_inspect_result_
static HRESULT
KestrelLapsResultAppend(
    _Inout_     KESTREL_LAPS_SCAN_RESULT *pResult,
    _In_  const KESTREL_LAPS_READER      *pReader)
{
    if (pResult->cReaders == pResult->cCapacity) {
        DWORD cNew = pResult->cCapacity ? pResult->cCapacity * 2 : 256;
        KESTREL_LAPS_READER *pNew = (KESTREL_LAPS_READER *)HeapReAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY,
            pResult->rgReaders, cNew * sizeof(KESTREL_LAPS_READER));
        if (!pNew) return E_OUTOFMEMORY;
        pResult->rgReaders  = pNew;
        pResult->cCapacity  = cNew;
    }
    pResult->rgReaders[pResult->cReaders++] = *pReader;
    return S_OK;
}

/*
 * Walk one computer's DACL and emit LAPS-reader findings.
 */
_Must_inspect_result_
static HRESULT
KestrelEmitLapsReadersFromSd(
    _In_      PSECURITY_DESCRIPTOR        pSD,
    _In_z_    LPCWSTR                     pwszComputerDN,
    _In_reads_(cAttrs) const KESTREL_LAPS_ATTR *rgAttrs,
    _In_      DWORD                       cAttrs,
    _Inout_   KESTREL_LAPS_SCAN_RESULT   *pResult)
{
    PACL pDacl = NULL;
    BOOL bPresent = FALSE, bDefault = FALSE;

    if (!IsValidSecurityDescriptor(pSD))                               return S_OK;
    if (!GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefault)) return S_OK;
    if (!bPresent || !pDacl)                                           return S_OK;

    ACL_SIZE_INFORMATION aclInfo = { 0 };
    if (!GetAclInformation(pDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation))
        return S_OK;

    for (DWORD i = 0; i < aclInfo.AceCount; i++) {
        LPVOID pAce = NULL;
        if (!GetAce(pDacl, i, &pAce)) continue;

        DWORD  dwMask   = 0;
        PSID   pSid     = NULL;
        GUID  *pObjType = NULL;
        BOOL   bDeny    = FALSE;

        if (!KestrelAceDecode(pAce, &dwMask, &pSid, &pObjType, &bDeny)) continue;
        if (bDeny || !pSid) continue;

        BOOL    bGrants    = FALSE;
        BOOL    bAllProps  = FALSE;
        LPCWSTR pwszAttr   = L"(LAPS)";

        if (dwMask & GENERIC_ALL) {
            bGrants = TRUE; bAllProps = TRUE; pwszAttr = L"(GenericAll)";
        }
        else if (pObjType) {
            /* Object ACE on a specific attribute: must match a LAPS GUID and
               grant ReadProperty or Control-Access (confidential read). */
            if (dwMask & (ADS_RIGHT_DS_READ_PROP | ADS_RIGHT_DS_CONTROL_ACCESS)) {
                for (DWORD a = 0; a < cAttrs; a++) {
                    if (rgAttrs[a].bValid &&
                        IsEqualGUID(pObjType, &rgAttrs[a].guid)) {
                        bGrants  = TRUE;
                        pwszAttr = rgAttrs[a].wszName;
                        break;
                    }
                }
            }
        }
        else {
            /* All-properties ACE (no ObjectType): reads every attribute,
               LAPS included. */
            if (dwMask & (ADS_RIGHT_DS_READ_PROP | ADS_RIGHT_GENERIC_READ)) {
                bGrants = TRUE; bAllProps = TRUE; pwszAttr = L"(all properties)";
            }
        }

        if (!bGrants) continue;

        LPWSTR pwszSidStr = NULL;
        if (!ConvertSidToStringSidW(pSid, &pwszSidStr) || !pwszSidStr)
            continue;

        /* Filter SYSTEM as pure noise; keep DA/EA visible for completeness. */
        if (_wcsicmp(pwszSidStr, L"S-1-5-18") == 0) { LocalFree(pwszSidStr); continue; }

        KESTREL_LAPS_READER r = { 0 };
        StringCchCopyW(r.wszComputerDN, ARRAYSIZE(r.wszComputerDN), pwszComputerDN);
        StringCchCopyW(r.wszTrusteeSid, ARRAYSIZE(r.wszTrusteeSid), pwszSidStr);
        StringCchCopyW(r.wszAttr,       ARRAYSIZE(r.wszAttr),       pwszAttr);
        r.bAllProperties = bAllProps;
        LocalFree(pwszSidStr);

        HRESULT hr = KestrelLapsResultAppend(pResult, &r);
        if (FAILED(hr)) return hr;
    }
    return S_OK;
}

/*
 * KestrelScanLapsReaders — PART D implementation.
 */
_Must_inspect_result_
HRESULT
KestrelScanLapsReaders(
    _In_z_   LPCWSTR                    pwszDomainNC,
    _In_z_   LPCWSTR                    pwszConfigNC,
    _Outptr_ KESTREL_LAPS_SCAN_RESULT **ppResult)
{
    HRESULT                   hr      = S_OK;
    IDirectorySearch         *pSearch = NULL;
    ADS_SEARCH_HANDLE         hSearch = NULL;
    KESTREL_LAPS_SCAN_RESULT *pResult = NULL;
    WCHAR                     wszConfigNC[512];
    WCHAR                     wszSchemaNC[600];
    WCHAR                     wszPath[512];

    KESTREL_LAPS_ATTR rgAttrs[KESTREL_LAPS_MAX_ATTRS] = { 0 };
    DWORD             cAttrs = 0;

    if (!pwszDomainNC || !ppResult) return E_INVALIDARG;
    *ppResult = NULL;

    pResult = (KESTREL_LAPS_SCAN_RESULT *)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, sizeof(*pResult));
    if (!pResult) return E_OUTOFMEMORY;

    /* ── 1. Resolve configNC → schemaNC ───────────────────────────────── */
    if (pwszConfigNC && *pwszConfigNC != L'\0') {
        StringCchCopyW(wszConfigNC, ARRAYSIZE(wszConfigNC), pwszConfigNC);
    } else {
        hr = KestrelGetConfigNC(wszConfigNC, ARRAYSIZE(wszConfigNC));
        if (FAILED(hr)) {
            wprintf(L"  [!] Failed to resolve configNC: 0x%08X\n", hr);
            goto Cleanup;
        }
    }
    hr = StringCchPrintfW(wszSchemaNC, ARRAYSIZE(wszSchemaNC),
        L"CN=Schema,%s", wszConfigNC);
    if (FAILED(hr)) goto Cleanup;

    /* ── 2. Resolve LAPS attribute GUIDs / presence ───────────────────── */
    {
        static const LPCWSTR rgszLapsNames[] = {
            L"ms-Mcs-AdmPwd",          /* legacy LAPS  */
            L"msLAPS-Password",        /* Windows LAPS */
            L"msLAPS-EncryptedPassword"
        };
        for (DWORD i = 0; i < ARRAYSIZE(rgszLapsNames) && cAttrs < KESTREL_LAPS_MAX_ATTRS; i++) {
            GUID  g = { 0 };
            BOOL  bFound = FALSE;
            HRESULT hrG = KestrelResolveSchemaGuid(wszSchemaNC, rgszLapsNames[i],
                                                   &g, &bFound);
            if (FAILED(hrG)) continue;          /* tolerate per-attr failure */
            if (!bFound) continue;

            rgAttrs[cAttrs].guid   = g;
            rgAttrs[cAttrs].bValid = TRUE;
            StringCchCopyW(rgAttrs[cAttrs].wszName,
                ARRAYSIZE(rgAttrs[cAttrs].wszName), rgszLapsNames[i]);
            cAttrs++;

            if (i == 0) pResult->bLegacyLapsPresent  = TRUE;
            else        pResult->bWindowsLapsPresent = TRUE;
        }
    }

    wprintf(L"  [*] LAPS schema: legacy(ms-Mcs-AdmPwd)=%s  windows(msLAPS-*)=%s\n",
        pResult->bLegacyLapsPresent  ? L"yes" : L"no",
        pResult->bWindowsLapsPresent ? L"yes" : L"no");

    if (cAttrs == 0) {
        wprintf(L"  [*] No LAPS attributes present in schema — nothing to enumerate.\n");
        *ppResult = pResult;
        pResult   = NULL;
        goto Cleanup;   /* S_OK with an empty, informative result */
    }

    /* ── 3. Enumerate computers, read DACL ─────────────────────────────── */
    hr = StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszDomainNC);
    if (FAILED(hr)) goto Cleanup;

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pSearch);
    if (FAILED(hr)) {
        wprintf(L"  [!] KestrelScanLapsReaders: ADsGetObject failed 0x%08X\n", hr);
        goto Cleanup;
    }

    ADS_SEARCHPREF_INFO prefs[3];
    prefs[0].dwSearchPref  = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref  = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    prefs[2].dwSearchPref  = ADS_SEARCHPREF_SECURITY_MASK;
    prefs[2].vValue.dwType = ADSTYPE_INTEGER;
    prefs[2].vValue.Integer = 0x4;   /* DACL_SECURITY_INFORMATION — domain-user readable */

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 3);
    if (FAILED(hr)) goto Cleanup;

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
        L"(objectClass=computer)",
        (LPWSTR *)g_rgszLapsObjAttrs, KESTREL_LAPS_OBJ_ATTR_COUNT,
        &hSearch);
    if (FAILED(hr)) goto Cleanup;

    wprintf(L"  [*] Enumerating LAPS readers on computer objects...\n\n");
    wprintf(L"  %-56s %-26s %s\n", L"Computer", L"Reader SID", L"Grants");
    wprintf(L"  %s\n",
        L"--------------------------------------------------------------------------------"
        L"------------------------------");

    while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {

        ADS_SEARCH_COLUMN colDN = { 0 };
        ADS_SEARCH_COLUMN colSD = { 0 };
        WCHAR wszDN[512] = { 0 };
        BOOL  bGotDN = FALSE, bGotSD = FALSE;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"distinguishedName", &colDN)) &&
            colDN.dwNumValues > 0 &&
            colDN.pADsValues[0].dwType == ADSTYPE_DN_STRING) {
            StringCchCopyW(wszDN, ARRAYSIZE(wszDN), colDN.pADsValues[0].DNString);
            bGotDN = TRUE;
            pSearch->lpVtbl->FreeColumn(pSearch, &colDN);
        }
        if (!bGotDN) { pResult->cComputersErrored++; continue; }

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                L"nTSecurityDescriptor", &colSD)) &&
            colSD.dwNumValues > 0 &&
            colSD.pADsValues[0].dwType == ADSTYPE_PROV_SPECIFIC &&
            colSD.pADsValues[0].ProviderSpecific.lpValue) {
            bGotSD = TRUE;
            PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)
                colSD.pADsValues[0].ProviderSpecific.lpValue;
            hr = KestrelEmitLapsReadersFromSd(pSD, wszDN, rgAttrs, cAttrs, pResult);
            if (FAILED(hr)) { pSearch->lpVtbl->FreeColumn(pSearch, &colSD); goto Cleanup; }
            pResult->cComputersScanned++;
        } else {
            pResult->cComputersErrored++;
        }
        if (bGotSD) pSearch->lpVtbl->FreeColumn(pSearch, &colSD);
    }

    for (DWORD i = 0; i < pResult->cReaders; i++) {
        KESTREL_LAPS_READER *pR = &pResult->rgReaders[i];
        wprintf(L"  %-56s %-26s %s\n",
            pR->wszComputerDN, pR->wszTrusteeSid, pR->wszAttr);
    }

    wprintf(L"\n  [*] Computers scanned: %lu  |  Reader grants: %lu  |  Errors: %lu\n",
        pResult->cComputersScanned, pResult->cReaders, pResult->cComputersErrored);
    wprintf(L"  [*] Note: Domain/Enterprise Admins reading LAPS is by design; "
            L"the signal is delegated/unexpected principals.\n");

    *ppResult = pResult;
    pResult   = NULL;

Cleanup:
    if (hSearch && pSearch)
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    if (pResult) KestrelFreeLapsScanResult(pResult);
    return hr;
}

VOID
KestrelFreeLapsScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_LAPS_SCAN_RESULT *pResult)
{
    if (!pResult) return;
    if (pResult->rgReaders)
        HeapFree(GetProcessHeap(), 0, pResult->rgReaders);
    HeapFree(GetProcessHeap(), 0, pResult);
}

/* ════════════════════════════════════════════════════════════════════════════
 * KestrelAnalyzeDCSync  —  post-process pACL, no LDAP traffic
 *
 * Walks already-collected ACL edges and finds principals with:
 *   DS-Replication-Get-Changes     {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}
 *   DS-Replication-Get-Changes-All {1131f6ab-9c07-11d1-f79f-00c04fc2dcd2}
 *
 * A principal with BOTH rights can execute a DCSync attack (mimikatz
 * lsadump::dcsync) and dump all password hashes without touching any DC disk.
 *
 * Expected default principals (marked [expected] in output):
 *   S-1-5-9          — Enterprise Domain Controllers (built-in)
 *   S-1-5-21-*-516   — Domain Controllers group
 *   S-1-5-32-544     — Administrators (builtin)
 *
 * Any other principal with GetChangesAll is CRITICAL.
 *
 * Returns: count of non-expected principals with full DCSync capability.
 * ════════════════════════════════════════════════════════════════════════════ */

#define DCSYNC_GUID_CHANGES     L"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
#define DCSYNC_GUID_CHANGES_ALL L"1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"

#define DCSYNC_RIGHT_CHANGES     0x1u
#define DCSYNC_RIGHT_CHANGES_ALL 0x2u
#define DCSYNC_FULL              (DCSYNC_RIGHT_CHANGES | DCSYNC_RIGHT_CHANGES_ALL)

#define DCSYNC_MAX_ENTRIES 256u

typedef struct _DCSYNC_ENTRY {
    WCHAR wszSid[128];
    DWORD dwRights;
} DCSYNC_ENTRY;

/*
 * Match a GUID string that may or may not be wrapped in braces.
 * Comparison is case-insensitive.
 */
static BOOL
_DCSync_GuidMatch(
    _In_z_ LPCWSTR pwszGuid,
    _In_z_ LPCWSTR pwszTarget)
{
    if (!pwszGuid || !*pwszGuid)
        return FALSE;

    /* Skip leading brace */
    if (pwszGuid[0] == L'{')
        pwszGuid++;

    WCHAR szCopy[64] = { 0 };
    StringCchCopyW(szCopy, ARRAYSIZE(szCopy), pwszGuid);

    /* Trim trailing brace */
    SIZE_T cch = wcslen(szCopy);
    if (cch > 0 && szCopy[cch - 1] == L'}')
        szCopy[cch - 1] = L'\0';

    return (_wcsicmp(szCopy, pwszTarget) == 0);
}

/*
 * Returns TRUE if the SID is one of the well-known default principals
 * that legitimately hold replication rights in every domain.
 */
static BOOL
_DCSync_IsExpected(_In_z_ LPCWSTR pwszSid)
{
    if (!pwszSid)
        return FALSE;

    /* S-1-5-9  — Enterprise Domain Controllers */
    if (_wcsicmp(pwszSid, L"S-1-5-9") == 0)
        return TRUE;

    /* S-1-5-32-544  — BUILTIN\Administrators */
    if (_wcsicmp(pwszSid, L"S-1-5-32-544") == 0)
        return TRUE;

    /* S-1-5-21-*-516  — Domain Controllers group (RID 516) */
    SIZE_T cch = wcslen(pwszSid);
    if (cch >= 4 &&
        _wcsicmp(pwszSid + cch - 4, L"-516") == 0 &&
        wcsncmp(pwszSid, L"S-1-5-21-", 9) == 0)
        return TRUE;

    /* S-1-5-21-*-519  — Enterprise Admins (expected in forest root) */
    if (cch >= 4 &&
        _wcsicmp(pwszSid + cch - 4, L"-519") == 0 &&
        wcsncmp(pwszSid, L"S-1-5-21-", 9) == 0)
        return TRUE;

    return FALSE;
}

_Must_inspect_result_
DWORD KestrelAnalyzeDCSync(
    _In_opt_ const KESTREL_ACL_SCAN_RESULT* pACL)
{
    if (!pACL || pACL->cEdges == 0) {
        wprintf(L"  [!] No ACL data — run with --acl first\n\n");
        return 0;
    }

    /* Local deduplication table — stack-allocated, no heap needed */
    DCSYNC_ENTRY entries[DCSYNC_MAX_ENTRIES];
    DWORD        cEntries = 0;
    ZeroMemory(entries, sizeof(entries));

    /* ── Walk every collected ACL edge ─────────────────────────── */
    for (DWORD i = 0; i < pACL->cEdges; i++) {
        const KESTREL_ACL_EDGE* pE = &pACL->rgEdges[i];

        /* Only allow-ACEs on ExtendedRight type */
        if (pE->bDeny)
            continue;
        if (pE->EdgeType != EDGE_EXTENDED_RIGHT)
            continue;

        /* Target must be the domain root object */
        if (_wcsicmp(pE->wszObjectClass, L"domainDNS") != 0)
            continue;

        /* Identify which replication right this edge grants */
        DWORD dwRight = 0;
        if (_DCSync_GuidMatch(pE->wszRightGuid, DCSYNC_GUID_CHANGES))
            dwRight = DCSYNC_RIGHT_CHANGES;
        else if (_DCSync_GuidMatch(pE->wszRightGuid, DCSYNC_GUID_CHANGES_ALL))
            dwRight = DCSYNC_RIGHT_CHANGES_ALL;
        else
            continue;

        /* Find existing entry for this trustee or create one */
        DWORD iEntry = DCSYNC_MAX_ENTRIES;
        for (DWORD j = 0; j < cEntries; j++) {
            if (_wcsicmp(entries[j].wszSid, pE->wszTrusteeSid) == 0) {
                iEntry = j;
                break;
            }
        }
        if (iEntry == DCSYNC_MAX_ENTRIES) {
            if (cEntries >= DCSYNC_MAX_ENTRIES)
                continue;   /* overflow guard — unlikely in any real domain */
            iEntry = cEntries++;
            StringCchCopyW(entries[iEntry].wszSid,
                ARRAYSIZE(entries[iEntry].wszSid),
                pE->wszTrusteeSid);
        }

        entries[iEntry].dwRights |= dwRight;
    }

    /* ── Tally ──────────────────────────────────────────────────── */
    DWORD cCritical = 0;
    DWORD cExpected = 0;

    for (DWORD i = 0; i < cEntries; i++) {
        BOOL bExpected = _DCSync_IsExpected(entries[i].wszSid);
        if (!bExpected && (entries[i].dwRights & DCSYNC_RIGHT_CHANGES_ALL))
            cCritical++;
        if (bExpected)
            cExpected++;
    }

    /* ── Console output ─────────────────────────────────────────── */
    wprintf(L"  Principals found: %lu total  |  %lu critical  |  %lu expected-default\n",
        cEntries, cCritical, cExpected);

    if (cEntries == 0) {
        wprintf(L"  [+] No DCSync-related rights found in ACL data\n\n");
        return 0;
    }

    wprintf(L"\n  %-64s  %-10s  %s\n",
        L"Trustee SID", L"Status", L"Rights granted");
    wprintf(L"  ────────────────────────────────────────────────────────────"
        L"──────────────────────────────────────────────────\n");

    for (DWORD i = 0; i < cEntries; i++) {
        BOOL    bExpected = _DCSync_IsExpected(entries[i].wszSid);
        LPCWSTR pwszStatus;
        WCHAR   wszRights[96] = { 0 };

        /* Build rights string */
        if ((entries[i].dwRights & DCSYNC_RIGHT_CHANGES) &&
            (entries[i].dwRights & DCSYNC_RIGHT_CHANGES_ALL))
            StringCchCopyW(wszRights, ARRAYSIZE(wszRights),
                L"GetChanges + GetChangesAll");
        else if (entries[i].dwRights & DCSYNC_RIGHT_CHANGES_ALL)
            StringCchCopyW(wszRights, ARRAYSIZE(wszRights), L"GetChangesAll");
        else
            StringCchCopyW(wszRights, ARRAYSIZE(wszRights), L"GetChanges");

        /* Status label */
        if (bExpected) {
            pwszStatus = L"[expected]";
        }
        else if (entries[i].dwRights & DCSYNC_RIGHT_CHANGES_ALL) {
            pwszStatus = L"CRITICAL  ";   /* can DCSync or is one right away  */
        }
        else {
            pwszStatus = L"partial   ";   /* GetChanges only — incomplete     */
        }

        wprintf(L"  %-64s  %-10s  %s\n",
            entries[i].wszSid, pwszStatus, wszRights);
    }

    if (cCritical > 0) {
        wprintf(L"\n  [!] %lu non-default principal(s) hold GetChangesAll —"
            L" DCSync attack is possible.\n", cCritical);
        wprintf(L"      Resolve SIDs with: Get-ADObject -Filter"
            L" {objectSID -eq '<SID>'} | Select Name\n");
    }
    else {
        wprintf(L"\n  [+] No unexpected DCSync rights detected.\n");
    }

    wprintf(L"\n");
    return cCritical;
}