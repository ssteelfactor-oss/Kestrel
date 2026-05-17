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
    L"nTSecurityDescriptor"
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

 /* Most Generic ADS Rights — bitmask of all possible الحقوق     */
#define ADS_RIGHT_ALL            (ADS_RIGHT_READ_PROP            | \
                                 ADS_RIGHT_WRITE_PROP           | \
                                 ADS_RIGHT_APPEND              | \
                                 ADS_RIGHT_READ_ATTRS          | \
                                 ADS_RIGHT_WRITE_ATTRS         | \
                                 ADS_RIGHT_CREATE_CHILD        | \
                                 ADS_RIGHT_DELETE_CHILD        | \
                                 ADS_RIGHT_READ_OWN            | \
                                 ADS_RIGHT_WRITE_OWN           | \
                                 ADS_RIGHT_READ_ACL            | \
                                 ADS_RIGHT_WRITE_ACL           | \
                                 ADS_RIGHT_DELETE               | \
                                 ADS_RIGHT_EXECUTE             | \
                                 ADS_RIGHT_CONTROL             | \
                                 ADS_RIGHT_GENERIC_ALL         )

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
    _Inout_  KESTREL_ACL_SCAN_RESULT* pResult
);

/*
 * Main entry point — orchestrates all three phases across the full domain.
 *
 * Executes IDirectorySearch with KESTREL_ACL_FILTER against pwszDomainNC.
 * For each result object: binds IDirectoryObject, retrieves SD, walks DACL.
 *
 * Parameters:
 *   pwszDomainNC    — defaultNamingContext from rootDSE
 *   pwszConfigNC    — configurationNamingContext from rootDSE
 *   ppResult        — receives allocated KESTREL_ACL_SCAN_RESULT; free via
 *                     KestrelFreeACLScanResult
 *
 * Returns S_OK even if some objects errored (check pResult->cObjectsErrored).
 * Returns failure HRESULT only if the LDAP search itself cannot be initiated.
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

_Must_inspect_result_
HRESULT
KestrelScanACLEdges(
    _In_z_   LPCWSTR                  pwszDomainNC,
    _In_z_   LPCWSTR                  pwszConfigNC,
    _Outptr_ KESTREL_ACL_SCAN_RESULT** ppResult)
{
    HRESULT                  hr = S_OK;
    KESTREL_EXTENDED_RIGHT* pRights = NULL;
    KESTREL_ACL_SCAN_RESULT* pResult = NULL;
    IDirectorySearch* pSearch = NULL;
    ADS_SEARCH_HANDLE        hSearch = NULL;
    WCHAR                    wszPath[512];
    WCHAR                    wszConfigNC[512];

    if (!pwszDomainNC || !ppResult) return E_INVALIDARG;
    *ppResult = NULL;

    /* ── 1. Allocate result container ────────────────────────────────── */
    pResult = (KESTREL_ACL_SCAN_RESULT*)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(*pResult));
    if (!pResult) return E_OUTOFMEMORY;

    /* ── 2. Resolve configNC if caller didn't supply it ──────────────── */
    if (pwszConfigNC && *pwszConfigNC != L'\0') {
        StringCchCopyW(wszConfigNC, ARRAYSIZE(wszConfigNC), pwszConfigNC);
    }
    else {
        hr = KestrelGetConfigNC(wszConfigNC, ARRAYSIZE(wszConfigNC));
        if (FAILED(hr)) {
            wprintf(L"  [!] Failed to resolve configurationNamingContext: 0x%08X\n", hr);
            goto Cleanup;
        }
    }

    /* ── 3. Phase 1: build Extended Rights table ──────────────────────── */
    wprintf(L"  [*] Building Extended Rights table...\n");
    hr = KestrelBuildExtendedRightsTable(wszConfigNC, &pRights);
    if (FAILED(hr)) {
        wprintf(L"  [!] KestrelBuildExtendedRightsTable failed: 0x%08X\n", hr);
        goto Cleanup;
    }

    /* ── 4. Bind IDirectorySearch to domain root ──────────────────────── */
    hr = StringCchPrintfW(wszPath, ARRAYSIZE(wszPath),
        L"LDAP://%s", pwszDomainNC);
    if (FAILED(hr)) goto Cleanup;

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void**)&pSearch);
    if (FAILED(hr)) {
        wprintf(L"  [!] ADsGetObject failed: 0x%08X\n", hr);
        goto Cleanup;
    }

    /* ── 5. Set search preferences ────────────────────────────────────── */
    ADS_SEARCHPREF_INFO prefs[3];

    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;

    prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;

    /*
     * ADS_SEARCHPREF_SECURITY_MASK — CRITICAL.
     * Without this, nTSecurityDescriptor is returned empty.
     * 0x7 = OWNER | GROUP | DACL
     */
    prefs[2].dwSearchPref = ADS_SEARCHPREF_SECURITY_MASK;
    prefs[2].vValue.dwType = ADSTYPE_INTEGER;
    prefs[2].vValue.Integer = 0x7;

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
        L"------------------------------------------------------------------------------------"
        L"--------------------");

    /* ── 7. Main loop: per-object SD fetch + DACL walk ───────────────── */
    while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {

        ADS_SEARCH_COLUMN colDN = { 0 };
        ADS_SEARCH_COLUMN colClass = { 0 };
        BOOL bGotDN = FALSE;
        BOOL bGotClass = FALSE;

        WCHAR wszDN[512] = { 0 };
        WCHAR wszClass[64] = { 0 };
        WCHAR wszObjPath[600] = { 0 };

        /* ── Get distinguishedName ─────────────────────────────────── */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
            L"distinguishedName", &colDN)) &&
            colDN.dwNumValues > 0 &&
            colDN.pADsValues[0].dwType == ADSTYPE_DN_STRING) {
            StringCchCopyW(wszDN, ARRAYSIZE(wszDN),
                colDN.pADsValues[0].DNString);
            bGotDN = TRUE;
            pSearch->lpVtbl->FreeColumn(pSearch, &colDN);
        }

        /* ── Get objectClass (last = most specific) ────────────────── */
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

        if (!bGotDN) {
            pResult->cObjectsErrored++;
            continue;
        }

        if (!bGotClass)
            StringCchCopyW(wszClass, ARRAYSIZE(wszClass), L"unknown");

        /* ── Build LDAP path for IDirectoryObject bind ─────────────── */
        if (FAILED(StringCchPrintfW(wszObjPath, ARRAYSIZE(wszObjPath),
            L"LDAP://%s", wszDN))) {
            pResult->cObjectsErrored++;
            continue;
        }

        /* ── Phase 2: bind IDirectoryObject, get SD ───────────────── */
        IDirectoryObject* pDirObj = NULL;
        PSECURITY_DESCRIPTOR pSD = NULL;
        DWORD                cbSD = 0;

        HRESULT hrObj = ADsGetObject(wszObjPath,
            &IID_IDirectoryObject, (void**)&pDirObj);
        if (FAILED(hrObj)) {
            pResult->cObjectsErrored++;
            continue;
        }

        hrObj = KestrelGetObjectSecurityDescriptor(pDirObj, &pSD, &cbSD);
        pDirObj->lpVtbl->Release(pDirObj);

        if (FAILED(hrObj) || !pSD) {
            pResult->cObjectsErrored++;
            continue;
        }

        /* ── Phase 3: extract DACL, walk ACEs ─────────────────────── */
        PACL  pDacl = NULL;
        BOOL  bDaclPresent = FALSE;
        BOOL  bDefault = FALSE;

        if (GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDefault) &&
            bDaclPresent && pDacl) {
            hrObj = KestrelWalkDacl(pDacl, wszDN, wszClass, pRights, pResult);
            if (FAILED(hrObj))
                pResult->cObjectsErrored++;
        }

        HeapFree(GetProcessHeap(), 0, pSD);
        pResult->cObjectsScanned++;
    }

    /* ── 8. Print collected edges ─────────────────────────────────────── */
    static const LPCWSTR rgszEdgeNames[] = {
        L"UNKNOWN",
        L"GenericAll",
        L"WriteDACL",
        L"WriteOwner",
        L"GenericWrite",
        L"ExtendedRight",
        L"WriteProperty",
        L"CreateChild",
        L"DeleteChild",
        L"Self"
    };

    for (DWORD i = 0; i < pResult->cEdges; i++) {
        KESTREL_ACL_EDGE* pE = &pResult->rgEdges[i];

        LPCWSTR pwszType = (pE->EdgeType < ARRAYSIZE(rgszEdgeNames))
            ? rgszEdgeNames[pE->EdgeType] : L"?";

        LPCWSTR pwszRight = (pE->wszRightName[0])
            ? pE->wszRightName : pE->wszRightGuid;

        wprintf(L"  %-50s %-20s %-18s %s%s\n",
            pE->wszTargetDN,
            pE->wszTrusteeSid,
            pwszType,
            pwszRight,
            pE->bDeny ? L" [DENY]" : L"");
    }

    wprintf(L"\n  [*] Objects scanned: %lu  |  Edges found: %lu  |  Errors: %lu\n",
        pResult->cObjectsScanned,
        pResult->cEdges,
        pResult->cObjectsErrored);

    *ppResult = pResult;
    pResult = NULL;   /* ownership transferred */

Cleanup:
    if (hSearch && pSearch)
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    KestrelFreeExtendedRightsTable(pRights);
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
