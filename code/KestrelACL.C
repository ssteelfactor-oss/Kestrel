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

/*
 * KESTREL_ACL_EDGE_TYPE
 * Semantic classification of an ACE into an attack-graph edge category.
 */
typedef enum _KESTREL_ACL_EDGE_TYPE {
    EDGE_UNKNOWN = 0,
    EDGE_GENERIC_ALL = 1,  /* ADS_RIGHT_GENERIC_ALL or 0xF01FF     */
    EDGE_WRITE_DACL = 2,  /* ADS_RIGHT_WRITE_DAC                  */
    EDGE_WRITE_OWNER = 3,  /* ADS_RIGHT_ACTRL_DS_LIST_OBJECT / WRITE_OWNER */
    EDGE_GENERIC_WRITE = 4,  /* ADS_RIGHT_GENERIC_WRITE              */
    EDGE_EXTENDED_RIGHT = 5,  /* ADS_RIGHT_DS_CONTROL_ACCESS + GUID   */
    EDGE_WRITE_PROPERTY = 6,  /* ADS_RIGHT_DS_WRITE_PROP + GUID       */
    EDGE_CREATE_CHILD = 7,  /* ADS_RIGHT_DS_CREATE_CHILD            */
    EDGE_DELETE_CHILD = 8,  /* ADS_RIGHT_DS_DELETE_CHILD            */
    EDGE_SELF = 9,  /* ADS_RIGHT_DS_SELF (self-write)       */
} KESTREL_ACL_EDGE_TYPE;

/*
 * KESTREL_ACL_EDGE
 * One resolved edge in the access-control graph.
 * trustee  → target, via right encoded in EdgeType + (optional) wszRightName.
 */
typedef struct _KESTREL_ACL_EDGE {
    WCHAR                  wszTrusteeSid[128]; /* string SID of ACE trustee        */
    WCHAR                  wszTargetDN[512];   /* DN of the object bearing the ACE */
    WCHAR                  wszObjectClass[64]; /* objectClass of target            */
    KESTREL_ACL_EDGE_TYPE  EdgeType;
    WCHAR                  wszRightName[128];  /* displayName if EDGE_EXTENDED_RIGHT/WRITE_PROP */
    WCHAR                  wszRightGuid[64];   /* raw GUID for WRITE_PROPERTY edges */
    BOOL                   bInherited;         /* ACE_INHERITED flag               */
    BOOL                   bDeny;              /* ACCESS_DENIED_OBJECT_ACE_TYPE    */
} KESTREL_ACL_EDGE;

/*
 * KESTREL_ACL_SCAN_RESULT
 * Flat array of edges produced by KestrelScanACLEdges.
 * cEdges may reach tens of thousands on a large domain.
 */
typedef struct _KESTREL_ACL_SCAN_RESULT {
    KESTREL_ACL_EDGE* rgEdges;
    DWORD              cEdges;
    DWORD              cCapacity;     /* allocated slots                   */
    DWORD              cObjectsScanned;
    DWORD              cObjectsErrored;
} KESTREL_ACL_SCAN_RESULT;

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

_Must_inspect_result_
HRESULT
KestrelBuildExtendedRightsTable(
    _In_z_  LPCWSTR                 pwszConfigNC,
    _Outptr_result_maybenull_
    KESTREL_EXTENDED_RIGHT** ppRightsHead)
{
    HRESULT                hr = S_OK;
    IDirectorySearch* pSearch = NULL;
    ADS_SEARCH_HANDLE      hSearch = NULL;
    KESTREL_EXTENDED_RIGHT* pHead = NULL;
    WCHAR                  wszPath[512];

    if (!pwszConfigNC || !ppRightsHead) return E_INVALIDARG;
    *ppRightsHead = NULL;

    /* Build LDAP path to CN=Extended-Rights */
    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath),
        L"LDAP://CN=Extended-Rights,%s", pwszConfigNC)))
        return E_UNEXPECTED;

    /* TODO: ADsGetObject → IDirectorySearch */
    /* TODO: SetSearchPreference (SCOPE_ONELEVEL, PAGESIZE=200) */
    /* TODO: ExecuteSearch with filter "(objectClass=controlAccessRight)" */
    /* TODO: loop GetNextRow → GetColumn(rightsGuid/displayName/appliesTo) */
    /* TODO: allocate and link KESTREL_EXTENDED_RIGHT per row             */

    *ppRightsHead = pHead;
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

_Must_inspect_result_
HRESULT
KestrelGetObjectSecurityDescriptor(
    _In_            IDirectoryObject* pDirObj,
    _Outptr_        PSECURITY_DESCRIPTOR* ppSD,
    _Out_           DWORD* pcbSD)
{
    HRESULT         hr = S_OK;
    ADS_ATTR_INFO* pAttrInfo = NULL;
    DWORD           cAttrs = 0;
    LPWSTR          rgszAttrs[] = { L"nTSecurityDescriptor" };

    if (!pDirObj || !ppSD || !pcbSD) return E_INVALIDARG;
    *ppSD = NULL;
    *pcbSD = 0;

    /* TODO: pDirObj->lpVtbl->GetObjectAttributes(pDirObj, rgszAttrs, 1, &pAttrInfo, &cAttrs) */
    /* TODO: verify cAttrs == 1 && pAttrInfo[0].pADsValues->dwType == ADSTYPE_PROV_SPECIFIC */
    /* TODO: extract lpValue / dwLength from ADS_PROV_SPECIFIC */
    /* TODO: *ppSD = (PSECURITY_DESCRIPTOR)pAttrInfo[0].pADsValues->ProviderSpecific.lpValue */
    /* TODO: *pcbSD = pAttrInfo[0].pADsValues->ProviderSpecific.dwLength */
    /* Note: caller frees pAttrInfo via FreeADsMem; *ppSD is a pointer into pAttrInfo */

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

        /* TODO: ConvertSidToStringSidW(pTrusteeSid, &pwszSid) → edge.wszTrusteeSid */

        if (pObjectType && (edgeType == EDGE_EXTENDED_RIGHT || edgeType == EDGE_WRITE_PROPERTY)) {
            KestrelGuidToString(pObjectType, edge.wszRightGuid, ARRAYSIZE(edge.wszRightGuid));
            const KESTREL_EXTENDED_RIGHT* pRight = KestrelLookupExtendedRight(pRightsHead, edge.wszRightGuid);
            if (pRight)
                StringCchCopyW(edge.wszRightName, ARRAYSIZE(edge.wszRightName), pRight->wszDisplayName);
        }

        HRESULT hr = KestrelACLResultAppend(pResult, &edge);
        if (FAILED(hr)) return hr;
    }

    return S_OK;
}

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

    if (!pwszDomainNC || !pwszConfigNC || !ppResult) return E_INVALIDARG;
    *ppResult = NULL;

    /* Allocate result container */
    pResult = (KESTREL_ACL_SCAN_RESULT*)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(*pResult));
    if (!pResult) return E_OUTOFMEMORY;

    /* Phase 1: Extended Rights table */
    hr = KestrelBuildExtendedRightsTable(pwszConfigNC, &pRights);
    if (FAILED(hr)) goto Cleanup;

    /* Build LDAP root path */
    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath),
        L"LDAP://%s", pwszDomainNC))) {
        hr = E_UNEXPECTED;
        goto Cleanup;
    }

    /* TODO: ADsGetObject(wszPath, IID_IDirectorySearch, &pSearch) */
    /* TODO: SetSearchPreference:
             ADS_SEARCHPREF_SEARCH_SCOPE = ADS_SCOPE_SUBTREE
             ADS_SEARCHPREF_PAGESIZE     = 200
             ADS_SEARCHPREF_SECURITY_MASK = (OWNER_SECURITY_INFORMATION |
                                             GROUP_SECURITY_INFORMATION |
                                             DACL_SECURITY_INFORMATION) */
                                             /* TODO: ExecuteSearch(KESTREL_ACL_FILTER, g_rgszObjectAttrs, KESTREL_OBJECT_ATTR_COUNT, &hSearch) */

                                             /* TODO: loop: GetNextRow → GetColumn(distinguishedName/objectClass/objectSid/nTSecurityDescriptor)
                                                      → ADsOpenObject(DN, IID_IDirectoryObject, &pDirObj)
                                                      → KestrelGetObjectSecurityDescriptor
                                                      → GetSecurityDescriptorDacl
                                                      → KestrelWalkDacl
                                                      → pResult->cObjectsScanned++ / cObjectsErrored++ */

    *ppResult = pResult;
    pResult = NULL;   /* ownership transferred */

Cleanup:
    if (hSearch && pSearch)
        IDirectorySearch_CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        IDirectorySearch_Release(pSearch);
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
