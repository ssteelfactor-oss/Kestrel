/*
 * KestrelGroup.c — v0.3
 * Transitive group membership resolution via LDAP_MATCHING_RULE_IN_CHAIN.
 *
 * One LDAP query per group resolves the full recursive membership chain.
 * The DC performs all traversal server-side — no client-side BFS required.
 *
 * OID: 1.2.840.113556.1.4.1941
 * Filter syntax: (memberOf:1.2.840.113556.1.4.1941:=<groupDN>)
 */

#include "../include/Kestrel.h"

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Constants                                                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

#define KESTREL_MATCHING_RULE_IN_CHAIN  L"1.2.840.113556.1.4.1941"

#define KESTREL_TRANSITIVE_FILTER_FMT \
    L"(memberOf:" KESTREL_MATCHING_RULE_IN_CHAIN L":=%s)"

static LPCWSTR g_rgszHighValueGroups[] = {
    L"Domain Admins",
    L"Enterprise Admins",
    L"Schema Admins",
    L"Administrators",
    L"Account Operators",
    L"Backup Operators",
    L"Print Operators",
    L"Server Operators",
    L"Group Policy Creator Owners",
    L"Domain Controllers",
};
#define KESTREL_HIGH_VALUE_GROUP_COUNT \
    (sizeof(g_rgszHighValueGroups) / sizeof(g_rgszHighValueGroups[0]))

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Forward declarations                                                       */
/* ─────────────────────────────────────────────────────────────────────────── */

VOID KestrelFreeMemberList(
    _In_opt_ _Post_ptr_invalid_ KESTREL_MEMBER* pHead);

VOID KestrelFreeGroupResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GROUP_RESULT* pResult);

VOID KestrelFreeGroupScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GROUP_SCAN_RESULT* pResult);

_Must_inspect_result_
static HRESULT
KestrelGetGroupDN(
    _In_z_                   LPCWSTR pwszRootPath,
    _In_z_                   LPCWSTR pwszGroupName,
    _Out_writes_z_(cchDNBuf) LPWSTR  pwszDNBuf,
    _In_                     SIZE_T  cchDNBuf);

_Must_inspect_result_
static HRESULT
KestrelTransitiveMembership(
    _In_z_   LPCWSTR               pwszRootPath,
    _In_z_   LPCWSTR               pwszGroupDN,
    _In_z_   LPCWSTR               pwszGroupName,
    _Outptr_ KESTREL_GROUP_RESULT **ppResult);

_Must_inspect_result_
static HRESULT
KestrelResolveACLTrustees(
    _In_z_   LPCWSTR                    pwszRootPath,
    _In_opt_ KESTREL_ACL_SCAN_RESULT   *pACLResult,
    _In_opt_ KESTREL_GROUP_SCAN_RESULT *pGroupResult);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  KestrelGetGroupDN                                                          */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
KestrelGetGroupDN(
    _In_z_                   LPCWSTR pwszRootPath,
    _In_z_                   LPCWSTR pwszGroupName,
    _Out_writes_z_(cchDNBuf) LPWSTR  pwszDNBuf,
    _In_                     SIZE_T  cchDNBuf)
{
    HRESULT           hr      = S_OK;
    IDirectorySearch *pSearch = NULL;
    ADS_SEARCH_HANDLE hSearch = NULL;
    WCHAR             wszFilter[256];
    BOOL              bFound  = FALSE;

    if (!pwszRootPath || !pwszGroupName || !pwszDNBuf || cchDNBuf == 0)
        return E_INVALIDARG;

    pwszDNBuf[0] = L'\0';

    hr = StringCchPrintfW(wszFilter, ARRAYSIZE(wszFilter),
            L"(&(objectClass=group)(sAMAccountName=%s))", pwszGroupName);
    if (FAILED(hr)) return hr;

    hr = ADsGetObject(pwszRootPath, &IID_IDirectorySearch, (void **)&pSearch);
    if (FAILED(hr)) goto Cleanup;

    ADS_SEARCHPREF_INFO prefs[2];
    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);
    if (FAILED(hr)) goto Cleanup;

    LPWSTR attrs[] = { L"distinguishedName" };
    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
            wszFilter, attrs, ARRAYSIZE(attrs), &hSearch);
    if (FAILED(hr)) goto Cleanup;

    if (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN col = { 0 };
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"distinguishedName", &col)) &&
            col.dwNumValues > 0 &&
            col.pADsValues[0].dwType == ADSTYPE_DN_STRING) {
            hr     = StringCchCopyW(pwszDNBuf, cchDNBuf,
                            col.pADsValues[0].DNString);
            bFound = TRUE;
        }
        pSearch->lpVtbl->FreeColumn(pSearch, &col);
    }

    if (!bFound)
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);

Cleanup:
    if (hSearch && pSearch)
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    return hr;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  KestrelTransitiveMembership                                                */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
KestrelTransitiveMembership(
    _In_z_   LPCWSTR               pwszRootPath,
    _In_z_   LPCWSTR               pwszGroupDN,
    _In_z_   LPCWSTR               pwszGroupName,
    _Outptr_ KESTREL_GROUP_RESULT **ppResult)
{
    HRESULT               hr      = S_OK;
    IDirectorySearch     *pSearch = NULL;
    ADS_SEARCH_HANDLE     hSearch = NULL;
    KESTREL_GROUP_RESULT *pRes    = NULL;
    KESTREL_MEMBER      **ppTail  = NULL;
    WCHAR                 wszFilter[1024];

    if (!pwszRootPath || !pwszGroupDN || !pwszGroupName || !ppResult)
        return E_INVALIDARG;

    *ppResult = NULL;

    pRes = (KESTREL_GROUP_RESULT *)HeapAlloc(GetProcessHeap(),
                                              HEAP_ZERO_MEMORY, sizeof(*pRes));
    if (!pRes) return E_OUTOFMEMORY;

    ppTail = &pRes->pMembers;
    StringCchCopyW(pRes->wszGroupDN,   ARRAYSIZE(pRes->wszGroupDN),   pwszGroupDN);
    StringCchCopyW(pRes->wszGroupName, ARRAYSIZE(pRes->wszGroupName), pwszGroupName);

    hr = StringCchPrintfW(wszFilter, ARRAYSIZE(wszFilter),
            KESTREL_TRANSITIVE_FILTER_FMT, pwszGroupDN);
    if (FAILED(hr)) goto Cleanup;

    hr = ADsGetObject(pwszRootPath, &IID_IDirectorySearch, (void **)&pSearch);
    if (FAILED(hr)) goto Cleanup;

    ADS_SEARCHPREF_INFO prefs[2];
    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);
    if (FAILED(hr)) goto Cleanup;

    LPWSTR attrs[] = {
        L"distinguishedName", L"sAMAccountName",
        L"objectSid", L"objectClass", L"userAccountControl"
    };

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
            wszFilter, attrs, ARRAYSIZE(attrs), &hSearch);
    if (FAILED(hr)) goto Cleanup;

    while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {

        ADS_SEARCH_COLUMN colDN    = { 0 };
        ADS_SEARCH_COLUMN colSAM   = { 0 };
        ADS_SEARCH_COLUMN colSid   = { 0 };
        ADS_SEARCH_COLUMN colClass = { 0 };
        ADS_SEARCH_COLUMN colUAC   = { 0 };

        BOOL bGotDN = FALSE, bGotSAM = FALSE;
        BOOL bGotSid = FALSE, bGotClass = FALSE, bGotUAC = FALSE;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"distinguishedName", &colDN)) &&
            colDN.dwNumValues > 0 &&
            colDN.pADsValues[0].dwType == ADSTYPE_DN_STRING)
            bGotDN = TRUE;

        if (!bGotDN) goto NextRow;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"sAMAccountName", &colSAM)) &&
            colSAM.dwNumValues > 0 &&
            colSAM.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING)
            bGotSAM = TRUE;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"objectSid", &colSid)) &&
            colSid.dwNumValues > 0 &&
            colSid.pADsValues[0].dwType == ADSTYPE_OCTET_STRING)
            bGotSid = TRUE;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"objectClass", &colClass)) &&
            colClass.dwNumValues > 0)
            bGotClass = TRUE;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"userAccountControl", &colUAC)) &&
            colUAC.dwNumValues > 0 &&
            colUAC.pADsValues[0].dwType == ADSTYPE_INTEGER)
            bGotUAC = TRUE;

        KESTREL_MEMBER *pMember = (KESTREL_MEMBER *)HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*pMember));
        if (!pMember) { hr = E_OUTOFMEMORY; goto NextRow; }

        StringCchCopyW(pMember->wszDN, ARRAYSIZE(pMember->wszDN),
                colDN.pADsValues[0].DNString);

        if (bGotSAM)
            StringCchCopyW(pMember->wszSAM, ARRAYSIZE(pMember->wszSAM),
                    colSAM.pADsValues[0].CaseIgnoreString);

        if (bGotSid) {
            PSID   pSid    = (PSID)colSid.pADsValues[0].OctetString.lpValue;
            LPWSTR pwszSid = NULL;
            if (IsValidSid(pSid) &&
                ConvertSidToStringSidW(pSid, &pwszSid) && pwszSid) {
                StringCchCopyW(pMember->wszSid, ARRAYSIZE(pMember->wszSid), pwszSid);
                LocalFree(pwszSid);
            }
        }

        if (bGotClass) {
            DWORD iLast = colClass.dwNumValues - 1;
            if (colClass.pADsValues[iLast].dwType == ADSTYPE_CASE_IGNORE_STRING)
                StringCchCopyW(pMember->wszClass, ARRAYSIZE(pMember->wszClass),
                        colClass.pADsValues[iLast].CaseIgnoreString);
        }

        pMember->bEnabled = TRUE;
        if (bGotUAC && (colUAC.pADsValues[0].Integer & 0x2))
            pMember->bEnabled = FALSE;

        *ppTail = pMember;
        ppTail  = &pMember->pNext;
        pRes->cMembers++;
        if (pMember->bEnabled) pRes->cEnabled++;

NextRow:
        if (bGotDN)    pSearch->lpVtbl->FreeColumn(pSearch, &colDN);
        if (bGotSAM)   pSearch->lpVtbl->FreeColumn(pSearch, &colSAM);
        if (bGotSid)   pSearch->lpVtbl->FreeColumn(pSearch, &colSid);
        if (bGotClass) pSearch->lpVtbl->FreeColumn(pSearch, &colClass);
        if (bGotUAC)   pSearch->lpVtbl->FreeColumn(pSearch, &colUAC);
    }

    wprintf(L"  %-30s  total: %-4lu  enabled: %lu\n",
            pwszGroupName, pRes->cMembers, pRes->cEnabled);

    *ppResult = pRes;
    pRes      = NULL;

Cleanup:
    if (hSearch && pSearch)
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    if (pRes)
        KestrelFreeGroupResult(pRes);
    return hr;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  KestrelResolveACLTrustees                                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
KestrelResolveACLTrustees(
    _In_z_   LPCWSTR                    pwszRootPath,
    _In_opt_ KESTREL_ACL_SCAN_RESULT   *pACLResult,
    _In_opt_ KESTREL_GROUP_SCAN_RESULT *pGroupResult)
{
    (void)pwszRootPath;

    if (!pACLResult || !pGroupResult) return S_OK;
    if (pACLResult->cEdges == 0 || pGroupResult->cGroups == 0) return S_OK;

    static const LPCWSTR rgszEdgeNames[] = {
        L"UNKNOWN", L"GenericAll", L"WriteDACL", L"WriteOwner",
        L"GenericWrite", L"ExtendedRight", L"WriteProperty",
        L"CreateChild", L"DeleteChild", L"Self"
    };

    DWORD cPathsFound = 0;

    wprintf(L"\n  [*] Cross-referencing %lu ACL edges against group membership...\n\n",
            pACLResult->cEdges);
    wprintf(L"  %-30s %-20s %-16s %s\n",
            L"Member", L"Via Group", L"Edge", L"Target");
    wprintf(L"  %s\n",
            L"--------------------------------------------------------------------------------");

    for (DWORD e = 0; e < pACLResult->cEdges; e++) {
        KESTREL_ACL_EDGE *pEdge = &pACLResult->rgEdges[e];

        if (pEdge->bDeny) continue;
        if (pEdge->wszTrusteeSid[0] == L'\0') continue;

        for (KESTREL_GROUP_RESULT *pGroup = pGroupResult->pGroups;
             pGroup; pGroup = pGroup->pNext) {

            for (KESTREL_MEMBER *pMember = pGroup->pMembers;
                 pMember; pMember = pMember->pNext) {

                if (_wcsicmp(pMember->wszSid, pEdge->wszTrusteeSid) != 0)
                    continue;

                LPCWSTR pwszEdgeName =
                    (pEdge->EdgeType < ARRAYSIZE(rgszEdgeNames))
                    ? rgszEdgeNames[pEdge->EdgeType] : L"?";

                LPCWSTR pwszRight =
                    pEdge->wszRightName[0] ? pEdge->wszRightName
                                           : pEdge->wszRightGuid;

                wprintf(L"  %-30s %-20s %-16s %s%s%s\n",
                        pMember->wszSAM[0] ? pMember->wszSAM : pMember->wszDN,
                        pGroup->wszGroupName,
                        pwszEdgeName,
                        pEdge->wszTargetDN,
                        pwszRight[0] ? L" / " : L"",
                        pwszRight[0] ? pwszRight : L"");

                if (!pMember->bEnabled)
                    wprintf(L"    ^ account disabled — can be re-enabled\n");

                cPathsFound++;
            }
        }
    }

    if (cPathsFound == 0)
        wprintf(L"  [+] No cross-group ACL paths found.\n");
    else
        wprintf(L"\n  [!] %lu attack path(s) found.\n", cPathsFound);

    return S_OK;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  KestrelRunGroupScan — public entry point                                   */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
HRESULT
KestrelRunGroupScan(
    _In_z_   LPCWSTR                    pwszRootPath,
    _In_opt_ KESTREL_ACL_SCAN_RESULT   *pACLResult,
    _Outptr_ KESTREL_GROUP_SCAN_RESULT **ppResult)
{
    HRESULT                   hr     = S_OK;
    KESTREL_GROUP_SCAN_RESULT *pRes  = NULL;
    KESTREL_GROUP_RESULT     **ppTail = NULL;

    if (!pwszRootPath || !ppResult) return E_INVALIDARG;
    *ppResult = NULL;

    pRes = (KESTREL_GROUP_SCAN_RESULT *)HeapAlloc(GetProcessHeap(),
                                                   HEAP_ZERO_MEMORY,
                                                   sizeof(*pRes));
    if (!pRes) return E_OUTOFMEMORY;

    ppTail = &pRes->pGroups;

    wprintf(L"\n═══ Kestrel v0.3 — Transitive Group Membership ═══\n\n");
    wprintf(L"  %-30s %-10s %s\n", L"Group", L"Total", L"Enabled");
    wprintf(L"  %s\n", L"--------------------------------------------------");

    for (SIZE_T i = 0; i < KESTREL_HIGH_VALUE_GROUP_COUNT; i++) {

        LPCWSTR pwszName   = g_rgszHighValueGroups[i];
        WCHAR   wszDN[512] = { 0 };

        HRESULT hrGroup = KestrelGetGroupDN(pwszRootPath, pwszName,
                                             wszDN, ARRAYSIZE(wszDN));

        if (hrGroup == HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
            continue;

        if (FAILED(hrGroup)) {
            wprintf(L"  [!] %-28s  resolve failed: 0x%08X\n", pwszName, hrGroup);
            pRes->cErrors++;
            continue;
        }

        KESTREL_GROUP_RESULT *pGroup = NULL;
        hrGroup = KestrelTransitiveMembership(pwszRootPath, wszDN,
                                               pwszName, &pGroup);

        if (FAILED(hrGroup) || !pGroup) {
            wprintf(L"  [!] %-28s  expand failed: 0x%08X\n", pwszName, hrGroup);
            pRes->cErrors++;
            continue;
        }

        *ppTail = pGroup;
        ppTail  = &pGroup->pNext;
        pRes->cGroups++;
    }

    wprintf(L"\n  [*] Groups scanned: %lu  |  Errors: %lu\n",
            pRes->cGroups, pRes->cErrors);

    hr = KestrelResolveACLTrustees(pwszRootPath, pACLResult, pRes);

    *ppResult = pRes;
    pRes      = NULL;

    if (pRes) KestrelFreeGroupScanResult(pRes);
    return hr;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Cleanup                                                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

VOID
KestrelFreeMemberList(
    _In_opt_ _Post_ptr_invalid_ KESTREL_MEMBER *pHead)
{
    while (pHead) {
        KESTREL_MEMBER *pNext = pHead->pNext;
        HeapFree(GetProcessHeap(), 0, pHead);
        pHead = pNext;
    }
}

VOID
KestrelFreeGroupResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GROUP_RESULT *pResult)
{
    if (!pResult) return;
    KestrelFreeMemberList(pResult->pMembers);
    HeapFree(GetProcessHeap(), 0, pResult);
}

VOID
KestrelFreeGroupScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GROUP_SCAN_RESULT *pResult)
{
    if (!pResult) return;
    KESTREL_GROUP_RESULT *p = pResult->pGroups;
    while (p) {
        KESTREL_GROUP_RESULT *pNext = p->pNext;
        KestrelFreeGroupResult(p);
        p = pNext;
    }
    HeapFree(GetProcessHeap(), 0, pResult);
}
