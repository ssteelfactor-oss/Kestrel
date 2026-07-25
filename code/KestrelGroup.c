/*
 * KestrelGroup.c — v0.3
 * Transitive group membership resolution via LDAP_MATCHING_RULE_IN_CHAIN.
 *
 * Groups are located by Well-Known RID + Domain SID, not by name.
 * Language/locale independent — works on any Windows domain.
 */

#include "../include/Kestrel.h"

 /* ─────────────────────────────────────────────────────────────────────────── */
 /*  Constants                                                                  */
 /* ─────────────────────────────────────────────────────────────────────────── */

#define KESTREL_MATCHING_RULE_IN_CHAIN  L"1.2.840.113556.1.4.1941"

#define KESTREL_TRANSITIVE_FILTER_FMT \
    L"(memberOf:" KESTREL_MATCHING_RULE_IN_CHAIN L":=%s)"

typedef struct _KESTREL_HV_GROUP {
    DWORD   dwRID;
    BOOL    bBuiltin;   /* TRUE = S-1-5-32-<RID> alias; FALSE = <domain>-<RID> */
    LPCWSTR pwszLabel;
} KESTREL_HV_GROUP;

static const KESTREL_HV_GROUP g_rgHighValueGroups[] = {
    { 512, FALSE, L"Domain Admins"                },
    { 516, FALSE, L"Domain Controllers"           },
    { 518, FALSE, L"Schema Admins"                },
    { 519, FALSE, L"Enterprise Admins"            },
    { 520, FALSE, L"Group Policy Creator Owners"  },
    { 521, FALSE, L"Read-only Domain Controllers" },
    { 522, FALSE, L"Cloneable Domain Controllers" },
    { 526, FALSE, L"Key Admins"                   },
    { 527, FALSE, L"Enterprise Key Admins"        },
    { 544, TRUE,  L"Administrators"               },
    { 548, TRUE,  L"Account Operators"            },
    { 549, TRUE,  L"Server Operators"             },
    { 550, TRUE,  L"Print Operators"              },
    { 551, TRUE,  L"Backup Operators"             },
    { 578, TRUE,  L"Hyper-V Administrators"       },
};
#define KESTREL_HV_GROUP_COUNT \
    (sizeof(g_rgHighValueGroups) / sizeof(g_rgHighValueGroups[0]))

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Cleanup forward declarations                                               */
/* ─────────────────────────────────────────────────────────────────────────── */

VOID KestrelFreeMemberList(
    _In_opt_ _Post_ptr_invalid_ KESTREL_MEMBER* pHead);

VOID KestrelFreeGroupResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GROUP_RESULT* pResult);

VOID KestrelFreeGroupScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GROUP_SCAN_RESULT* pResult);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Internal forward declarations                                              */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
KestrelGetDomainSID(
    _In_z_   LPCWSTR pwszRootPath,
    _Outptr_ PSID* ppDomainSid);

_Must_inspect_result_
static HRESULT
KestrelBuildGroupSid(
    _In_     PSID   pDomainSid,
    _In_     DWORD  dwRID,
    _Outptr_ PSID* ppGroupSid);

static HRESULT
KestrelSidToLdapFilter(
    _In_                   PSID   pSid,
    _Out_writes_z_(cchBuf) LPWSTR pwszBuf,
    _In_                   SIZE_T cchBuf);

_Must_inspect_result_
static HRESULT
KestrelGetGroupDNBySid(
    _In_z_                   LPCWSTR pwszRootPath,
    _In_                     PSID    pGroupSid,
    _In_z_                   LPCWSTR pwszLabel,
    _Out_writes_z_(cchDNBuf) LPWSTR  pwszDNBuf,
    _In_                     SIZE_T  cchDNBuf,
    _Out_writes_z_(cchSAM)   LPWSTR  pwszSAMBuf,
    _In_                     SIZE_T  cchSAM);

_Must_inspect_result_
static HRESULT
KestrelTransitiveMembership(
    _In_z_   LPCWSTR               pwszRootPath,
    _In_z_   LPCWSTR               pwszGroupDN,
    _In_z_   LPCWSTR               pwszGroupName,
    _Outptr_ KESTREL_GROUP_RESULT** ppResult);

_Must_inspect_result_
static HRESULT
KestrelResolveACLTrustees(
    _In_z_   LPCWSTR                    pwszRootPath,
    _In_opt_ KESTREL_ACL_SCAN_RESULT* pACLResult,
    _In_opt_ KESTREL_GROUP_SCAN_RESULT* pGroupResult);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  KestrelGetDomainSID                                                        */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
KestrelGetDomainSID(
    _In_z_   LPCWSTR pwszRootPath,
    _Outptr_ PSID* ppDomainSid)
{
    HRESULT           hr = S_OK;
    IDirectorySearch* pSearch = NULL;
    ADS_SEARCH_HANDLE hSearch = NULL;
    PSID              pSid = NULL;

    if (!pwszRootPath || !ppDomainSid) return E_INVALIDARG;
    *ppDomainSid = NULL;

    KTRACE(L" KestrelGetDomainSID: binding to %s\n", pwszRootPath);

    hr = ADsGetObject(pwszRootPath, &IID_IDirectorySearch, (void**)&pSearch);
    if (FAILED(hr)) {
        KTRACE(L" KestrelGetDomainSID: ADsGetObject failed 0x%08X\n", hr);
        goto Cleanup;
    }

    KTRACE(L" KestrelGetDomainSID: ADsGetObject OK, setting BASE scope\n");

    ADS_SEARCHPREF_INFO prefs[1];
    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_BASE;

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 1);
    if (FAILED(hr)) {
        KTRACE(L" KestrelGetDomainSID: SetSearchPreference failed 0x%08X\n", hr);
        goto Cleanup;
    }

    LPWSTR attrs[] = { L"objectSid" };
    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
        L"(objectClass=domainDNS)",
        attrs, ARRAYSIZE(attrs), &hSearch);
    if (FAILED(hr)) {
        KTRACE(L" KestrelGetDomainSID: ExecuteSearch failed 0x%08X\n", hr);
        goto Cleanup;
    }

    KTRACE(L" KestrelGetDomainSID: ExecuteSearch OK, reading row\n");

    if (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) == S_ADS_NOMORE_ROWS) {
        KTRACE(L" KestrelGetDomainSID: no rows returned\n");
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        goto Cleanup;
    }

    ADS_SEARCH_COLUMN col = { 0 };
    if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
        L"objectSid", &col)) &&
        col.dwNumValues > 0 &&
        col.pADsValues[0].dwType == ADSTYPE_OCTET_STRING) {

        DWORD cbSid = col.pADsValues[0].OctetString.dwLength;
        BYTE* pbSid = col.pADsValues[0].OctetString.lpValue;

        KTRACE(L" KestrelGetDomainSID: objectSid found, %lu bytes\n", cbSid);

        pSid = (PSID)HeapAlloc(GetProcessHeap(), 0, cbSid);
        if (!pSid) {
            hr = E_OUTOFMEMORY;
        }
        else {
            CopyMemory(pSid, pbSid, cbSid);
            if (!IsValidSid(pSid)) {
                KTRACE(L" KestrelGetDomainSID: SID validation failed\n");
                HeapFree(GetProcessHeap(), 0, pSid);
                pSid = NULL;
                hr = E_UNEXPECTED;
            }
            else {
                LPWSTR pwszSid = NULL;
                if (ConvertSidToStringSidW(pSid, &pwszSid)) {
                    KTRACE(L" KestrelGetDomainSID: Domain SID = %s\n", pwszSid);
                    LocalFree(pwszSid);
                }
            }
        }
        pSearch->lpVtbl->FreeColumn(pSearch, &col);
    }
    else {
        KTRACE(L" KestrelGetDomainSID: objectSid column missing or wrong type\n");
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }

    if (SUCCEEDED(hr) && pSid) {
        *ppDomainSid = pSid;
        pSid = NULL;
    }

Cleanup:
    if (hSearch && pSearch)
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    if (pSid)
        HeapFree(GetProcessHeap(), 0, pSid);

    KTRACE(L" KestrelGetDomainSID: exit hr=0x%08X\n", hr);
    return hr;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  KestrelBuildGroupSid                                                       */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
KestrelBuildGroupSid(
    _In_     PSID   pDomainSid,
    _In_     DWORD  dwRID,
    _Outptr_ PSID* ppGroupSid)
{
    if (!pDomainSid || !ppGroupSid) return E_INVALIDARG;
    *ppGroupSid = NULL;

    UCHAR subAuthCount = *GetSidSubAuthorityCount(pDomainSid);
    if (subAuthCount >= SID_MAX_SUB_AUTHORITIES) return E_INVALIDARG;

    SID_IDENTIFIER_AUTHORITY authority = *GetSidIdentifierAuthority(pDomainSid);

    DWORD subAuths[SID_MAX_SUB_AUTHORITIES] = { 0 };
    for (UCHAR i = 0; i < subAuthCount; i++)
        subAuths[i] = *GetSidSubAuthority(pDomainSid, i);
    subAuths[subAuthCount] = dwRID;

    PSID pGroupSid = NULL;
    if (!AllocateAndInitializeSid(&authority,
        (BYTE)(subAuthCount + 1),
        subAuths[0], subAuths[1], subAuths[2], subAuths[3],
        subAuths[4], subAuths[5], subAuths[6], subAuths[7],
        &pGroupSid))
        return HRESULT_FROM_WIN32(GetLastError());

    *ppGroupSid = pGroupSid;
    return S_OK;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  KestrelBuildBuiltinSid — S-1-5-32-<RID> (BUILTIN alias, e.g. Backup Ops)   */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
KestrelBuildBuiltinSid(
    _In_     DWORD  dwRID,
    _Outptr_ PSID  *ppSid)
{
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;

    if (!ppSid) return E_INVALIDARG;
    *ppSid = NULL;

    if (!AllocateAndInitializeSid(&nt, 2,
            SECURITY_BUILTIN_DOMAIN_RID, dwRID, 0, 0, 0, 0, 0, 0, ppSid))
        return HRESULT_FROM_WIN32(GetLastError());
    return S_OK;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  KestrelSidToLdapFilter                                                     */
/* ─────────────────────────────────────────────────────────────────────────── */

static HRESULT
KestrelSidToLdapFilter(
    _In_                   PSID   pSid,
    _Out_writes_z_(cchBuf) LPWSTR pwszBuf,
    _In_                   SIZE_T cchBuf)
{
    if (!pSid || !pwszBuf || cchBuf == 0) return E_INVALIDARG;

    DWORD  cbSid = GetLengthSid(pSid);
    BYTE* pb = (BYTE*)pSid;
    WCHAR  wszTmp[8];

    pwszBuf[0] = L'\0';

    for (DWORD i = 0; i < cbSid; i++) {
        StringCchPrintfW(wszTmp, ARRAYSIZE(wszTmp), L"\\%02X", pb[i]);
        HRESULT hr = StringCchCatW(pwszBuf, cchBuf, wszTmp);
        if (FAILED(hr)) return hr;
    }
    return S_OK;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  KestrelGetGroupDNBySid                                                     */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
KestrelGetGroupDNBySid(
    _In_z_                   LPCWSTR pwszRootPath,
    _In_                     PSID    pGroupSid,
    _In_z_                   LPCWSTR pwszLabel,
    _Out_writes_z_(cchDNBuf) LPWSTR  pwszDNBuf,
    _In_                     SIZE_T  cchDNBuf,
    _Out_writes_z_(cchSAM)   LPWSTR  pwszSAMBuf,
    _In_                     SIZE_T  cchSAM)
{
    HRESULT           hr = S_OK;
    IDirectorySearch* pSearch = NULL;
    ADS_SEARCH_HANDLE hSearch = NULL;
    WCHAR             wszSidOctet[512];
    WCHAR             wszFilter[600];
    BOOL              bFound = FALSE;

    if (!pwszRootPath || !pGroupSid || !pwszDNBuf || !pwszSAMBuf)
        return E_INVALIDARG;

    pwszDNBuf[0] = L'\0';
    pwszSAMBuf[0] = L'\0';

    wprintf(L"\n[TRACE] KestrelGetGroupDNBySid: label='%s' RID=", pwszLabel);

    /* Print RID from SID for trace */
    UCHAR subAuthCount = *GetSidSubAuthorityCount(pGroupSid);
    DWORD dwRID = *GetSidSubAuthority(pGroupSid, subAuthCount - 1);
    wprintf(L"%lu\n", dwRID);

    hr = KestrelSidToLdapFilter(pGroupSid, wszSidOctet, ARRAYSIZE(wszSidOctet));
    if (FAILED(hr)) {
        KTRACE(L" SidToLdapFilter failed: 0x%08X\n", hr);
        return hr;
    }

    hr = StringCchPrintfW(wszFilter, ARRAYSIZE(wszFilter),
        L"(&(objectClass=group)(objectSid=%s))", wszSidOctet);
    if (FAILED(hr)) return hr;

    KTRACE(L" Filter built OK, binding to root path\n");

    hr = ADsGetObject(pwszRootPath, &IID_IDirectorySearch, (void**)&pSearch);
    if (FAILED(hr)) {
        KTRACE(L" ADsGetObject failed: 0x%08X\n", hr);
        goto Cleanup;
    }

    ADS_SEARCHPREF_INFO prefs[2];
    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);
    if (FAILED(hr)) {
        KTRACE(L" SetSearchPreference failed: 0x%08X\n", hr);
        goto Cleanup;
    }

    LPWSTR attrs[] = { L"distinguishedName", L"sAMAccountName" };
    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
        wszFilter, attrs, ARRAYSIZE(attrs), &hSearch);
    if (FAILED(hr)) {
        KTRACE(L" ExecuteSearch failed: 0x%08X\n", hr);
        goto Cleanup;
    }

    KTRACE(L" ExecuteSearch OK, waiting for first row\n");

    if (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {

        ADS_SEARCH_COLUMN colDN = { 0 };
        ADS_SEARCH_COLUMN colSAM = { 0 };

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
            L"distinguishedName", &colDN)) &&
            colDN.dwNumValues > 0 &&
            colDN.pADsValues[0].dwType == ADSTYPE_DN_STRING) {
            StringCchCopyW(pwszDNBuf, cchDNBuf, colDN.pADsValues[0].DNString);
            bFound = TRUE;
            KTRACE(L" Found DN: %s\n", pwszDNBuf);
        }

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
            L"sAMAccountName", &colSAM)) &&
            colSAM.dwNumValues > 0 &&
            colSAM.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING) {
            StringCchCopyW(pwszSAMBuf, cchSAM,
                colSAM.pADsValues[0].CaseIgnoreString);
            KTRACE(L" sAMAccountName: %s\n", pwszSAMBuf);
        }

        pSearch->lpVtbl->FreeColumn(pSearch, &colDN);
        pSearch->lpVtbl->FreeColumn(pSearch, &colSAM);
    }
    else {
        KTRACE(L" No rows returned — group not in this domain\n");
    }

    if (!bFound)
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);

Cleanup:
    if (hSearch && pSearch)
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);

    KTRACE(L" KestrelGetGroupDNBySid exit: hr=0x%08X found=%d\n", hr, bFound);
    return hr;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  KestrelGetGroupDNByName — locate a group by sAMAccountName (no fixed RID,   */
/*  e.g. DnsAdmins, DHCP Administrators)                                        */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
KestrelGetGroupDNByName(
    _In_z_                   LPCWSTR pwszRootPath,
    _In_z_                   LPCWSTR pwszName,
    _Out_writes_z_(cchDNBuf) LPWSTR  pwszDNBuf,
    _In_                     SIZE_T  cchDNBuf,
    _Out_writes_z_(cchSAM)   LPWSTR  pwszSAMBuf,
    _In_                     SIZE_T  cchSAM)
{
    HRESULT           hr = S_OK;
    IDirectorySearch* pSearch = NULL;
    ADS_SEARCH_HANDLE hSearch = NULL;
    WCHAR             wszFilter[300];
    BOOL              bFound = FALSE;

    if (!pwszRootPath || !pwszName || !pwszDNBuf || !pwszSAMBuf)
        return E_INVALIDARG;

    pwszDNBuf[0] = L'\0';
    pwszSAMBuf[0] = L'\0';

    hr = StringCchPrintfW(wszFilter, ARRAYSIZE(wszFilter),
        L"(&(objectClass=group)(sAMAccountName=%s))", pwszName);
    if (FAILED(hr)) return hr;

    hr = ADsGetObject(pwszRootPath, &IID_IDirectorySearch, (void**)&pSearch);
    if (FAILED(hr)) goto Cleanup;

    ADS_SEARCHPREF_INFO prefs[2];
    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);
    if (FAILED(hr)) goto Cleanup;

    LPWSTR attrs[] = { L"distinguishedName", L"sAMAccountName" };
    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
        wszFilter, attrs, ARRAYSIZE(attrs), &hSearch);
    if (FAILED(hr)) goto Cleanup;

    if (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN colDN = { 0 };
        ADS_SEARCH_COLUMN colSAM = { 0 };

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
            L"distinguishedName", &colDN)) &&
            colDN.dwNumValues > 0 &&
            colDN.pADsValues[0].dwType == ADSTYPE_DN_STRING) {
            StringCchCopyW(pwszDNBuf, cchDNBuf, colDN.pADsValues[0].DNString);
            bFound = TRUE;
        }

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
            L"sAMAccountName", &colSAM)) &&
            colSAM.dwNumValues > 0 &&
            colSAM.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING) {
            StringCchCopyW(pwszSAMBuf, cchSAM,
                colSAM.pADsValues[0].CaseIgnoreString);
        }

        pSearch->lpVtbl->FreeColumn(pSearch, &colDN);
        pSearch->lpVtbl->FreeColumn(pSearch, &colSAM);
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
    _Outptr_ KESTREL_GROUP_RESULT** ppResult)
{
    HRESULT               hr = S_OK;
    IDirectorySearch* pSearch = NULL;
    ADS_SEARCH_HANDLE     hSearch = NULL;
    KESTREL_GROUP_RESULT* pRes = NULL;
    KESTREL_MEMBER** ppTail = NULL;
    WCHAR                 wszFilter[1024];

    if (!pwszRootPath || !pwszGroupDN || !pwszGroupName || !ppResult)
        return E_INVALIDARG;

    *ppResult = NULL;

    wprintf(L"\n[TRACE] KestrelTransitiveMembership: group='%s'\n", pwszGroupName);
    KTRACE(L" DN: %s\n", pwszGroupDN);

    pRes = (KESTREL_GROUP_RESULT*)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, sizeof(*pRes));
    if (!pRes) return E_OUTOFMEMORY;

    ppTail = &pRes->pMembers;
    StringCchCopyW(pRes->wszGroupDN, ARRAYSIZE(pRes->wszGroupDN), pwszGroupDN);
    StringCchCopyW(pRes->wszGroupName, ARRAYSIZE(pRes->wszGroupName), pwszGroupName);

    hr = StringCchPrintfW(wszFilter, ARRAYSIZE(wszFilter),
        KESTREL_TRANSITIVE_FILTER_FMT, pwszGroupDN);
    if (FAILED(hr)) goto Cleanup;

    KTRACE(L" Transitive filter built, binding to root\n");

    hr = ADsGetObject(pwszRootPath, &IID_IDirectorySearch, (void**)&pSearch);
    if (FAILED(hr)) {
        KTRACE(L" ADsGetObject failed: 0x%08X\n", hr);
        goto Cleanup;
    }

    ADS_SEARCHPREF_INFO prefs[2];
    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);
    if (FAILED(hr)) goto Cleanup;

    LPWSTR attrs[] = {
        L"distinguishedName", L"sAMAccountName",
        L"objectSid", L"objectClass", L"userAccountControl"
    };

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
        wszFilter, attrs, ARRAYSIZE(attrs), &hSearch);
    if (FAILED(hr)) {
        KTRACE(L" ExecuteSearch failed: 0x%08X\n", hr);
        goto Cleanup;
    }

    KTRACE(L" ExecuteSearch OK, iterating members\n");

    while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {

        ADS_SEARCH_COLUMN colDN = { 0 };
        ADS_SEARCH_COLUMN colSAM = { 0 };
        ADS_SEARCH_COLUMN colSid = { 0 };
        ADS_SEARCH_COLUMN colClass = { 0 };
        ADS_SEARCH_COLUMN colUAC = { 0 };

        BOOL bGotDN = FALSE, bGotSAM = FALSE;
        BOOL bGotSid = FALSE, bGotClass = FALSE, bGotUAC = FALSE;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
            L"distinguishedName", &colDN)) &&
            colDN.dwNumValues > 0 &&
            colDN.pADsValues[0].dwType == ADSTYPE_DN_STRING)
            bGotDN = TRUE;

        if (!bGotDN) {
            KTRACE(L"   Skipping row — no DN\n");
            goto NextRow;
        }

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

        KESTREL_MEMBER* pMember = (KESTREL_MEMBER*)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*pMember));
        if (!pMember) { hr = E_OUTOFMEMORY; goto NextRow; }

        StringCchCopyW(pMember->wszDN, ARRAYSIZE(pMember->wszDN),
            colDN.pADsValues[0].DNString);

        if (bGotSAM)
            StringCchCopyW(pMember->wszSAM, ARRAYSIZE(pMember->wszSAM),
                colSAM.pADsValues[0].CaseIgnoreString);

        if (bGotSid) {
            PSID   pSid = (PSID)colSid.pADsValues[0].OctetString.lpValue;
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

        /* Foreign security principal: a trustee from another domain/forest
           carried into this privileged group. Cross-domain privilege — and a
           blind spot when the SID no longer resolves (stale or external-forest).
           BloodHound-class tools model FSP edges, but the unresolved / external
           case is easy to miss on a quick review. */
        if (_wcsicmp(pMember->wszClass, L"foreignSecurityPrincipal") == 0 ||
            wcsstr(pMember->wszDN, L"CN=ForeignSecurityPrincipals") != NULL) {
            pMember->bForeign = TRUE;
            pRes->cForeign++;
            {
                PSID         pFsp = NULL;
                WCHAR        nm[256] = L"", dm[256] = L"";
                DWORD        cn = ARRAYSIZE(nm), cd = ARRAYSIZE(dm);
                SID_NAME_USE use;
                BOOL         bOk = FALSE;
                if (pMember->wszSid[0] &&
                    ConvertStringSidToSidW(pMember->wszSid, &pFsp) && pFsp) {
                    bOk = LookupAccountSidW(NULL, pFsp, nm, &cn, dm, &cd, &use);
                    LocalFree(pFsp);
                }
                if (bOk)
                    wprintf(L"  [FSP] %s: foreign trustee %s\\%s (%s)\n",
                            pRes->wszGroupName, dm, nm,
                            pMember->wszSid[0] ? pMember->wszSid : L"?");
                else {
                    wprintf(L"  [FSP] %s: foreign trustee %s [UNRESOLVABLE — stale or external-forest SID]\n",
                            pRes->wszGroupName,
                            pMember->wszSid[0] ? pMember->wszSid : pMember->wszDN);
                    KestrelAddFinding(KESTREL_SEV_MEDIUM, L"FSP", pRes->wszGroupName,
                        L"unresolvable foreign trustee in a privileged group (stale or external-forest SID)",
                L"remove the stale foreign SID from the privileged group");
                }
            }
        }

        pMember->bEnabled = TRUE;
        if (bGotUAC && (colUAC.pADsValues[0].Integer & 0x2))
            pMember->bEnabled = FALSE;

        KTRACE(L"   Member #%lu: %-30s [%s] %s\n",
            pRes->cMembers + 1,
            pMember->wszSAM[0] ? pMember->wszSAM : pMember->wszDN,
            pMember->wszClass,
            pMember->bEnabled ? L"enabled" : L"DISABLED");

        *ppTail = pMember;
        ppTail = &pMember->pNext;
        pRes->cMembers++;
        if (pMember->bEnabled) pRes->cEnabled++;

    NextRow:
        if (bGotDN)    pSearch->lpVtbl->FreeColumn(pSearch, &colDN);
        if (bGotSAM)   pSearch->lpVtbl->FreeColumn(pSearch, &colSAM);
        if (bGotSid)   pSearch->lpVtbl->FreeColumn(pSearch, &colSid);
        if (bGotClass) pSearch->lpVtbl->FreeColumn(pSearch, &colClass);
        if (bGotUAC)   pSearch->lpVtbl->FreeColumn(pSearch, &colUAC);
    }

    KTRACE(L" KestrelTransitiveMembership: done — %lu members (%lu enabled)\n",
        pRes->cMembers, pRes->cEnabled);

    *ppResult = pRes;
    pRes = NULL;

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
    _In_opt_ KESTREL_ACL_SCAN_RESULT* pACLResult,
    _In_opt_ KESTREL_GROUP_SCAN_RESULT* pGroupResult)
{
    (void)pwszRootPath;

    wprintf(L"\n[TRACE] KestrelResolveACLTrustees: edges=%lu groups=%lu\n",
        pACLResult ? pACLResult->cEdges : 0,
        pGroupResult ? pGroupResult->cGroups : 0);

    if (!pACLResult || !pGroupResult) {
        KTRACE(L" KestrelResolveACLTrustees: NULL input — skipping\n");
        return S_OK;
    }
    if (pACLResult->cEdges == 0 || pGroupResult->cGroups == 0) {
        KTRACE(L" KestrelResolveACLTrustees: no edges or no groups — skipping\n");
        return S_OK;
    }

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
        KESTREL_ACL_EDGE* pEdge = &pACLResult->rgEdges[e];

        if (pEdge->bDeny) continue;
        if (pEdge->wszTrusteeSid[0] == L'\0') continue;

        for (KESTREL_GROUP_RESULT* pGroup = pGroupResult->pGroups;
            pGroup; pGroup = pGroup->pNext) {

            for (KESTREL_MEMBER* pMember = pGroup->pMembers;
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
    _In_opt_ KESTREL_ACL_SCAN_RESULT* pACLResult,
    _Outptr_ KESTREL_GROUP_SCAN_RESULT** ppResult)
{
    HRESULT                   hr = S_OK;
    KESTREL_GROUP_SCAN_RESULT* pRes = NULL;
    KESTREL_GROUP_RESULT** ppTail = NULL;
    PSID                       pDomainSid = NULL;

    if (!pwszRootPath || !ppResult) return E_INVALIDARG;
    *ppResult = NULL;

    wprintf(L"\n[TRACE] === KestrelRunGroupScan start ===\n");
    KTRACE(L" Root path: %s\n", pwszRootPath);
    KTRACE(L" ACL result: %s (%lu edges)\n",
        pACLResult ? L"provided" : L"NULL",
        pACLResult ? pACLResult->cEdges : 0);

    pRes = (KESTREL_GROUP_SCAN_RESULT*)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(*pRes));
    if (!pRes) return E_OUTOFMEMORY;

    ppTail = &pRes->pGroups;

    wprintf(L"\n═══ Kestrel v0.3 — Transitive Group Membership ═══\n\n");

    /* ── 1. Resolve Domain SID ───────────────────────────────────────── */
    KTRACE(L" Step 1: resolving Domain SID\n");
    hr = KestrelGetDomainSID(pwszRootPath, &pDomainSid);
    if (FAILED(hr)) {
        wprintf(L"  [!] Failed to resolve Domain SID: 0x%08X\n", hr);
        goto Cleanup;
    }

    LPWSTR pwszDomainSidStr = NULL;
    if (ConvertSidToStringSidW(pDomainSid, &pwszDomainSidStr)) {
        wprintf(L"  [*] Domain SID: %s\n\n", pwszDomainSidStr);
        LocalFree(pwszDomainSidStr);
    }

    wprintf(L"  %-40s %-32s %-10s %s\n",
        L"Group (label)", L"sAMAccountName", L"Total", L"Enabled");
    wprintf(L"  %s\n",
        L"--------------------------------------------------------------------------------");

    /* ── 2. Iterate high-value groups by RID ─────────────────────────── */
    KTRACE(L" Step 2: iterating %zu high-value RIDs\n",
        KESTREL_HV_GROUP_COUNT);

    for (SIZE_T i = 0; i < KESTREL_HV_GROUP_COUNT; i++) {

        DWORD   dwRID = g_rgHighValueGroups[i].dwRID;
        LPCWSTR pwszLabel = g_rgHighValueGroups[i].pwszLabel;

        wprintf(L"\n[TRACE] --- Processing RID %lu (%s) ---\n", dwRID, pwszLabel);

        PSID  pGroupSid = NULL;
        WCHAR wszDN[512] = { 0 };
        WCHAR wszSAM[128] = { 0 };

        HRESULT hrGroup = g_rgHighValueGroups[i].bBuiltin
            ? KestrelBuildBuiltinSid(dwRID, &pGroupSid)
            : KestrelBuildGroupSid(pDomainSid, dwRID, &pGroupSid);
        if (FAILED(hrGroup)) {
            KTRACE(L" BuildGroupSid failed: 0x%08X\n", hrGroup);
            pRes->cErrors++;
            continue;
        }

        LPWSTR pwszGroupSidStr = NULL;
        if (ConvertSidToStringSidW(pGroupSid, &pwszGroupSidStr)) {
            KTRACE(L" Group SID: %s\n", pwszGroupSidStr);
            LocalFree(pwszGroupSidStr);
        }

        hrGroup = KestrelGetGroupDNBySid(pwszRootPath, pGroupSid, pwszLabel,
            wszDN, ARRAYSIZE(wszDN),
            wszSAM, ARRAYSIZE(wszSAM));
        FreeSid(pGroupSid);

        if (hrGroup == HRESULT_FROM_WIN32(ERROR_NOT_FOUND)) {
            KTRACE(L" Group not found in domain — skipping\n");
            continue;
        }

        if (FAILED(hrGroup)) {
            KTRACE(L" GetGroupDNBySid failed: 0x%08X\n", hrGroup);
            pRes->cErrors++;
            continue;
        }

        LPCWSTR pwszName = wszSAM[0] ? wszSAM : pwszLabel;

        KTRACE(L" Resolved: SAM='%s' DN='%s'\n", pwszName, wszDN);
        KTRACE(L" Starting transitive expansion\n");

        KESTREL_GROUP_RESULT* pGroup = NULL;
        hrGroup = KestrelTransitiveMembership(pwszRootPath, wszDN,
            pwszName, &pGroup);
        if (FAILED(hrGroup) || !pGroup) {
            KTRACE(L" TransitiveMembership failed: 0x%08X\n", hrGroup);
            pRes->cErrors++;
            continue;
        }

        wprintf(L"  %-40s %-32s %-10lu %lu\n",
            pwszLabel, pwszName, pGroup->cMembers, pGroup->cEnabled);

        KestrelPrintGroupProvenance(wszDN, pwszLabel);

        *ppTail = pGroup;
        ppTail = &pGroup->pNext;
        pRes->cGroups++;
        pRes->cForeign += pGroup->cForeign;
    }

    /* ── 2b. Named high-value groups without a fixed RID ─────────────── */
    {
        static const LPCWSTR g_rgNamedHVGroups[] = {
            L"DnsAdmins", L"DHCP Administrators"
        };
        for (SIZE_T i = 0; i < ARRAYSIZE(g_rgNamedHVGroups); i++) {
            LPCWSTR pwszNm  = g_rgNamedHVGroups[i];
            WCHAR   wszDN[512]  = { 0 };
            WCHAR   wszSAM[128] = { 0 };
            KESTREL_GROUP_RESULT* pGroup = NULL;

            HRESULT hrN = KestrelGetGroupDNByName(pwszRootPath, pwszNm,
                wszDN, ARRAYSIZE(wszDN), wszSAM, ARRAYSIZE(wszSAM));
            if (hrN == HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
                continue;                       /* group not present in domain */
            if (FAILED(hrN)) { pRes->cErrors++; continue; }

            hrN = KestrelTransitiveMembership(pwszRootPath, wszDN,
                wszSAM[0] ? wszSAM : pwszNm, &pGroup);
            if (FAILED(hrN) || !pGroup) { pRes->cErrors++; continue; }

            wprintf(L"  %-40s %-32s %-10lu %lu\n",
                pwszNm, wszSAM[0] ? wszSAM : pwszNm,
                pGroup->cMembers, pGroup->cEnabled);

            KestrelPrintGroupProvenance(wszDN, wszSAM[0] ? wszSAM : pwszNm);

            *ppTail = pGroup;
            ppTail = &pGroup->pNext;
            pRes->cGroups++;
            pRes->cForeign += pGroup->cForeign;
        }
    }

    wprintf(L"\n  [*] Groups scanned: %lu  |  Foreign principals: %lu  |  Errors: %lu\n",
        pRes->cGroups, pRes->cForeign, pRes->cErrors);

    /* ── 3. Cross-reference with ACL edges ───────────────────────────── */
    KTRACE(L" Step 3: cross-referencing ACL trustees\n");
    hr = KestrelResolveACLTrustees(pwszRootPath, pACLResult, pRes);

    *ppResult = pRes;
    pRes = NULL;

    KTRACE(L" === KestrelRunGroupScan complete ===\n");

Cleanup:
    if (pDomainSid) HeapFree(GetProcessHeap(), 0, pDomainSid);
    if (pRes)       KestrelFreeGroupScanResult(pRes);
    return hr;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Cleanup                                                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

VOID
KestrelFreeMemberList(
    _In_opt_ _Post_ptr_invalid_ KESTREL_MEMBER* pHead)
{
    while (pHead) {
        KESTREL_MEMBER* pNext = pHead->pNext;
        HeapFree(GetProcessHeap(), 0, pHead);
        pHead = pNext;
    }
}

VOID
KestrelFreeGroupResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GROUP_RESULT* pResult)
{
    if (!pResult) return;
    KestrelFreeMemberList(pResult->pMembers);
    HeapFree(GetProcessHeap(), 0, pResult);
}

VOID
KestrelFreeGroupScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GROUP_SCAN_RESULT* pResult)
{
    if (!pResult) return;
    KESTREL_GROUP_RESULT* p = pResult->pGroups;
    while (p) {
        KESTREL_GROUP_RESULT* pNext = p->pNext;
        KestrelFreeGroupResult(p);
        p = pNext;
    }
    HeapFree(GetProcessHeap(), 0, pResult);
}
