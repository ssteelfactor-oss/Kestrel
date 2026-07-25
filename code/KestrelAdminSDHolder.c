/*
 * KestrelAdminSDHolder.c — orphaned adminCount detection
 *
 * SDProp stamps adminCount=1 (and disables ACE inheritance) on every object that
 * is a member — direct or nested — of a protected group. When an object is later
 * removed from that group, the marker and the frozen, inheritance-disabled
 * security descriptor are NOT rolled back and no event is written. The result is
 * an "orphan": adminCount=1 on an object that is no longer protected — residual
 * privileged ACL posture, a stealthy non-inheriting SD, and a classic hiding
 * spot for a planted backdoor marker.
 *
 * This scan builds the set of currently-protected principals (the protected
 * groups, their transitive members via LDAP_MATCHING_RULE_IN_CHAIN, and the two
 * protected users Administrator/krbtgt), then flags every adminCount=1 object
 * that is NOT in that set. Each orphan gets nTSecurityDescriptor provenance
 * (when its frozen SD was last written, and from which DSA).
 *
 * NOTE on the other AdminSDHolder axis — dangerous ACEs planted on the
 * CN=AdminSDHolder / CN=System objects themselves (the SDProp backdoor) — is
 * already surfaced by the --acl scan, which walks the whole domain NC subtree
 * and emits those as GenericAll/WriteDacl/etc. edges targeting AdminSDHolder.
 *
 * Invariant-clean: read-only LDAP, ordinary user, directory-side.
 */

#include "../include/Kestrel.h"
#include <stdlib.h>

#define KESTREL_ASDH_INCHAIN  L"1.2.840.113556.1.4.1941"

/* SDProp-protected groups. Domain groups keyed by RID off the domain SID;
 * BUILTIN aliases keyed off S-1-5-32. (Group Policy Creator Owners, RID 520, is
 * deliberately absent — it is not an SDProp-protected group.) */
static const DWORD g_rgProtectedDomainRid[] = {
    512,  /* Domain Admins             */
    516,  /* Domain Controllers        */
    518,  /* Schema Admins             */
    519,  /* Enterprise Admins         */
    521,  /* Read-only Domain Controllers */
    526,  /* Key Admins                */
    527   /* Enterprise Key Admins     */
};
static const DWORD g_rgProtectedBuiltinRid[] = {
    544,  /* Administrators            */
    548,  /* Account Operators         */
    549,  /* Server Operators          */
    550,  /* Print Operators           */
    551,  /* Backup Operators          */
    552   /* Replicator                */
};

/* ── a sorted set of SID strings ──────────────────────────────────────────── */
typedef struct { WCHAR **items; DWORD count, cap; } SIDSET;

static BOOL _SetAdd(_Inout_ SIDSET *s, _In_z_ LPCWSTR sid)
{
    SIZE_T cch;
    if (!sid || !sid[0]) return TRUE;
    if (s->count == s->cap) {
        DWORD nc = s->cap ? s->cap * 2 : 128;
        WCHAR **ni = (WCHAR **)realloc(s->items, nc * sizeof(WCHAR *));
        if (!ni) return FALSE;
        s->items = ni; s->cap = nc;
    }
    cch = wcslen(sid) + 1;
    s->items[s->count] = (WCHAR *)malloc(cch * sizeof(WCHAR));
    if (!s->items[s->count]) return FALSE;
    memcpy(s->items[s->count], sid, cch * sizeof(WCHAR));
    s->count++;
    return TRUE;
}
static int __cdecl _CmpW(const void *a, const void *b)
{
    return _wcsicmp(*(const WCHAR * const *)a, *(const WCHAR * const *)b);
}
static void _SetSort(_Inout_ SIDSET *s)
{
    if (s->count) qsort(s->items, s->count, sizeof(WCHAR *), _CmpW);
}
static BOOL _SetHas(_In_ const SIDSET *s, _In_z_ LPCWSTR sid)
{
    return (s->count &&
            bsearch(&sid, s->items, s->count, sizeof(WCHAR *), _CmpW) != NULL);
}
static void _SetFree(_Inout_ SIDSET *s)
{
    for (DWORD i = 0; i < s->count; i++) free(s->items[i]);
    free(s->items);
    s->items = NULL; s->count = s->cap = 0;
}

/* Read the local domain SID string from the NC head. */
static BOOL
_ReadDomainSid(_In_z_ LPCWSTR pwszDomainNC, _Out_writes_z_(cch) LPWSTR pwszOut, _In_ size_t cch)
{
    HRESULT             hr;
    IDirectorySearch   *pSearch = NULL;
    ADS_SEARCH_HANDLE   hSearch = NULL;
    WCHAR               wszPath[512];
    ADS_SEARCHPREF_INFO prefs[1];
    LPWSTR              attrs[] = { (LPWSTR)L"objectSid" };
    BOOL                bOk = FALSE;

    if (cch) pwszOut[0] = L'\0';
    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszDomainNC))) return FALSE;
    if (FAILED(ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pSearch))) return FALSE;

    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_BASE;
    pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 1);

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch, (LPWSTR)L"(objectClass=*)", attrs, 1, &hSearch);
    if (SUCCEEDED(hr) && pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN col = { 0 };
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch, (LPWSTR)L"objectSid", &col)) &&
            col.dwNumValues > 0 && col.pADsValues[0].dwType == ADSTYPE_OCTET_STRING) {
            PSID pSid = (PSID)col.pADsValues[0].OctetString.lpValue;
            LPWSTR s = NULL;
            if (pSid && IsValidSid(pSid) && ConvertSidToStringSidW(pSid, &s) && s) {
                StringCchCopyW(pwszOut, cch, s); LocalFree(s); bOk = TRUE;
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }
    }
    if (hSearch) pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)  pSearch->lpVtbl->Release(pSearch);
    return bOk;
}

/* Resolve a SID to its DN via <SID=...> binding. */
static BOOL
_SidToDN(_In_z_ LPCWSTR pwszSid, _Out_writes_z_(cch) LPWSTR pwszDN, _In_ size_t cch)
{
    HRESULT             hr;
    IDirectorySearch   *pSearch = NULL;
    ADS_SEARCH_HANDLE   hSearch = NULL;
    WCHAR               wszPath[128];
    ADS_SEARCHPREF_INFO prefs[1];
    LPWSTR              attrs[] = { (LPWSTR)L"distinguishedName" };
    BOOL                bOk = FALSE;

    if (cch) pwszDN[0] = L'\0';
    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://<SID=%s>", pwszSid))) return FALSE;
    if (FAILED(ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pSearch))) return FALSE;

    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_BASE;
    pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 1);

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch, (LPWSTR)L"(objectClass=*)", attrs, 1, &hSearch);
    if (SUCCEEDED(hr) && pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN col = { 0 };
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch, (LPWSTR)L"distinguishedName", &col)) &&
            col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues) {
            StringCchCopyW(pwszDN, cch, col.pADsValues[0].CaseIgnoreString); bOk = TRUE;
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }
    }
    if (hSearch) pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)  pSearch->lpVtbl->Release(pSearch);
    return bOk;
}

/* Add all transitive members of pwszGroupDN (by objectSid) to the set. */
static void
_AddChainMembers(_In_ IDirectorySearch *pRoot, _In_z_ LPCWSTR pwszGroupDN, _Inout_ SIDSET *pSet)
{
    HRESULT           hr;
    ADS_SEARCH_HANDLE hSearch = NULL;
    WCHAR             wszFilter[700];
    LPWSTR            attrs[] = { (LPWSTR)L"objectSid" };

    if (FAILED(StringCchPrintfW(wszFilter, ARRAYSIZE(wszFilter),
            L"(memberOf:" KESTREL_ASDH_INCHAIN L":=%s)", pwszGroupDN)))
        return;

    hr = pRoot->lpVtbl->ExecuteSearch(pRoot, wszFilter, attrs, 1, &hSearch);
    if (FAILED(hr)) return;

    while (pRoot->lpVtbl->GetNextRow(pRoot, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN col = { 0 };
        if (SUCCEEDED(pRoot->lpVtbl->GetColumn(pRoot, hSearch, (LPWSTR)L"objectSid", &col)) &&
            col.dwADsType == ADSTYPE_OCTET_STRING && col.dwNumValues) {
            PSID pSid = (PSID)col.pADsValues[0].OctetString.lpValue;
            LPWSTR s = NULL;
            if (pSid && IsValidSid(pSid) && ConvertSidToStringSidW(pSid, &s) && s) {
                _SetAdd(pSet, s); LocalFree(s);
            }
            pRoot->lpVtbl->FreeColumn(pRoot, &col);
        }
    }
    pRoot->lpVtbl->CloseSearchHandle(pRoot, hSearch);
}

_Must_inspect_result_
HRESULT
KestrelRunAdminSDHolderScan(_In_z_ LPCWSTR pwszDomainNC)
{
    HRESULT             hr;
    IDirectorySearch   *pRoot = NULL;
    ADS_SEARCH_HANDLE   hSearch = NULL;
    WCHAR               wszRoot[600];
    WCHAR               wszDomSid[80] = L"";
    ADS_SEARCHPREF_INFO prefs[2];
    SIDSET              prot = { 0 };
    DWORD               cAdmin = 0, cOrphan = 0, i;
    LPWSTR rgAttrs[] = {
        (LPWSTR)L"sAMAccountName", (LPWSTR)L"distinguishedName",
        (LPWSTR)L"objectClass",   (LPWSTR)L"objectSid"
    };

    if (!pwszDomainNC) return E_INVALIDARG;
    if (FAILED(StringCchPrintfW(wszRoot, ARRAYSIZE(wszRoot), L"LDAP://%s", pwszDomainNC)))
        return E_FAIL;

    wprintf(L"\n[*] Orphaned adminCount (AdminSDHolder)\n");

    if (!_ReadDomainSid(pwszDomainNC, wszDomSid, ARRAYSIZE(wszDomSid)) || !wszDomSid[0]) {
        wprintf(L"  [!] could not read domain SID — aborting\n");
        return E_FAIL;
    }

    hr = ADsGetObject(wszRoot, &IID_IDirectorySearch, (void **)&pRoot);
    if (FAILED(hr)) { wprintf(L"  [!] ADsGetObject 0x%08X\n", hr); return hr; }

    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pRoot->lpVtbl->SetSearchPreference(pRoot, prefs, ARRAYSIZE(prefs));

    /* Build the currently-protected set. */
    for (i = 0; i < ARRAYSIZE(g_rgProtectedDomainRid); i++) {
        WCHAR sid[96], dn[600];
        StringCchPrintfW(sid, ARRAYSIZE(sid), L"%s-%lu", wszDomSid, g_rgProtectedDomainRid[i]);
        _SetAdd(&prot, sid);
        if (_SidToDN(sid, dn, ARRAYSIZE(dn))) _AddChainMembers(pRoot, dn, &prot);
    }
    for (i = 0; i < ARRAYSIZE(g_rgProtectedBuiltinRid); i++) {
        WCHAR sid[96], dn[600];
        StringCchPrintfW(sid, ARRAYSIZE(sid), L"S-1-5-32-%lu", g_rgProtectedBuiltinRid[i]);
        _SetAdd(&prot, sid);
        if (_SidToDN(sid, dn, ARRAYSIZE(dn))) _AddChainMembers(pRoot, dn, &prot);
    }
    /* Protected users that legitimately carry adminCount=1. */
    {
        WCHAR sid[96];
        StringCchPrintfW(sid, ARRAYSIZE(sid), L"%s-500", wszDomSid); _SetAdd(&prot, sid);
        StringCchPrintfW(sid, ARRAYSIZE(sid), L"%s-502", wszDomSid); _SetAdd(&prot, sid);
    }
    _SetSort(&prot);

    /* Enumerate adminCount=1 objects and flag those not in the protected set. */
    hr = pRoot->lpVtbl->ExecuteSearch(pRoot, (LPWSTR)L"(adminCount=1)",
            rgAttrs, ARRAYSIZE(rgAttrs), &hSearch);
    if (FAILED(hr)) { wprintf(L"  [!] ExecuteSearch 0x%08X\n", hr); goto Cleanup; }

    for (;;) {
        ADS_SEARCH_COLUMN col;
        WCHAR wszSam[128] = L"", wszDN[600] = L"", wszSid[96] = L"", wszClass[64] = L"";

        hr = pRoot->lpVtbl->GetNextRow(pRoot, hSearch);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr)) { wprintf(L"  [!] GetNextRow 0x%08X\n", hr); break; }

        if (SUCCEEDED(pRoot->lpVtbl->GetColumn(pRoot, hSearch, (LPWSTR)L"objectSid", &col))) {
            if (col.dwADsType == ADSTYPE_OCTET_STRING && col.dwNumValues) {
                PSID pSid = (PSID)col.pADsValues[0].OctetString.lpValue;
                LPWSTR s = NULL;
                if (pSid && IsValidSid(pSid) && ConvertSidToStringSidW(pSid, &s) && s) {
                    StringCchCopyW(wszSid, ARRAYSIZE(wszSid), s); LocalFree(s);
                }
            }
            pRoot->lpVtbl->FreeColumn(pRoot, &col);
        }
        cAdmin++;
        if (!wszSid[0] || _SetHas(&prot, wszSid)) continue;   /* legitimately protected */

        if (SUCCEEDED(pRoot->lpVtbl->GetColumn(pRoot, hSearch, (LPWSTR)L"sAMAccountName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszSam, ARRAYSIZE(wszSam), col.pADsValues[0].CaseIgnoreString);
            pRoot->lpVtbl->FreeColumn(pRoot, &col);
        }
        if (SUCCEEDED(pRoot->lpVtbl->GetColumn(pRoot, hSearch, (LPWSTR)L"distinguishedName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszDN, ARRAYSIZE(wszDN), col.pADsValues[0].CaseIgnoreString);
            pRoot->lpVtbl->FreeColumn(pRoot, &col);
        }
        if (SUCCEEDED(pRoot->lpVtbl->GetColumn(pRoot, hSearch, (LPWSTR)L"objectClass", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszClass, ARRAYSIZE(wszClass),
                    col.pADsValues[col.dwNumValues - 1].CaseIgnoreString);
            pRoot->lpVtbl->FreeColumn(pRoot, &col);
        }

        wprintf(L"\n  [ORPHAN] %-24s (%s)  adminCount=1, not in any protected group\n",
                wszSam[0] ? wszSam : L"(unknown)", wszClass[0] ? wszClass : L"?");
        KestrelAddFinding(KESTREL_SEV_MEDIUM, L"AdminSDHolder", wszSam,
            L"orphaned adminCount=1 — residual privileged posture (SDProp no longer protects it)");
        cOrphan++;

        if (wszDN[0]) {
            static const LPCWSTR rgSd[] = { L"nTSecurityDescriptor" };
            KestrelPrintAttrProvenance(wszDN, L"orphan-adminCount", rgSd, 1, FALSE);
        }
    }

    wprintf(L"\n  [=] %lu object(s) with adminCount=1, %lu orphaned (residual privileged posture)\n",
            cAdmin, cOrphan);
    if (cOrphan == 0)
        wprintf(L"  [=] No orphaned adminCount objects\n");

Cleanup:
    if (hSearch) pRoot->lpVtbl->CloseSearchHandle(pRoot, hSearch);
    if (pRoot)   pRoot->lpVtbl->Release(pRoot);
    _SetFree(&prot);
    return hr;
}
