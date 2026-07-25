/*
 * KestrelSidHistory.c — sIDHistory enumeration
 *
 * sIDHistory carries SIDs a principal previously held (from domain/forest
 * migration). Injecting a privileged SID into a low-priv account's sIDHistory
 * grants that account the injected SID's access on every logon — a stealthy
 * escalation/persistence primitive that leaves no group membership and no ACE.
 *
 * This scan enumerates every object with a populated sIDHistory and classifies
 * each historical SID:
 *   - PRIVILEGED — the SID is a well-known privileged principal (DA/EA/Schema/
 *     DCs/krbtgt/Administrator, or a BUILTIN admin alias). In sIDHistory this is
 *     an alarming stealthy-escalation signal, local or cross-forest.
 *   - FOREIGN    — a domain SID from another domain/forest (legit migration, or
 *     cross-forest injection; the pair to Kestrel's foreign-SID RBCD finding).
 * Each holder also gets msDS-ReplAttributeMetaData provenance on sIDHistory
 * (when it was last written, from which DSA — i.e. when it was injected).
 *
 * The findings feed the graph as HasSIDHistory edges (holder -> SID it carries)
 * via KestrelGraphAddSidHistoryEdges in KestrelReport.c.
 *
 * Invariant-clean: read-only LDAP, ordinary user, directory-side. sIDHistory is
 * a normal SID-syntax multi-valued attribute (ADSI returns octet-string SIDs).
 */

#include "../include/Kestrel.h"
#include <stdlib.h>

/* Read the local domain SID string (S-1-5-21-a-b-c) from the NC head. */
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
    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszDomainNC)))
        return FALSE;
    if (FAILED(ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pSearch)))
        return FALSE;

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_BASE;
    pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 1);

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch, (LPWSTR)L"(objectClass=*)", attrs, 1, &hSearch);
    if (SUCCEEDED(hr) &&
        pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN col = { 0 };
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch, (LPWSTR)L"objectSid", &col)) &&
            col.dwNumValues > 0 && col.pADsValues[0].dwType == ADSTYPE_OCTET_STRING) {
            PSID   pSid = (PSID)col.pADsValues[0].OctetString.lpValue;
            LPWSTR s    = NULL;
            if (pSid && IsValidSid(pSid) && ConvertSidToStringSidW(pSid, &s) && s) {
                StringCchCopyW(pwszOut, cch, s);
                LocalFree(s);
                bOk = TRUE;
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }
    }
    if (hSearch) pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)  pSearch->lpVtbl->Release(pSearch);
    return bOk;
}

/* A privileged historical SID: BUILTIN admin alias, or a domain SID whose RID is
 * a well-known privileged one (in ANY domain, so cross-forest EA/DA injection is
 * caught too). */
static BOOL
_IsPrivileged(_In_z_ LPCWSTR sid)
{
    LPCWSTR rid;

    if (_wcsnicmp(sid, L"S-1-5-32-", 9) == 0) {
        rid = sid + 9;
        return (!wcscmp(rid, L"544") || !wcscmp(rid, L"548") || !wcscmp(rid, L"549") ||
                !wcscmp(rid, L"550") || !wcscmp(rid, L"551") || !wcscmp(rid, L"552"));
    }
    if (_wcsnicmp(sid, L"S-1-5-21-", 9) == 0) {
        rid = wcsrchr(sid, L'-');
        if (!rid) return FALSE;
        rid++;
        return (!wcscmp(rid, L"502") || !wcscmp(rid, L"512") || !wcscmp(rid, L"516") ||
                !wcscmp(rid, L"518") || !wcscmp(rid, L"519") || !wcscmp(rid, L"520") ||
                !wcscmp(rid, L"521") || !wcscmp(rid, L"526") || !wcscmp(rid, L"527"));
    }
    return FALSE;
}

/* A domain SID that is not the local domain's. */
static BOOL
_IsForeign(_In_z_ LPCWSTR sid, _In_z_ LPCWSTR localDomainSid)
{
    WCHAR  pfx[80];

    if (_wcsnicmp(sid, L"S-1-5-21-", 9) != 0) return FALSE;
    if (!localDomainSid || !localDomainSid[0]) return FALSE;
    if (FAILED(StringCchPrintfW(pfx, ARRAYSIZE(pfx), L"%s-", localDomainSid))) return FALSE;
    return (_wcsnicmp(sid, pfx, wcslen(pfx)) != 0);
}

static KESTREL_NODE_CLASS
_ClassOf(_In_ IDirectorySearch *pSearch, _In_ ADS_SEARCH_HANDLE hSearch)
{
    ADS_SEARCH_COLUMN col;
    KESTREL_NODE_CLASS cls = NODE_CLASS_UNKNOWN;

    if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch, (LPWSTR)L"objectClass", &col))) {
        if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING) {
            for (DWORD i = 0; i < col.dwNumValues; i++) {
                LPCWSTR c = col.pADsValues[i].CaseIgnoreString;
                if (!_wcsicmp(c, L"computer")) cls = NODE_CLASS_COMPUTER;
                else if (!_wcsicmp(c, L"group") && cls == NODE_CLASS_UNKNOWN) cls = NODE_CLASS_GROUP;
                else if (!_wcsicmp(c, L"user")  && cls == NODE_CLASS_UNKNOWN) cls = NODE_CLASS_USER;
            }
        }
        pSearch->lpVtbl->FreeColumn(pSearch, &col);
    }
    return cls;
}

static BOOL
_Append(_Inout_ KESTREL_SIDHISTORY_SCAN_RESULT *pRes, _In_ const KESTREL_SIDHIST_FINDING *pF)
{
    if (pRes->cFindings == pRes->cCapacity) {
        DWORD nc = pRes->cCapacity ? pRes->cCapacity * 2 : 64;
        KESTREL_SIDHIST_FINDING *np = (KESTREL_SIDHIST_FINDING *)realloc(
            pRes->rgFindings, nc * sizeof(*np));
        if (!np) return FALSE;
        pRes->rgFindings = np;
        pRes->cCapacity  = nc;
    }
    pRes->rgFindings[pRes->cFindings++] = *pF;
    return TRUE;
}

_Must_inspect_result_
HRESULT
KestrelRunSidHistoryScan(
    _In_z_   LPCWSTR                          pwszDomainNC,
    _Outptr_ KESTREL_SIDHISTORY_SCAN_RESULT **ppResult)
{
    HRESULT             hr;
    IDirectorySearch   *pSearch = NULL;
    ADS_SEARCH_HANDLE   hSearch = NULL;
    WCHAR               wszRoot[600];
    WCHAR               wszDomSid[64] = L"";
    ADS_SEARCHPREF_INFO prefs[2];
    KESTREL_SIDHISTORY_SCAN_RESULT *pRes = NULL;
    LPWSTR rgAttrs[] = {
        (LPWSTR)L"sAMAccountName",
        (LPWSTR)L"distinguishedName",
        (LPWSTR)L"objectClass",
        (LPWSTR)L"objectSid",
        (LPWSTR)L"sIDHistory"
    };

    if (!pwszDomainNC || !ppResult) return E_INVALIDARG;
    *ppResult = NULL;

    pRes = (KESTREL_SIDHISTORY_SCAN_RESULT *)calloc(1, sizeof(*pRes));
    if (!pRes) return E_OUTOFMEMORY;

    _ReadDomainSid(pwszDomainNC, wszDomSid, ARRAYSIZE(wszDomSid));

    if (FAILED(StringCchPrintfW(wszRoot, ARRAYSIZE(wszRoot), L"LDAP://%s", pwszDomainNC))) {
        free(pRes); return E_FAIL;
    }

    wprintf(L"\n[*] SID history (sIDHistory)\n");

    hr = ADsGetObject(wszRoot, &IID_IDirectorySearch, (void **)&pSearch);
    if (FAILED(hr)) { wprintf(L"  [!] ADsGetObject 0x%08X\n", hr); free(pRes); return hr; }

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, ARRAYSIZE(prefs));

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
            (LPWSTR)L"(sIDHistory=*)", rgAttrs, ARRAYSIZE(rgAttrs), &hSearch);
    if (FAILED(hr)) { wprintf(L"  [!] ExecuteSearch 0x%08X\n", hr); goto Cleanup; }

    for (;;) {
        ADS_SEARCH_COLUMN  col;
        WCHAR              wszSam[128] = L"";
        WCHAR              wszDN[600]  = L"";
        WCHAR              wszHolderSid[96] = L"";
        KESTREL_NODE_CLASS cls;

        hr = pSearch->lpVtbl->GetNextRow(pSearch, hSearch);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr)) { wprintf(L"  [!] GetNextRow 0x%08X\n", hr); break; }

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch, (LPWSTR)L"sAMAccountName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszSam, ARRAYSIZE(wszSam), col.pADsValues[0].CaseIgnoreString);
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch, (LPWSTR)L"distinguishedName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszDN, ARRAYSIZE(wszDN), col.pADsValues[0].CaseIgnoreString);
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch, (LPWSTR)L"objectSid", &col))) {
            if (col.dwADsType == ADSTYPE_OCTET_STRING && col.dwNumValues) {
                LPWSTR s = NULL;
                PSID   pSid = (PSID)col.pADsValues[0].OctetString.lpValue;
                if (pSid && IsValidSid(pSid) && ConvertSidToStringSidW(pSid, &s) && s) {
                    StringCchCopyW(wszHolderSid, ARRAYSIZE(wszHolderSid), s);
                    LocalFree(s);
                }
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }
        cls = _ClassOf(pSearch, hSearch);

        wprintf(L"\n  [SH] %-24s\n", wszSam[0] ? wszSam : L"(unknown)");
        KestrelAddFinding(KESTREL_SEV_MEDIUM, L"SID History",
            wszSam[0] ? wszSam : L"(unknown)",
            L"populated sIDHistory (review for privileged or foreign SIDs)",
                L"remove sIDHistory after migration; a privileged/foreign historical SID is an injection marker");

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch, (LPWSTR)L"sIDHistory", &col))) {
            if (col.dwADsType == ADSTYPE_OCTET_STRING) {
                for (DWORD i = 0; i < col.dwNumValues; i++) {
                    PSID   pSid = (PSID)col.pADsValues[i].OctetString.lpValue;
                    LPWSTR s    = NULL;
                    if (!pSid || !IsValidSid(pSid)) continue;
                    if (!ConvertSidToStringSidW(pSid, &s) || !s) continue;

                    {
                        KESTREL_SIDHIST_FINDING f = { 0 };
                        BOOL bPriv = _IsPrivileged(s);
                        BOOL bForn = _IsForeign(s, wszDomSid);

                        wprintf(L"       has-sid %-46s%s%s\n", s,
                            bPriv ? L"  [PRIVILEGED — stealthy escalation]" : L"",
                            bForn ? L"  [FOREIGN — cross-domain/forest]"     : L"");

                        StringCchCopyW(f.wszHolderSid,   ARRAYSIZE(f.wszHolderSid),   wszHolderSid);
                        StringCchCopyW(f.wszHolderLabel, ARRAYSIZE(f.wszHolderLabel), wszSam[0] ? wszSam : s);
                        StringCchCopyW(f.wszHistSid,     ARRAYSIZE(f.wszHistSid),     s);
                        f.HolderClass = cls;
                        f.bPrivileged = bPriv;
                        f.bForeign    = bForn;
                        _Append(pRes, &f);
                        if (bPriv) pRes->cPrivileged++;
                    }
                    LocalFree(s);
                }
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }

        pRes->cObjects++;

        if (wszDN[0]) {
            static const LPCWSTR rgSh[] = { L"sIDHistory" };
            KestrelPrintAttrProvenance(wszDN, L"sid-history", rgSh, 1, FALSE);
        }
    }

    wprintf(L"\n  [=] %lu object(s) with sIDHistory, %lu historical SID(s), %lu privileged\n",
            pRes->cObjects, pRes->cFindings, pRes->cPrivileged);
    if (pRes->cObjects == 0)
        wprintf(L"  [=] No populated sIDHistory found\n");

Cleanup:
    if (hSearch) pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)  pSearch->lpVtbl->Release(pSearch);

    if (FAILED(hr)) { KestrelFreeSidHistoryScanResult(pRes); return hr; }
    *ppResult = pRes;
    return S_OK;
}

VOID
KestrelFreeSidHistoryScanResult(_In_opt_ KESTREL_SIDHISTORY_SCAN_RESULT *pResult)
{
    if (!pResult) return;
    free(pResult->rgFindings);
    free(pResult);
}
