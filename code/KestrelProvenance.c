/*
 * KestrelProvenance.c — replication-metadata provenance enrichment
 *
 * An add-on, not a scan of its own. Given a high-value group, it reads the
 * constructed msDS-ReplValueMetaData attribute (per linked-value replication
 * metadata) and surfaces WHEN each direct member was added and from WHICH
 * originating DSA. Recently-added members of a privileged group are a classic
 * persistence / attack signal that raw membership alone does not reveal.
 *
 * Invariant-clean:
 *   - msDS-ReplValueMetaData is a constructed, non-secret attribute readable by
 *     anyone who can already read the object (per Microsoft: "as long as you
 *     have the right to read an object you can read its metadata"). It is NOT
 *     gated by DS-Replication-Get-Changes / DCSync.
 *   - It is requested explicitly for one object at a time (targeted, not a bulk
 *     subtree enrichment), so the footprint stays small.
 *   - If the attribute comes back empty (not readable, or no members), the
 *     enrichment degrades silently — the finding is unaffected.
 *
 * Note: for very large groups msDS-ReplValueMetaData may be range-limited; this
 * first cut reads what the server returns in one page (privileged groups are
 * typically small).
 */

#include "../include/Kestrel.h"

#define KESTREL_PROV_RECENT_DAYS 90

/* Extract text between <tag> and </tag>, searching only within [xml, limit).
 * Returns TRUE and fills out on a hit. limit may be NULL (search to end). */
static BOOL
_XmlField(_In_z_ LPCWSTR xml, _In_opt_ LPCWSTR limit, _In_z_ LPCWSTR tag,
          _Out_writes_z_(cch) LPWSTR out, _In_ SIZE_T cch)
{
    WCHAR        open[64], close[64];
    const WCHAR *s, *e;

    if (cch) out[0] = L'\0';
    if (FAILED(StringCchPrintfW(open,  ARRAYSIZE(open),  L"<%s>",  tag))) return FALSE;
    if (FAILED(StringCchPrintfW(close, ARRAYSIZE(close), L"</%s>", tag))) return FALSE;

    s = wcsstr(xml, open);
    if (!s || (limit && s >= limit)) return FALSE;
    s += wcslen(open);
    e = wcsstr(s, close);
    if (!e || (limit && e >= limit)) return FALSE;

    StringCchCopyNW(out, cch, s, (SIZE_T)(e - s));
    return TRUE;
}

/* "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Site,..." -> "DC01" */
static VOID
_DsaShort(_In_z_ LPCWSTR dsaDN, _Out_writes_z_(cch) LPWSTR out, _In_ SIZE_T cch)
{
    const WCHAR *p;
    SIZE_T       n = 0;

    if (cch) out[0] = L'\0';
    if (!dsaDN || !dsaDN[0]) { StringCchCopyW(out, cch, L"(local)"); return; }

    p = wcsstr(dsaDN, L",CN=");          /* skip "CN=NTDS Settings," */
    if (p) p += 4;
    else { p = dsaDN; if (_wcsnicmp(p, L"CN=", 3) == 0) p += 3; }

    while (p[n] && p[n] != L',' && n + 1 < cch) n++;
    StringCchCopyNW(out, cch, p, n);
}

/* "now - dwDays" as an ISO-8601 UTC prefix for lexical compare vs ftimeCreated. */
static VOID
_RecentCutoff(_Out_writes_z_(cch) LPWSTR out, _In_ SIZE_T cch, _In_ DWORD dwDays)
{
    FILETIME       ft;
    ULARGE_INTEGER uli;
    SYSTEMTIME     st;

    GetSystemTimeAsFileTime(&ft);
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    uli.QuadPart -= (ULONGLONG)dwDays * 24ULL * 60ULL * 60ULL * 10000000ULL;
    ft.dwLowDateTime  = uli.LowPart;
    ft.dwHighDateTime = uli.HighPart;

    if (FileTimeToSystemTime(&ft, &st))
        StringCchPrintfW(out, cch, L"%04d-%02d-%02dT%02d:%02d:%02d",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    else
        StringCchCopyW(out, cch, L"0000");
}

/* Parse one <DS_REPL_VALUE_META_DATA> block (an active 'member' value) and, if
 * it was added within the recent window, print it. Returns TRUE if the block
 * was an active member (counted), regardless of recency. */
static BOOL
_EmitBlock(_In_z_ LPCWSTR block, _In_opt_ LPCWSTR limit,
           _In_z_ LPCWSTR pwszCutoff, _In_z_ LPCWSTR pwszLabel,
           _Inout_ DWORD *pcRecent)
{
    WCHAR wszAttr[64], wszDeleted[40], wszDN[400], wszCreated[40], wszDsa[160], wszShort[64];

    if (_XmlField(block, limit, L"pszAttributeName", wszAttr, ARRAYSIZE(wszAttr)) &&
        _wcsicmp(wszAttr, L"member") != 0)
        return FALSE;                    /* not a membership link */

    if (!_XmlField(block, limit, L"ftimeDeleted", wszDeleted, ARRAYSIZE(wszDeleted)))
        wszDeleted[0] = L'\0';
    if (_wcsnicmp(wszDeleted, L"1601", 4) != 0)
        return FALSE;                    /* tombstoned (removed) member */

    _XmlField(block, limit, L"pszObjectDn",             wszDN,      ARRAYSIZE(wszDN));
    _XmlField(block, limit, L"ftimeCreated",            wszCreated, ARRAYSIZE(wszCreated));
    _XmlField(block, limit, L"pszLastOriginatingDsaDN", wszDsa,     ARRAYSIZE(wszDsa));
    _DsaShort(wszDsa, wszShort, ARRAYSIZE(wszShort));

    if (wszCreated[0] && wcscmp(wszCreated, pwszCutoff) >= 0) {
        if (*pcRecent == 0)
            wprintf(L"  [provenance] %s - members added in last %d days:\n",
                    pwszLabel, KESTREL_PROV_RECENT_DAYS);
        wprintf(L"      + %-48s added %s  from %s\n",
                wszDN[0] ? wszDN : L"(unknown)", wszCreated, wszShort);
        (*pcRecent)++;
    }
    return TRUE;
}

VOID
KestrelPrintGroupProvenance(
    _In_z_ LPCWSTR pwszGroupDN,
    _In_z_ LPCWSTR pwszLabel)
{
    HRESULT             hr;
    IDirectorySearch   *pSearch = NULL;
    ADS_SEARCH_HANDLE   hSearch = NULL;
    WCHAR               wszPath[600];
    WCHAR               wszCutoff[40];
    LPWSTR              attrs[] = { (LPWSTR)L"msDS-ReplValueMetaData" };
    ADS_SEARCHPREF_INFO prefs[1];
    DWORD               cRecent = 0;
    DWORD               cTotal  = 0;

    if (!pwszGroupDN || !pwszGroupDN[0]) return;

    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszGroupDN)))
        return;

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pSearch);
    if (FAILED(hr)) return;

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_BASE;
    pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 1);

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch, (LPWSTR)L"(objectClass=*)",
            attrs, 1, &hSearch);
    if (FAILED(hr)) goto Cleanup;

    _RecentCutoff(wszCutoff, ARRAYSIZE(wszCutoff), KESTREL_PROV_RECENT_DAYS);

    if (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN col = { 0 };

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                (LPWSTR)L"msDS-ReplValueMetaData", &col)) && col.dwNumValues > 0) {

            for (DWORD v = 0; v < col.dwNumValues; v++) {
                const WCHAR *p, *b, *e;

                if (col.pADsValues[v].dwType != ADSTYPE_CASE_IGNORE_STRING) continue;
                p = col.pADsValues[v].CaseIgnoreString;
                if (!p) continue;

                /* a value may hold one or several concatenated blocks */
                while ((b = wcsstr(p, L"<DS_REPL_VALUE_META_DATA>")) != NULL) {
                    e = wcsstr(b, L"</DS_REPL_VALUE_META_DATA>");
                    if (!e) break;
                    if (_EmitBlock(b, e, wszCutoff, pwszLabel, &cRecent))
                        cTotal++;
                    p = e + 1;
                }
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }
    }

    if (cTotal > 0 && cRecent == 0)
        wprintf(L"  [provenance] %s - %lu direct member(s), none added in last %d days\n",
                pwszLabel, cTotal, KESTREL_PROV_RECENT_DAYS);

Cleanup:
    if (hSearch) pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)  pSearch->lpVtbl->Release(pSearch);
}
