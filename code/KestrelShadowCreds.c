/*
 * KestrelShadowCreds.c — shadow-credential detection (msDS-KeyCredentialLink)
 *
 * A shadow-credentials attack plants a key credential (an NGC/WHfB key the
 * attacker controls) on a target account, then authenticates as it via PKINIT —
 * a stealthy persistence primitive that survives a password reset and is
 * invisible to ACL analysis. This scan surfaces the *result*: every object that
 * already carries a populated msDS-KeyCredentialLink, decoded to key usage and
 * creation time, plus when the attribute was last written and from which DSA.
 *
 * Computers legitimately carry device keys, so those are noted but not alarming;
 * a key credential on a *user* — especially a privileged (adminCount=1) or
 * service account — is the classic shadow-credential signal and is flagged for
 * review. Recently-created keys (< 90 days) are highlighted.
 *
 * Invariant-clean: read-only LDAP, ordinary user, directory-side. The attribute
 * is a normal DN-Binary attribute (ADSI hands back ADS_DN_WITH_BINARY, so the
 * blob arrives already separated from the owner DN and hex-decoded).
 *
 * Blob format (MS-ADTS 2.2.20 KEYCREDENTIALLINK_BLOB):
 *   DWORD Version (== 0x00000200), then entries [len:2 LE][id:1][value:len]:
 *     id 0x04 KeyUsage (1 byte; 0x01 = NGC), id 0x09 KeyCreationTime (FILETIME).
 */

#include "../include/Kestrel.h"

#define KESTREL_SC_RECENT_DAYS 90

/* Parse one KEYCREDENTIALLINK_BLOB. Fills usage + creation time when present. */
static BOOL
_ParseKeyCred(_In_reads_bytes_(cb) const BYTE *p, _In_ DWORD cb,
              _Out_ BYTE *pUsage, _Out_ FILETIME *pCreated, _Out_ BOOL *pbCreated)
{
    DWORD off;

    *pUsage    = 0xFF;
    *pbCreated = FALSE;
    pCreated->dwLowDateTime = pCreated->dwHighDateTime = 0;

    if (!p || cb < 4) return FALSE;
    /* Version DWORD (LE) — expect KEY_CREDENTIAL_LINK_VERSION_2 (0x00000200) */
    /* (parse regardless; a wrong version just means we may find no entries)   */

    off = 4;
    while (off + 3 <= cb) {
        WORD  elen = (WORD)(p[off] | (p[off + 1] << 8));
        BYTE  id   = p[off + 2];
        DWORD voff = off + 3;

        if ((DWORD)voff + elen > cb) break;

        if (id == 0x04 && elen >= 1) {
            *pUsage = p[voff];
        } else if (id == 0x09 && elen >= 8) {
            ULONGLONG ft = 0;
            for (int k = 0; k < 8; k++)
                ft |= ((ULONGLONG)p[voff + k]) << (8 * k);
            pCreated->dwLowDateTime  = (DWORD)(ft & 0xFFFFFFFF);
            pCreated->dwHighDateTime = (DWORD)(ft >> 32);
            *pbCreated = TRUE;
        }
        off = voff + elen;
    }
    return TRUE;
}

static LPCWSTR
_UsageName(_In_ BYTE u)
{
    switch (u) {
        case 0x01: return L"NGC";      /* Windows Hello / shadow-cred key */
        case 0x02: return L"STK";
        case 0x03: return L"BitLockerRecovery";
        case 0x05: return L"FIDO";
        case 0x06: return L"FEK";
        default:   return L"other";
    }
}

/* FILETIME -> "YYYY-MM-DDThh:mm:ss" (UTC); returns FALSE if the time is empty. */
static BOOL
_FtToIso(_In_ const FILETIME *pft, _Out_writes_z_(cch) LPWSTR out, _In_ SIZE_T cch)
{
    SYSTEMTIME st;

    if (cch) out[0] = L'\0';
    if ((pft->dwLowDateTime == 0 && pft->dwHighDateTime == 0) ||
        !FileTimeToSystemTime(pft, &st))
        return FALSE;
    StringCchPrintfW(out, cch, L"%04d-%02d-%02dT%02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return TRUE;
}

static BOOL
_IsRecent(_In_ const FILETIME *pft, _In_ DWORD dwDays)
{
    FILETIME       now;
    ULARGE_INTEGER u, c;

    GetSystemTimeAsFileTime(&now);
    u.LowPart = now.dwLowDateTime; u.HighPart = now.dwHighDateTime;
    c.LowPart = pft->dwLowDateTime; c.HighPart = pft->dwHighDateTime;
    if (c.QuadPart == 0) return FALSE;
    return (u.QuadPart - c.QuadPart) < (ULONGLONG)dwDays * 24ULL * 3600ULL * 10000000ULL;
}

_Must_inspect_result_
HRESULT
KestrelRunShadowCredScan(_In_z_ LPCWSTR pwszDomainNC)
{
    HRESULT             hr;
    IDirectorySearch   *pSearch = NULL;
    ADS_SEARCH_HANDLE   hSearch = NULL;
    WCHAR               wszRoot[600];
    ADS_SEARCHPREF_INFO prefs[2];
    DWORD               cObjects = 0, cUserKeys = 0;
    LPWSTR rgAttrs[] = {
        (LPWSTR)L"sAMAccountName",
        (LPWSTR)L"distinguishedName",
        (LPWSTR)L"objectClass",
        (LPWSTR)L"adminCount",
        (LPWSTR)L"msDS-KeyCredentialLink"
    };

    if (!pwszDomainNC) return E_INVALIDARG;

    if (FAILED(StringCchPrintfW(wszRoot, ARRAYSIZE(wszRoot), L"LDAP://%s", pwszDomainNC)))
        return E_FAIL;

    wprintf(L"\n[*] Shadow credentials (msDS-KeyCredentialLink)\n");

    hr = ADsGetObject(wszRoot, &IID_IDirectorySearch, (void **)&pSearch);
    if (FAILED(hr)) {
        wprintf(L"  [!] ADsGetObject failed 0x%08X\n", hr);
        return hr;
    }

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, ARRAYSIZE(prefs));
    if (FAILED(hr)) { wprintf(L"  [!] SetSearchPreference 0x%08X\n", hr); goto Cleanup; }

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
            (LPWSTR)L"(msDS-KeyCredentialLink=*)", rgAttrs, ARRAYSIZE(rgAttrs), &hSearch);
    if (FAILED(hr)) { wprintf(L"  [!] ExecuteSearch 0x%08X\n", hr); goto Cleanup; }

    for (;;) {
        ADS_SEARCH_COLUMN col;
        WCHAR   wszSam[128]   = L"";
        WCHAR   wszDN[600]    = L"";
        BOOL    bComputer     = FALSE;
        BOOL    bAdmin        = FALSE;
        DWORD   cKeys         = 0;
        DWORD   cRecent       = 0;

        hr = pSearch->lpVtbl->GetNextRow(pSearch, hSearch);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr)) { wprintf(L"  [!] GetNextRow 0x%08X\n", hr); break; }

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                (LPWSTR)L"sAMAccountName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszSam, ARRAYSIZE(wszSam), col.pADsValues[0].CaseIgnoreString);
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                (LPWSTR)L"distinguishedName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszDN, ARRAYSIZE(wszDN), col.pADsValues[0].CaseIgnoreString);
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                (LPWSTR)L"objectClass", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING) {
                for (DWORD i = 0; i < col.dwNumValues; i++)
                    if (_wcsicmp(col.pADsValues[i].CaseIgnoreString, L"computer") == 0)
                        bComputer = TRUE;
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                (LPWSTR)L"adminCount", &col))) {
            if (col.dwADsType == ADSTYPE_INTEGER && col.dwNumValues &&
                col.pADsValues[0].Integer == 1)
                bAdmin = TRUE;
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }

        /* Header line for this object. */
        wprintf(L"\n  [KC] %-24s %s%s%s\n",
            wszSam[0] ? wszSam : L"(unknown)",
            bComputer ? L"(computer — device key, usually benign)" : L"[USER — review]",
            bAdmin    ? L"  [adminCount=1 / TIER-0]" : L"",
            L"");

        /* Decode each key credential. */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                (LPWSTR)L"msDS-KeyCredentialLink", &col))) {
            if (col.dwADsType == ADSTYPE_DN_WITH_BINARY) {
                for (DWORD i = 0; i < col.dwNumValues; i++) {
                    PADS_DN_WITH_BINARY pdb = col.pADsValues[i].pDNWithBinary;
                    BYTE      usage = 0xFF;
                    FILETIME  ftCreated;
                    BOOL      bHasTime = FALSE;
                    WCHAR     wszWhen[40];

                    if (!pdb || !pdb->lpBinaryValue) continue;
                    cKeys++;

                    _ParseKeyCred(pdb->lpBinaryValue, pdb->dwLength,
                                  &usage, &ftCreated, &bHasTime);

                    _FtToIso(&ftCreated, wszWhen, ARRAYSIZE(wszWhen));
                    BOOL bRecent = bHasTime && _IsRecent(&ftCreated, KESTREL_SC_RECENT_DAYS);
                    if (bRecent) cRecent++;

                    wprintf(L"       key usage=%-6s created=%s%s\n",
                        _UsageName(usage),
                        wszWhen[0] ? wszWhen : L"(unknown)",
                        bRecent ? L"   *** RECENT ***" : L"");
                }
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }

        cObjects++;
        if (!bComputer) cUserKeys++;

        /* Provenance: when was the attribute last written, and from where. */
        if (wszDN[0]) {
            static const LPCWSTR rgKcl[] = { L"msDS-KeyCredentialLink" };
            KestrelPrintAttrProvenance(wszDN,
                bComputer ? L"shadow-cred(computer)" : L"shadow-cred(USER)",
                rgKcl, 1, FALSE);
        }

        (void)cKeys; (void)cRecent;
    }

    wprintf(L"\n  [=] %lu object(s) with key credentials (%lu on user/service accounts)\n",
            cObjects, cUserKeys);
    if (cObjects == 0)
        wprintf(L"  [=] No populated msDS-KeyCredentialLink found\n");

Cleanup:
    if (hSearch) pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)  pSearch->lpVtbl->Release(pSearch);
    return hr;
}
