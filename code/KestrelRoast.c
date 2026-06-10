/*
 * KestrelRoast.c  —  v0.6  Kerberoastable + AS-REP Roastable user detection
 *
 * Two read-only LDAP queries via ADSI/IDirectorySearch.
 * Network profile: indistinguishable from ordinary domain activity.
 *
 * Kerberoastable   — enabled user accounts with a servicePrincipalName set
 *                    (krbtgt excluded). An attacker requests a service ticket
 *                    encrypted with the account password hash and cracks it
 *                    offline. No elevated privileges required to request.
 *
 * AS-REP Roastable — accounts with DONT_REQ_PREAUTH (UAC 0x400000).
 *                    An attacker obtains an AS-REP TGT without knowing the
 *                    password and cracks it offline. Always HIGH risk.
 *
 * Risk heuristic (Kerberoastable):
 *   pwdLastSet > 365 days  ->  HIGH   (stale password, likely weak or skipped rotation)
 *   pwdLastSet  90-365 d   ->  MEDIUM
 *   pwdLastSet  <  90 d    ->  LOW    (recent rotation, harder to crack in time)
 *   pwdLastSet unknown     ->  MEDIUM (treat as potentially stale)
 *
 * Risk heuristic (AS-REP Roastable):
 *   Always HIGH — pre-auth bypass grants TGT with no credential required.
 *
 * TODO (graph integration v0.6+):
 *   Add BOOL bKerberoastable / bASREPRoastable to KESTREL_GRAPH_NODE.
 *   Pass pRoast into KestrelBuildGraph() and set flags during node merge.
 *   HTML report: add risk-colour ring on Kerberoastable/AS-REP nodes.
 */

#include "../include/Kestrel.h"

/* ════════════════════════════════════════════════════════════════════════════
 * Internal helpers
 * ════════════════════════════════════════════════════════════════════════════ */

/*
 * Convert a FILETIME-encoded 64-bit integer (100-ns ticks since 1601-01-01)
 * to an approximate age in days relative to now.
 * Returns -1 if the value is zero / negative (attribute absent or not yet set).
 */
static LONG
_RoastFileTimeAgeDays(_In_ LONGLONG llFT)
{
    if (llFT <= 0LL)
        return -1L;

    FILETIME  ftNow;
    GetSystemTimeAsFileTime(&ftNow);

    ULONGLONG ullNow = ((ULONGLONG)ftNow.dwHighDateTime << 32)
                     | (ULONGLONG)ftNow.dwLowDateTime;
    ULONGLONG ullVal = (ULONGLONG)llFT;

    if (ullVal >= ullNow)
        return 0L;

    return (LONG)((ullNow - ullVal) / KESTREL_FT_PER_DAY);
}

/*
 * Convert a binary SID in an ADS_OCTET_STRING to a string SID.
 * Returns TRUE on success.
 */
static BOOL
_RoastOctetToSidString(
    _In_                    const ADS_OCTET_STRING *pOctet,
    _Out_writes_(cchBuf)    WCHAR                  *pwszBuf,
    _In_                    DWORD                   cchBuf)
{
    if (!pOctet || pOctet->dwLength < 8 || !pOctet->lpValue)
        return FALSE;

    PSID pSid = (PSID)pOctet->lpValue;
    if (!IsValidSid(pSid))
        return FALSE;

    LPWSTR pwszSid = NULL;
    if (!ConvertSidToStringSidW(pSid, &pwszSid))
        return FALSE;

    StringCchCopyW(pwszBuf, cchBuf, pwszSid);
    LocalFree(pwszSid);
    return TRUE;
}

/*
 * Grow rgFindings by 2x.
 * HeapReAlloc does NOT free the original block on failure — the caller's
 * pointer remains valid.
 */
static HRESULT
_RoastGrowFindings(_Inout_ KESTREL_ROAST_SCAN_RESULT *pResult)
{
    DWORD cNew = pResult->cCapacity ? pResult->cCapacity * 2 : 64;

    KESTREL_ROAST_FINDING *pNew =
        (KESTREL_ROAST_FINDING *)HeapReAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            pResult->rgFindings,
            (SIZE_T)cNew * sizeof(KESTREL_ROAST_FINDING));

    if (!pNew)
        return E_OUTOFMEMORY;

    pResult->rgFindings = pNew;
    pResult->cCapacity  = cNew;
    return S_OK;
}


/* ════════════════════════════════════════════════════════════════════════════
 * Internal: execute one LDAP query, append findings to pResult
 * ════════════════════════════════════════════════════════════════════════════ */

static HRESULT
_RoastRunQuery(
    _In_z_  LPCWSTR                    pwszRootPath,
    _In_z_  LPCWSTR                    pwszFilter,
    _In_    KESTREL_ROAST_KIND         Kind,
    _Inout_ KESTREL_ROAST_SCAN_RESULT *pResult)
{
    HRESULT           hr      = S_OK;
    IDirectorySearch *pSearch = NULL;
    ADS_SEARCH_HANDLE hSearch = NULL;

    /* Attributes to retrieve.
     * servicePrincipalName is multi-valued; ADSI returns all values.        */
    LPWSTR rgAttrs[] = {
        L"sAMAccountName",
        L"distinguishedName",
        L"objectSid",
        L"servicePrincipalName",
        L"pwdLastSet",
        L"lastLogonTimestamp",
        L"userAccountControl"
    };
    const DWORD cAttrs = ARRAYSIZE(rgAttrs);

    hr = ADsGetObject((LPWSTR)pwszRootPath,
                      &IID_IDirectorySearch,
                      (void **)&pSearch);
    if (FAILED(hr)) {
        wprintf(L"  [!] _RoastRunQuery: ADsGetObject failed 0x%08X\n", hr);
        return hr;
    }

    /* Subtree scope, paged results */
    ADS_SEARCHPREF_INFO prefs[2];

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;

    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;

    hr = pSearch->lpVtbl->SetSearchPreference(
        pSearch, prefs, ARRAYSIZE(prefs));
    if (FAILED(hr)) {
        wprintf(L"  [!] SetSearchPreference failed 0x%08X\n", hr);
        goto Cleanup;
    }

    hr = pSearch->lpVtbl->ExecuteSearch(
        pSearch, (LPWSTR)pwszFilter, rgAttrs, cAttrs, &hSearch);
    if (FAILED(hr)) {
        wprintf(L"  [!] ExecuteSearch failed 0x%08X\n", hr);
        goto Cleanup;
    }

    /* ── Row loop ───────────────────────────────────────────────────── */
    for (;;) {
        hr = pSearch->lpVtbl->GetNextRow(pSearch, hSearch);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr))              {              break; }

        pResult->cObjectsScanned++;

        /* Grow buffer if needed */
        if (pResult->cFindings >= pResult->cCapacity) {
            hr = _RoastGrowFindings(pResult);
            if (FAILED(hr)) goto Cleanup;
        }

        KESTREL_ROAST_FINDING *pF = &pResult->rgFindings[pResult->cFindings];
        pF->Kind = Kind;

        ADS_SEARCH_COLUMN col;
        ZeroMemory(&col, sizeof(col));

        /* ── sAMAccountName ─────────────────────────────────────────── */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(
                pSearch, hSearch, L"sAMAccountName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING &&
                col.pADsValues && col.dwNumValues > 0 &&
                col.pADsValues[0].CaseIgnoreString) {
                StringCchCopyW(pF->wszSAM, ARRAYSIZE(pF->wszSAM),
                               col.pADsValues[0].CaseIgnoreString);
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }

        /* ── distinguishedName ──────────────────────────────────────── */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(
                pSearch, hSearch, L"distinguishedName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING &&
                col.pADsValues && col.dwNumValues > 0 &&
                col.pADsValues[0].CaseIgnoreString) {
                StringCchCopyW(pF->wszDN, ARRAYSIZE(pF->wszDN),
                               col.pADsValues[0].CaseIgnoreString);
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }

        /* ── objectSid ──────────────────────────────────────────────── */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(
                pSearch, hSearch, L"objectSid", &col))) {
            if (col.dwADsType == ADSTYPE_OCTET_STRING &&
                col.pADsValues && col.dwNumValues > 0) {
                _RoastOctetToSidString(
                    &col.pADsValues[0].OctetString,
                    pF->wszSid, ARRAYSIZE(pF->wszSid));
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }

        /* ── servicePrincipalName (multi-value, Kerberoastable only) ── */
        if (Kind == ROAST_KERBEROASTABLE) {
            if (SUCCEEDED(pSearch->lpVtbl->GetColumn(
                    pSearch, hSearch, L"servicePrincipalName", &col))) {
                if (col.pADsValues &&
                    col.dwADsType == ADSTYPE_CASE_IGNORE_STRING) {
                    for (DWORD v = 0; v < col.dwNumValues; v++) {
                        LPCWSTR pwszSpn =
                            col.pADsValues[v].CaseIgnoreString;
                        if (!pwszSpn)
                            continue;
                        if (pF->wszSPNs[0] != L'\0')
                            StringCchCatW(pF->wszSPNs,
                                ARRAYSIZE(pF->wszSPNs), L"; ");
                        StringCchCatW(pF->wszSPNs,
                            ARRAYSIZE(pF->wszSPNs), pwszSpn);
                    }
                }
                pSearch->lpVtbl->FreeColumn(pSearch, &col);
            }
        }

        /* ── pwdLastSet (Integer8 / ADSTYPE_LARGE_INTEGER) ─────────── */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(
                pSearch, hSearch, L"pwdLastSet", &col))) {
            if (col.dwADsType == ADSTYPE_LARGE_INTEGER &&
                col.pADsValues && col.dwNumValues > 0) {
                pF->llPwdLastSet =
                    col.pADsValues[0].LargeInteger.QuadPart;
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }

        /* ── lastLogonTimestamp (Integer8 / ADSTYPE_LARGE_INTEGER) ─── */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(
                pSearch, hSearch, L"lastLogonTimestamp", &col))) {
            if (col.dwADsType == ADSTYPE_LARGE_INTEGER &&
                col.pADsValues && col.dwNumValues > 0) {
                pF->llLastLogon =
                    col.pADsValues[0].LargeInteger.QuadPart;
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }

        /* ── userAccountControl (ADSTYPE_INTEGER) ───────────────────── */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(
                pSearch, hSearch, L"userAccountControl", &col))) {
            if (col.dwADsType == ADSTYPE_INTEGER &&
                col.pADsValues && col.dwNumValues > 0) {
                pF->dwUAC = (DWORD)col.pADsValues[0].Integer;
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }

        /* ── Risk classification ────────────────────────────────────── */
        LONG lPwdAge = _RoastFileTimeAgeDays(pF->llPwdLastSet);

        if (Kind == ROAST_ASREPROASTABLE) {
            pF->Risk = ROAST_RISK_HIGH;
        } else {
            if      (lPwdAge < 0)    pF->Risk = ROAST_RISK_MEDIUM;
            else if (lPwdAge > 365)  pF->Risk = ROAST_RISK_HIGH;
            else if (lPwdAge > 90)   pF->Risk = ROAST_RISK_MEDIUM;
            else                     pF->Risk = ROAST_RISK_LOW;
        }

        pResult->cFindings++;
    }

Cleanup:
    if (hSearch && pSearch)
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    return hr;
}


/* ════════════════════════════════════════════════════════════════════════════
 * Internal: console table for one ROAST_KIND
 * ════════════════════════════════════════════════════════════════════════════ */

static VOID
_RoastPrintSection(
    _In_ const KESTREL_ROAST_SCAN_RESULT *pResult,
    _In_ KESTREL_ROAST_KIND               Kind)
{
    BOOL  bKerb    = (Kind == ROAST_KERBEROASTABLE);
    DWORD cSection = 0;

    for (DWORD i = 0; i < pResult->cFindings; i++)
        if (pResult->rgFindings[i].Kind == Kind)
            cSection++;

    wprintf(bKerb
        ? L"\n  Kerberoastable users — %lu found\n"
        : L"\n  AS-REP Roastable users — %lu found\n",
        cSection);

    if (cSection == 0)
        return;

    /* Header */
    if (bKerb)
        wprintf(L"\n  %-32s  %-9s  %-10s  %-6s  %s\n",
                L"Account", L"PwdAge(d)", L"LastLog(d)", L"Risk", L"SPNs");
    else
        wprintf(L"\n  %-32s  %-9s  %-10s  %-6s\n",
                L"Account", L"PwdAge(d)", L"LastLog(d)", L"Risk");

    wprintf(L"  ─────────────────────────────────────────────────────────"
            L"──────────────────────────────────────────\n");

    /* Rows */
    for (DWORD i = 0; i < pResult->cFindings; i++) {
        const KESTREL_ROAST_FINDING *pF = &pResult->rgFindings[i];
        if (pF->Kind != Kind)
            continue;

        LONG lPwdAge = _RoastFileTimeAgeDays(pF->llPwdLastSet);
        LONG lLLAge  = _RoastFileTimeAgeDays(pF->llLastLogon);

        WCHAR wszPwdAge[12] = L"-";
        WCHAR wszLLAge[12]  = L"-";

        if (lPwdAge >= 0)
            StringCchPrintfW(wszPwdAge, ARRAYSIZE(wszPwdAge), L"%ld", lPwdAge);
        if (lLLAge >= 0)
            StringCchPrintfW(wszLLAge,  ARRAYSIZE(wszLLAge),  L"%ld", lLLAge);

        LPCWSTR pwszRisk =
            pF->Risk == ROAST_RISK_HIGH   ? L"HIGH  " :
            pF->Risk == ROAST_RISK_MEDIUM ? L"MEDIUM" :
                                            L"LOW   ";

        if (bKerb)
            wprintf(L"  %-32s  %-9s  %-10s  %-6s  %s\n",
                    pF->wszSAM, wszPwdAge, wszLLAge,
                    pwszRisk, pF->wszSPNs);
        else
            wprintf(L"  %-32s  %-9s  %-10s  %-6s\n",
                    pF->wszSAM, wszPwdAge, wszLLAge, pwszRisk);
    }
}


/* ════════════════════════════════════════════════════════════════════════════
 * Public API — KestrelRunRoastScan
 * ════════════════════════════════════════════════════════════════════════════ */

_Must_inspect_result_
HRESULT KestrelRunRoastScan(
    _In_z_   LPCWSTR                    pwszDomainNC,
    _Outptr_ KESTREL_ROAST_SCAN_RESULT **ppResult)
{
    if (!pwszDomainNC || !ppResult)
        return E_INVALIDARG;

    *ppResult = NULL;

    KESTREL_ROAST_SCAN_RESULT *pResult =
        (KESTREL_ROAST_SCAN_RESULT *)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY,
            sizeof(KESTREL_ROAST_SCAN_RESULT));
    if (!pResult)
        return E_OUTOFMEMORY;

    /* Initial findings buffer — 64 entries, grows by 2x as needed */
    pResult->rgFindings = (KESTREL_ROAST_FINDING *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY,
        64 * sizeof(KESTREL_ROAST_FINDING));
    if (!pResult->rgFindings) {
        HeapFree(GetProcessHeap(), 0, pResult);
        return E_OUTOFMEMORY;
    }
    pResult->cCapacity = 64;

    WCHAR   wszRootPath[512] = { 0 };
    HRESULT hr               = S_OK;

    StringCchPrintfW(wszRootPath, ARRAYSIZE(wszRootPath),
                     L"LDAP://%s", pwszDomainNC);

    /* ── Query 1: Kerberoastable ─────────────────────────────────────
     * Enabled users with at least one SPN; krbtgt excluded.
     * LDAP_MATCHING_RULE_BIT_AND (1.2.840.113556.1.4.803) on
     * userAccountControl bit 0x2 = ACCOUNTDISABLE.                         */
    wprintf(L"  [*] Querying Kerberoastable users (SPN + enabled)...\n");

    hr = _RoastRunQuery(
        wszRootPath,
        L"(&"
            L"(objectCategory=user)"
            L"(servicePrincipalName=*)"
            L"(!cn=krbtgt)"
            L"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        L")",
        ROAST_KERBEROASTABLE,
        pResult);

    if (FAILED(hr)) {
        wprintf(L"  [!] Kerberoastable query failed: 0x%08X\n", hr);
        hr = S_OK;  /* non-fatal: continue to AS-REP query */
    }

    /* ── Query 2: AS-REP Roastable ───────────────────────────────────
     * Enabled users with DONT_REQ_PREAUTH (UAC 0x400000 = 4194304).        */
    wprintf(L"  [*] Querying AS-REP Roastable users (DONT_REQ_PREAUTH)...\n");

    hr = _RoastRunQuery(
        wszRootPath,
        L"(&"
            L"(objectCategory=user)"
            L"(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            L"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        L")",
        ROAST_ASREPROASTABLE,
        pResult);

    if (FAILED(hr)) {
        wprintf(L"  [!] AS-REP Roastable query failed: 0x%08X\n", hr);
        hr = S_OK;
    }

    /* ── Tally by kind ───────────────────────────────────────────── */
    for (DWORD i = 0; i < pResult->cFindings; i++) {
        if (pResult->rgFindings[i].Kind == ROAST_KERBEROASTABLE)
            pResult->cKerberoastable++;
        else
            pResult->cASREP++;
    }

    /* ── Console summary ─────────────────────────────────────────── */
    wprintf(L"\n  Scanned %lu objects  |  Kerberoastable: %lu  |  AS-REP: %lu\n",
            pResult->cObjectsScanned,
            pResult->cKerberoastable,
            pResult->cASREP);

    _RoastPrintSection(pResult, ROAST_KERBEROASTABLE);
    _RoastPrintSection(pResult, ROAST_ASREPROASTABLE);

    wprintf(L"\n");

    *ppResult = pResult;
    return S_OK;
}


/* ════════════════════════════════════════════════════════════════════════════
 * Public API — KestrelFreeRoastScanResult
 * ════════════════════════════════════════════════════════════════════════════ */

VOID KestrelFreeRoastScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_ROAST_SCAN_RESULT *pResult)
{
    if (!pResult)
        return;
    if (pResult->rgFindings)
        HeapFree(GetProcessHeap(), 0, pResult->rgFindings);
    HeapFree(GetProcessHeap(), 0, pResult);
}