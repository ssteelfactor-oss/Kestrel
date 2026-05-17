/*
 * adws_scan.c — Kestrel v0.1
 * Passive Active Directory security posture scanner.
 *
 * Five scan modules, all read-only:
 *   1. ScanADWSEndpoints     — probe port 9389/TCP per DC
 *   2. ScanComputerTopology  — SPN-based service inference
 *   3. ScanDelegationRisks   — unconstrained / constrained / S4U2Self
 *   4. ScanLAPSCoverage      — legacy LAPS + Windows LAPS 2023+
 *   5. ScanStaleComputers    — lastLogonTimestamp vs lastLogon
 *
 * All queries use ADSI COM interfaces (IDirectorySearch) over LDAP.
 * Traffic is indistinguishable from normal domain workstation activity.
 * No .NET, no PowerShell, no managed runtime.
 *
 * rootDSE (defaultNamingContext) is resolved once in RunADWSScan and
 * passed as a parameter to all five scan functions — never re-queried.
 *
 * SAL 2.0 annotations validated by /analyze (PREfast).
 * Build: cl adws_scan.c /W4 /analyze /Zi
 * Link:  activeds.lib adsiid.lib ws2_32.lib
 */


#include "../include/Kestrel.h" 

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Constants                                                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

/* UAC flags */
#define UAC_TRUSTED_FOR_DELEGATION          0x00080000
#define UAC_NOT_DELEGATED                   0x00100000
#define UAC_TRUSTED_TO_AUTH_FOR_DELEGATION  0x01000000  /* S4U2Self */
#define UAC_SERVER_TRUST_ACCOUNT            0x00002000  /* DC */

/* ─────────────────────────────────────────────────────────────────────────── */
/*  SPN service-class mapping table                                            */
/* ─────────────────────────────────────────────────────────────────────────── */

typedef struct _KESTREL_SPN_MAP {
    LPCWSTR pwszPrefix;   /* SPN service class prefix, e.g. L"MSSQLSvc" */
    LPCWSTR pwszService;  /* Human-readable service name                  */
} KESTREL_SPN_MAP;

static const KESTREL_SPN_MAP g_SpnMap[] = {
    { L"MSSQLSvc",          L"SQL Server"           },
    { L"WSMAN",             L"WinRM"                },
    { L"TERMSRV",           L"RDP"                  },
    { L"HOST",              L"SMB/RPC host"         },
    { L"LDAP",              L"LDAP"                 },
    { L"GC",                L"Global Catalog"       },
    { L"DNS",               L"DNS"                  },
    { L"http",              L"HTTP/IIS"             },
    { L"exchangeMDB",       L"Exchange MDB"         },
    { L"exchangeRFR",       L"Exchange RFR"         },
    { L"exchangeAB",        L"Exchange AB"          },
    { L"SMTP",              L"SMTP"                 },
    { L"iSCSITarget",       L"iSCSI Target"         },
    { L"MSClusterVirtualServer", L"Failover Cluster"},
};
#define KESTREL_SPN_MAP_COUNT (sizeof(g_SpnMap) / sizeof(g_SpnMap[0]))

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Forward declarations                                                       */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
KestrelGetRootPath(
    _Out_writes_z_(cchBuf) LPWSTR pwszBuf,
    _In_                   SIZE_T cchBuf);

_Must_inspect_result_
static HRESULT
KestrelBuildSearch(
    _In_z_                  LPCWSTR           pwszRootPath,
    _Outptr_                IDirectorySearch **ppSearch);

static VOID
KestrelFileTimeToString(
    _In_                        LONGLONG          llFt,
    _Out_writes_z_(cchBuf)      LPWSTR            pwszBuf,
    _In_                        SIZE_T            cchBuf);

_Must_inspect_result_
static BOOL
KestrelProbeADWS(
    _In_z_ LPCWSTR pwszHostname);

_Must_inspect_result_
static HRESULT ScanADWSEndpoints   (_In_z_ LPCWSTR pwszRootPath);

_Must_inspect_result_
static HRESULT ScanComputerTopology(_In_z_ LPCWSTR pwszRootPath);

_Must_inspect_result_
static HRESULT ScanDelegationRisks (_In_z_ LPCWSTR pwszRootPath);

_Must_inspect_result_
static HRESULT ScanLAPSCoverage    (_In_z_ LPCWSTR pwszRootPath);

_Must_inspect_result_
static HRESULT ScanStaleComputers  (_In_z_ LPCWSTR pwszRootPath);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public entry point                                                         */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
HRESULT RunADWSScan(void)
{
    HRESULT hr      = S_OK;
    HRESULT hrFinal = S_OK;
    BOOL    wsaInit = FALSE;
    WSADATA wsd     = { 0 };
    WCHAR   rootPath[512] = { 0 };

    /* WSA needed for ADWS TCP probes */
    if (WSAStartup(MAKEWORD(2, 2), &wsd) == 0)
        wsaInit = TRUE;

    /* Resolve rootDSE once — passed to all five scans */
    hr = KestrelGetRootPath(rootPath, ARRAYSIZE(rootPath));
    if (FAILED(hr)) {
        wprintf(L"[!] Failed to resolve rootDSE: 0x%08X\n", hr);
        if (wsaInit) WSACleanup();
        return hr;
    }

    wprintf(L"\n[*] Domain root: %s\n\n", rootPath);

    /* ── Run all five passive scans ───────────────────────────────────── */

    wprintf(L"[1/5] ADWS Endpoint Detection\n");
    if (FAILED(ScanADWSEndpoints(rootPath))) {
        wprintf(L"  [!] ScanADWSEndpoints failed.\n");
        hrFinal = E_FAIL;
    }

    wprintf(L"\n[2/5] Computer Topology\n");
    if (FAILED(ScanComputerTopology(rootPath))) {
        wprintf(L"  [!] ScanComputerTopology failed.\n");
        hrFinal = E_FAIL;
    }

    wprintf(L"\n[3/5] Delegation Risks\n");
    if (FAILED(ScanDelegationRisks(rootPath))) {
        wprintf(L"  [!] ScanDelegationRisks failed.\n");
        hrFinal = E_FAIL;
    }

    wprintf(L"\n[4/5] LAPS Coverage\n");
    if (FAILED(ScanLAPSCoverage(rootPath))) {
        wprintf(L"  [!] ScanLAPSCoverage failed.\n");
        hrFinal = E_FAIL;
    }

    wprintf(L"\n[5/5] Stale Computers\n");
    if (FAILED(ScanStaleComputers(rootPath))) {
        wprintf(L"  [!] ScanStaleComputers failed.\n");
        hrFinal = E_FAIL;
    }

    if (wsaInit) WSACleanup();
    return hrFinal;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Infrastructure helpers                                                     */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * KestrelGetRootPath
 * Binds rootDSE and reads defaultNamingContext.
 * Returns LDAP path suitable for ADsGetObject, e.g.
 * "LDAP://DC=corp,DC=example,DC=com"
 */
_Must_inspect_result_
static HRESULT
KestrelGetRootPath(
    _Out_writes_z_(cchBuf) LPWSTR pwszBuf,
    _In_                   SIZE_T cchBuf)
{
    HRESULT  hr       = S_OK;
    IADs    *pRootDSE = NULL;
    VARIANT  var;

    VariantInit(&var);

    hr = ADsGetObject(L"LDAP://rootDSE", &IID_IADs, (void **)&pRootDSE);
    if (FAILED(hr)) goto Cleanup;

    hr = pRootDSE->lpVtbl->Get(pRootDSE, L"defaultNamingContext", &var);
    if (FAILED(hr)) goto Cleanup;

    if (var.vt != VT_BSTR || !var.bstrVal) {
        hr = E_UNEXPECTED;
        goto Cleanup;
    }

    hr = StringCchPrintfW(pwszBuf, cchBuf, L"LDAP://%s", var.bstrVal);

Cleanup:
    VariantClear(&var);
    if (pRootDSE) pRootDSE->lpVtbl->Release(pRootDSE);
    return hr;
}

/*
 * KestrelBuildSearch
 * Creates a paged IDirectorySearch bound to pwszRootPath.
 * Caller must Release when done.
 */
_Must_inspect_result_
static HRESULT
KestrelBuildSearch(
    _In_z_   LPCWSTR           pwszRootPath,
    _Outptr_ IDirectorySearch **ppSearch)
{
    HRESULT             hr    = S_OK;
    IDirectorySearch   *pSrch = NULL;
    ADS_SEARCHPREF_INFO prefs[2];

    *ppSearch = NULL;

    hr = ADsGetObject(pwszRootPath, &IID_IDirectorySearch, (void **)&pSrch);
    if (FAILED(hr)) return hr;

    prefs[0].dwSearchPref          = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType         = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer        = ADS_SCOPE_SUBTREE;

    prefs[1].dwSearchPref          = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType         = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer        = KESTREL_LDAP_PAGESIZE;

    hr = pSrch->lpVtbl->SetSearchPreference(pSrch, prefs, 2);
    if (FAILED(hr)) {
        pSrch->lpVtbl->Release(pSrch);
        return hr;
    }

    *ppSearch = pSrch;
    return S_OK;
}

/*
 * KestrelFileTimeToString
 * Converts a FILETIME stored as LONGLONG to a readable date string.
 * Writes "never" for zero/negative values.
 */
static VOID
KestrelFileTimeToString(
    _In_                   LONGLONG llFt,
    _Out_writes_z_(cchBuf) LPWSTR   pwszBuf,
    _In_                   SIZE_T   cchBuf)
{
    FILETIME   ft  = { 0 };
    SYSTEMTIME st  = { 0 };

    if (llFt <= 0) {
        StringCchCopyW(pwszBuf, cchBuf, L"never");
        return;
    }

    ft.dwLowDateTime  = (DWORD)(llFt & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(llFt >> 32);

    FileTimeToSystemTime(&ft, &st);
    StringCchPrintfW(pwszBuf, cchBuf, L"%04d-%02d-%02d",
                     st.wYear, st.wMonth, st.wDay);
}

/*
 * KestrelProbeADWS
 * Non-blocking TCP connect to port 9389 on pwszHostname.
 * Returns TRUE if the port is open, FALSE otherwise.
 * Uses SO_ERROR + select() — no ADWS/WCF framing sent.
 */
_Must_inspect_result_
static BOOL
KestrelProbeADWS(
    _In_z_ LPCWSTR pwszHostname)
{
    BOOL            bOpen   = FALSE;
    ADDRINFOW       hints   = { 0 };
    PADDRINFOW      pResult = NULL;
    PADDRINFOW      pCur    = NULL;
    WCHAR           wszPort[8];

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    StringCchPrintfW(wszPort, ARRAYSIZE(wszPort), L"%d", KESTREL_ADWS_PORT);

    if (GetAddrInfoW(pwszHostname, wszPort, &hints, &pResult) != 0)
        return FALSE;

    /* Iterate all addresses (dual-stack DC support) */
    for (pCur = pResult; pCur && !bOpen; pCur = pCur->ai_next) {
        SOCKET s = socket(pCur->ai_family, pCur->ai_socktype, pCur->ai_protocol);
        if (s == INVALID_SOCKET) continue;

        /* Set non-blocking */
        u_long mode = 1;
        ioctlsocket(s, FIONBIO, &mode);

        connect(s, pCur->ai_addr, (int)pCur->ai_addrlen);

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);

        struct timeval tv;
        tv.tv_sec  = KESTREL_PROBE_TIMEOUT_MS / 1000;
        tv.tv_usec = (KESTREL_PROBE_TIMEOUT_MS % 1000) * 1000;

        if (select(0, NULL, &wfds, NULL, &tv) > 0) {
            int err    = 0;
            int errlen = sizeof(err);
            getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);
            if (err == 0) bOpen = TRUE;
        }

        closesocket(s);
    }

    FreeAddrInfoW(pResult);
    return bOpen;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Scan 1 — ADWS Endpoint Detection                                          */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
ScanADWSEndpoints(_In_z_ LPCWSTR pwszRootPath)
{
    HRESULT           hr      = S_OK;
    IDirectorySearch *pSearch = NULL;
    ADS_SEARCH_HANDLE hSearch = NULL;
    DWORD             cOpen   = 0;
    DWORD             cTotal  = 0;

    LPWSTR attrs[] = { L"dNSHostName", L"name" };

    hr = KestrelBuildSearch(pwszRootPath, &pSearch);
    if (FAILED(hr)) return hr;

    /* Query all Domain Controllers */
    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
            L"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            attrs, ARRAYSIZE(attrs), &hSearch);
    if (FAILED(hr)) goto Cleanup;

    while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN col = { 0 };
        LPCWSTR pwszHost = NULL;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"dNSHostName", &col))) {
            if (col.dwNumValues > 0 &&
                col.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING)
                pwszHost = col.pADsValues[0].CaseIgnoreString;
        }

        if (pwszHost) {
            cTotal++;
            BOOL bOpen = KestrelProbeADWS(pwszHost);
            wprintf(L"  %-40s port 9389: %s\n",
                    pwszHost, bOpen ? L"OPEN" : L"closed");
            if (bOpen) cOpen++;
        }

        pSearch->lpVtbl->FreeColumn(pSearch, &col);
    }

    wprintf(L"  [*] %lu/%lu DCs have ADWS enabled\n", cOpen, cTotal);

Cleanup:
    if (hSearch) pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)  pSearch->lpVtbl->Release(pSearch);
    return hr;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Scan 2 — Computer Topology (SPN-based service inference)                  */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
ScanComputerTopology(_In_z_ LPCWSTR pwszRootPath)
{
    HRESULT           hr      = S_OK;
    IDirectorySearch *pSearch = NULL;
    ADS_SEARCH_HANDLE hSearch = NULL;

    LPWSTR attrs[] = {
        L"dNSHostName",
        L"servicePrincipalName",
        L"operatingSystem",
        L"msLAPS-Password",
        L"msLAPS-EncryptedPassword"
    };

    hr = KestrelBuildSearch(pwszRootPath, &pSearch);
    if (FAILED(hr)) return hr;

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
            L"(objectClass=computer)",
            attrs, ARRAYSIZE(attrs), &hSearch);
    if (FAILED(hr)) goto Cleanup;

    while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN colHost = { 0 };
        ADS_SEARCH_COLUMN colSpn  = { 0 };
        ADS_SEARCH_COLUMN colOS   = { 0 };

        LPCWSTR pwszHost = L"(unknown)";
        LPCWSTR pwszOS   = L"";

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"dNSHostName", &colHost)) &&
            colHost.dwNumValues > 0 &&
            colHost.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING)
            pwszHost = colHost.pADsValues[0].CaseIgnoreString;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"operatingSystem", &colOS)) &&
            colOS.dwNumValues > 0 &&
            colOS.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING)
            pwszOS = colOS.pADsValues[0].CaseIgnoreString;

        wprintf(L"  %s  [%s]\n", pwszHost, pwszOS);

        /* Walk SPNs and match against service map */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"servicePrincipalName", &colSpn))) {
            for (DWORD i = 0; i < colSpn.dwNumValues; i++) {
                if (colSpn.pADsValues[i].dwType != ADSTYPE_CASE_IGNORE_STRING)
                    continue;

                LPCWSTR pwszSpn = colSpn.pADsValues[i].CaseIgnoreString;

                for (SIZE_T m = 0; m < KESTREL_SPN_MAP_COUNT; m++) {
                    SIZE_T cchPfx = wcslen(g_SpnMap[m].pwszPrefix);
                    if (_wcsnicmp(pwszSpn, g_SpnMap[m].pwszPrefix, cchPfx) == 0 &&
                        pwszSpn[cchPfx] == L'/') {
                        wprintf(L"    + %-20s  (%s)\n",
                                g_SpnMap[m].pwszService, pwszSpn);
                        break;
                    }
                }
            }
            pSearch->lpVtbl->FreeColumn(pSearch, &colSpn);
        }

        pSearch->lpVtbl->FreeColumn(pSearch, &colHost);
        pSearch->lpVtbl->FreeColumn(pSearch, &colOS);
    }

Cleanup:
    if (hSearch) pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)  pSearch->lpVtbl->Release(pSearch);
    return hr;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Scan 3 — Delegation Risks                                                 */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
ScanDelegationRisks(_In_z_ LPCWSTR pwszRootPath)
{
    HRESULT           hr       = S_OK;
    IDirectorySearch *pSearch  = NULL;
    ADS_SEARCH_HANDLE hSearch  = NULL;
    DWORD             cUnconst = 0;
    DWORD             cConst   = 0;
    DWORD             cS4U2    = 0;

    LPWSTR attrs[] = {
        L"sAMAccountName",
        L"userAccountControl",
        L"msDS-AllowedToDelegateTo",
        L"objectClass"
    };

    hr = KestrelBuildSearch(pwszRootPath, &pSearch);
    if (FAILED(hr)) return hr;

    /* All user and computer objects with any delegation setting */
    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
            L"(|(userAccountControl:1.2.840.113556.1.4.803:=524288)"  /* TRUSTED_FOR_DELEGATION */
            L"(userAccountControl:1.2.840.113556.1.4.803:=16777216)"  /* S4U2Self */
            L"(msDS-AllowedToDelegateTo=*))",
            attrs, ARRAYSIZE(attrs), &hSearch);
    if (FAILED(hr)) goto Cleanup;

    wprintf(L"  %-40s %-16s %s\n", L"Account", L"Type", L"Detail");
    wprintf(L"  %s\n", L"------------------------------------------------------------------------");

    while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN colName = { 0 };
        ADS_SEARCH_COLUMN colUAC  = { 0 };
        ADS_SEARCH_COLUMN colDel  = { 0 };

        LPCWSTR pwszName = L"(unknown)";
        DWORD   dwUAC    = 0;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"sAMAccountName", &colName)) &&
            colName.dwNumValues > 0 &&
            colName.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING)
            pwszName = colName.pADsValues[0].CaseIgnoreString;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"userAccountControl", &colUAC)) &&
            colUAC.dwNumValues > 0 &&
            colUAC.pADsValues[0].dwType == ADSTYPE_INTEGER)
            dwUAC = (DWORD)colUAC.pADsValues[0].Integer;

        BOOL bIsDC = !!(dwUAC & UAC_SERVER_TRUST_ACCOUNT);

        /* Unconstrained delegation — skip DCs (expected) */
        if ((dwUAC & UAC_TRUSTED_FOR_DELEGATION) && !bIsDC) {
            wprintf(L"  %-40s %-16s TGT forwarded on auth\n",
                    pwszName, L"[UNCONSTRAINED]");
            cUnconst++;
        }

        /* S4U2Self — Protocol Transition */
        if (dwUAC & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) {
            wprintf(L"  %-40s %-16s Can obtain ticket for any user\n",
                    pwszName, L"[S4U2Self]");
            cS4U2++;
        }

        /* Constrained delegation — list target SPNs */
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"msDS-AllowedToDelegateTo", &colDel))) {
            for (DWORD i = 0; i < colDel.dwNumValues; i++) {
                if (colDel.pADsValues[i].dwType != ADSTYPE_CASE_IGNORE_STRING)
                    continue;
                wprintf(L"  %-40s %-16s → %s\n",
                        i == 0 ? pwszName : L"",
                        i == 0 ? L"[CONSTRAINED]" : L"",
                        colDel.pADsValues[i].CaseIgnoreString);
            }
            if (colDel.dwNumValues > 0) cConst++;
            pSearch->lpVtbl->FreeColumn(pSearch, &colDel);
        }

        pSearch->lpVtbl->FreeColumn(pSearch, &colName);
        pSearch->lpVtbl->FreeColumn(pSearch, &colUAC);
    }

    wprintf(L"\n  [*] Unconstrained: %lu  Constrained: %lu  S4U2Self: %lu\n",
            cUnconst, cConst, cS4U2);

Cleanup:
    if (hSearch) pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)  pSearch->lpVtbl->Release(pSearch);
    return hr;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Scan 4 — LAPS Coverage                                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
ScanLAPSCoverage(_In_z_ LPCWSTR pwszRootPath)
{
    HRESULT           hr         = S_OK;
    IDirectorySearch *pSearch    = NULL;
    ADS_SEARCH_HANDLE hSearch    = NULL;
    DWORD             cTotal     = 0;
    DWORD             cLegacy    = 0;
    DWORD             cModern    = 0;
    DWORD             cUnmanaged = 0;

    LPWSTR attrs[] = {
        L"sAMAccountName",
        L"ms-Mcs-AdmPwdExpirationTime",   /* Legacy LAPS          */
        L"msLAPS-EncryptedPasswordHistory" /* Windows LAPS 2023+   */
    };

    hr = KestrelBuildSearch(pwszRootPath, &pSearch);
    if (FAILED(hr)) return hr;

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
            L"(objectClass=computer)",
            attrs, ARRAYSIZE(attrs), &hSearch);
    if (FAILED(hr)) goto Cleanup;

    while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN colName   = { 0 };
        ADS_SEARCH_COLUMN colLegacy = { 0 };
        ADS_SEARCH_COLUMN colModern = { 0 };

        BOOL bLegacy = FALSE;
        BOOL bModern = FALSE;

        cTotal++;

        LPCWSTR pwszName = L"(unknown)";
        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"sAMAccountName", &colName)) &&
            colName.dwNumValues > 0 &&
            colName.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING)
            pwszName = colName.pADsValues[0].CaseIgnoreString;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"ms-Mcs-AdmPwdExpirationTime", &colLegacy)) &&
            colLegacy.dwNumValues > 0)
            bLegacy = TRUE;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"msLAPS-EncryptedPasswordHistory", &colModern)) &&
            colModern.dwNumValues > 0)
            bModern = TRUE;

        if (bModern)       { cModern++;    wprintf(L"  %-40s  LAPS 2023+\n", pwszName); }
        else if (bLegacy)  { cLegacy++;    wprintf(L"  %-40s  LAPS (legacy)\n", pwszName); }
        else               { cUnmanaged++; wprintf(L"  %-40s  NOT MANAGED\n", pwszName); }

        pSearch->lpVtbl->FreeColumn(pSearch, &colName);
        pSearch->lpVtbl->FreeColumn(pSearch, &colLegacy);
        pSearch->lpVtbl->FreeColumn(pSearch, &colModern);
    }

    wprintf(L"\n  [*] Total: %lu  |  LAPS 2023+: %lu  |  Legacy: %lu  |  Unmanaged: %lu (%.0f%%)\n",
            cTotal, cModern, cLegacy, cUnmanaged,
            cTotal ? (double)cUnmanaged / cTotal * 100.0 : 0.0);

Cleanup:
    if (hSearch) pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)  pSearch->lpVtbl->Release(pSearch);
    return hr;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Scan 5 — Stale Computers                                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
ScanStaleComputers(_In_z_ LPCWSTR pwszRootPath)
{
    HRESULT           hr      = S_OK;
    IDirectorySearch *pSearch = NULL;
    ADS_SEARCH_HANDLE hSearch = NULL;
    DWORD             cStale  = 0;
    DWORD             cTotal  = 0;
    ULARGE_INTEGER    uliNow  = { 0 };
    FILETIME          ftNow   = { 0 };

    /* Compute the stale threshold as a FILETIME */
    GetSystemTimeAsFileTime(&ftNow);
    uliNow.LowPart  = ftNow.dwLowDateTime;
    uliNow.HighPart = ftNow.dwHighDateTime;
    LONGLONG llThreshold = (LONGLONG)(uliNow.QuadPart -
                            (ULONGLONG)KESTREL_STALE_DAYS * KESTREL_FT_PER_DAY);

    LPWSTR attrs[] = {
        L"sAMAccountName",
        L"lastLogonTimestamp",  /* Replicates across all DCs — use as primary */
        L"lastLogon"            /* Per-DC only — reported for comparison       */
    };

    hr = KestrelBuildSearch(pwszRootPath, &pSearch);
    if (FAILED(hr)) return hr;

    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
            L"(objectClass=computer)",
            attrs, ARRAYSIZE(attrs), &hSearch);
    if (FAILED(hr)) goto Cleanup;

    wprintf(L"  %-40s %-14s %-14s %s\n",
            L"Computer", L"LastLogonTS", L"LastLogon", L"Status");
    wprintf(L"  %s\n",
            L"-----------------------------------------------------------------------");

    while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN colName  = { 0 };
        ADS_SEARCH_COLUMN colTS    = { 0 };
        ADS_SEARCH_COLUMN colLL    = { 0 };

        LONGLONG llTS = 0;
        LONGLONG llLL = 0;
        LPCWSTR pwszName = L"(unknown)";

        cTotal++;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"sAMAccountName", &colName)) &&
            colName.dwNumValues > 0 &&
            colName.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING)
            pwszName = colName.pADsValues[0].CaseIgnoreString;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"lastLogonTimestamp", &colTS)) &&
            colTS.dwNumValues > 0 &&
            colTS.pADsValues[0].dwType == ADSTYPE_LARGE_INTEGER)
            llTS = colTS.pADsValues[0].LargeInteger.QuadPart;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"lastLogon", &colLL)) &&
            colLL.dwNumValues > 0 &&
            colLL.pADsValues[0].dwType == ADSTYPE_LARGE_INTEGER)
            llLL = colLL.pADsValues[0].LargeInteger.QuadPart;

        WCHAR wszTS[32], wszLL[32];
        KestrelFileTimeToString(llTS, wszTS, ARRAYSIZE(wszTS));
        KestrelFileTimeToString(llLL, wszLL, ARRAYSIZE(wszLL));

        BOOL bStale = (llTS == 0 || llTS < llThreshold);
        if (bStale) cStale++;

        wprintf(L"  %-40s %-14s %-14s %s\n",
                pwszName, wszTS, wszLL,
                bStale ? L"*** STALE ***" : L"active");

        pSearch->lpVtbl->FreeColumn(pSearch, &colName);
        pSearch->lpVtbl->FreeColumn(pSearch, &colTS);
        pSearch->lpVtbl->FreeColumn(pSearch, &colLL);
    }

    wprintf(L"\n  [*] Stale (>%d days): %lu / %lu  (%.0f%%)\n",
            KESTREL_STALE_DAYS, cStale, cTotal,
            cTotal ? (double)cStale / cTotal * 100.0 : 0.0);

Cleanup:
    if (hSearch) pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)  pSearch->lpVtbl->Release(pSearch);
    return hr;
}
