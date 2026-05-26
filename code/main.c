/*
 * main.c — Kestrel entry point.
 */

#include "../include/Kestrel.h"


BOOL g_bVerbose = FALSE; // --verbose flag

int wmain(int argc, wchar_t* argv[])
{

    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"--verbose") == 0 ||
            _wcsicmp(argv[i], L"-v") == 0)
            g_bVerbose = TRUE;
    }

    //(void)argc; (void)argv;

    wprintf(L"\n[TRACE] === Program Start ===\n");
    wprintf(L"New ersiob hey there\n");

    KTRACE(L" Initializing COM...\n");
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"[!] CoInitializeEx failed: 0x%08X\n", hr);
        return (int)hr;
    }
    KTRACE(L" COM initialized successfully\n");

    WCHAR   wszDomainNC[512] = { 0 };
    WCHAR   wszConfigNC[512] = { 0 };
    IADs* pRootDSE = NULL;
    KESTREL_ACL_SCAN_RESULT* pACL = NULL;
    KESTREL_GROUP_SCAN_RESULT* pGroup = NULL;
    VARIANT varDomain, varConfig;
    VariantInit(&varDomain);
    VariantInit(&varConfig);

    /* ── Resolve rootDSE once — passed to all modules ────────────────── */
    KTRACE(L" Connecting to LDAP://rootDSE...\n");
    hr = ADsGetObject(L"LDAP://rootDSE", &IID_IADs, (void**)&pRootDSE);
    if (FAILED(hr)) {
        wprintf(L"[!] rootDSE bind failed: 0x%08X\n", hr);
        KTRACE(L" This usually means:\n");
        KTRACE(L"   - Not running on domain-joined machine\n");
        KTRACE(L"   - No domain controller reachable\n");
        KTRACE(L"   - LDAP service not available\n");
        goto Cleanup;
    }
    KTRACE(L" rootDSE connected successfully\n");

    KTRACE(L" Getting defaultNamingContext...\n");
    if (SUCCEEDED(pRootDSE->lpVtbl->Get(pRootDSE,
        L"defaultNamingContext", &varDomain)) &&
        varDomain.vt == VT_BSTR) {
        StringCchCopyW(wszDomainNC, ARRAYSIZE(wszDomainNC), varDomain.bstrVal);
        KTRACE(L" Domain NC: %ls\n", wszDomainNC);
    }
    else {
        wprintf(L"[!] Failed to get defaultNamingContext\n");
    }

    KTRACE(L" Getting configurationNamingContext...\n");
    if (SUCCEEDED(pRootDSE->lpVtbl->Get(pRootDSE,
        L"configurationNamingContext", &varConfig)) &&
        varConfig.vt == VT_BSTR) {
        StringCchCopyW(wszConfigNC, ARRAYSIZE(wszConfigNC), varConfig.bstrVal);
        KTRACE(L" Config NC: %ls\n", wszConfigNC);
    }
    else {
        wprintf(L"[!] Failed to get configurationNamingContext\n");
    }

    pRootDSE->lpVtbl->Release(pRootDSE);
    VariantClear(&varDomain);
    VariantClear(&varConfig);

    if (wszDomainNC[0] == L'\0') {
        wprintf(L"[!] CRITICAL: No domain context available, cannot proceed\n");
        goto Cleanup;
    }

    /* ── v0.1: five passive AD scans ─────────────────────────────────── */
    wprintf(L"\n[TRACE] === Starting v0.1 AD Passive Scan ===\n");
    wprintf(L"\n═══ Kestrel v0.1 — AD Passive Scan ═══\n\n");
    hr = RunADWSScan();
    if (FAILED(hr))
        wprintf(L"[!] RunADWSScan reported errors: 0x%08X\n", hr);
    else
        KTRACE(L" RunADWSScan completed successfully\n");

    /* ── v0.2: ACL edge extraction ───────────────────────────────────── */
    wprintf(L"\n[TRACE] === Starting v0.2 ACL Edge Scan ===\n");
    KTRACE(L" Domain NC: %ls\n", wszDomainNC);
    KTRACE(L" Config NC: %ls\n", wszConfigNC);
    wprintf(L"\n═══ Kestrel v0.2 — ACL Edge Scan ═══\n\n");
    hr = KestrelScanACLEdges(wszDomainNC, wszConfigNC, &pACL);
    if (FAILED(hr))
        wprintf(L"[!] KestrelScanACLEdges failed: 0x%08X\n", hr);
    else
        KTRACE(L" KestrelScanACLEdges completed (edges: %lu)\n",
            pACL ? pACL->cEdges : 0);

    /* ── v0.3: transitive group membership ───────────────────────────── */
    wprintf(L"\n[TRACE] === Starting v0.3 Group Scan ===\n");
    WCHAR wszRootPath[512] = { 0 };
    StringCchPrintfW(wszRootPath, ARRAYSIZE(wszRootPath), L"LDAP://%ls", wszDomainNC);
    KTRACE(L" Root path constructed: %ls\n", wszRootPath);

    hr = KestrelRunGroupScan(wszRootPath, pACL, &pGroup);
    if (FAILED(hr))
        wprintf(L"[!] KestrelRunGroupScan failed: 0x%08X\n", hr);
    else
        KTRACE(L" KestrelRunGroupScan completed (groups: %lu)\n",
            pGroup ? pGroup->cGroups : 0);

Cleanup:
    wprintf(L"\n[TRACE] === Cleanup Phase ===\n");
    if (pACL) {
        KTRACE(L" Freeing ACL results...\n");
        KestrelFreeACLScanResult(pACL);
    }
    if (pGroup) {
        KTRACE(L" Freeing Group results...\n");
        KestrelFreeGroupScanResult(pGroup);
    }
    KTRACE(L" Uninitializing COM...\n");
    CoUninitialize();
    KTRACE(L" === Program Exit (code: %d) ===\n", HRESULT_CODE(hr));
    return HRESULT_CODE(hr);
}
