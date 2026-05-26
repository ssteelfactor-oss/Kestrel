/*
 * main.c — Kestrel entry point.
 */

#include "../include/Kestrel.h"

int wmain(int argc, wchar_t* argv[])
{
    (void)argc; (void)argv;

    wprintf(L"\n[TRACE] === Program Start ===\n");
    wprintf(L"New ersiob hey there\n");

    wprintf(L"[TRACE] Initializing COM...\n");
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"[!] CoInitializeEx failed: 0x%08X\n", hr);
        return (int)hr;
    }
    wprintf(L"[TRACE] COM initialized successfully\n");

    WCHAR   wszDomainNC[512] = { 0 };
    WCHAR   wszConfigNC[512] = { 0 };
    IADs* pRootDSE = NULL;
    KESTREL_ACL_SCAN_RESULT* pACL = NULL;
    KESTREL_GROUP_SCAN_RESULT* pGroup = NULL;
    VARIANT varDomain, varConfig;
    VariantInit(&varDomain);
    VariantInit(&varConfig);

    /* ── Resolve rootDSE once — passed to all modules ────────────────── */
    wprintf(L"[TRACE] Connecting to LDAP://rootDSE...\n");
    hr = ADsGetObject(L"LDAP://rootDSE", &IID_IADs, (void**)&pRootDSE);
    if (FAILED(hr)) {
        wprintf(L"[!] rootDSE bind failed: 0x%08X\n", hr);
        wprintf(L"[TRACE] This usually means:\n");
        wprintf(L"[TRACE]   - Not running on domain-joined machine\n");
        wprintf(L"[TRACE]   - No domain controller reachable\n");
        wprintf(L"[TRACE]   - LDAP service not available\n");
        goto Cleanup;
    }
    wprintf(L"[TRACE] rootDSE connected successfully\n");

    wprintf(L"[TRACE] Getting defaultNamingContext...\n");
    if (SUCCEEDED(pRootDSE->lpVtbl->Get(pRootDSE,
        L"defaultNamingContext", &varDomain)) &&
        varDomain.vt == VT_BSTR) {
        StringCchCopyW(wszDomainNC, ARRAYSIZE(wszDomainNC), varDomain.bstrVal);
        wprintf(L"[TRACE] Domain NC: %ls\n", wszDomainNC);
    }
    else {
        wprintf(L"[!] Failed to get defaultNamingContext\n");
    }

    wprintf(L"[TRACE] Getting configurationNamingContext...\n");
    if (SUCCEEDED(pRootDSE->lpVtbl->Get(pRootDSE,
        L"configurationNamingContext", &varConfig)) &&
        varConfig.vt == VT_BSTR) {
        StringCchCopyW(wszConfigNC, ARRAYSIZE(wszConfigNC), varConfig.bstrVal);
        wprintf(L"[TRACE] Config NC: %ls\n", wszConfigNC);
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
        wprintf(L"[TRACE] RunADWSScan completed successfully\n");

    /* ── v0.2: ACL edge extraction ───────────────────────────────────── */
    wprintf(L"\n[TRACE] === Starting v0.2 ACL Edge Scan ===\n");
    wprintf(L"[TRACE] Domain NC: %ls\n", wszDomainNC);
    wprintf(L"[TRACE] Config NC: %ls\n", wszConfigNC);
    wprintf(L"\n═══ Kestrel v0.2 — ACL Edge Scan ═══\n\n");
    hr = KestrelScanACLEdges(wszDomainNC, wszConfigNC, &pACL);
    if (FAILED(hr))
        wprintf(L"[!] KestrelScanACLEdges failed: 0x%08X\n", hr);
    else
        wprintf(L"[TRACE] KestrelScanACLEdges completed (edges: %lu)\n",
            pACL ? pACL->cEdges : 0);

    /* ── v0.3: transitive group membership ───────────────────────────── */
    wprintf(L"\n[TRACE] === Starting v0.3 Group Scan ===\n");
    WCHAR wszRootPath[512] = { 0 };
    StringCchPrintfW(wszRootPath, ARRAYSIZE(wszRootPath), L"LDAP://%ls", wszDomainNC);
    wprintf(L"[TRACE] Root path constructed: %ls\n", wszRootPath);

    hr = KestrelRunGroupScan(wszRootPath, pACL, &pGroup);
    if (FAILED(hr))
        wprintf(L"[!] KestrelRunGroupScan failed: 0x%08X\n", hr);
    else
        wprintf(L"[TRACE] KestrelRunGroupScan completed (groups: %lu)\n",
            pGroup ? pGroup->cGroups : 0);

Cleanup:
    wprintf(L"\n[TRACE] === Cleanup Phase ===\n");
    if (pACL) {
        wprintf(L"[TRACE] Freeing ACL results...\n");
        KestrelFreeACLScanResult(pACL);
    }
    if (pGroup) {
        wprintf(L"[TRACE] Freeing Group results...\n");
        KestrelFreeGroupScanResult(pGroup);
    }
    wprintf(L"[TRACE] Uninitializing COM...\n");
    CoUninitialize();
    wprintf(L"[TRACE] === Program Exit (code: %d) ===\n", HRESULT_CODE(hr));
    return HRESULT_CODE(hr);
}
