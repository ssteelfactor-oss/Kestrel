/*
 * main.c — Kestrel entry point.
 */

#include "../include/Kestrel.h"

int wmain(int argc, wchar_t *argv[])
{
    (void)argc; (void)argv;

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"[!] CoInitializeEx failed: 0x%08X\n", hr);
        return (int)hr;
    }

    WCHAR   wszDomainNC[512]          = { 0 };
    WCHAR   wszConfigNC[512]          = { 0 };
    IADs   *pRootDSE                  = NULL;
    KESTREL_ACL_SCAN_RESULT   *pACL   = NULL;
    KESTREL_GROUP_SCAN_RESULT *pGroup = NULL;
    VARIANT varDomain, varConfig;
    VariantInit(&varDomain);
    VariantInit(&varConfig);

    /* ── Resolve rootDSE once — passed to all modules ────────────────── */
    hr = ADsGetObject(L"LDAP://rootDSE", &IID_IADs, (void **)&pRootDSE);
    if (FAILED(hr)) {
        wprintf(L"[!] rootDSE bind failed: 0x%08X\n", hr);
        goto Cleanup;
    }

    if (SUCCEEDED(pRootDSE->lpVtbl->Get(pRootDSE,
                L"defaultNamingContext", &varDomain)) &&
        varDomain.vt == VT_BSTR)
        StringCchCopyW(wszDomainNC, ARRAYSIZE(wszDomainNC), varDomain.bstrVal);

    if (SUCCEEDED(pRootDSE->lpVtbl->Get(pRootDSE,
                L"configurationNamingContext", &varConfig)) &&
        varConfig.vt == VT_BSTR)
        StringCchCopyW(wszConfigNC, ARRAYSIZE(wszConfigNC), varConfig.bstrVal);

    pRootDSE->lpVtbl->Release(pRootDSE);
    VariantClear(&varDomain);
    VariantClear(&varConfig);

    /* ── v0.1: five passive AD scans ─────────────────────────────────── */
    wprintf(L"\n═══ Kestrel v0.1 — AD Passive Scan ═══\n\n");
    hr = RunADWSScan();
    if (FAILED(hr))
        wprintf(L"[!] RunADWSScan reported errors: 0x%08X\n", hr);

    /* ── v0.2: ACL edge extraction ───────────────────────────────────── */
    wprintf(L"\n═══ Kestrel v0.2 — ACL Edge Scan ═══\n\n");
    hr = KestrelScanACLEdges(wszDomainNC, wszConfigNC, &pACL);
    if (FAILED(hr))
        wprintf(L"[!] KestrelScanACLEdges failed: 0x%08X\n", hr);

    /* ── v0.3: transitive group membership ───────────────────────────── */
    WCHAR wszRootPath[512] = { 0 };
    StringCchPrintfW(wszRootPath, ARRAYSIZE(wszRootPath), L"LDAP://%s", wszDomainNC);

    hr = KestrelRunGroupScan(wszDomainNC, pACL, &pGroup);
    if (FAILED(hr))
        wprintf(L"[!] KestrelRunGroupScan failed: 0x%08X\n", hr);

Cleanup:
    KestrelFreeACLScanResult(pACL);
    KestrelFreeGroupScanResult(pGroup);
    CoUninitialize();
    return HRESULT_CODE(hr);
}
