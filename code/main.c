#include "../include/Kestrel.h"


int wmain(int argc, wchar_t* argv[])
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"[!] CoInitializeEx failed: 0x%08X\n", hr);
        return (int)hr;
    }

    /* ── Resolve rootDSE once ────────────────────────────────────────── */
    WCHAR  wszDomainNC[512] = { 0 };
    WCHAR  wszConfigNC[512] = { 0 };
    IADs* pRootDSE = NULL;
    VARIANT varDomain, varConfig;
    VariantInit(&varDomain);
    VariantInit(&varConfig);

    hr = ADsGetObject(L"LDAP://rootDSE", &IID_IADs, (void**)&pRootDSE);
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

    /* ── v0.1: пять пассивных сканов ────────────────────────────────── */
    wprintf(L"\n═══ Kestrel v0.1 — AD Passive Scan ═══\n\n");
    hr = RunADWSScan();
    if (FAILED(hr))
        wprintf(L"[!] RunADWSScan reported errors: 0x%08X\n", hr);

    /* ── v0.2: ACL edge extraction ───────────────────────────────────── */
    wprintf(L"\n═══ Kestrel v0.2 — ACL Edge Scan ═══\n\n");
    KESTREL_ACL_SCAN_RESULT* pResult = NULL;
    hr = KestrelScanACLEdges(wszDomainNC, wszConfigNC, &pResult);
    if (FAILED(hr))
        wprintf(L"[!] KestrelScanACLEdges failed: 0x%08X\n", hr);
    KestrelFreeACLScanResult(pResult);

Cleanup:
    CoUninitialize();
    return HRESULT_CODE(hr);
}