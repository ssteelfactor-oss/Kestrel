#include "../include/Kestrel.h"

int wmain(int argc, wchar_t * argv[])
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"[!] CoInitializeEx failed: 0x%08X\n", hr);
        return (int)hr;
    }

    /* TODO: resolve rootDSE, call KestrelScanACLEdges */

    CoUninitialize();
    return 0;
}