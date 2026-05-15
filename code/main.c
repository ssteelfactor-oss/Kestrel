#include <winsock2.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <sal.h>

/* Forward declaration */
_Must_inspect_result_
HRESULT KestrelScanACLEdges(
    _In_z_  LPCWSTR pwszDomainNC,
    _In_z_  LPCWSTR pwszConfigNC,
    _Outptr_ void  **ppResult);

int wmain(int argc, wchar * argv[])
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