/*
  sql_probe.c
  - Пассивная инвентаризация MS SQL / OLE DB / ODBC компонентов на Windows.
  - Сбор провайдеров OLE DB (по реестру / HKCR), чтение CLSID -> InprocServer32 -> версия файла,
    перечисление ODBC-драйверов, локальных SQL-инстансов из реестра,
    опрос SQL Browser (UDP 1434) и опциональный безопасный sp_configure тест через ODBC.
  - Компиляция (MSVC):
      cl /nologo /O2 sql_probe.c /link Ws2_32.lib Odbc32.lib Ole32.lib Version.lib
    MinGW:
      x86_64-w64-mingw32-gcc -O2 sql_probe.c -lws2_32 -lodbc32 -lole32 -lversion -municode -o sql_probe.exe
  - Примечание: код ориентирован на Windows API (UNICODE).
*/

#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <tchar.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sql.h>
#include <sqlext.h>
#include <schnlsp.h>    // не обязательно
#include <versionhelpers.h>
#include <stdlib.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Odbc32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Version.lib")

// Utility printing
static void printw(const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vwprintf(fmt, ap);
    va_end(ap);
}

// Read default (unnamed) value from registry key, return newly-alloc wchar* (must free with free())
static wchar_t *read_reg_default_value(HKEY hRoot, const wchar_t *subkey)
{
    HKEY hKey = NULL;
    wchar_t *buf = NULL;
    DWORD size = 0, type = 0;
    LONG rc = RegOpenKeyExW(hRoot, subkey, 0, KEY_READ, &hKey);
    if (rc != ERROR_SUCCESS) return NULL;
    // query size
    rc = RegQueryValueExW(hKey, NULL, NULL, &type, NULL, &size);
    if (rc != ERROR_SUCCESS || type != REG_SZ) { RegCloseKey(hKey); return NULL; }
    buf = (wchar_t*)malloc(size);
    if (!buf) { RegCloseKey(hKey); return NULL; }
    rc = RegQueryValueExW(hKey, NULL, NULL, NULL, (LPBYTE)buf, &size);
    if (rc != ERROR_SUCCESS) { free(buf); buf = NULL; }
    RegCloseKey(hKey);
    return buf;
}

// Get file version string for given full path
static wchar_t *get_file_version_string(const wchar_t *path)
{
    if (!path) return NULL;
    DWORD dummy = 0;
    DWORD len = GetFileVersionInfoSizeW(path, &dummy);
    if (len == 0) return NULL;
    void *data = malloc(len);
    if (!data) return NULL;
    if (!GetFileVersionInfoW(path, 0, len, data)) { free(data); return NULL; }
    VS_FIXEDFILEINFO *ffi = NULL;
    UINT ffiLen = 0;
    if (!VerQueryValueW(data, L"\\", (LPVOID*)&ffi, &ffiLen) || ffiLen == 0) { free(data); return NULL; }
    DWORD major = (ffi->dwFileVersionMS >> 16) & 0xffff;
    DWORD minor = (ffi->dwFileVersionMS) & 0xffff;
    DWORD build = (ffi->dwFileVersionLS >> 16) & 0xffff;
    DWORD rev = (ffi->dwFileVersionLS) & 0xffff;
    wchar_t *out = (wchar_t*)malloc(128 * sizeof(wchar_t));
    if (out) swprintf(out, 128, L"%u.%u.%u.%u", major, minor, build, rev);
    free(data);
    return out;
}

// Find CLSID from ProgID: HKCR\<ProgID>\CLSID (default)
static wchar_t *clsid_from_progid(const wchar_t *progid)
{
    wchar_t key[512];
    _snwprintf_s(key, _countof(key), _TRUNCATE, L"%s\\CLSID", progid);
    return read_reg_default_value(HKEY_CLASSES_ROOT, key);
}

// Given CLSID (like "{...}" or "....") return InprocServer32 default value (path to dll)
static wchar_t *inproc_from_clsid(const wchar_t *clsid)
{
    if (!clsid) return NULL;
    wchar_t key[512];
    _snwprintf_s(key, _countof(key), _TRUNCATE, L"CLSID\\%s\\InprocServer32", clsid);
    return read_reg_default_value(HKEY_CLASSES_ROOT, key);
}

// Enumerate HKCR top-level keys and print those containing tokens
static void enum_hkcr_for_tokens(const wchar_t **tokens, size_t tokcnt)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, NULL, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        printw(L"Failed to open HKCR root\n");
        return;
    }
    DWORD idx = 0;
    wchar_t name[512];
    DWORD nameLen = sizeof(name)/sizeof(wchar_t);
    FILETIME ft;
    printw(L"Scanning HKCR for provider-like ProgIDs (this may be slow)...\n");
    while (TRUE) {
        nameLen = _countof(name);
        LONG rc = RegEnumKeyExW(hKey, idx++, name, &nameLen, NULL, NULL, NULL, &ft);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) continue;
        // check tokens
        for (size_t t = 0; t < tokcnt; ++t) {
            if (wcsstr(_wcsupr(_wcsdup(name)), _wcsupr(_wcsdup(tokens[t])))) {
                // found candidate
                wchar_t *clsid = clsid_from_progid(name);
                wchar_t *inproc = NULL;
                wchar_t *ver = NULL;
                if (clsid) {
                    inproc = inproc_from_clsid(clsid);
                    ver = get_file_version_string(inproc);
                }
                printw(L"ProgID: %s\n  CLSID: %s\n  Inproc: %s\n  FileVer: %s\n", name,
                       clsid ? clsid : L"(none)",
                       inproc ? inproc : L"(none)",
                       ver ? ver : L"(unknown)");
                if (clsid) free(clsid);
                if (inproc) free(inproc);
                if (ver) free(ver);
                break;
            }
        }
    }
    RegCloseKey(hKey);
}

// Read ODBC drivers from registry
static void enum_odbc_drivers(void)
{
    const wchar_t *paths[] = {
        L"SOFTWARE\\ODBC\\ODBCINST.INI\\ODBC Drivers",
        L"SOFTWARE\\WOW6432Node\\ODBC\\ODBCINST.INI\\ODBC Drivers"
    };
    for (size_t i = 0; i < _countof(paths); ++i) {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paths[i], 0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;
        DWORD idx = 0;
        wchar_t name[512];
        DWORD nameLen = _countof(name);
        DWORD type = 0;
        BYTE data[256];
        DWORD dataLen = sizeof(data);
        printw(L"\nODBC drivers under HKLM\\%s:\n", paths[i]);
        while (TRUE) {
            nameLen = _countof(name);
            dataLen = sizeof(data);
            LONG rc = RegEnumValueW(hKey, idx++, name, &nameLen, NULL, &type, data, &dataLen);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) continue;
            printw(L"  %s\n", name);
        }
        RegCloseKey(hKey);
    }
}

// Enumerate local SQL Server instances from registry
static void enum_local_sql_instances(void)
{
    const wchar_t *paths[] = {
        L"SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL"
    };
    printw(L"\nLocal SQL instances (registry):\n");
    for (size_t i = 0; i < _countof(paths); ++i) {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paths[i], 0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;
        DWORD idx = 0;
        wchar_t name[256];
        DWORD nameLen = _countof(name);
        wchar_t data[256];
        DWORD dataLen = sizeof(data);
        DWORD type = 0;
        while (TRUE) {
            nameLen = _countof(name);
            dataLen = sizeof(data);
            LONG rc = RegEnumValueW(hKey, idx++, name, &nameLen, NULL, &type, (LPBYTE)data, &dataLen);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) continue;
            printw(L"  Instance: %s  -> RegistryValue: %s\n", name, data);
        }
        RegCloseKey(hKey);
    }
}

// Query SQL Browser via UDP 1434 (simple implementation)
static void query_sql_browser(const wchar_t *host)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printw(L"WSAStartup failed\n");
        return;
    }
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { printw(L"socket() failed\n"); WSACleanup(); return; }

    // resolve host
    struct addrinfoW hints, *res = NULL;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    WCHAR hostbuf[256];
    wcscpy_s(hostbuf, _countof(hostbuf), host);
    if (GetAddrInfoW(hostbuf, L"1434", &hints, &res) != 0) {
        printw(L"GetAddrInfoW failed for %s\n", host);
        closesocket(s); WSACleanup(); return;
    }

    // request byte 0x02 (list instances)
    char req[1] = { 0x02 };
    struct sockaddr_in to;
    memcpy(&to, res->ai_addr, sizeof(struct sockaddr_in));
    int tolen = sizeof(to);
    sendto(s, req, 1, 0, (struct sockaddr*)&to, tolen);

    // set timeout
    DWORD timeout = 2000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    char buf[8192];
    int rv = recvfrom(s, buf, sizeof(buf)-1, 0, NULL, NULL);
    if (rv == SOCKET_ERROR) {
        printw(L"SQL Browser no response or blocked\n");
    } else {
        buf[rv] = 0;
        // ASCII parse
        printw(L"\nSQL Browser response from %s:\n", host);
        // convert to wide for printing
        wchar_t wbuf[8192];
        MultiByteToWideChar(CP_ACP, 0, buf, -1, wbuf, _countof(wbuf));
        // naive output
        printw(L"%s\n", wbuf);
    }

    FreeAddrInfoW(res);
    closesocket(s);
    WSACleanup();
}

// Run sp_configure 'Ole Automation Procedures' via ODBC if credentials provided
static void test_sql_ole_automation(const wchar_t *connstr)
{
    // connstr is typical ODBC connection string: "Driver={SQL Server};Server=...;Database=master;Trusted_Connection=Yes;"
    SQLHENV hEnv = NULL;
    SQLHDBC hDbc = NULL;
    SQLHSTMT hStmt = NULL;
    SQLRETURN ret;

    ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &hEnv);
    if (!SQL_SUCCEEDED(ret)) { printw(L"ODBC: SQLAllocHandle ENV failed\n"); goto cleanup; }
    SQLSetEnvAttr(hEnv, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);
    ret = SQLAllocHandle(SQL_HANDLE_DBC, hEnv, &hDbc);
    if (!SQL_SUCCEEDED(ret)) { printw(L"ODBC: SQLAllocHandle DBC failed\n"); goto cleanup; }

    // Connect using connection string
    SQLWCHAR outstr[1024];
    SQLSMALLINT outstrlen = 0;
    ret = SQLDriverConnectW(hDbc, NULL, (SQLWCHAR*)connstr, SQL_NTS, outstr, sizeof(outstr)/sizeof(SQLWCHAR), &outstrlen, SQL_DRIVER_COMPLETE);
    if (!SQL_SUCCEEDED(ret)) {
        printw(L"ODBC: SQLDriverConnect failed (check creds/connstr)\n");
        goto cleanup;
    }
    printw(L"ODBC: connected; executing sp_configure check (this generates a standard SQL login event)\n");

    ret = SQLAllocHandle(SQL_HANDLE_STMT, hDbc, &hStmt);
    if (!SQL_SUCCEEDED(ret)) { printw(L"ODBC: SQLAllocHandle STMT failed\n"); goto cleanup; }

    // Execute: sp_configure 'show advanced options', 1; RECONFIGURE; sp_configure 'Ole Automation Procedures';
    // Note: we run a single batch and fetch results if any.
    const wchar_t *sql = L"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures';";
    ret = SQLExecDirectW(hStmt, (SQLWCHAR*)sql, SQL_NTS);
    if (SQL_SUCCEEDED(ret) || ret == SQL_SUCCESS_WITH_INFO) {
        // fetch columns and rows (naive)
        SQLSMALLINT cols = 0;
        SQLNumResultCols(hStmt, &cols);
        printw(L"ODBC: result columns: %d\n", cols);
        SQLWCHAR colbuf[1024];
        while (SQLFetch(hStmt) == SQL_SUCCESS) {
            for (SQLUSMALLINT c = 1; c <= cols; ++c) {
                SQLLEN ind;
                SQLGetData(hStmt, c, SQL_C_WCHAR, colbuf, sizeof(colbuf), &ind);
                if (ind == SQL_NULL_DATA) wcscpy_s(colbuf, _countof(colbuf), L"(null)");
                printw(L"%s\t", colbuf);
            }
            printw(L"\n");
        }
    } else {
        printw(L"ODBC: SQLExecDirect failed\n");
    }

cleanup:
    if (hStmt) SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
    if (hDbc) { SQLDisconnect(hDbc); SQLFreeHandle(SQL_HANDLE_DBC, hDbc); }
    if (hEnv) SQLFreeHandle(SQL_HANDLE_ENV, hEnv);
}

// Main demo
int wmain(int argc, wchar_t **argv)
{
    // minimal COM init (ready if we later use IDataInitialize / OLE DB)
    if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
        printw(L"CoInitializeEx failed\n");
    }

    // tokens to look for in HKCR ProgIDs
    const wchar_t *tokens[] = { L"sql", L"sqloledb", L"sqlncli", L"msoledb", L"microsoft.sql", L"msdtc" };
    enum_hkcr_for_tokens(tokens, _countof(tokens));

    enum_odbc_drivers();
    enum_local_sql_instances();

    // Simple SQL Browser query example (host from argv or localhost)
    const wchar_t *host = (argc >= 2) ? argv[1] : L"localhost";
    query_sql_browser(host);

    // Optional ODBC test if user passes DSN/connstr as second arg
    if (argc >= 3) {
        const wchar_t *conn = argv[2];
        test_sql_ole_automation(conn);
    } else {
        printw(L"\nTo test Ole Automation via SQL, pass an ODBC connection string as second argument.\n");
        printw(L"Example: sql_probe.exe my-sql-host \"Driver={SQL Server};Server=MYHOST;Database=master;Trusted_Connection=Yes;\"\n");
    }

    CoUninitialize();
    return 0;
}