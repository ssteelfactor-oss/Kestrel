/*
 * KestrelGPP.c — v0.7  Group Policy Preferences cpassword recovery
 *
 * Group Policy Preferences could store credentials (local admins, mapped-drive
 * creds, service / scheduled-task run-as accounts) in XML files on SYSVOL,
 * AES-256 encrypted with a key Microsoft published in 2014 (MS14-025). Any
 * domain user who can read SYSVOL can recover them. This module walks SYSVOL
 * over SMB, finds every cpassword in the Preferences XML, and decrypts it —
 * proving the credential is recoverable so it can be rotated.
 *
 * Footprint: like KestrelPolicy.c this steps outside LDAP. It reads files from
 * \\<domain>\SYSVOL\<domain>\Policies over SMB. Normal for any domain member,
 * but a file-share read, not an LDAP query.
 *
 * Scope (v1): cpassword across all Preference types (Groups, Services,
 * ScheduledTasks, DataSources, Drives, Printers). Parsing Groups.xml for
 * local-Administrators additions is a documented follow-up.
 *
 * cpassword is largely legacy — MS14-025 (2014) stopped new ones being created,
 * but old values persist on SYSVOL for years. High signal when present, clean
 * when absent.
 */

#include "../include/Kestrel.h"
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

/* The MS14-025 public AES-256 key. */
static const BYTE g_GppKey[32] = {
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
    0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
    0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b
};

/* ════════════════════════════════════════════════════════════════════════════
 * Small string helpers
 * ════════════════════════════════════════════════════════════════════════════ */

/* Case-insensitive byte-buffer search (needle is ASCII). */
static const char *_GppFindCI(_In_reads_(hayLen) const char *hay, DWORD hayLen,
                              _In_z_ const char *needle)
{
    DWORD nl = (DWORD)strlen(needle);
    if (nl == 0 || hayLen < nl)
        return NULL;
    for (DWORD i = 0; i + nl <= hayLen; i++) {
        DWORD j = 0;
        for (; j < nl; j++) {
            char c = hay[i + j], d = needle[j];
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            if (d >= 'A' && d <= 'Z') d = (char)(d - 'A' + 'a');
            if (c != d) break;
        }
        if (j == nl)
            return hay + i;
    }
    return NULL;
}

/* defaultNamingContext DN → dotted DNS:  DC=corp,DC=local → corp.local */
static void _GppDnToDns(_In_z_ LPCWSTR pwszDN, _Out_writes_z_(cch) LPWSTR pwszOut, size_t cch)
{
    const WCHAR *p = pwszDN;
    BOOL bFirst = TRUE;
    pwszOut[0] = L'\0';

    while (*p) {
        if ((p[0] == L'D' || p[0] == L'd') &&
            (p[1] == L'C' || p[1] == L'c') && p[2] == L'=') {
            WCHAR comp[128];
            int   ci = 0;
            p += 3;
            while (*p && *p != L',' && ci < (int)ARRAYSIZE(comp) - 1)
                comp[ci++] = *p++;
            comp[ci] = L'\0';
            if (!bFirst)
                StringCchCatW(pwszOut, cch, L".");
            StringCchCatW(pwszOut, cch, comp);
            bFirst = FALSE;
        } else {
            p++;
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * Base64 + AES
 * ════════════════════════════════════════════════════════════════════════════ */

static int _GppB64Idx(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;   /* '=' / whitespace / invalid */
}

/* Decode base64, tolerating missing padding. Returns byte count written. */
static DWORD _GppB64Decode(_In_reads_(inLen) const char *in, DWORD inLen,
                           _Out_writes_(outCap) BYTE *out, DWORD outCap)
{
    int   q[4];
    int   qn = 0;
    DWORD o  = 0;

    for (DWORD i = 0; i < inLen; i++) {
        int v = _GppB64Idx(in[i]);
        if (v < 0)
            continue;
        q[qn++] = v;
        if (qn == 4) {
            if (o + 3 > outCap) return o;
            out[o++] = (BYTE)((q[0] << 2) | (q[1] >> 4));
            out[o++] = (BYTE)((q[1] << 4) | (q[2] >> 2));
            out[o++] = (BYTE)((q[2] << 6) |  q[3]);
            qn = 0;
        }
    }
    if (qn >= 2 && o < outCap) {
        out[o++] = (BYTE)((q[0] << 2) | (q[1] >> 4));
        if (qn >= 3 && o < outCap)
            out[o++] = (BYTE)((q[1] << 4) | (q[2] >> 2));
    }
    return o;
}

/* AES-256-CBC decrypt with the static key and a zero IV; plaintext is UTF-16LE. */
static BOOL _GppAesDecrypt(_In_reads_(cbCipher) const BYTE *pCipher, DWORD cbCipher,
                           _Out_writes_z_(cchPwd) LPWSTR pwszPwd, DWORD cchPwd)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS          st;
    BOOL              bOk = FALSE;
    BYTE              iv[16] = { 0 };
    BYTE              plain[544];
    DWORD             cbPlain = 0;

    pwszPwd[0] = L'\0';
    if (cbCipher == 0 || (cbCipher % 16) != 0 || cbCipher > sizeof(plain))
        return FALSE;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st)) goto done;

    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(st)) goto done;

    st = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
            (PUCHAR)g_GppKey, sizeof(g_GppKey), 0);
    if (!BCRYPT_SUCCESS(st)) goto done;

    /* No block padding flag — GPP ciphertext is block-aligned UTF-16LE. */
    st = BCryptDecrypt(hKey, (PUCHAR)pCipher, cbCipher, NULL,
            iv, sizeof(iv), plain, sizeof(plain), &cbPlain, 0);
    if (!BCRYPT_SUCCESS(st)) goto done;

    {
        DWORD cch = cbPlain / sizeof(WCHAR);
        if (cch >= cchPwd) cch = cchPwd - 1;
        memcpy(pwszPwd, plain, (SIZE_T)cch * sizeof(WCHAR));
        pwszPwd[cch] = L'\0';   /* %s stops at the first embedded NUL anyway */
        bOk = TRUE;
    }

done:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    SecureZeroMemory(plain, sizeof(plain));
    return bOk;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Finding management
 * ════════════════════════════════════════════════════════════════════════════ */

static HRESULT _GppAppend(_Inout_ KESTREL_GPP_SCAN_RESULT *pResult,
                          _In_ const KESTREL_GPP_FINDING *pF)
{
    if (pResult->cFindings >= pResult->cCapacity) {
        DWORD  cNew = pResult->cCapacity ? pResult->cCapacity * 2 : 8;
        SIZE_T cb   = (SIZE_T)cNew * sizeof(KESTREL_GPP_FINDING);
        KESTREL_GPP_FINDING *p = pResult->rgFindings
            ? (KESTREL_GPP_FINDING *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pResult->rgFindings, cb)
            : (KESTREL_GPP_FINDING *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
        if (!p) return E_OUTOFMEMORY;
        pResult->rgFindings = p;
        pResult->cCapacity  = cNew;
    }
    pResult->rgFindings[pResult->cFindings++] = *pF;
    return S_OK;
}

/* GUID, type, file name (from path) and the first account-like attribute (from buf). */
static void _GppFillContext(_In_z_ LPCWSTR pwszPath,
                            _In_reads_(cbBuf) const char *buf, DWORD cbBuf,
                            _Inout_ KESTREL_GPP_FINDING *pF)
{
    static const wchar_t *rgTypes[] = {
        L"Groups", L"Services", L"ScheduledTasks", L"DataSources", L"Drives", L"Printers"
    };
    static const char *rgAttrs[] = {
        "userName=\"", "accountName=\"", "runAs=\"", "newName=\"", "name=\""
    };

    /* {GUID} */
    const WCHAR *lb = wcschr(pwszPath, L'{');
    if (lb) {
        const WCHAR *rb = wcschr(lb, L'}');
        if (rb && (rb - lb) < (ptrdiff_t)ARRAYSIZE(pF->wszGpoGuid) - 1)
            StringCchCopyNW(pF->wszGpoGuid, ARRAYSIZE(pF->wszGpoGuid), lb, (size_t)(rb - lb) + 1);
    }

    /* type from path */
    for (int i = 0; i < (int)ARRAYSIZE(rgTypes); i++)
        if (wcsstr(pwszPath, rgTypes[i])) {
            StringCchCopyW(pF->wszType, ARRAYSIZE(pF->wszType), rgTypes[i]);
            break;
        }
    if (!pF->wszType[0])
        StringCchCopyW(pF->wszType, ARRAYSIZE(pF->wszType), L"Pref");

    /* file name */
    {
        const WCHAR *slash = wcsrchr(pwszPath, L'\\');
        StringCchCopyW(pF->wszFile, ARRAYSIZE(pF->wszFile), slash ? slash + 1 : pwszPath);
    }

    /* first account-like attribute */
    for (int i = 0; i < (int)ARRAYSIZE(rgAttrs); i++) {
        const char *a = _GppFindCI(buf, cbBuf, rgAttrs[i]);
        if (a) {
            a += strlen(rgAttrs[i]);
            const char *e = (const char *)memchr(a, '"', (SIZE_T)((buf + cbBuf) - a));
            if (e && (e - a) > 0 && (e - a) < 256) {
                int wn = MultiByteToWideChar(CP_UTF8, 0, a, (int)(e - a),
                            pF->wszAccount, ARRAYSIZE(pF->wszAccount) - 1);
                pF->wszAccount[wn > 0 ? wn : 0] = L'\0';
                break;
            }
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * XML scan + SYSVOL walk
 * ════════════════════════════════════════════════════════════════════════════ */

static void _GppScanXml(_In_z_ LPCWSTR pwszPath, _Inout_ KESTREL_GPP_SCAN_RESULT *pResult)
{
    HANDLE h;
    DWORD  cbFile, cbRead = 0;
    char  *buf;

    h = CreateFileW(pwszPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;

    cbFile = GetFileSize(h, NULL);
    if (cbFile == INVALID_FILE_SIZE || cbFile == 0 || cbFile > (1u << 20)) {
        CloseHandle(h);
        return;
    }

    buf = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)cbFile + 1);
    if (!buf) { CloseHandle(h); return; }

    if (!ReadFile(h, buf, cbFile, &cbRead, NULL) || cbRead == 0) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(h);
        return;
    }
    CloseHandle(h);
    buf[cbRead] = '\0';
    pResult->cFilesScanned++;

    /* every cpassword="..." in the file */
    const char *p   = buf;
    DWORD       rem = cbRead;
    for (;;) {
        const char *hit = _GppFindCI(p, rem, "cpassword=\"");
        if (!hit) break;
        const char *val = hit + strlen("cpassword=\"");
        const char *end = (const char *)memchr(val, '"', (SIZE_T)((buf + cbRead) - val));
        if (!end) break;

        DWORD vlen = (DWORD)(end - val);
        if (vlen > 0 && vlen < 1024) {       /* skip empty cpassword="" */
            BYTE  cipher[768];
            DWORD cbCipher = _GppB64Decode(val, vlen, cipher, sizeof(cipher));
            WCHAR wszPwd[256];
            KESTREL_GPP_FINDING f;

            ZeroMemory(&f, sizeof(f));
            _GppFillContext(pwszPath, buf, cbRead, &f);

            if (cbCipher && _GppAesDecrypt(cipher, cbCipher, wszPwd, ARRAYSIZE(wszPwd))) {
                StringCchCopyW(f.wszPassword, ARRAYSIZE(f.wszPassword), wszPwd);
                f.bDecrypted = TRUE;
            } else {
                StringCchCopyW(f.wszPassword, ARRAYSIZE(f.wszPassword), L"(decrypt failed)");
            }
            _GppAppend(pResult, &f);
            SecureZeroMemory(wszPwd, sizeof(wszPwd));
            SecureZeroMemory(cipher, sizeof(cipher));
        }

        p   = end + 1;
        rem = (DWORD)((buf + cbRead) - p);
        if (rem == 0) break;
    }

    SecureZeroMemory(buf, cbRead);
    HeapFree(GetProcessHeap(), 0, buf);
}

static void _GppWalkDir(_In_z_ LPCWSTR pwszDir, int depth,
                        _Inout_ KESTREL_GPP_SCAN_RESULT *pResult)
{
    WIN32_FIND_DATAW fd;
    HANDLE           h;
    WCHAR            wszPattern[1024];

    if (depth > 8)
        return;

    if (FAILED(StringCchPrintfW(wszPattern, ARRAYSIZE(wszPattern), L"%s\\*", pwszDir)))
        return;

    h = FindFirstFileW(wszPattern, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;

    do {
        WCHAR wszChild[1024];

        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;
        if (FAILED(StringCchPrintfW(wszChild, ARRAYSIZE(wszChild), L"%s\\%s",
                pwszDir, fd.cFileName)))
            continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            _GppWalkDir(wszChild, depth + 1, pResult);
        } else {
            size_t len = wcslen(fd.cFileName);
            if (len > 4 && _wcsicmp(fd.cFileName + len - 4, L".xml") == 0)
                _GppScanXml(wszChild, pResult);
        }
    } while (FindNextFileW(h, &fd));

    FindClose(h);
}

/* ════════════════════════════════════════════════════════════════════════════
 * Output
 * ════════════════════════════════════════════════════════════════════════════ */

static void _GppPrint(_In_ const KESTREL_GPP_SCAN_RESULT *pResult)
{
    wprintf(L"\n  GPP: %lu XML file(s) scanned  |  %lu cpassword finding(s)\n",
            pResult->cFilesScanned, pResult->cFindings);

    if (pResult->cFindings == 0) {
        wprintf(L"\n  [*] No GPP cpassword found in SYSVOL.\n\n");
        return;
    }

    wprintf(L"\n  [!] Recoverable credentials — decrypted with the public MS14-025 key.\n");
    wprintf(L"      Any domain user can do this. Rotate these immediately.\n\n");
    wprintf(L"  %-15s  %-26s  %-26s  %s\n", L"Type", L"Account", L"Password", L"GPO");
    wprintf(L"  ───────────────────────────────────────────────────────────────"
            L"──────────────────────────────────────────\n");

    for (DWORD i = 0; i < pResult->cFindings; i++) {
        const KESTREL_GPP_FINDING *pF = &pResult->rgFindings[i];
        wprintf(L"  %-15s  %-26s  %-26s  %s\n",
                pF->wszType,
                pF->wszAccount[0]  ? pF->wszAccount  : L"(unknown)",
                pF->wszPassword[0] ? pF->wszPassword : L"(empty)",
                pF->wszGpoGuid[0]  ? pF->wszGpoGuid  : L"?");
    }
    wprintf(L"\n");
}

/* ════════════════════════════════════════════════════════════════════════════
 * Public API
 * ════════════════════════════════════════════════════════════════════════════ */

VOID KestrelFreeGPPScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GPP_SCAN_RESULT *pResult)
{
    if (!pResult)
        return;
    if (pResult->rgFindings) {
        /* findings carry plaintext — scrub before release */
        SecureZeroMemory(pResult->rgFindings,
            (SIZE_T)pResult->cCapacity * sizeof(KESTREL_GPP_FINDING));
        HeapFree(GetProcessHeap(), 0, pResult->rgFindings);
    }
    HeapFree(GetProcessHeap(), 0, pResult);
}

_Must_inspect_result_
HRESULT KestrelRunGPPScan(
    _In_z_   LPCWSTR                   pwszDomainNC,
    _Outptr_ KESTREL_GPP_SCAN_RESULT **ppResult)
{
    KESTREL_GPP_SCAN_RESULT *pResult;
    WCHAR wszDns[256]  = { 0 };
    WCHAR wszBase[600];

    if (!ppResult || !pwszDomainNC)
        return E_INVALIDARG;
    *ppResult = NULL;

    pResult = (KESTREL_GPP_SCAN_RESULT *)HeapAlloc(GetProcessHeap(),
                  HEAP_ZERO_MEMORY, sizeof(*pResult));
    if (!pResult)
        return E_OUTOFMEMORY;

    _GppDnToDns(pwszDomainNC, wszDns, ARRAYSIZE(wszDns));
    if (wszDns[0] == L'\0') {
        wprintf(L"\n  [!] Could not derive domain DNS from %s\n\n", pwszDomainNC);
        *ppResult = pResult;
        return S_OK;
    }

    if (FAILED(StringCchPrintfW(wszBase, ARRAYSIZE(wszBase),
            L"\\\\%s\\SYSVOL\\%s\\Policies", wszDns, wszDns))) {
        *ppResult = pResult;
        return S_OK;
    }

    KTRACE(L"GPP: walking %s", wszBase);
    _GppWalkDir(wszBase, 0, pResult);
    KTRACE(L"GPP: %lu files, %lu findings", pResult->cFilesScanned, pResult->cFindings);

    if (pResult->cFilesScanned == 0)
        wprintf(L"\n  [*] SYSVOL Policies tree empty or unreachable (%s).\n\n", wszBase);

    _GppPrint(pResult);
    *ppResult = pResult;
    return S_OK;
}
