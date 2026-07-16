/*
 * KestrelHygiene.c — credential-hygiene sweep (v0.14)
 *
 * Cheap userAccountControl / attribute checks that widen the credential-attack
 * surface an attacker sprays and cracks against:
 *
 *   PASSWD_NOTREQD       (UAC 0x20)    — the account may have an EMPTY password;
 *                                        on an enabled account this is severe.
 *   DONT_EXPIRE_PASSWORD (UAC 0x10000) — password never rotates; on privileged
 *                                        or service accounts a stale/weak secret
 *                                        lingers indefinitely.
 *   ENCRYPTED_TEXT_PWD_ALLOWED (0x80)  — reversible encryption: the password is
 *                                        recoverable to plaintext from NTDS.
 *   password in description/info       — a credential typed into a readable
 *                                        attribute (any authenticated user reads it).
 *
 * Enabled and adminCount=1 accounts are highlighted. Read-only, ordinary user.
 */

#include "../include/Kestrel.h"
#include <wctype.h>

#define UAC_ACCOUNTDISABLE          0x00000002
#define UAC_PASSWD_NOTREQD          0x00000020
#define UAC_ENCRYPTED_TEXT_PWD      0x00000080
#define UAC_DONT_EXPIRE_PASSWORD    0x00010000

/* Heuristic: does a description/info string look like it carries a password? */
static BOOL
_LooksLikeSecret(_In_opt_z_ LPCWSTR s)
{
    static const WCHAR *kw[] = {
        L"password", L"passwd", L"pwd", L"pw:", L"pw=", L"pass:", L"pass=",
        L"cred", L"login:", L"secret"
    };
    WCHAR low[512];
    DWORD i;

    if (!s || !s[0]) return FALSE;
    StringCchCopyW(low, ARRAYSIZE(low), s);
    for (i = 0; low[i]; i++) low[i] = (WCHAR)towlower(low[i]);
    for (i = 0; i < ARRAYSIZE(kw); i++)
        if (wcsstr(low, kw[i])) return TRUE;
    return FALSE;
}

_Must_inspect_result_
HRESULT
KestrelRunHygieneScan(_In_z_ LPCWSTR pwszDomainNC)
{
    HRESULT             hr;
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h = NULL;
    WCHAR               wszRoot[600];
    ADS_SEARCHPREF_INFO prefs[2];
    DWORD               cNoReq = 0, cNoExp = 0, cRev = 0, cDesc = 0, cFlagged = 0;
    LPWSTR rgAttrs[] = {
        (LPWSTR)L"sAMAccountName", (LPWSTR)L"userAccountControl",
        (LPWSTR)L"adminCount", (LPWSTR)L"description", (LPWSTR)L"info"
    };

    if (!pwszDomainNC) return E_INVALIDARG;
    if (FAILED(StringCchPrintfW(wszRoot, ARRAYSIZE(wszRoot), L"LDAP://%s", pwszDomainNC)))
        return E_FAIL;

    wprintf(L"\n[*] Credential hygiene (UAC flags + description secrets)\n");

    hr = ADsGetObject(wszRoot, &IID_IDirectorySearch, (void **)&pS);
    if (FAILED(hr)) { wprintf(L"  [!] ADsGetObject 0x%08X\n", hr); return hr; }

    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pS->lpVtbl->SetSearchPreference(pS, prefs, ARRAYSIZE(prefs));

    hr = pS->lpVtbl->ExecuteSearch(pS,
            (LPWSTR)L"(&(objectClass=user)(objectCategory=person))",
            rgAttrs, ARRAYSIZE(rgAttrs), &h);
    if (FAILED(hr)) { wprintf(L"  [!] ExecuteSearch 0x%08X\n", hr); goto Cleanup; }

    for (;;) {
        ADS_SEARCH_COLUMN col;
        WCHAR wszSam[128] = L"", wszDesc[512] = L"", wszInfo[512] = L"";
        LONG  lUac = 0, lAdmin = 0;
        BOOL  bEnabled, bNoReq, bNoExp, bRev, bDesc;

        hr = pS->lpVtbl->GetNextRow(pS, h);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr)) { wprintf(L"  [!] GetNextRow 0x%08X\n", hr); break; }

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"userAccountControl", &col))) {
            if (col.dwADsType == ADSTYPE_INTEGER && col.dwNumValues)
                lUac = col.pADsValues[0].Integer;
            pS->lpVtbl->FreeColumn(pS, &col);
        }

        bNoReq = (lUac & UAC_PASSWD_NOTREQD)       != 0;
        bNoExp = (lUac & UAC_DONT_EXPIRE_PASSWORD) != 0;
        bRev   = (lUac & UAC_ENCRYPTED_TEXT_PWD)   != 0;

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"description", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszDesc, ARRAYSIZE(wszDesc), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"info", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszInfo, ARRAYSIZE(wszInfo), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        bDesc = _LooksLikeSecret(wszDesc) || _LooksLikeSecret(wszInfo);

        if (!bNoReq && !bNoExp && !bRev && !bDesc)
            continue;   /* clean account */

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"sAMAccountName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszSam, ARRAYSIZE(wszSam), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"adminCount", &col))) {
            if (col.dwADsType == ADSTYPE_INTEGER && col.dwNumValues)
                lAdmin = col.pADsValues[0].Integer;
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        bEnabled = (lUac & UAC_ACCOUNTDISABLE) == 0;

        wprintf(L"  [HYG] %-24s %s%s\n", wszSam[0] ? wszSam : L"(unknown)",
            bEnabled ? L"" : L"(disabled) ",
            (lAdmin == 1) ? L"[adminCount=1]" : L"");
        if (bNoReq) { wprintf(L"        PASSWD_NOTREQD%s\n",
                        bEnabled ? L"  *** empty password possible on ENABLED account ***" : L""); cNoReq++; }
        if (bRev)   { wprintf(L"        ENCRYPTED_TEXT_PWD_ALLOWED  (reversible encryption — plaintext recoverable)\n"); cRev++; }
        if (bNoExp) { wprintf(L"        DONT_EXPIRE_PASSWORD\n"); cNoExp++; }
        if (bDesc)  { wprintf(L"        secret-like text in description/info  \"%.60s\"\n",
                        wszDesc[0] ? wszDesc : wszInfo); cDesc++; }
        cFlagged++;
    }

    wprintf(L"\n  [=] %lu account(s) flagged — PASSWD_NOTREQD:%lu  DONT_EXPIRE:%lu  reversible:%lu  desc-secret:%lu\n",
            cFlagged, cNoReq, cNoExp, cRev, cDesc);
    if (cFlagged == 0)
        wprintf(L"  [=] No credential-hygiene issues found\n");

Cleanup:
    if (h)  pS->lpVtbl->CloseSearchHandle(pS, h);
    if (pS) pS->lpVtbl->Release(pS);
    return hr;
}
