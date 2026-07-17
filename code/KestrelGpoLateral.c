/*
 * KestrelGpoLateral.c — GPO local-group membership → lateral-movement edges
 *
 * Restricted Groups (GptTmpl.inf [Group Membership]) push local-group membership
 * onto every computer a GPO applies to. Membership of the privileged local
 * groups is exactly the lateral-movement surface BloodHound models as first-class
 * edges:
 *
 *   Administrators           (S-1-5-32-544) -> AdminTo
 *   Remote Desktop Users     (S-1-5-32-555) -> CanRDP
 *   Distributed COM Users    (S-1-5-32-562) -> ExecuteDCOM
 *   Remote Management Users  (S-1-5-32-580) -> CanPSRemote
 *
 * For each GPO that sets one of these, the scan resolves the GPO's links
 * (gPLink) to OUs/domain, enumerates the computers in scope, and emits a
 * principal -> computer edge of the mapped kind. Those become native pathfinding
 * edges in the OpenGraph export.
 *
 * Invariant-clean: read-only LDAP + SYSVOL reads (indistinguishable from normal
 * Group Policy processing), ordinary user.
 *
 * SCOPE (honest limitations, v1): resolves "GPO linked to OU -> applies to every
 * computer in that OU subtree". It does NOT model block-inheritance, security
 * filtering, WMI filtering, or enforced links, and it reads SID-form members
 * from [Group Membership] (name-form members are skipped). It therefore over- or
 * under-approximates in filtered environments; treat the edges as candidates.
 */

#include "../include/Kestrel.h"
#include <stdlib.h>

/* Read a GPO's GptTmpl.inf from SYSVOL as NUL-terminated wide text (UTF-16LE
 * with BOM, or UTF-8). Caller frees with HeapFree. NULL if absent/oversized. */
static WCHAR *
_ReadGptTmpl(_In_z_ LPCWSTR pwszGpoPath)
{
    WCHAR   wszInf[700];
    HANDLE  hFile;
    DWORD   cbFile, cbRead = 0;
    BYTE   *pRaw = NULL;
    WCHAR  *pwszText = NULL;

    if (FAILED(StringCchPrintfW(wszInf, ARRAYSIZE(wszInf),
            L"%s\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf", pwszGpoPath)))
        return NULL;

    hFile = CreateFileW(wszInf, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    cbFile = GetFileSize(hFile, NULL);
    if (cbFile == INVALID_FILE_SIZE || cbFile == 0 || cbFile > (1u << 20)) {
        CloseHandle(hFile); return NULL;
    }
    pRaw = (BYTE *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)cbFile + 2);
    if (!pRaw) { CloseHandle(hFile); return NULL; }
    if (!ReadFile(hFile, pRaw, cbFile, &cbRead, NULL) || cbRead == 0) {
        HeapFree(GetProcessHeap(), 0, pRaw); CloseHandle(hFile); return NULL;
    }
    CloseHandle(hFile);

    if (cbRead >= 2 && pRaw[0] == 0xFF && pRaw[1] == 0xFE) {
        DWORD cch = (cbRead - 2) / sizeof(WCHAR);
        pwszText = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)(cch + 1) * sizeof(WCHAR));
        if (pwszText) { memcpy(pwszText, pRaw + 2, (SIZE_T)cch * sizeof(WCHAR)); pwszText[cch] = 0; }
    } else {
        int cch = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)pRaw, (int)cbRead, NULL, 0);
        if (cch > 0) {
            pwszText = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)(cch + 1) * sizeof(WCHAR));
            if (pwszText) {
                MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)pRaw, (int)cbRead, pwszText, cch);
                pwszText[cch] = 0;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, pRaw);
    return pwszText;
}

/* Map a BUILTIN local-group SID to a lateral edge type; GEDGE_ACL_GENERIC_ALL
 * as a "not mapped" sentinel (never emitted for these). */
static KESTREL_GRAPH_EDGE_TYPE
_LocalGroupEdge(_In_z_ LPCWSTR pwszGroupSid, _Out_ BOOL *pbMapped)
{
    *pbMapped = TRUE;
    if (_wcsicmp(pwszGroupSid, L"S-1-5-32-544") == 0) return GEDGE_ADMIN_TO;
    if (_wcsicmp(pwszGroupSid, L"S-1-5-32-555") == 0) return GEDGE_CAN_RDP;
    if (_wcsicmp(pwszGroupSid, L"S-1-5-32-580") == 0) return GEDGE_CAN_PSREMOTE;
    if (_wcsicmp(pwszGroupSid, L"S-1-5-32-562") == 0) return GEDGE_EXECUTE_DCOM;
    *pbMapped = FALSE;
    return GEDGE_ADMIN_TO;
}

static BOOL
_Append(_Inout_ KESTREL_GPOLATERAL_SCAN_RESULT *pRes,
        _In_z_ LPCWSTR pwszPrin, _In_z_ LPCWSTR pwszCompSid,
        _In_z_ LPCWSTR pwszCompName, _In_ KESTREL_GRAPH_EDGE_TYPE type)
{
    KESTREL_GPOLAT_FINDING *pF;
    if (pRes->cFindings == pRes->cCapacity) {
        DWORD nc = pRes->cCapacity ? pRes->cCapacity * 2 : 128;
        KESTREL_GPOLAT_FINDING *np = (KESTREL_GPOLAT_FINDING *)realloc(
            pRes->rgFindings, nc * sizeof(*np));
        if (!np) return FALSE;
        pRes->rgFindings = np; pRes->cCapacity = nc;
    }
    pF = &pRes->rgFindings[pRes->cFindings++];
    ZeroMemory(pF, sizeof(*pF));
    StringCchCopyW(pF->wszPrincipalSid, ARRAYSIZE(pF->wszPrincipalSid), pwszPrin);
    StringCchCopyW(pF->wszComputerSid,  ARRAYSIZE(pF->wszComputerSid),  pwszCompSid);
    StringCchCopyW(pF->wszComputerName, ARRAYSIZE(pF->wszComputerName), pwszCompName);
    pF->EdgeType = type;
    return TRUE;
}

/* Enumerate computers under an OU subtree; emit an edge from pwszPrin to each. */
static void
_EmitForOu(_In_z_ LPCWSTR pwszOuDN, _In_z_ LPCWSTR pwszPrin,
           _In_ KESTREL_GRAPH_EDGE_TYPE type,
           _Inout_ KESTREL_GPOLATERAL_SCAN_RESULT *pRes)
{
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h = NULL;
    WCHAR               wszPath[700];
    ADS_SEARCHPREF_INFO prefs[2];
    LPWSTR attrs[] = { (LPWSTR)L"objectSid", (LPWSTR)L"sAMAccountName" };

    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszOuDN))) return;
    if (FAILED(ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pS))) return;

    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pS->lpVtbl->SetSearchPreference(pS, prefs, ARRAYSIZE(prefs));

    if (FAILED(pS->lpVtbl->ExecuteSearch(pS, (LPWSTR)L"(objectClass=computer)",
            attrs, ARRAYSIZE(attrs), &h)))
        goto done;

    while (pS->lpVtbl->GetNextRow(pS, h) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN col;
        WCHAR wszSid[96] = L"", wszName[128] = L"";

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"objectSid", &col))) {
            if (col.dwADsType == ADSTYPE_OCTET_STRING && col.dwNumValues) {
                PSID pSid = (PSID)col.pADsValues[0].OctetString.lpValue;
                LPWSTR s = NULL;
                if (pSid && IsValidSid(pSid) && ConvertSidToStringSidW(pSid, &s) && s) {
                    StringCchCopyW(wszSid, ARRAYSIZE(wszSid), s); LocalFree(s);
                }
            }
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"sAMAccountName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszName, ARRAYSIZE(wszName), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (wszSid[0]) {
            _Append(pRes, pwszPrin, wszSid, wszName[0] ? wszName : wszSid, type);
            pRes->cComputers++;
        }
    }
    pS->lpVtbl->CloseSearchHandle(pS, h);
done:
    if (pS) pS->lpVtbl->Release(pS);
}

/* Resolve a GPO cn ("{GUID}") to the OUs/domain that link it (gPLink), and emit
 * edges for every computer in each linked OU. */
static void
_ResolveLinks(_In_ IDirectorySearch *pRoot, _In_z_ LPCWSTR pwszGpoCn,
              _In_z_ LPCWSTR pwszPrin, _In_ KESTREL_GRAPH_EDGE_TYPE type,
              _Inout_ KESTREL_GPOLATERAL_SCAN_RESULT *pRes)
{
    ADS_SEARCH_HANDLE h = NULL;
    WCHAR             wszFilter[256];
    LPWSTR            attrs[] = { (LPWSTR)L"distinguishedName" };

    if (FAILED(StringCchPrintfW(wszFilter, ARRAYSIZE(wszFilter),
            L"(gPLink=*%s*)", pwszGpoCn)))
        return;
    if (FAILED(pRoot->lpVtbl->ExecuteSearch(pRoot, wszFilter, attrs, 1, &h)))
        return;

    while (pRoot->lpVtbl->GetNextRow(pRoot, h) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN col;
        if (SUCCEEDED(pRoot->lpVtbl->GetColumn(pRoot, h, (LPWSTR)L"distinguishedName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                _EmitForOu(col.pADsValues[0].CaseIgnoreString, pwszPrin, type, pRes);
            pRoot->lpVtbl->FreeColumn(pRoot, &col);
        }
    }
    pRoot->lpVtbl->CloseSearchHandle(pRoot, h);
}

/* Parse [Group Membership] of one GptTmpl.inf; for each privileged local group,
 * resolve links and emit edges. Lines look like:
 *   *S-1-5-32-544__Members = *S-1-5-21-..-1111,*S-1-5-21-..-2222   */
static void
_ParseGroupMembership(_In_ IDirectorySearch *pRoot, _In_z_ LPCWSTR pwszText,
                      _In_z_ LPCWSTR pwszGpoCn, _In_z_ LPCWSTR pwszGpoName,
                      _Inout_ KESTREL_GPOLATERAL_SCAN_RESULT *pRes,
                      _Inout_ DWORD *pcGpoHits)
{
    const WCHAR *p = wcsstr(pwszText, L"[Group Membership]");
    const WCHAR *end;
    BOOL bHit = FALSE;

    if (!p) return;
    p += 18;
    end = wcschr(p, L'[');           /* next section (rough; INI sections start with '[') */

    while (p && (!end || p < end)) {
        const WCHAR *eol = wcschr(p, L'\n');
        WCHAR line[1024];
        SIZE_T n;
        const WCHAR *mem, *grpEnd;
        WCHAR wszGrpSid[64];
        BOOL  bMapped;
        KESTREL_GRAPH_EDGE_TYPE type;

        if (end && (!eol || eol > end)) eol = end;
        if (!eol) eol = p + wcslen(p);
        n = (SIZE_T)(eol - p);
        if (n >= ARRAYSIZE(line)) n = ARRAYSIZE(line) - 1;
        memcpy(line, p, n * sizeof(WCHAR)); line[n] = 0;
        p = (*eol) ? eol + 1 : NULL;

        /* interested only in "<group>__Members =" */
        mem = wcsstr(line, L"__Members");
        if (!mem) continue;

        /* group token = start of line (skip leading '*'/spaces) up to "__Members" */
        {
            const WCHAR *g = line;
            SIZE_T gl;
            while (*g == L'*' || *g == L' ' || *g == L'\t') g++;
            grpEnd = mem;
            gl = (SIZE_T)(grpEnd - g);
            if (gl == 0 || gl >= ARRAYSIZE(wszGrpSid)) continue;
            memcpy(wszGrpSid, g, gl * sizeof(WCHAR)); wszGrpSid[gl] = 0;
        }

        type = _LocalGroupEdge(wszGrpSid, &bMapped);
        if (!bMapped) continue;

        /* RHS after '=' : comma-separated members, each *<SID> or name */
        mem = wcschr(mem, L'=');
        if (!mem) continue;
        mem++;

        {
            WCHAR tok[128];
            const WCHAR *q = mem;
            while (*q) {
                const WCHAR *c = q;
                SIZE_T tl;
                while (*c && *c != L',') c++;
                /* trim */
                while (*q == L' ' || *q == L'\t' || *q == L'*') q++;
                tl = (SIZE_T)(c - q);
                while (tl && (q[tl-1] == L' ' || q[tl-1] == L'\t' || q[tl-1] == L'\r')) tl--;
                if (tl > 0 && tl < ARRAYSIZE(tok)) {
                    memcpy(tok, q, tl * sizeof(WCHAR)); tok[tl] = 0;
                    if (_wcsnicmp(tok, L"S-1-", 4) == 0) {   /* SID-form member only */
                        _ResolveLinks(pRoot, pwszGpoCn, tok, type, pRes);
                        bHit = TRUE;
                    }
                }
                q = (*c) ? c + 1 : c;
            }
        }
    }

    if (bHit) {
        (*pcGpoHits)++;
        wprintf(L"  [GPO] %s  — pushes privileged local-group membership\n",
                pwszGpoName[0] ? pwszGpoName : pwszGpoCn);
    }
}

_Must_inspect_result_
HRESULT
KestrelRunGpoLateralScan(
    _In_z_   LPCWSTR                         pwszDomainNC,
    _Outptr_ KESTREL_GPOLATERAL_SCAN_RESULT **ppResult)
{
    HRESULT             hr;
    IDirectorySearch   *pPol = NULL, *pRoot = NULL;
    ADS_SEARCH_HANDLE   h = NULL;
    WCHAR               wszPolPath[600], wszRootPath[600];
    ADS_SEARCHPREF_INFO prefs[2];
    KESTREL_GPOLATERAL_SCAN_RESULT *pRes = NULL;
    DWORD               cGpoHits = 0;
    LPWSTR attrs[] = { (LPWSTR)L"cn", (LPWSTR)L"gPCFileSysPath", (LPWSTR)L"displayName" };

    if (!pwszDomainNC || !ppResult) return E_INVALIDARG;
    *ppResult = NULL;

    pRes = (KESTREL_GPOLATERAL_SCAN_RESULT *)calloc(1, sizeof(*pRes));
    if (!pRes) return E_OUTOFMEMORY;

    wprintf(L"\n[*] GPO local-group membership -> lateral edges\n");

    if (FAILED(StringCchPrintfW(wszRootPath, ARRAYSIZE(wszRootPath), L"LDAP://%s", pwszDomainNC)) ||
        FAILED(StringCchPrintfW(wszPolPath, ARRAYSIZE(wszPolPath),
            L"LDAP://CN=Policies,CN=System,%s", pwszDomainNC))) {
        free(pRes); return E_FAIL;
    }

    /* Root handle reused for gPLink + computer searches. */
    hr = ADsGetObject(wszRootPath, &IID_IDirectorySearch, (void **)&pRoot);
    if (FAILED(hr)) { wprintf(L"  [!] ADsGetObject(root) 0x%08X\n", hr); free(pRes); return hr; }
    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pRoot->lpVtbl->SetSearchPreference(pRoot, prefs, ARRAYSIZE(prefs));

    hr = ADsGetObject(wszPolPath, &IID_IDirectorySearch, (void **)&pPol);
    if (FAILED(hr)) { wprintf(L"  [!] ADsGetObject(policies) 0x%08X\n", hr); goto Cleanup; }
    pPol->lpVtbl->SetSearchPreference(pPol, prefs, ARRAYSIZE(prefs));

    hr = pPol->lpVtbl->ExecuteSearch(pPol, (LPWSTR)L"(objectClass=groupPolicyContainer)",
            attrs, ARRAYSIZE(attrs), &h);
    if (FAILED(hr)) { wprintf(L"  [!] ExecuteSearch 0x%08X\n", hr); goto Cleanup; }

    while (pPol->lpVtbl->GetNextRow(pPol, h) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN col;
        WCHAR  wszCn[64] = L"", wszPath[512] = L"", wszName[256] = L"";
        WCHAR *pwszText;

        if (SUCCEEDED(pPol->lpVtbl->GetColumn(pPol, h, (LPWSTR)L"cn", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszCn, ARRAYSIZE(wszCn), col.pADsValues[0].CaseIgnoreString);
            pPol->lpVtbl->FreeColumn(pPol, &col);
        }
        if (SUCCEEDED(pPol->lpVtbl->GetColumn(pPol, h, (LPWSTR)L"gPCFileSysPath", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszPath, ARRAYSIZE(wszPath), col.pADsValues[0].CaseIgnoreString);
            pPol->lpVtbl->FreeColumn(pPol, &col);
        }
        if (SUCCEEDED(pPol->lpVtbl->GetColumn(pPol, h, (LPWSTR)L"displayName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszName, ARRAYSIZE(wszName), col.pADsValues[0].CaseIgnoreString);
            pPol->lpVtbl->FreeColumn(pPol, &col);
        }
        if (!wszCn[0] || !wszPath[0]) continue;
        pRes->cGpos++;

        pwszText = _ReadGptTmpl(wszPath);
        if (!pwszText) continue;
        _ParseGroupMembership(pRoot, pwszText, wszCn, wszName, pRes, &cGpoHits);
        HeapFree(GetProcessHeap(), 0, pwszText);
    }

    wprintf(L"\n  [=] %lu GPO(s) scanned, %lu push local-group membership, %lu edge(s) over %lu computer-hit(s)\n",
            pRes->cGpos, cGpoHits, pRes->cFindings, pRes->cComputers);
    if (pRes->cFindings == 0)
        wprintf(L"  [=] No GPO-delivered lateral membership found\n");
    hr = S_OK;

Cleanup:
    if (h)    pPol->lpVtbl->CloseSearchHandle(pPol, h);
    if (pPol) pPol->lpVtbl->Release(pPol);
    if (pRoot) pRoot->lpVtbl->Release(pRoot);

    if (FAILED(hr)) { KestrelFreeGpoLateralScanResult(pRes); return hr; }
    *ppResult = pRes;
    return S_OK;
}

VOID
KestrelFreeGpoLateralScanResult(_In_opt_ KESTREL_GPOLATERAL_SCAN_RESULT *pResult)
{
    if (!pResult) return;
    free(pResult->rgFindings);
    free(pResult);
}
