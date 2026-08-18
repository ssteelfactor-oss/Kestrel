/*
 * KestrelHardening.c — domain hardening flags (v1.1)
 *
 * Two cheap, high-signal checks that live in single attributes / a single group
 * and are almost never reviewed after the domain is built:
 *
 *   1. dSHeuristics  (CN=Directory Service,CN=Windows NT,CN=Services,<configNC>)
 *      A fixed-order Unicode string; each position is a heuristic flag. Three
 *      positions matter for security (1-indexed as Microsoft documents them):
 *        - 7th  == '2'  -> fLDAPBlockAnonOps off = anonymous LDAP enabled
 *                          (unauthenticated enumeration of the directory).
 *        - 8th  != '0'  -> fAllowAnonNSPI = anonymous NSPI (address-book) access.
 *        - 16th != '0'  -> dwAdminSDExMask = some privileged groups are EXCLUDED
 *                          from AdminSDHolder/SDProp protection, so ACL edits on
 *                          them are never reverted (a quiet persistence lever).
 *      Omitted trailing characters default to '0', so length is checked first.
 *
 *   2. Pre-Windows 2000 Compatible Access  (BUILTIN group, SID S-1-5-32-554)
 *      If Everyone (S-1-1-0) or Anonymous Logon (S-1-5-7) is a member, broad /
 *      unauthenticated principals get legacy read access to account attributes
 *      across the domain. The group is found by its well-known SID, not its cn,
 *      because the name is localized on non-English domains.
 *
 * Read-only, ordinary domain user, on-prem. Core AD check (part of --all).
 */

#include "../include/Kestrel.h"

static VOID
_HardeningDSHeuristics(_In_z_ LPCWSTR pwszConfigNC)
{
    WCHAR               wszPath[700];
    IADs               *pDS = NULL;
    VARIANT             v;
    BSTR                bstrAttr;
    HRESULT             hr;
    WCHAR               wszVal[64] = L"";
    size_t              len;

    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath),
            L"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,%s", pwszConfigNC)))
        return;

    hr = ADsGetObject(wszPath, &IID_IADs, (void **)&pDS);
    if (FAILED(hr)) {
        wprintf(L"  [=] dSHeuristics not readable (Directory Service object absent?)\n");
        return;
    }

    VariantInit(&v);
    bstrAttr = SysAllocString(L"dSHeuristics");
    hr = pDS->lpVtbl->Get(pDS, bstrAttr, &v);
    if (SUCCEEDED(hr) && v.vt == VT_BSTR && v.bstrVal)
        StringCchCopyW(wszVal, ARRAYSIZE(wszVal), v.bstrVal);
    SysFreeString(bstrAttr);
    VariantClear(&v);
    pDS->lpVtbl->Release(pDS);

    if (!wszVal[0]) {
        wprintf(L"  [=] dSHeuristics unset (secure default: no anonymous access, no SDProp exclusions)\n");
        return;
    }

    wprintf(L"  [*] dSHeuristics = \"%s\"\n", wszVal);
    len = wcslen(wszVal);

    /* 7th char (index 6): anonymous LDAP. */
    if (len > 6 && wszVal[6] == L'2') {
        wprintf(L"  [HARD-ANON] anonymous LDAP is ENABLED (dSHeuristics[7]='2') - "
                L"unauthenticated directory enumeration\n");
        KestrelAddFinding(KESTREL_SEV_HIGH, L"Hardening", L"dSHeuristics",
            L"anonymous LDAP operations enabled (fLDAPBlockAnonOps off) - unauthenticated enumeration",
            L"set the 7th character of dSHeuristics back to '0' on CN=Directory Service in the forest root");
    }
    /* 8th char (index 7): anonymous NSPI. */
    if (len > 7 && wszVal[7] != L'0') {
        wprintf(L"  [HARD-ANON] anonymous NSPI is ENABLED (dSHeuristics[8]='%c')\n", wszVal[7]);
        KestrelAddFinding(KESTREL_SEV_MEDIUM, L"Hardening", L"dSHeuristics",
            L"anonymous NSPI address-book access enabled (fAllowAnonNSPI)",
            L"set the 8th character of dSHeuristics back to '0'");
    }
    /* 16th char (index 15): AdminSDHolder exclusion mask. */
    if (len > 15 && wszVal[15] != L'0') {
        wprintf(L"  [HARD-SDPROP] AdminSDHolder exclusion mask set (dSHeuristics[16]='%c') - "
                L"some privileged groups are NOT protected by SDProp\n", wszVal[15]);
        KestrelAddFinding(KESTREL_SEV_HIGH, L"Hardening", L"dSHeuristics",
            L"dwAdminSDExMask excludes privileged groups from AdminSDHolder/SDProp protection (persistence lever)",
            L"set the 16th character of dSHeuristics back to '0' so all default groups are SDProp-protected");
    }
}

static VOID
_HardeningPreWin2000(_In_z_ LPCWSTR pwszDomainNC)
{
    WCHAR               wszRoot[600];
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h  = NULL;
    ADS_SEARCHPREF_INFO prefs[2];
    ADS_SEARCH_COLUMN   col;
    HRESULT             hr;
    BOOL                bEveryone = FALSE, bAnon = FALSE, bAuth = FALSE;
    LPWSTR rgAttrs[] = { (LPWSTR)L"member" };

    if (FAILED(StringCchPrintfW(wszRoot, ARRAYSIZE(wszRoot), L"LDAP://%s", pwszDomainNC)))
        return;
    if (FAILED(ADsGetObject(wszRoot, &IID_IDirectorySearch, (void **)&pS)))
        return;

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pS->lpVtbl->SetSearchPreference(pS, prefs, ARRAYSIZE(prefs));

    /* Find the group by its well-known SID S-1-5-32-554 (language-independent). */
    hr = pS->lpVtbl->ExecuteSearch(pS,
            (LPWSTR)L"(objectSid=\\01\\02\\00\\00\\00\\00\\00\\05\\20\\00\\00\\00\\2a\\02\\00\\00)",
            rgAttrs, ARRAYSIZE(rgAttrs), &h);
    if (FAILED(hr)) { pS->lpVtbl->Release(pS); return; }

    if (pS->lpVtbl->GetNextRow(pS, h) == S_OK &&
        pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"member", &col) == S_OK) {
        if (col.dwADsType == ADSTYPE_DN_STRING) {
            DWORD v;
            for (v = 0; v < col.dwNumValues; v++) {
                LPWSTR dn = col.pADsValues[v].DNString;
                if (!dn) continue;
                if (wcsstr(dn, L"S-1-1-0,"))  bEveryone = TRUE;   /* Everyone            */
                if (wcsstr(dn, L"S-1-5-7,"))  bAnon     = TRUE;   /* Anonymous Logon     */
                if (wcsstr(dn, L"S-1-5-11,")) bAuth     = TRUE;   /* Authenticated Users */
            }
        }
        pS->lpVtbl->FreeColumn(pS, &col);
    }

    if (bEveryone || bAnon) {
        wprintf(L"  [HARD-COMPAT] Pre-Windows 2000 Compatible Access contains %s%s%s - "
                L"broad legacy read access to account attributes\n",
                bEveryone ? L"Everyone" : L"",
                (bEveryone && bAnon) ? L" + " : L"",
                bAnon ? L"Anonymous Logon" : L"");
        KestrelAddFinding(KESTREL_SEV_HIGH, L"Hardening",
            L"Pre-Windows 2000 Compatible Access",
            L"Everyone / Anonymous is a member of Pre-Windows 2000 Compatible Access (broad legacy directory read)",
            L"remove Everyone and Anonymous Logon from the group; leave only Authenticated Users if compatibility is required");
    } else if (bAuth) {
        wprintf(L"  [=] Pre-Windows 2000 Compatible Access: only Authenticated Users (acceptable)\n");
    } else {
        wprintf(L"  [=] Pre-Windows 2000 Compatible Access: no broad principals\n");
    }

    if (h) pS->lpVtbl->CloseSearchHandle(pS, h);
    pS->lpVtbl->Release(pS);
}

_Must_inspect_result_
HRESULT
KestrelRunHardeningScan(_In_z_ LPCWSTR pwszConfigNC, _In_z_ LPCWSTR pwszDomainNC)
{
    if (!pwszConfigNC || !pwszDomainNC) return E_INVALIDARG;

    wprintf(L"\n[*] Domain hardening flags (passive - from Active Directory only)\n");

    _HardeningDSHeuristics(pwszConfigNC);
    _HardeningPreWin2000(pwszDomainNC);

    return S_OK;
}
