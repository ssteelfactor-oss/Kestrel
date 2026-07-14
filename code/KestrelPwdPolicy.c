/*
 * KestrelPwdPolicy.c — entry-condition posture (v0.13)
 *
 * The preconditions an attacker checks before the first credential:
 *
 *   1. Default domain password policy (attributes on the domain NC head):
 *      lockoutThreshold == 0 means no account lockout — password spraying is
 *      free. Short minPwdLength, no complexity, or non-expiring passwords widen
 *      the same surface.
 *   2. Fine-Grained Password Policies (msDS-PasswordSettings / PSO objects):
 *      per-principal overrides that are frequently WEAKER than the domain
 *      default and applied to service accounts — a common blind spot.
 *   3. krbtgt password age (pwdLastSet on krbtgt / RODC krbtgt_*): an account
 *      whose key has not rotated in a long time means any leaked krbtgt hash
 *      still forges valid Golden Tickets, and signals the domain never went
 *      through compromise recovery.
 *   4. ms-DS-MachineAccountQuota > 0: any authenticated user can join machine
 *      accounts — the enabler for noPac (CVE-2021-42278/42287) and Certifried
 *      (CVE-2022-26923).
 *
 * All of it is a read on the domain object, one container enumeration, and a
 * krbtgt read — read-only, ordinary user, directory-side.
 */

#include "../include/Kestrel.h"

#define KESTREL_PWD_KRBTGT_WARN_DAYS  180
#define KESTREL_PWD_KRBTGT_CRIT_DAYS  365
#define FT_PER_DAY  864000000000ULL   /* 100-ns intervals per day */

/* Read an ADSTYPE_INTEGER column; returns TRUE + *out on success. */
static BOOL
_ColInt(_In_ IDirectorySearch *pS, _In_ ADS_SEARCH_HANDLE h,
        _In_z_ LPCWSTR attr, _Out_ LONG *out)
{
    ADS_SEARCH_COLUMN col;
    BOOL ok = FALSE;
    *out = 0;
    if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)attr, &col))) {
        if (col.dwADsType == ADSTYPE_INTEGER && col.dwNumValues) {
            *out = col.pADsValues[0].Integer; ok = TRUE;
        }
        pS->lpVtbl->FreeColumn(pS, &col);
    }
    return ok;
}

/* Read an ADSTYPE_LARGE_INTEGER column as INT64. */
static BOOL
_ColI8(_In_ IDirectorySearch *pS, _In_ ADS_SEARCH_HANDLE h,
       _In_z_ LPCWSTR attr, _Out_ LONGLONG *out)
{
    ADS_SEARCH_COLUMN col;
    BOOL ok = FALSE;
    *out = 0;
    if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)attr, &col))) {
        if (col.dwADsType == ADSTYPE_LARGE_INTEGER && col.dwNumValues) {
            *out = col.pADsValues[0].LargeInteger.QuadPart; ok = TRUE;
        }
        pS->lpVtbl->FreeColumn(pS, &col);
    }
    return ok;
}

/* Age in days of a FILETIME-as-INT64 (pwdLastSet); -1 if unset/invalid. */
static LONGLONG
_AgeDays(_In_ LONGLONG ftQuad)
{
    FILETIME       now;
    ULARGE_INTEGER u;
    if (ftQuad <= 0) return -1;
    GetSystemTimeAsFileTime(&now);
    u.LowPart = now.dwLowDateTime; u.HighPart = now.dwHighDateTime;
    if ((LONGLONG)u.QuadPart <= ftQuad) return 0;
    return (LONGLONG)(((ULONGLONG)u.QuadPart - (ULONGLONG)ftQuad) / FT_PER_DAY);
}

/* maxPwdAge / msDS-MaximumPasswordAge (negative 100-ns interval) -> days,
 * or -1 for "never expires" (0 or the LLONG_MIN sentinel). */
static LONGLONG
_MaxAgeDays(_In_ LONGLONG i8)
{
    if (i8 == 0 || i8 == _I64_MIN) return -1;
    if (i8 < 0) i8 = -i8;
    return (LONGLONG)((ULONGLONG)i8 / FT_PER_DAY);
}

static void
_ReportDefaultPolicy(_In_ IDirectorySearch *pS, _In_ ADS_SEARCH_HANDLE h)
{
    LONG     lMinLen = 0, lLockout = 0, lProps = 0, lHist = 0, lMAQ = -1;
    LONGLONG i8MaxAge = 0;

    _ColInt(pS, h, L"minPwdLength",             &lMinLen);
    _ColInt(pS, h, L"lockoutThreshold",         &lLockout);
    _ColInt(pS, h, L"pwdProperties",            &lProps);
    _ColInt(pS, h, L"pwdHistoryLength",         &lHist);
    _ColInt(pS, h, L"ms-DS-MachineAccountQuota",&lMAQ);
    _ColI8 (pS, h, L"maxPwdAge",                &i8MaxAge);

    {
        LONGLONG maxDays = _MaxAgeDays(i8MaxAge);
        BOOL bComplex = (lProps & 0x1) != 0;   /* DOMAIN_PASSWORD_COMPLEX */

        wprintf(L"  default policy: minLen=%ld  lockoutThreshold=%ld  complexity=%s  history=%ld  maxPwdAge=%s\n",
            lMinLen, lLockout, bComplex ? L"on" : L"OFF", lHist,
            (maxDays < 0) ? L"never" : L"set");

        if (lLockout == 0)
            wprintf(L"      [SPRAY-SAFE] account lockout is DISABLED (threshold=0) — password spraying is unthrottled\n");
        if (lMinLen < 8)
            wprintf(L"      [WEAK] minimum password length is %ld\n", lMinLen);
        if (!bComplex)
            wprintf(L"      [WEAK] password complexity is disabled\n");
        if (maxDays < 0)
            wprintf(L"      [NOTE] domain passwords never expire (maxPwdAge)\n");
        if (lMAQ > 0)
            wprintf(L"      [noPac/Certifried] ms-DS-MachineAccountQuota=%ld — any user can join machine accounts (CVE-2021-42278/42287, CVE-2022-26923)\n", lMAQ);
    }
}

static void
_ReportKrbtgt(_In_ IDirectorySearch *pS)
{
    ADS_SEARCH_HANDLE h = NULL;
    LPWSTR attrs[] = { (LPWSTR)L"sAMAccountName", (LPWSTR)L"pwdLastSet" };

    if (FAILED(pS->lpVtbl->ExecuteSearch(pS,
            (LPWSTR)L"(&(objectClass=user)(sAMAccountName=krbtgt*))", attrs, 2, &h)))
        return;

    while (pS->lpVtbl->GetNextRow(pS, h) != S_ADS_NOMORE_ROWS) {
        WCHAR    wszSam[128] = L"";
        LONGLONG i8 = 0;
        LONGLONG age;
        ADS_SEARCH_COLUMN col;

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"sAMAccountName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszSam, ARRAYSIZE(wszSam), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        _ColI8(pS, h, L"pwdLastSet", &i8);
        age = _AgeDays(i8);

        wprintf(L"  %-16s pwdLastSet age: %s\n",
            wszSam[0] ? wszSam : L"krbtgt",
            (age < 0) ? L"unknown" : L"");
        if (age >= 0)
            wprintf(L"      %lld days%s\n", age,
                (age >= KESTREL_PWD_KRBTGT_CRIT_DAYS)
                    ? L"  [CRITICAL — Golden Ticket exposure, key never rotated]"
                : (age >= KESTREL_PWD_KRBTGT_WARN_DAYS)
                    ? L"  [WARN — rotate krbtgt (twice) as hygiene]" : L"");
    }
    pS->lpVtbl->CloseSearchHandle(pS, h);
}

static void
_ReportPSOs(_In_z_ LPCWSTR pwszDomainNC)
{
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h = NULL;
    WCHAR               wszPath[600];
    ADS_SEARCHPREF_INFO prefs[2];
    LPWSTR attrs[] = {
        (LPWSTR)L"cn", (LPWSTR)L"msDS-PasswordSettingsPrecedence",
        (LPWSTR)L"msDS-LockoutThreshold", (LPWSTR)L"msDS-MinimumPasswordLength",
        (LPWSTR)L"msDS-PasswordComplexityEnabled", (LPWSTR)L"msDS-PSOAppliesTo"
    };
    DWORD cPso = 0;

    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath),
            L"LDAP://CN=Password Settings Container,CN=System,%s", pwszDomainNC)))
        return;
    if (FAILED(ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pS)))
        return;   /* container absent (older domains) — nothing to report */

    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_ONELEVEL;
    prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pS->lpVtbl->SetSearchPreference(pS, prefs, ARRAYSIZE(prefs));

    if (FAILED(pS->lpVtbl->ExecuteSearch(pS,
            (LPWSTR)L"(objectClass=msDS-PasswordSettings)", attrs, ARRAYSIZE(attrs), &h)))
        goto done;

    while (pS->lpVtbl->GetNextRow(pS, h) != S_ADS_NOMORE_ROWS) {
        WCHAR wszCn[128] = L"";
        LONG  lPrec = 0, lLockout = 0, lMinLen = 0;
        BOOL  bComplex = TRUE;
        ADS_SEARCH_COLUMN col;

        if (cPso == 0) wprintf(L"\n  fine-grained policies (PSO):\n");
        cPso++;

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"cn", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszCn, ARRAYSIZE(wszCn), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        _ColInt(pS, h, L"msDS-PasswordSettingsPrecedence", &lPrec);
        _ColInt(pS, h, L"msDS-LockoutThreshold",           &lLockout);
        _ColInt(pS, h, L"msDS-MinimumPasswordLength",      &lMinLen);
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"msDS-PasswordComplexityEnabled", &col))) {
            if (col.dwADsType == ADSTYPE_BOOLEAN && col.dwNumValues)
                bComplex = col.pADsValues[0].Boolean ? TRUE : FALSE;
            pS->lpVtbl->FreeColumn(pS, &col);
        }

        wprintf(L"    [PSO] %-24s prec=%ld  lockoutThreshold=%ld  minLen=%ld  complexity=%s\n",
            wszCn[0] ? wszCn : L"(unknown)", lPrec, lLockout, lMinLen,
            bComplex ? L"on" : L"OFF");
        if (lLockout == 0)
            wprintf(L"          [SPRAY-SAFE] this PSO disables lockout\n");
        if (lMinLen && lMinLen < 8)
            wprintf(L"          [WEAK] PSO min length %ld\n", lMinLen);
        if (!bComplex)
            wprintf(L"          [WEAK] PSO complexity disabled\n");

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"msDS-PSOAppliesTo", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING) {
                for (DWORD i = 0; i < col.dwNumValues; i++)
                    wprintf(L"          applies to: %s\n", col.pADsValues[i].CaseIgnoreString);
            }
            pS->lpVtbl->FreeColumn(pS, &col);
        }
    }
    pS->lpVtbl->CloseSearchHandle(pS, h);

done:
    if (pS) pS->lpVtbl->Release(pS);
}

_Must_inspect_result_
HRESULT
KestrelRunPwdPolicyScan(_In_z_ LPCWSTR pwszDomainNC)
{
    HRESULT             hr;
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h = NULL;
    WCHAR               wszRoot[600];
    ADS_SEARCHPREF_INFO pref;
    LPWSTR attrs[] = {
        (LPWSTR)L"minPwdLength", (LPWSTR)L"lockoutThreshold", (LPWSTR)L"pwdProperties",
        (LPWSTR)L"pwdHistoryLength", (LPWSTR)L"maxPwdAge", (LPWSTR)L"ms-DS-MachineAccountQuota"
    };

    if (!pwszDomainNC) return E_INVALIDARG;
    if (FAILED(StringCchPrintfW(wszRoot, ARRAYSIZE(wszRoot), L"LDAP://%s", pwszDomainNC)))
        return E_FAIL;

    wprintf(L"\n[*] Password policy + entry-condition posture\n");

    hr = ADsGetObject(wszRoot, &IID_IDirectorySearch, (void **)&pS);
    if (FAILED(hr)) { wprintf(L"  [!] ADsGetObject 0x%08X\n", hr); return hr; }

    /* Default domain policy + MAQ — BASE read of the domain object. */
    pref.dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    pref.vValue.dwType = ADSTYPE_INTEGER;
    pref.vValue.Integer = ADS_SCOPE_BASE;
    pS->lpVtbl->SetSearchPreference(pS, &pref, 1);

    hr = pS->lpVtbl->ExecuteSearch(pS, (LPWSTR)L"(objectClass=*)",
            attrs, ARRAYSIZE(attrs), &h);
    if (SUCCEEDED(hr) && pS->lpVtbl->GetNextRow(pS, h) != S_ADS_NOMORE_ROWS)
        _ReportDefaultPolicy(pS, h);
    if (h) { pS->lpVtbl->CloseSearchHandle(pS, h); h = NULL; }

    /* krbtgt age — subtree search on the same object. */
    pref.vValue.Integer = ADS_SCOPE_SUBTREE;
    pS->lpVtbl->SetSearchPreference(pS, &pref, 1);
    _ReportKrbtgt(pS);

    pS->lpVtbl->Release(pS);

    /* Fine-grained PSOs — separate container bind. */
    _ReportPSOs(pwszDomainNC);

    return S_OK;
}
