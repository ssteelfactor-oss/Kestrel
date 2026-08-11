/*
 * KestrelSQL.c — passive SQL Server posture from AD (v1.1)
 *
 * SQL Server registers a Service Principal Name for every instance so clients
 * can authenticate with Kerberos:
 *
 *     MSSQLSvc/<fqdn>:<tcpport>     TCP instance (default or named)
 *     MSSQLSvc/<fqdn>:<instance>    named pipes / shared memory
 *     MSSQLSvc/<fqdn>               default instance, non-TCP
 *
 * That SPN is written onto the account the SQL service runs under: a computer
 * object when SQL runs as LocalSystem / NetworkService, or a *domain user*
 * object when it runs under a dedicated service account. So the directory
 * already holds two things Kestrel can read without ever connecting to SQL:
 *
 *   1. an inventory of every SQL instance in the domain (host, port/instance);
 *   2. which account each instance runs under — and whether that account is
 *      dangerous.
 *
 * The catastrophe everyone knows and nobody audits is SQL running under a
 * *privileged* domain account (Domain Admin, or delegation-enabled). A SQL
 * service compromise then becomes domain compromise. All of it is visible from
 * AD: the SPN says "this is SQL", the parent object says "here is its account",
 * and adminCount / userAccountControl / msDS-AllowedToDelegateTo say "and it is
 * over-privileged".
 *
 * Read-only, ordinary domain user, on-prem. This never talks to a SQL instance;
 * it reads what SQL published about itself.
 */

#include "../include/Kestrel.h"

#define UAC_ACCOUNTDISABLE                 0x00000002
#define UAC_TRUSTED_FOR_DELEGATION         0x00080000   /* unconstrained          */
#define UAC_TRUSTED_TO_AUTH_FOR_DELEGATION 0x01000000   /* constrained w/ S4U2Self */

/* Pull the descriptor after "MSSQLSvc/" out of one SPN value.
 * Returns TRUE and fills out when the value is an MSSQLSvc SPN. */
static BOOL
_SqlSpnDescriptor(_In_z_ LPCWSTR pwszSpn, _Out_writes_z_(cch) LPWSTR out, _In_ SIZE_T cch)
{
    const WCHAR prefix[] = L"MSSQLSvc/";
    size_t      n = ARRAYSIZE(prefix) - 1;
    if (_wcsnicmp(pwszSpn, prefix, n) != 0)
        return FALSE;
    StringCchCopyW(out, cch, pwszSpn + n);
    return TRUE;
}

_Must_inspect_result_
HRESULT
KestrelRunSqlScan(_In_z_ LPCWSTR pwszDomainNC)
{
    HRESULT             hr;
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h  = NULL;
    WCHAR               wszRoot[600];
    ADS_SEARCHPREF_INFO prefs[2];
    DWORD               cInstances = 0, cAccounts = 0, cPriv = 0, cDeleg = 0;
    LPWSTR rgAttrs[] = {
        (LPWSTR)L"sAMAccountName",   (LPWSTR)L"servicePrincipalName",
        (LPWSTR)L"adminCount",       (LPWSTR)L"userAccountControl",
        (LPWSTR)L"msDS-AllowedToDelegateTo", (LPWSTR)L"distinguishedName"
    };

    if (!pwszDomainNC) return E_INVALIDARG;
    if (FAILED(StringCchPrintfW(wszRoot, ARRAYSIZE(wszRoot), L"LDAP://%s", pwszDomainNC)))
        return E_FAIL;

    wprintf(L"\n[*] SQL Server posture (passive - from Active Directory only)\n");

    hr = ADsGetObject(wszRoot, &IID_IDirectorySearch, (void **)&pS);
    if (FAILED(hr)) { wprintf(L"  [!] ADsGetObject 0x%08X\n", hr); return hr; }

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pS->lpVtbl->SetSearchPreference(pS, prefs, ARRAYSIZE(prefs));

    /* Prefix match on the SPN: every SQL instance in the domain. */
    hr = pS->lpVtbl->ExecuteSearch(pS, (LPWSTR)L"(servicePrincipalName=MSSQLSvc/*)",
            rgAttrs, ARRAYSIZE(rgAttrs), &h);
    if (FAILED(hr)) { wprintf(L"  [!] ExecuteSearch 0x%08X\n", hr); goto Cleanup; }

    for (;;) {
        ADS_SEARCH_COLUMN col;
        WCHAR   wszSam[128] = L"", wszDN[600] = L"";
        WCHAR   wszFirst[320] = L"";
        LONG    lUac = 0, lAdmin = 0;
        DWORD   cSqlSpn = 0;
        BOOL    bComputer, bDisabled, bDeleg = FALSE, bConstrained = FALSE;

        hr = pS->lpVtbl->GetNextRow(pS, h);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr)) { wprintf(L"  [!] GetNextRow 0x%08X\n", hr); break; }

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"sAMAccountName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszSam, ARRAYSIZE(wszSam), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"distinguishedName", &col))) {
            if (col.dwNumValues) {
                if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING)
                    StringCchCopyW(wszDN, ARRAYSIZE(wszDN), col.pADsValues[0].CaseIgnoreString);
                else if (col.dwADsType == ADSTYPE_DN_STRING)
                    StringCchCopyW(wszDN, ARRAYSIZE(wszDN), col.pADsValues[0].DNString);
            }
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        /* count MSSQLSvc SPNs, keep the first descriptor for display */
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"servicePrincipalName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING) {
                DWORD v;
                for (v = 0; v < col.dwNumValues; v++) {
                    WCHAR desc[320];
                    if (_SqlSpnDescriptor(col.pADsValues[v].CaseIgnoreString, desc, ARRAYSIZE(desc))) {
                        if (cSqlSpn == 0)
                            StringCchCopyW(wszFirst, ARRAYSIZE(wszFirst), desc);
                        cSqlSpn++;
                    }
                }
            }
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"adminCount", &col))) {
            if (col.dwADsType == ADSTYPE_INTEGER && col.dwNumValues)
                lAdmin = col.pADsValues[0].Integer;
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"userAccountControl", &col))) {
            if (col.dwADsType == ADSTYPE_INTEGER && col.dwNumValues)
                lUac = col.pADsValues[0].Integer;
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"msDS-AllowedToDelegateTo", &col))) {
            if (col.dwNumValues) bConstrained = TRUE;
            pS->lpVtbl->FreeColumn(pS, &col);
        }

        if (cSqlSpn == 0) continue;   /* matched on a non-MSSQLSvc SPN prefix — skip */
        cInstances++;

        bComputer = (wszSam[0] && wszSam[wcslen(wszSam) - 1] == L'$');
        bDisabled = (lUac & UAC_ACCOUNTDISABLE) != 0;
        if (lUac & UAC_TRUSTED_FOR_DELEGATION)         bDeleg = TRUE;
        if (lUac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) bDeleg = TRUE;
        if (bConstrained)                              bDeleg = TRUE;

        wprintf(L"  [SQL] %-40s runs as %s (%s)%s%s\n",
            wszFirst[0] ? wszFirst : L"(instance)",
            wszSam[0] ? wszSam : L"(unknown)",
            bComputer ? L"machine account" : L"domain user account",
            cSqlSpn > 1 ? L"  [+more SPNs]" : L"",
            bDisabled ? L"  [disabled]" : L"");

        if (bComputer)
            continue;   /* LocalSystem/NetworkService: inventory only, low risk */

        cAccounts++;

        /* Domain service account — the exposure surface. */
        if (lAdmin == 1) {
            cPriv++;
            wprintf(L"        *** privileged service account (adminCount=1) - SQL compromise "
                    L"becomes domain compromise ***\n");
            KestrelAddFinding(KESTREL_SEV_CRITICAL, L"SQL", wszSam,
                L"SQL Server runs under a privileged domain account (adminCount=1)",
                L"run SQL under a low-privilege dedicated service account (or a gMSA); "
                L"remove it from privileged groups");
        }
        if (bDeleg) {
            cDeleg++;
            wprintf(L"        [delegation] account is %s - SQL-to-DA pivot risk\n",
                bConstrained ? L"trusted for constrained delegation"
                             : L"trusted for unconstrained delegation");
            KestrelAddFinding(KESTREL_SEV_HIGH, L"SQL", wszSam,
                bConstrained ? L"SQL service account is configured for constrained delegation"
                             : L"SQL service account is trusted for unconstrained delegation",
                L"remove delegation from the SQL service account unless strictly required; "
                L"prefer resource-based constrained delegation scoped to the target");
        }

        /* A SQL service account always has an SPN, so it is Kerberoastable by
           definition; --roast covers the crack risk. Note provenance of the
           account's SPN/UAC for the non-machine, flagged cases. */
        if (wszDN[0] && (lAdmin == 1 || bDeleg)) {
            static const LPCWSTR rgProv[] = { L"servicePrincipalName", L"userAccountControl" };
            KestrelPrintAttrProvenance(wszDN, L"sql-account", rgProv, 2, FALSE);
        }
    }

    wprintf(L"\n  [=] %lu SQL instance(s) found via MSSQLSvc SPN - %lu under domain accounts, "
            L"%lu privileged, %lu delegation-enabled\n",
            cInstances, cAccounts, cPriv, cDeleg);
    if (cInstances == 0)
        wprintf(L"  [=] No MSSQLSvc SPNs in the domain (no Kerberos-registered SQL, or none deployed)\n");
    else if (cPriv == 0 && cDeleg == 0)
        wprintf(L"  [=] No SQL instance runs under a privileged or delegation-enabled account\n");

Cleanup:
    if (h)  pS->lpVtbl->CloseSearchHandle(pS, h);
    if (pS) pS->lpVtbl->Release(pS);
    return hr;
}
