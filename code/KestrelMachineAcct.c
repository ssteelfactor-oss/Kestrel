/*
 * KestrelMachineAcct.c — machine accounts created by ordinary users (v0.19)
 *
 * ms-DS-MachineAccountQuota (default 10) lets ANY authenticated user create
 * computer accounts. When a computer object is created this way — by a principal
 * that is not an administrator — Active Directory records the creator's SID in
 * the object's `mS-DS-CreatorSID` attribute. Accounts provisioned by admins do
 * not normally carry it.
 *
 * That attribute is therefore a durable, directory-side footprint of the whole
 * MachineAccountQuota-abuse family, which needs an attacker-controlled machine
 * account as its first step:
 *
 *   noPac        (CVE-2021-42278 / 42287) — sAMAccountName spoofing
 *   Certifried   (CVE-2022-26923)         — dNSHostName manipulation → AD CS
 *   Certighost   (CVE-2026-54121)         — rogue chase endpoint must be a
 *                                           valid domain principal
 *   RBCD         — the created account is the delegation target
 *
 * Kestrel cannot see whether a CA is patched, and does not try to: that is
 * host-side. What it can do is surface the precondition (quota > 0) together
 * with the accounts already created through it, who created them, and when.
 *
 * Note honestly: self-service domain join is a legitimate workflow, and it
 * produces exactly the same artifact. This scan is an inventory to review, not
 * a list of confirmed abuse. Read-only, ordinary domain user.
 */

#include "../include/Kestrel.h"

#define UAC_ACCOUNTDISABLE      0x00000002
#define UAC_SERVER_TRUST_ACCOUNT 0x00002000   /* a real Domain Controller */

/* Creators we treat as expected provisioning rather than quota use. */
static BOOL
_MaIsAdminCreator(_In_z_ LPCWSTR sid)
{
    LPCWSTR r;
    if (_wcsicmp(sid, L"S-1-5-18")     == 0) return TRUE;  /* SYSTEM         */
    if (_wcsicmp(sid, L"S-1-5-32-544") == 0) return TRUE;  /* Administrators */
    r = wcsrchr(sid, L'-');
    if (r) {
        r++;
        if (!wcscmp(r, L"500") || !wcscmp(r, L"512") ||    /* Administrator / Domain Admins */
            !wcscmp(r, L"519") || !wcscmp(r, L"518"))      /* Enterprise / Schema Admins    */
            return TRUE;
    }
    return FALSE;
}

_Must_inspect_result_
HRESULT
KestrelRunMachineAcctScan(_In_z_ LPCWSTR pwszDomainNC)
{
    HRESULT             hr;
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h  = NULL;
    WCHAR               wszRoot[600];
    ADS_SEARCHPREF_INFO prefs[2];
    DWORD               dwMAQ = 0;
    DWORD               cTotal = 0, cNonAdmin = 0, cEnabled = 0, cWithSpn = 0;
    LPWSTR rgAttrs[] = {
        (LPWSTR)L"sAMAccountName",   (LPWSTR)L"mS-DS-CreatorSID",
        (LPWSTR)L"whenCreated",      (LPWSTR)L"dNSHostName",
        (LPWSTR)L"servicePrincipalName", (LPWSTR)L"userAccountControl",
        (LPWSTR)L"distinguishedName"
    };

    if (!pwszDomainNC) return E_INVALIDARG;
    if (FAILED(StringCchPrintfW(wszRoot, ARRAYSIZE(wszRoot), L"LDAP://%s", pwszDomainNC)))
        return E_FAIL;

    wprintf(L"\n[*] Machine accounts created by ordinary users (MachineAccountQuota footprint)\n");

    /* Precondition: is the quota even open? */
    if (SUCCEEDED(KestrelReadMachineAccountQuota(pwszDomainNC, &dwMAQ))) {
        if (dwMAQ > 0)
            wprintf(L"  [*] ms-DS-MachineAccountQuota = %lu — any authenticated user may create "
                    L"up to %lu machine account(s)\n", dwMAQ, dwMAQ);
        else
            wprintf(L"  [*] ms-DS-MachineAccountQuota = 0 — quota closed; any objects below are "
                    L"historical\n");
    }

    hr = ADsGetObject(wszRoot, &IID_IDirectorySearch, (void **)&pS);
    if (FAILED(hr)) { wprintf(L"  [!] ADsGetObject 0x%08X\n", hr); return hr; }

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pS->lpVtbl->SetSearchPreference(pS, prefs, ARRAYSIZE(prefs));

    /* objectCategory is indexed and leads the filter; the creator-SID presence
       test then runs over computer objects only. */
    hr = pS->lpVtbl->ExecuteSearch(pS,
            (LPWSTR)L"(&(objectCategory=computer)(mS-DS-CreatorSID=*))",
            rgAttrs, ARRAYSIZE(rgAttrs), &h);
    if (FAILED(hr)) { wprintf(L"  [!] ExecuteSearch 0x%08X\n", hr); goto Cleanup; }

    for (;;) {
        ADS_SEARCH_COLUMN col;
        WCHAR   wszSam[128] = L"", wszDns[300] = L"", wszDN[600] = L"";
        WCHAR   wszCreator[128] = L"", wszWhen[64] = L"";
        WCHAR   nm[256] = L"", dm[256] = L"";
        LONG    lUac = 0;
        DWORD   cSpn = 0;
        BOOL    bEnabled, bAdminCreator = FALSE, bIsDC;

        hr = pS->lpVtbl->GetNextRow(pS, h);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr)) { wprintf(L"  [!] GetNextRow 0x%08X\n", hr); break; }

        /* creator SID (octet string → textual SID → account name) */
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"mS-DS-CreatorSID", &col))) {
            if (col.dwADsType == ADSTYPE_OCTET_STRING && col.dwNumValues) {
                PSID   pSid = (PSID)col.pADsValues[0].OctetString.lpValue;
                LPWSTR s    = NULL;
                if (pSid && IsValidSid(pSid) && ConvertSidToStringSidW(pSid, &s) && s) {
                    DWORD        cn = ARRAYSIZE(nm), cd = ARRAYSIZE(dm);
                    SID_NAME_USE use;
                    StringCchCopyW(wszCreator, ARRAYSIZE(wszCreator), s);
                    bAdminCreator = _MaIsAdminCreator(s);
                    if (!LookupAccountSidW(NULL, pSid, nm, &cn, dm, &cd, &use))
                        nm[0] = L'\0';
                    LocalFree(s);
                }
            }
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (!wszCreator[0]) continue;      /* unreadable — skip quietly */
        cTotal++;

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
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"whenCreated", &col))) {
            if (col.dwADsType == ADSTYPE_UTC_TIME && col.dwNumValues) {
                SYSTEMTIME *st = &col.pADsValues[0].UTCTime;
                StringCchPrintfW(wszWhen, ARRAYSIZE(wszWhen), L"%04u-%02u-%02u %02u:%02u",
                    st->wYear, st->wMonth, st->wDay, st->wHour, st->wMinute);
            }
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"dNSHostName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszDns, ARRAYSIZE(wszDns), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"servicePrincipalName", &col))) {
            cSpn = col.dwNumValues;
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"userAccountControl", &col))) {
            if (col.dwADsType == ADSTYPE_INTEGER && col.dwNumValues)
                lUac = col.pADsValues[0].Integer;
            pS->lpVtbl->FreeColumn(pS, &col);
        }

        bEnabled = (lUac & UAC_ACCOUNTDISABLE) == 0;
        bIsDC    = (lUac & UAC_SERVER_TRUST_ACCOUNT) != 0;
        if (bEnabled)       cEnabled++;
        if (cSpn)           cWithSpn++;
        if (!bAdminCreator) cNonAdmin++;

        wprintf(L"  [MAQ-ACCT] %-24s created %s by %s%s%s\n",
            wszSam[0] ? wszSam : L"(unknown)",
            wszWhen[0] ? wszWhen : L"(unknown time)",
            nm[0] ? dm : L"", nm[0] ? L"\\" : L"",
            nm[0] ? nm : wszCreator);
        if (!bEnabled)
            wprintf(L"        (disabled)\n");
        if (wszDns[0])
            wprintf(L"        dNSHostName: %s\n", wszDns);
        if (cSpn)
            wprintf(L"        %lu SPN(s) registered%s\n", cSpn,
                    bEnabled ? L" — usable for authentication" : L"");
        if (bIsDC)
            wprintf(L"        *** SERVER_TRUST_ACCOUNT set — this object claims to be a "
                    L"Domain Controller ***\n");
        if (bAdminCreator)
            wprintf(L"        (creator is an administrator — normal provisioning)\n");
        if (!bAdminCreator)
            KestrelAddFinding(
                bIsDC ? KESTREL_SEV_CRITICAL : (cSpn && bEnabled) ? KESTREL_SEV_HIGH
                                                                  : KESTREL_SEV_LOW,
                L"Machine Acct", wszSam[0] ? wszSam : wszCreator,
                bIsDC ? L"created via quota and claims to be a Domain Controller"
                      : (cSpn && bEnabled) ? L"created via quota, enabled, with SPNs"
                                           : L"created via quota by a non-admin");

        /* When did the identity attributes last change, and from which DSA?
           dNSHostName / SPN rewrites are the Certifried-class manipulation. */
        if (wszDN[0] && !bAdminCreator && (wszDns[0] || cSpn)) {
            static const LPCWSTR rgProv[] = { L"dNSHostName", L"servicePrincipalName" };
            KestrelPrintAttrProvenance(wszDN, L"machine-identity", rgProv, 2, FALSE);
        }
    }

    wprintf(L"\n  [=] %lu machine account(s) carry mS-DS-CreatorSID — %lu created by non-admins, "
            L"%lu enabled, %lu with SPNs\n", cTotal, cNonAdmin, cEnabled, cWithSpn);
    if (cTotal == 0)
        wprintf(L"  [=] No machine accounts created through the quota were found\n");
    else
        wprintf(L"  [=] Self-service domain join produces the same artifact — review this as an "
                L"inventory, not as confirmed abuse. Set ms-DS-MachineAccountQuota to 0 and "
                L"delegate machine creation explicitly to remove the class.\n");

Cleanup:
    if (h)  pS->lpVtbl->CloseSearchHandle(pS, h);
    if (pS) pS->lpVtbl->Release(pS);
    return hr;
}
