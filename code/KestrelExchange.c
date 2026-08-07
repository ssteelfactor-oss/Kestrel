/*
 * KestrelExchange.c — passive Exchange posture audit (v1.1)
 *
 * Exchange writes an enormous amount about itself into the Configuration NC, and
 * it grants its own security groups standing rights inside Active Directory. Both
 * are readable by an ordinary domain user, so Kestrel can audit the security
 * posture of Exchange *without ever touching an Exchange server* — no OWA probe,
 * no EWS call, no packet to the transport service. Exchange already told the
 * directory everything below.
 *
 * Two passes:
 *
 *   1. Inventory — enumerate msExchExchangeServer objects: version (serialNumber),
 *      roles, and FQDN. End-of-life builds (2010 / 2013 and, since Oct 2025,
 *      2016 / 2019) are unsupported and therefore unpatched forever.
 *
 *   2. Escalation surface — the documented Exchange-to-Domain-Admin path
 *      (Fox-IT / dirkjanm / Trimarc): the "Exchange Windows Permissions" group
 *      holds WriteDACL on the domain object by default, which lets any member
 *      grant itself DCSync. "Exchange Trusted Subsystem" and "Organization
 *      Management" are frequently found with GenericAll at the domain root.
 *      Kestrel reads the domain object's DACL (DACL-only mask, ordinary user)
 *      and reports which Exchange group actually holds a dangerous right on it.
 *
 * Read-only, ordinary domain user, on-prem only. If Exchange is not deployed the
 * scan reports nothing and returns — it never errors on a missing org.
 */

#include "../include/Kestrel.h"
#include <sddl.h>

/* Rights on the domain object that hand an Exchange group a path to DA. */
#define KESTREL_EXCH_DANGER_MASK \
    (ADS_RIGHT_WRITE_DAC | ADS_RIGHT_GENERIC_ALL | ADS_RIGHT_WRITE_OWNER)

/* msExchCurrentServerRoles bitmask → role names. */
static VOID
_ExchRoles(_In_ LONG roles, _Out_writes_z_(cch) LPWSTR out, _In_ SIZE_T cch)
{
    out[0] = L'\0';
    if (roles & 2)  StringCchCatW(out, cch, L"MBX ");
    if (roles & 4)  StringCchCatW(out, cch, L"CAS ");
    if (roles & 16) StringCchCatW(out, cch, L"UM ");
    if (roles & 32) StringCchCatW(out, cch, L"HUB ");
    if (roles & 64) StringCchCatW(out, cch, L"EDGE ");
    if (!out[0])    StringCchCatW(out, cch, L"(none)");
}

/* Map the leading "Version A.B" of serialNumber to a product line + EOL verdict.
 * Returns a static name; *pbEol set when the line is out of support. */
static LPCWSTR
_ExchProductLine(_In_z_ LPCWSTR pwszSerial, _Out_ BOOL *pbEol, _Out_ KESTREL_SEVERITY *pSev)
{
    *pbEol = FALSE;
    *pSev  = KESTREL_SEV_INFO;

    if (!pwszSerial) return L"Exchange (unknown)";

    /* serialNumber looks like "Version 15.1 (Build 2507.6)". */
    if (wcsstr(pwszSerial, L"6.5"))  { *pbEol = TRUE; *pSev = KESTREL_SEV_HIGH; return L"Exchange 2003 (EOL)"; }
    if (wcsstr(pwszSerial, L"8."))   { *pbEol = TRUE; *pSev = KESTREL_SEV_HIGH; return L"Exchange 2007 (EOL)"; }
    if (wcsstr(pwszSerial, L"14."))  { *pbEol = TRUE; *pSev = KESTREL_SEV_HIGH; return L"Exchange 2010 (EOL 2020)"; }
    if (wcsstr(pwszSerial, L"15.0")) { *pbEol = TRUE; *pSev = KESTREL_SEV_HIGH; return L"Exchange 2013 (EOL 2023)"; }
    if (wcsstr(pwszSerial, L"15.1")) { *pbEol = TRUE; *pSev = KESTREL_SEV_MEDIUM; return L"Exchange 2016 (support ended Oct 2025)"; }
    if (wcsstr(pwszSerial, L"15.2")) { *pbEol = TRUE; *pSev = KESTREL_SEV_MEDIUM; return L"Exchange 2019 (support ended Oct 2025)"; }
    return L"Exchange (verify build against current advisories)";
}

/* Trustee SID of an allow / allow-object ACE. */
static PSID
_ExchAceSid(_In_ ACE_HEADER *pAce)
{
    switch (pAce->AceType) {
    case ACCESS_ALLOWED_ACE_TYPE:
        return (PSID)&((ACCESS_ALLOWED_ACE *)pAce)->SidStart;
    case ACCESS_ALLOWED_OBJECT_ACE_TYPE: {
        ACCESS_ALLOWED_OBJECT_ACE *p = (ACCESS_ALLOWED_OBJECT_ACE *)pAce;
        return (PSID)((BYTE *)p + sizeof(ACCESS_ALLOWED_OBJECT_ACE) -
            (2 - !!(p->Flags & ACE_OBJECT_TYPE_PRESENT)
               - !!(p->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT)) * sizeof(GUID));
    }
    default:
        return NULL;
    }
}

/* Pass 1 — enumerate Exchange servers from the Configuration NC. Returns count. */
static DWORD
_ExchInventory(_In_z_ LPCWSTR pwszConfigNC)
{
    WCHAR               wszPath[600];
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h  = NULL;
    ADS_SEARCHPREF_INFO prefs[2];
    HRESULT             hr;
    DWORD               cServers = 0;
    LPWSTR rgAttrs[] = {
        (LPWSTR)L"cn", (LPWSTR)L"serialNumber",
        (LPWSTR)L"msExchCurrentServerRoles", (LPWSTR)L"networkAddress"
    };

    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath),
            L"LDAP://CN=Microsoft Exchange,CN=Services,%s", pwszConfigNC)))
        return 0;

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pS);
    if (FAILED(hr)) {
        wprintf(L"  [=] No Exchange organization in the Configuration NC "
                L"(Exchange not deployed here)\n");
        return 0;
    }

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pS->lpVtbl->SetSearchPreference(pS, prefs, ARRAYSIZE(prefs));

    hr = pS->lpVtbl->ExecuteSearch(pS, (LPWSTR)L"(objectClass=msExchExchangeServer)",
            rgAttrs, ARRAYSIZE(rgAttrs), &h);
    if (FAILED(hr)) { pS->lpVtbl->Release(pS); return 0; }

    for (;;) {
        ADS_SEARCH_COLUMN col;
        WCHAR   wszName[128] = L"", wszSerial[128] = L"", wszFqdn[256] = L"", wszRoles[64];
        LONG    lRoles = 0;
        BOOL    bEol;
        KESTREL_SEVERITY sev;
        LPCWSTR pwszLine;

        hr = pS->lpVtbl->GetNextRow(pS, h);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr)) break;

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"cn", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszName, ARRAYSIZE(wszName), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        {
            HRESULT hrc = pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"serialNumber", &col);
            if (SUCCEEDED(hrc)) {
                if (col.dwNumValues) {
                    if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING)
                        StringCchCopyW(wszSerial, ARRAYSIZE(wszSerial), col.pADsValues[0].CaseIgnoreString);
                    else if (col.dwADsType == ADSTYPE_PRINTABLE_STRING)
                        StringCchCopyW(wszSerial, ARRAYSIZE(wszSerial), col.pADsValues[0].PrintableString);
                    else if (col.dwADsType == ADSTYPE_DN_STRING)
                        StringCchCopyW(wszSerial, ARRAYSIZE(wszSerial), col.pADsValues[0].DNString);
                }
                wprintf(L"  [EXCH-DBG] serialNumber type=%lu nvals=%lu val='%s'\n",
                    (unsigned long)col.dwADsType, (unsigned long)col.dwNumValues, wszSerial);
                pS->lpVtbl->FreeColumn(pS, &col);
            } else {
                wprintf(L"  [EXCH-DBG] serialNumber not read (GetColumn hr=0x%08X)\n", (unsigned)hrc);
            }
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"msExchCurrentServerRoles", &col))) {
            if (col.dwADsType == ADSTYPE_INTEGER && col.dwNumValues)
                lRoles = col.pADsValues[0].Integer;
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"networkAddress", &col))) {
            /* networkAddress is multi-valued; take the ncacn_ip_tcp entry. */
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING) {
                DWORD v;
                for (v = 0; v < col.dwNumValues; v++) {
                    LPWSTR na = col.pADsValues[v].CaseIgnoreString;
                    if (na && wcsstr(na, L"ncacn_ip_tcp:")) {
                        StringCchCopyW(wszFqdn, ARRAYSIZE(wszFqdn), wcschr(na, L':') + 1);
                        break;
                    }
                }
            }
            pS->lpVtbl->FreeColumn(pS, &col);
        }

        cServers++;
        _ExchRoles(lRoles, wszRoles, ARRAYSIZE(wszRoles));
        pwszLine = _ExchProductLine(wszSerial, &bEol, &sev);

        wprintf(L"  [EXCH] %-20s %-40s roles: %s%s%s\n",
            wszName[0] ? wszName : L"(server)",
            pwszLine,
            wszRoles,
            wszFqdn[0] ? L" @ " : L"", wszFqdn[0] ? wszFqdn : L"");
        if (wszSerial[0])
            wprintf(L"        build: %s\n", wszSerial);

        if (bEol) {
            wprintf(L"        *** out of support - unpatched forever; migrate or isolate ***\n");
            KestrelAddFinding(sev, L"Exchange",
                wszName[0] ? wszName : L"(server)", pwszLine,
                L"migrate off end-of-life Exchange, or isolate it from the network");
        }
    }

    if (h) pS->lpVtbl->CloseSearchHandle(pS, h);
    pS->lpVtbl->Release(pS);
    return cServers;
}

/* Pass 2 — does an Exchange group hold a dangerous right on the domain object? */
static VOID
_ExchDomainEscalation(_In_z_ LPCWSTR pwszDomainNC)
{
    static const LPCWSTR rgGroups[] = {
        L"Exchange Windows Permissions",
        L"Exchange Trusted Subsystem",
        L"Organization Management",
        L"Exchange Recipient Administrators"
    };
    BYTE   rgSidBuf[ARRAYSIZE(rgGroups)][SECURITY_MAX_SID_SIZE];
    PSID   rgSid[ARRAYSIZE(rgGroups)] = { 0 };
    int    i;

    WCHAR               wszPath[600];
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h  = NULL;
    ADS_SEARCHPREF_INFO prefs[2];
    ADS_SEARCH_COLUMN   col;
    HRESULT             hr;
    DWORD               cHits = 0;
    int                 cResolved = 0;
    LPWSTR rgAttrs[] = { (LPWSTR)L"nTSecurityDescriptor" };

    /* Resolve the Exchange group SIDs (best-effort: they live in the forest root). */
    for (i = 0; i < ARRAYSIZE(rgGroups); i++) {
        DWORD cbSid = SECURITY_MAX_SID_SIZE, cchDom = 0;
        WCHAR wszDom[256]; DWORD cchD = ARRAYSIZE(wszDom);
        SID_NAME_USE use;
        cchDom = cchD;
        if (LookupAccountNameW(NULL, rgGroups[i], rgSidBuf[i], &cbSid, wszDom, &cchDom, &use))
            rgSid[i] = rgSidBuf[i];
    }
    for (i = 0; i < ARRAYSIZE(rgGroups); i++) if (rgSid[i]) cResolved++;
    wprintf(L"  [EXCH-DBG] resolved %d/%d Exchange group SID(s) via LookupAccountName\n",
            cResolved, (int)ARRAYSIZE(rgGroups));

    /* Read the domain object's DACL (DACL-only mask, base scope). */
    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszDomainNC)))
        return;
    if (FAILED(ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pS)))
        return;

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_BASE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_SECURITY_MASK;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = ADS_SECURITY_INFO_DACL;
    pS->lpVtbl->SetSearchPreference(pS, prefs, ARRAYSIZE(prefs));

    hr = pS->lpVtbl->ExecuteSearch(pS, (LPWSTR)L"(objectClass=*)",
            rgAttrs, ARRAYSIZE(rgAttrs), &h);
    if (FAILED(hr)) { pS->lpVtbl->Release(pS); return; }

    if (pS->lpVtbl->GetNextRow(pS, h) == S_OK &&
        pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"nTSecurityDescriptor", &col) == S_OK) {
        wprintf(L"  [EXCH-DBG] domain nTSecurityDescriptor read: type=%lu nvals=%lu\n",
                (unsigned long)col.dwADsType, (unsigned long)col.dwNumValues);
        if (col.dwADsType == ADSTYPE_NT_SECURITY_DESCRIPTOR && col.dwNumValues) {
            PSECURITY_DESCRIPTOR pSD =
                (PSECURITY_DESCRIPTOR)col.pADsValues[0].SecurityDescriptor.lpValue;
            PACL pDacl = 0;
            BOOL bPresent = FALSE, bDefault = FALSE;
            if (pSD && IsValidSecurityDescriptor(pSD) &&
                GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefault) && bPresent && pDacl) {
                WORD a = 0;
                wprintf(L"  [EXCH-DBG] domain DACL present, %u ACE(s) to scan\n",
                        (unsigned)pDacl->AceCount);
                for (a = 0; a < pDacl->AceCount; a++) {
                    ACE_HEADER *pAce = NULL;
                    ACCESS_MASK mask;
                    PSID        pSid;
                    if (!GetAce(pDacl, a, (LPVOID *)&pAce) || !pAce) continue;
                    if (pAce->AceType != ACCESS_ALLOWED_ACE_TYPE &&
                        pAce->AceType != ACCESS_ALLOWED_OBJECT_ACE_TYPE) continue;
                    mask = ((ACCESS_ALLOWED_ACE *)pAce)->Mask;
                    if (!(mask & KESTREL_EXCH_DANGER_MASK)) continue;
                    pSid = _ExchAceSid(pAce);
                    if (!pSid) continue;
                    for (i = 0; i < ARRAYSIZE(rgGroups); i++) {
                        if (rgSid[i] && EqualSid(pSid, rgSid[i])) {
                            LPCWSTR r = (mask & ADS_RIGHT_GENERIC_ALL) ? L"GenericAll"
                                      : (mask & ADS_RIGHT_WRITE_DAC)   ? L"WriteDACL"
                                                                       : L"WriteOwner";
                            wprintf(L"  [EXCH-PRIVESC] \"%s\" holds %s on the domain object "
                                    L"- Exchange-to-Domain-Admin escalation path\n", rgGroups[i], r);
                            KestrelAddFinding(KESTREL_SEV_CRITICAL, L"Exchange", rgGroups[i],
                                L"Exchange group holds WriteDACL/GenericAll on the domain object (privesc to DA via DCSync)",
                                L"apply Exchange split permissions and remove the ACE from the domain root per Microsoft ADV190007 / Trimarc guidance");
                            cHits++;
                            break;
                        }
                    }
                }
            }
        }
        pS->lpVtbl->FreeColumn(pS, &col);
    }

    if (cHits == 0)
        wprintf(L"  [=] Exchange escalation: no Exchange group holds a dangerous right on the "
                L"domain object (or the groups did not resolve)\n");

    if (h) pS->lpVtbl->CloseSearchHandle(pS, h);
    pS->lpVtbl->Release(pS);
}

_Must_inspect_result_
HRESULT
KestrelRunExchangeScan(_In_z_ LPCWSTR pwszConfigNC, _In_z_ LPCWSTR pwszDomainNC)
{
    DWORD cServers;

    wprintf(L"\n[*] Exchange posture (passive - from Active Directory only)\n");

    cServers = _ExchInventory(pwszConfigNC);
    if (cServers == 0)
        return S_OK;   /* no Exchange: inventory already said so */

    _ExchDomainEscalation(pwszDomainNC);

    wprintf(L"\n  [=] %lu Exchange server(s) inventoried from the Configuration NC\n", cServers);
    return S_OK;
}
