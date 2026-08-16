/*
 * KestrelSCCM.c — passive SCCM / MECM posture from AD (v1.1)
 *
 * When an SCCM (Configuration Manager) hierarchy is configured to publish to
 * Active Directory, it extends the schema and writes its infrastructure into a
 * single container:
 *
 *     CN=System Management,CN=System,<domainDN>
 *
 * Everything below is readable by an ordinary domain user, so Kestrel can audit
 * SCCM's exposure without ever touching a site server or a management point.
 *
 * Three passes:
 *
 *   1. Container ACL (the flagship). Site servers legitimately hold Full Control
 *      on this container — that is by design, and it is how you identify them.
 *      The danger is a *non* site-server principal with write / create rights:
 *      a broad group (Authenticated Users, Domain Users, Everyone) or an
 *      unexpected user who can write here can publish rogue SCCM objects and
 *      take over the hierarchy. This is the SCCM analogue of the Exchange
 *      WriteDACL-on-the-domain finding.
 *
 *   2. Management Points (mSSMSManagementPoint) — the servers SCCM clients trust
 *      for policy. Their dNSHostName + site code is an inventory of high-value
 *      targets a defender should know about.
 *
 *   3. Sites (mSSMSSite) — site codes and versions; the shape of the hierarchy.
 *
 * Honest footprint: Kestrel binds the container by its exact DN and scopes the
 * object searches under it — it never runs the noisy domain-wide "*sccm*" /
 * "*mecm*" wildcard search that defenders flag as reconnaissance. It reads the
 * container the way a legitimate SCCM client does. Read-only, ordinary user.
 */

#include "../include/Kestrel.h"

/* Rights on the container that let a principal publish / redirect SCCM. */
#define KESTREL_SCCM_DANGER_MASK \
    (ADS_RIGHT_GENERIC_ALL   | ADS_RIGHT_GENERIC_WRITE | ADS_RIGHT_WRITE_DAC | \
     ADS_RIGHT_WRITE_OWNER   | ADS_RIGHT_DS_CREATE_CHILD | ADS_RIGHT_DS_WRITE_PROP)

/* Broad groups that should never hold write on the container. */
static BOOL
_SccmIsBroadSid(_In_z_ LPCWSTR sid)
{
    size_t len = wcslen(sid);
    if (_wcsicmp(sid, L"S-1-1-0")     == 0) return TRUE;  /* Everyone            */
    if (_wcsicmp(sid, L"S-1-5-11")    == 0) return TRUE;  /* Authenticated Users */
    if (_wcsicmp(sid, L"S-1-5-32-545")== 0) return TRUE;  /* BUILTIN\Users       */
    if (len > 4 &&
        (_wcsicmp(sid + len - 4, L"-513") == 0 ||         /* Domain Users        */
         _wcsicmp(sid + len - 4, L"-515") == 0))          /* Domain Computers    */
        return TRUE;
    return FALSE;
}

/* Principals that legitimately hold rights here (site servers are computer
 * accounts, handled separately by SID class, not by name). */
static BOOL
_SccmIsDefaultAdmin(_In_z_ LPCWSTR sid)
{
    size_t len = wcslen(sid);
    if (_wcsicmp(sid, L"S-1-5-18")     == 0) return TRUE; /* SYSTEM         */
    if (_wcsicmp(sid, L"S-1-5-32-544") == 0) return TRUE; /* Administrators */
    if (len > 4 &&
        (_wcsicmp(sid + len - 4, L"-512") == 0 ||         /* Domain Admins     */
         _wcsicmp(sid + len - 4, L"-519") == 0 ||         /* Enterprise Admins */
         _wcsicmp(sid + len - 4, L"-516") == 0 ||         /* Domain Controllers*/
         _wcsicmp(sid + len - 4, L"-518") == 0))          /* Schema Admins     */
        return TRUE;
    return FALSE;
}

static PSID
_SccmAceSid(_In_ ACE_HEADER *pAce)
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

/* Pass 1 — the container's own DACL. */
static VOID
_SccmContainerAcl(_In_z_ LPCWSTR pwszContainer)
{
    WCHAR               wszPath[700];
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h  = NULL;
    ADS_SEARCHPREF_INFO prefs[2];
    ADS_SEARCH_COLUMN   col;
    HRESULT             hr;
    DWORD               cSiteServers = 0, cDanger = 0;
    LPWSTR rgAttrs[] = { (LPWSTR)L"nTSecurityDescriptor" };

    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszContainer)))
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
        if (col.dwADsType == ADSTYPE_NT_SECURITY_DESCRIPTOR && col.dwNumValues) {
            PSECURITY_DESCRIPTOR pSD =
                (PSECURITY_DESCRIPTOR)col.pADsValues[0].SecurityDescriptor.lpValue;
            PACL pDacl = NULL;
            BOOL bPresent = FALSE, bDefault = FALSE;
            if (pSD && IsValidSecurityDescriptor(pSD) &&
                GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefault) && bPresent && pDacl) {
                WORD a;
                for (a = 0; a < pDacl->AceCount; a++) {
                    ACE_HEADER *pAce = NULL;
                    ACCESS_MASK mask;
                    PSID        pSid;
                    LPWSTR      s = NULL;
                    if (!GetAce(pDacl, a, (LPVOID *)&pAce) || !pAce) continue;
                    if (pAce->AceType != ACCESS_ALLOWED_ACE_TYPE &&
                        pAce->AceType != ACCESS_ALLOWED_OBJECT_ACE_TYPE) continue;
                    mask = ((ACCESS_ALLOWED_ACE *)pAce)->Mask;
                    if (!(mask & KESTREL_SCCM_DANGER_MASK)) continue;
                    pSid = _SccmAceSid(pAce);
                    if (!pSid || !IsValidSid(pSid) || !ConvertSidToStringSidW(pSid, &s) || !s)
                        continue;

                    if (_SccmIsBroadSid(s)) {
                        WCHAR nm[256] = L"", dm[256] = L"";
                        DWORD cn = ARRAYSIZE(nm), cd = ARRAYSIZE(dm);
                        SID_NAME_USE use;
                        LookupAccountSidW(NULL, pSid, nm, &cn, dm, &cd, &use);
                        cDanger++;
                        wprintf(L"  [SCCM-ACL] broad principal %s can write to the System Management "
                                L"container - anyone in it can take over SCCM publishing\n",
                                nm[0] ? nm : s);
                        KestrelAddFinding(KESTREL_SEV_CRITICAL, L"SCCM",
                            nm[0] ? nm : s,
                            L"a broad group holds write/create on the System Management container (SCCM hierarchy takeover)",
                            L"remove the broad ACE; only site server computer accounts and admins should have write on the container");
                    }
                    else if (!_SccmIsDefaultAdmin(s)) {
                        WCHAR nm[256] = L"", dm[256] = L"";
                        DWORD cn = ARRAYSIZE(nm), cd = ARRAYSIZE(dm);
                        SID_NAME_USE use;
                        BOOL bComputer;
                        LookupAccountSidW(NULL, pSid, nm, &cn, dm, &cd, &use);
                        bComputer = (use == SidTypeComputer) ||
                                    (nm[0] && nm[wcslen(nm) - 1] == L'$');
                        if (bComputer) {
                            cSiteServers++;
                            wprintf(L"  [SCCM] site server: %s (Full Control on container)\n",
                                    nm[0] ? nm : s);
                        } else {
                            cDanger++;
                            wprintf(L"  [SCCM-ACL] non-site-server principal %s holds write on the "
                                    L"System Management container\n", nm[0] ? nm : s);
                            KestrelAddFinding(KESTREL_SEV_HIGH, L"SCCM",
                                nm[0] ? nm : s,
                                L"a non-site-server principal can write to the System Management container",
                                L"remove the ACE unless this is a verified site server; write here allows SCCM takeover");
                        }
                    }
                    LocalFree(s);
                }
            }
        }
        pS->lpVtbl->FreeColumn(pS, &col);
    }

    wprintf(L"  [=] %lu site server(s) identified via container Full Control, %lu risky ACE(s)\n",
            cSiteServers, cDanger);

    if (h) pS->lpVtbl->CloseSearchHandle(pS, h);
    pS->lpVtbl->Release(pS);
}

/* Passes 2 & 3 — enumerate published child objects under the container. */
static DWORD
_SccmEnumClass(_In_z_ LPCWSTR pwszContainer, _In_z_ LPCWSTR pwszFilter,
               _In_z_ LPCWSTR pwszLabel)
{
    WCHAR               wszPath[700];
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h  = NULL;
    ADS_SEARCHPREF_INFO prefs[2];
    HRESULT             hr;
    DWORD               cFound = 0;
    LPWSTR rgAttrs[] = {
        (LPWSTR)L"dNSHostName", (LPWSTR)L"mSSMSSiteCode",
        (LPWSTR)L"mSSMSMPName", (LPWSTR)L"mSSMSVersion", (LPWSTR)L"cn"
    };

    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszContainer)))
        return 0;
    if (FAILED(ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pS)))
        return 0;

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pS->lpVtbl->SetSearchPreference(pS, prefs, ARRAYSIZE(prefs));

    hr = pS->lpVtbl->ExecuteSearch(pS, (LPWSTR)pwszFilter, rgAttrs, ARRAYSIZE(rgAttrs), &h);
    if (FAILED(hr)) { pS->lpVtbl->Release(pS); return 0; }

    for (;;) {
        ADS_SEARCH_COLUMN col;
        WCHAR wszDns[300] = L"", wszSite[64] = L"", wszVer[64] = L"", wszCn[128] = L"";

        hr = pS->lpVtbl->GetNextRow(pS, h);
        if (hr == S_ADS_NOMORE_ROWS) break;
        if (FAILED(hr)) break;

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"dNSHostName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszDns, ARRAYSIZE(wszDns), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"mSSMSSiteCode", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszSite, ARRAYSIZE(wszSite), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"mSSMSVersion", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszVer, ARRAYSIZE(wszVer), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"cn", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszCn, ARRAYSIZE(wszCn), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }

        cFound++;
        wprintf(L"  [SCCM] %s: %s%s%s%s%s\n",
            pwszLabel,
            wszDns[0] ? wszDns : (wszCn[0] ? wszCn : L"(object)"),
            wszSite[0] ? L"  site=" : L"", wszSite[0] ? wszSite : L"",
            wszVer[0]  ? L"  version=" : L"", wszVer[0] ? wszVer : L"");
    }

    if (h) pS->lpVtbl->CloseSearchHandle(pS, h);
    pS->lpVtbl->Release(pS);
    return cFound;
}

_Must_inspect_result_
HRESULT
KestrelRunSccmScan(_In_z_ LPCWSTR pwszDomainNC)
{
    WCHAR             wszContainer[700];
    WCHAR             wszTest[720];
    IADs             *pTest = NULL;
    HRESULT           hr;
    DWORD             cMP, cSite;

    if (!pwszDomainNC) return E_INVALIDARG;

    wprintf(L"\n[*] SCCM / MECM posture (passive - from Active Directory only)\n");

    /* Exact-DN bind to the container - no noisy wildcard recon. */
    if (FAILED(StringCchPrintfW(wszContainer, ARRAYSIZE(wszContainer),
            L"CN=System Management,CN=System,%s", pwszDomainNC)))
        return E_FAIL;
    if (FAILED(StringCchPrintfW(wszTest, ARRAYSIZE(wszTest), L"LDAP://%s", wszContainer)))
        return E_FAIL;

    hr = ADsGetObject(wszTest, &IID_IADs, (void **)&pTest);
    if (FAILED(hr)) {
        wprintf(L"  [=] No System Management container - SCCM AD publishing is not enabled "
                L"(or SCCM is not deployed)\n");
        return S_OK;
    }
    pTest->lpVtbl->Release(pTest);

    _SccmContainerAcl(wszContainer);
    cMP   = _SccmEnumClass(wszContainer, L"(objectClass=mSSMSManagementPoint)", L"management point");
    cSite = _SccmEnumClass(wszContainer, L"(objectClass=mSSMSSite)", L"site");

    wprintf(L"\n  [=] SCCM published to AD: %lu management point(s), %lu site(s)\n", cMP, cSite);
    return S_OK;
}
