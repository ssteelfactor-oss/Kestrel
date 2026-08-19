/*
 * KestrelDNS.c — passive AD-integrated DNS (ADIDNS) posture from AD (v1.1)
 *
 * When DNS is AD-integrated, its zones and records live in the directory:
 *
 *     CN=MicrosoftDNS,DC=DomainDnsZones,<domainDN>     (modern, per-domain)
 *     CN=MicrosoftDNS,DC=ForestDnsZones,<forestDN>     (forest-wide)
 *     CN=MicrosoftDNS,CN=System,<domainDN>             (legacy)
 *
 * Zones are dnsZone objects, records are dnsNode objects — all readable by an
 * ordinary domain user. That means the single most common DNS misconfiguration
 * in Active Directory is visible without touching the DNS service at all:
 *
 *   The default ADIDNS zone DACL grants Authenticated Users the CreateChild
 *   right, so *any* domain account can inject DNS records. Combined with a
 *   wildcard or WPAD record it becomes domain-wide traffic hijacking / MITM.
 *   This ACL is rarely reviewed; it survives migrations untouched.
 *
 * Three passes, all passive:
 *
 *   1. Zone DACL (flagship). Flag zones where a broad principal (Authenticated
 *      Users, Everyone, Domain Users) holds CreateChild — the ADIDNS-poisoning
 *      precondition.
 *   2. Dangerous records already present: a wildcard (*), wpad, or isatap
 *      dnsNode — a catch-all or classic poisoning target sitting in the zone.
 *   3. DnsAdmins membership. DnsAdmins can load an arbitrary DLL on a DC
 *      (ServerLevelPluginDll) → SYSTEM on the DC → domain compromise. Treat it
 *      as Tier-0; its members are rarely monitored the way Domain Admins are.
 *
 * Read-only, ordinary domain user, on-prem.
 */

#include "../include/Kestrel.h"

/* Broad principals that must not be able to create records in a zone. */
static BOOL
_DnsIsBroadSid(_In_z_ LPCWSTR sid)
{
    size_t len = wcslen(sid);
    if (_wcsicmp(sid, L"S-1-1-0")      == 0) return TRUE;  /* Everyone            */
    if (_wcsicmp(sid, L"S-1-5-11")     == 0) return TRUE;  /* Authenticated Users */
    if (_wcsicmp(sid, L"S-1-5-32-545") == 0) return TRUE;  /* BUILTIN\Users       */
    if (len > 4 &&
        (_wcsicmp(sid + len - 4, L"-513") == 0 ||          /* Domain Users        */
         _wcsicmp(sid + len - 4, L"-515") == 0))           /* Domain Computers    */
        return TRUE;
    return FALSE;
}

static PSID
_DnsAceSid(_In_ ACE_HEADER *pAce)
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

/* Does this zone's DACL let a broad principal create records? */
static BOOL
_DnsZoneBroadCreate(_In_ PSECURITY_DESCRIPTOR pSD, _Out_writes_z_(cch) LPWSTR whoOut, _In_ SIZE_T cch)
{
    PACL pDacl = NULL;
    BOOL bPresent = FALSE, bDefault = FALSE;
    WORD a;

    whoOut[0] = L'\0';
    if (!pSD || !IsValidSecurityDescriptor(pSD)) return FALSE;
    if (!GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefault) || !bPresent || !pDacl)
        return FALSE;

    for (a = 0; a < pDacl->AceCount; a++) {
        ACE_HEADER *pAce = NULL;
        ACCESS_MASK mask;
        PSID        pSid;
        LPWSTR      s = NULL;
        if (!GetAce(pDacl, a, (LPVOID *)&pAce) || !pAce) continue;
        if (pAce->AceType != ACCESS_ALLOWED_ACE_TYPE &&
            pAce->AceType != ACCESS_ALLOWED_OBJECT_ACE_TYPE) continue;
        mask = ((ACCESS_ALLOWED_ACE *)pAce)->Mask;
        if (!(mask & (ADS_RIGHT_DS_CREATE_CHILD | ADS_RIGHT_GENERIC_ALL | ADS_RIGHT_GENERIC_WRITE)))
            continue;
        pSid = _DnsAceSid(pAce);
        if (!pSid || !IsValidSid(pSid) || !ConvertSidToStringSidW(pSid, &s) || !s) continue;
        if (_DnsIsBroadSid(s)) {
            WCHAR nm[256] = L"", dm[256] = L"";
            DWORD cn = ARRAYSIZE(nm), cd = ARRAYSIZE(dm);
            SID_NAME_USE use;
            LookupAccountSidW(NULL, pSid, nm, &cn, dm, &cd, &use);
            StringCchCopyW(whoOut, cch, nm[0] ? nm : s);
            LocalFree(s);
            return TRUE;
        }
        LocalFree(s);
    }
    return FALSE;
}

/* Pass 1 — enumerate zones under a MicrosoftDNS container and check each DACL. */
static DWORD
_DnsZones(_In_z_ LPCWSTR pwszContainer, _Inout_ DWORD *pcRisky)
{
    WCHAR               wszPath[720];
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h  = NULL;
    ADS_SEARCHPREF_INFO prefs[3];
    HRESULT             hr;
    DWORD               cZones = 0;
    LPWSTR rgAttrs[] = { (LPWSTR)L"name", (LPWSTR)L"nTSecurityDescriptor" };

    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszContainer)))
        return 0;
    if (FAILED(ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pS)))
        return 0;   /* container absent — caller tries the next path */

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    prefs[2].dwSearchPref   = ADS_SEARCHPREF_SECURITY_MASK;
    prefs[2].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[2].vValue.Integer = ADS_SECURITY_INFO_DACL;
    pS->lpVtbl->SetSearchPreference(pS, prefs, ARRAYSIZE(prefs));

    hr = pS->lpVtbl->ExecuteSearch(pS, (LPWSTR)L"(objectClass=dnsZone)",
            rgAttrs, ARRAYSIZE(rgAttrs), &h);
    if (FAILED(hr)) { pS->lpVtbl->Release(pS); return 0; }

    for (;;) {
        ADS_SEARCH_COLUMN col;
        WCHAR wszZone[256] = L"", wszWho[256] = L"";
        BOOL  bBroad = FALSE;

        hr = pS->lpVtbl->GetNextRow(pS, h);
        if (hr == S_ADS_NOMORE_ROWS) break;
        if (FAILED(hr)) break;

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"name", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszZone, ARRAYSIZE(wszZone), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"nTSecurityDescriptor", &col))) {
            if (col.dwADsType == ADSTYPE_NT_SECURITY_DESCRIPTOR && col.dwNumValues)
                bBroad = _DnsZoneBroadCreate(
                    (PSECURITY_DESCRIPTOR)col.pADsValues[0].SecurityDescriptor.lpValue,
                    wszWho, ARRAYSIZE(wszWho));
            pS->lpVtbl->FreeColumn(pS, &col);
        }

        cZones++;
        if (bBroad) {
            (*pcRisky)++;
            wprintf(L"  [DNS-ACL] zone \"%s\": %s can create records - ADIDNS injection / "
                    L"spoofing possible by any such principal\n",
                    wszZone[0] ? wszZone : L"(zone)", wszWho);
            KestrelAddFinding(KESTREL_SEV_CRITICAL, L"DNS",
                wszZone[0] ? wszZone : L"(zone)",
                L"a broad principal holds CreateChild on the DNS zone (ADIDNS poisoning / traffic hijack)",
                L"restrict the zone DACL to DNSAdmins and Domain Controllers; remove CreateChild from Authenticated Users");
        } else if (wszZone[0]) {
            wprintf(L"  [DNS] zone: %s\n", wszZone);
        }
    }

    if (h) pS->lpVtbl->CloseSearchHandle(pS, h);
    pS->lpVtbl->Release(pS);
    return cZones;
}

/* Pass 2 — dangerous records already present (wildcard / wpad / isatap). */
static VOID
_DnsDangerRecords(_In_z_ LPCWSTR pwszContainer)
{
    WCHAR               wszPath[720];
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h  = NULL;
    ADS_SEARCHPREF_INFO prefs[2];
    HRESULT             hr;
    LPWSTR rgAttrs[] = { (LPWSTR)L"name", (LPWSTR)L"distinguishedName" };

    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszContainer)))
        return;
    if (FAILED(ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pS)))
        return;

    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pS->lpVtbl->SetSearchPreference(pS, prefs, ARRAYSIZE(prefs));

    /* '*' is escaped as \2a in an LDAP filter. */
    hr = pS->lpVtbl->ExecuteSearch(pS,
            (LPWSTR)L"(&(objectClass=dnsNode)(|(name=\\2a)(name=wpad)(name=isatap)))",
            rgAttrs, ARRAYSIZE(rgAttrs), &h);
    if (FAILED(hr)) { pS->lpVtbl->Release(pS); return; }

    for (;;) {
        ADS_SEARCH_COLUMN col;
        WCHAR wszName[128] = L"";

        hr = pS->lpVtbl->GetNextRow(pS, h);
        if (hr == S_ADS_NOMORE_ROWS) break;
        if (FAILED(hr)) break;

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"name", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszName, ARRAYSIZE(wszName), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (!wszName[0]) continue;

        wprintf(L"  [DNS-REC] dangerous record present: \"%s\" - %s\n", wszName,
            (wcscmp(wszName, L"*") == 0) ? L"wildcard catch-all (MITM if attacker-owned)"
          : (_wcsicmp(wszName, L"wpad") == 0) ? L"WPAD (proxy auto-config hijack target)"
          : L"ISATAP (tunnel host hijack target)");
        KestrelAddFinding(KESTREL_SEV_HIGH, L"DNS", wszName,
            L"high-risk DNS record present in an AD-integrated zone (wildcard / WPAD / ISATAP)",
            L"verify the record is a deliberate benign block; otherwise remove it and add wpad/isatap to the Global Query Block List");
    }

    if (h) pS->lpVtbl->CloseSearchHandle(pS, h);
    pS->lpVtbl->Release(pS);
}

/* Pass 3 — DnsAdmins membership (Tier-0: DLL load on a DC). */
static VOID
_DnsAdmins(_In_z_ LPCWSTR pwszDomainNC)
{
    WCHAR               wszRoot[600];
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h  = NULL;
    ADS_SEARCHPREF_INFO prefs[2];
    ADS_SEARCH_COLUMN   col;
    HRESULT             hr;
    DWORD               cMembers = 0;
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

    hr = pS->lpVtbl->ExecuteSearch(pS, (LPWSTR)L"(&(objectClass=group)(cn=DnsAdmins))",
            rgAttrs, ARRAYSIZE(rgAttrs), &h);
    if (FAILED(hr)) { pS->lpVtbl->Release(pS); return; }

    if (pS->lpVtbl->GetNextRow(pS, h) == S_OK &&
        pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"member", &col) == S_OK) {
        if (col.dwADsType == ADSTYPE_DN_STRING) {
            DWORD v;
            for (v = 0; v < col.dwNumValues; v++) {
                wprintf(L"  [DNS-ADMIN] DnsAdmins member: %s\n", col.pADsValues[v].DNString);
                cMembers++;
            }
        }
        pS->lpVtbl->FreeColumn(pS, &col);
    }

    if (cMembers > 0)
        KestrelAddFinding(KESTREL_SEV_HIGH, L"DNS", L"DnsAdmins",
            L"DnsAdmins has members; the group can load a DLL on a DC (ServerLevelPluginDll) = SYSTEM on the DC",
            L"treat DnsAdmins as Tier-0: minimise membership, use dedicated admin accounts, and monitor DNS service restarts / ServerLevelPluginDll");

    if (h) pS->lpVtbl->CloseSearchHandle(pS, h);
    pS->lpVtbl->Release(pS);
}


/* Forest-root DN from RootDSE, for the forest-wide ForestDnsZones partition.
 * Falls back to the domain NC on failure (correct in a single-domain forest). */
static VOID
_DnsForestRootDN(_In_z_ LPCWSTR pwszDomainNC, _Out_writes_z_(cch) LPWSTR out, _In_ SIZE_T cch)
{
    IADs   *pRoot = NULL;
    VARIANT v;
    BSTR    attr;

    StringCchCopyW(out, cch, pwszDomainNC);   /* safe default */

    if (FAILED(ADsGetObject(L"LDAP://RootDSE", &IID_IADs, (void **)&pRoot)))
        return;
    VariantInit(&v);
    attr = SysAllocString(L"rootDomainNamingContext");
    if (SUCCEEDED(pRoot->lpVtbl->Get(pRoot, attr, &v)) && v.vt == VT_BSTR && v.bstrVal)
        StringCchCopyW(out, cch, v.bstrVal);
    SysFreeString(attr);
    VariantClear(&v);
    pRoot->lpVtbl->Release(pRoot);
}

_Must_inspect_result_
HRESULT
KestrelRunDnsScan(_In_z_ LPCWSTR pwszDomainNC)
{
    WCHAR wszC1[700], wszC2[700], wszC3[700], wszForest[512];
    DWORD cZones = 0, cRisky = 0;

    if (!pwszDomainNC) return E_INVALIDARG;

    wprintf(L"\n[*] AD-integrated DNS (ADIDNS) posture (passive - from Active Directory only)\n");

    _DnsForestRootDN(pwszDomainNC, wszForest, ARRAYSIZE(wszForest));

    /* Domain application partition, forest-wide partition (_msdcs etc.), and the
       legacy System location. In a single-domain forest wszForest == domain NC. */
    StringCchPrintfW(wszC1, ARRAYSIZE(wszC1), L"CN=MicrosoftDNS,DC=DomainDnsZones,%s", pwszDomainNC);
    StringCchPrintfW(wszC2, ARRAYSIZE(wszC2), L"CN=MicrosoftDNS,CN=System,%s", pwszDomainNC);
    StringCchPrintfW(wszC3, ARRAYSIZE(wszC3), L"CN=MicrosoftDNS,DC=ForestDnsZones,%s", wszForest);

    cZones += _DnsZones(wszC1, &cRisky);
    cZones += _DnsZones(wszC2, &cRisky);
    if (_wcsicmp(wszForest, pwszDomainNC) != 0)   /* skip duplicate in single-domain forest */
        cZones += _DnsZones(wszC3, &cRisky);

    if (cZones == 0) {
        wprintf(L"  [=] No AD-integrated DNS zones found (DNS may be file-backed or on another partition)\n");
        return S_OK;
    }

    _DnsDangerRecords(wszC1);
    _DnsDangerRecords(wszC2);
    if (_wcsicmp(wszForest, pwszDomainNC) != 0)
        _DnsDangerRecords(wszC3);
    _DnsAdmins(pwszDomainNC);

    wprintf(L"\n  [=] %lu AD-integrated DNS zone(s), %lu with broad record-creation rights\n",
            cZones, cRisky);
    if (cRisky == 0)
        wprintf(L"  [=] No zone grants record creation to a broad principal\n");
    return S_OK;
}
