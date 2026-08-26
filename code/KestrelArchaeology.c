/*
 * KestrelArchaeology.c — dead owners, live rights (v1.2)
 *
 * Active Directory is a decade-old sediment. Services get uninstalled, admins
 * leave, domains get migrated — but the *rights* they were granted are almost
 * never cleaned up. When you delete a principal, Windows removes the object; it
 * does NOT walk the domain removing that principal's SID from every ACL it sat
 * in. The permission outlives the account.
 *
 * That leftover is self-proving from AD alone, which is what makes it a clean
 * passive check: an ACE whose trustee SID no longer resolves to any name is,
 * by definition, a right held by a deleted principal. No host to query, no
 * service to touch — the directory already contains the proof.
 *
 * Two passes:
 *
 *   1. Orphaned dangerous ACE (flagship). Walk the DACLs of the highest-value
 *      objects (the domain head and the AdminSDHolder object) and flag any ACE
 *      that grants a dangerous right (WriteDACL / GenericAll / WriteOwner /
 *      WriteProperty / control-access / CreateChild) to a SID that no longer
 *      resolves. "Your Exchange is gone. Its WriteDACL on the domain is still
 *      there." — and a fresh account that lands on a reused RID inherits it.
 *
 *   2. Stale privileged accounts. Enabled members of privileged groups whose
 *      password has not changed in a long time (default 180 days) — the
 *      forgotten service accounts that botnets harvest for quiet persistence.
 *      pwdLastSet is read passively; the threshold is deliberately conservative
 *      to avoid flagging legitimate seasonal-cadence workloads.
 *
 * Read-only, ordinary domain user, on-prem.
 */

#include "../include/Kestrel.h"
#include <sddl.h>

/* Rights that matter when held by a dead principal. */
#define KESTREL_ARCH_DANGER_MASK \
    (ADS_RIGHT_GENERIC_ALL | WRITE_DAC | WRITE_OWNER | ADS_RIGHT_DS_WRITE_PROP | \
     ADS_RIGHT_DS_CONTROL_ACCESS | ADS_RIGHT_DS_CREATE_CHILD)

/* Stale threshold: a privileged account whose password is older than this many
   days is very likely forgotten. Conservative on purpose. */
#define KESTREL_ARCH_STALE_DAYS 180

static PSID
_ArchAceSid(_In_ ACE_HEADER *pAce)
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

/* A SID is "domain-local orphaned" only if it belongs to THIS domain and no
   longer resolves. A non-resolving SID from another domain/forest is not proof
   of deletion (its DC may just be unreachable), so we require the domain SID
   prefix to match before calling it orphaned. */
static BOOL
_ArchIsOrphanedSid(_In_ PSID pSid, _In_z_ LPCWSTR pwszDomainSidPrefix)
{
    WCHAR        nm[256], dm[256];
    DWORD        cn = ARRAYSIZE(nm), cd = ARRAYSIZE(dm);
    SID_NAME_USE use;
    LPWSTR       s = NULL;
    BOOL         bOrphan;

    if (LookupAccountSidW(NULL, pSid, nm, &cn, dm, &cd, &use))
        return FALSE;   /* resolves -> alive */

    /* Does not resolve. Confirm it is one of OUR domain's SIDs before trusting
       that as deletion (S-1-5-21-<domain>-<rid>). */
    if (!ConvertSidToStringSidW(pSid, &s) || !s)
        return FALSE;
    bOrphan = (pwszDomainSidPrefix[0] &&
               _wcsnicmp(s, pwszDomainSidPrefix, wcslen(pwszDomainSidPrefix)) == 0);
    LocalFree(s);
    return bOrphan;
}

/* Fetch the domain SID prefix ("S-1-5-21-a-b-c") from the domain object. */
static VOID
_ArchDomainSidPrefix(_In_z_ LPCWSTR pwszDomainNC, _Out_writes_z_(cch) LPWSTR out, _In_ SIZE_T cch)
{
    WCHAR   wszPath[600];
    IADs   *pDom = NULL;
    VARIANT v;
    BSTR    attr;

    out[0] = L'\0';
    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszDomainNC)))
        return;
    if (FAILED(ADsGetObject(wszPath, &IID_IADs, (void **)&pDom)))
        return;

    VariantInit(&v);
    attr = SysAllocString(L"objectSid");
    if (SUCCEEDED(pDom->lpVtbl->Get(pDom, attr, &v)) &&
        (v.vt & VT_ARRAY) && v.parray) {
        /* objectSid comes back as a SAFEARRAY of bytes; convert to string SID. */
        void *pv = NULL;
        if (SUCCEEDED(SafeArrayAccessData(v.parray, &pv)) && pv) {
            LPWSTR s = NULL;
            if (IsValidSid((PSID)pv) && ConvertSidToStringSidW((PSID)pv, &s) && s) {
                StringCchCopyW(out, cch, s);   /* full domain SID, e.g. S-1-5-21-a-b-c */
                LocalFree(s);
            }
            SafeArrayUnaccessData(v.parray);
        }
    }
    SysFreeString(attr);
    VariantClear(&v);
    pDom->lpVtbl->Release(pDom);
}

/* Pass 1 — walk one object's DACL for dangerous ACEs held by orphaned SIDs. */
static VOID
_ArchObjectAcl(_In_z_ LPCWSTR pwszDN, _In_z_ LPCWSTR pwszLabel,
               _In_z_ LPCWSTR pwszDomainSidPrefix, _Inout_ DWORD *pcHits)
{
    WCHAR               wszPath[700];
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h  = NULL;
    ADS_SEARCHPREF_INFO prefs[2];
    ADS_SEARCH_COLUMN   col;
    HRESULT             hr;
    LPWSTR rgAttrs[] = { (LPWSTR)L"nTSecurityDescriptor" };

    if (FAILED(StringCchPrintfW(wszPath, ARRAYSIZE(wszPath), L"LDAP://%s", pwszDN)))
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
                    if (!GetAce(pDacl, a, (LPVOID *)&pAce) || !pAce) continue;
                    if (pAce->AceType != ACCESS_ALLOWED_ACE_TYPE &&
                        pAce->AceType != ACCESS_ALLOWED_OBJECT_ACE_TYPE) continue;
                    mask = ((ACCESS_ALLOWED_ACE *)pAce)->Mask;
                    if (!(mask & KESTREL_ARCH_DANGER_MASK)) continue;
                    pSid = _ArchAceSid(pAce);
                    if (!pSid || !IsValidSid(pSid)) continue;
                    if (_ArchIsOrphanedSid(pSid, pwszDomainSidPrefix)) {
                        LPWSTR s = NULL;
                        ConvertSidToStringSidW(pSid, &s);
                        wprintf(L"  [ARCH-ACE] %s: dangerous right held by a DELETED principal %s "
                                L"- the permission outlived its owner\n",
                                pwszLabel, s ? s : L"(orphaned SID)");
                        KestrelAddFinding(KESTREL_SEV_CRITICAL, L"Archaeology", pwszLabel,
                            L"a deleted principal still holds a dangerous right (orphaned ACE); a reused RID inherits it",
                            L"remove the orphaned ACE; audit how the principal was deleted without cleaning its ACLs");
                        if (s) LocalFree(s);
                        (*pcHits)++;
                    }
                }
            }
        }
        pS->lpVtbl->FreeColumn(pS, &col);
    }

    if (h) pS->lpVtbl->CloseSearchHandle(pS, h);
    pS->lpVtbl->Release(pS);
}

/* Pass 2 — enabled, privileged, password not changed in a long time. */
static VOID
_ArchStalePrivileged(_In_z_ LPCWSTR pwszDomainNC, _Inout_ DWORD *pcStale)
{
    WCHAR               wszRoot[600];
    IDirectorySearch   *pS = NULL;
    ADS_SEARCH_HANDLE   h  = NULL;
    ADS_SEARCHPREF_INFO prefs[2];
    HRESULT             hr;
    LPWSTR rgAttrs[] = { (LPWSTR)L"sAMAccountName", (LPWSTR)L"pwdLastSet",
                         (LPWSTR)L"userAccountControl" };

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

    /* Privileged = adminCount stamped; enabled = not disabled. */
    hr = pS->lpVtbl->ExecuteSearch(pS,
            (LPWSTR)L"(&(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            rgAttrs, ARRAYSIZE(rgAttrs), &h);
    if (FAILED(hr)) { pS->lpVtbl->Release(pS); return; }

    for (;;) {
        ADS_SEARCH_COLUMN col;
        WCHAR    wszSam[128] = L"";
        LONGLONG llPwd = 0;
        LONG     ageDays;

        hr = pS->lpVtbl->GetNextRow(pS, h);
        if (hr == S_ADS_NOMORE_ROWS) break;
        if (FAILED(hr)) break;

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"sAMAccountName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszSam, ARRAYSIZE(wszSam), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"pwdLastSet", &col))) {
            if (col.dwADsType == ADSTYPE_LARGE_INTEGER && col.dwNumValues)
                llPwd = col.pADsValues[0].LargeInteger.QuadPart;
            pS->lpVtbl->FreeColumn(pS, &col);
        }

        ageDays = -1;
        if (llPwd > 0) {   /* compute age with the shared per-day constant */
            FILETIME  ftNow; ULONGLONG now, val;
            GetSystemTimeAsFileTime(&ftNow);
            now = ((ULONGLONG)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;
            val = (ULONGLONG)llPwd;
            ageDays = (val >= now) ? 0 : (LONG)((now - val) / KESTREL_FT_PER_DAY);
        }

        if (ageDays >= KESTREL_ARCH_STALE_DAYS) {
            wprintf(L"  [ARCH-STALE] %s: privileged, enabled, password unchanged for %ld days "
                    L"- forgotten account, standing privilege\n",
                    wszSam[0] ? wszSam : L"(account)", ageDays);
            KestrelAddFinding(KESTREL_SEV_HIGH, L"Archaeology",
                wszSam[0] ? wszSam : L"(account)",
                L"privileged account with a very old password (likely forgotten; standing privilege, weak credential)",
                L"confirm ownership and need; rotate the password or disable/remove the account");
            (*pcStale)++;
        }
    }

    if (h) pS->lpVtbl->CloseSearchHandle(pS, h);
    pS->lpVtbl->Release(pS);
}

_Must_inspect_result_
HRESULT
KestrelRunArchaeologyScan(_In_z_ LPCWSTR pwszDomainNC)
{
    WCHAR wszAdminSDH[700];
    WCHAR wszDomainSid[128] = L"";
    DWORD cHits = 0, cStale = 0;

    if (!pwszDomainNC) return E_INVALIDARG;

    wprintf(L"\n[*] AD archaeology - dead owners, live rights (passive - from AD only)\n");

    _ArchDomainSidPrefix(pwszDomainNC, wszDomainSid, ARRAYSIZE(wszDomainSid));

    /* Pass 1: highest-value objects first. */
    _ArchObjectAcl(pwszDomainNC, L"domain head", wszDomainSid, &cHits);
    if (SUCCEEDED(StringCchPrintfW(wszAdminSDH, ARRAYSIZE(wszAdminSDH),
            L"CN=AdminSDHolder,CN=System,%s", pwszDomainNC)))
        _ArchObjectAcl(wszAdminSDH, L"AdminSDHolder", wszDomainSid, &cHits);

    /* Pass 2: stale privileged accounts. */
    _ArchStalePrivileged(pwszDomainNC, &cStale);

    wprintf(L"\n  [=] archaeology: %lu orphaned dangerous ACE(s), %lu stale privileged account(s)\n",
            cHits, cStale);
    if (cHits == 0 && cStale == 0)
        wprintf(L"  [=] no orphaned rights or forgotten privileged accounts on the checked objects\n");
    return S_OK;
}
