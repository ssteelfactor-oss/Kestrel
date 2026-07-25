/*
 * KestrelSchemaAudit.c — schema defaultSecurityDescriptor audit (v0.15)
 *
 * Every classSchema object carries a defaultSecurityDescriptor (SDDL) that is
 * stamped onto the DACL of every NEW object of that class. Editing it is a quiet,
 * domain-wide, forward-looking backdoor: grant yourself control in, say, the
 * `user` or `computer` class default, and every account created afterwards is
 * born owned/controllable — with no ACE on any existing object to find.
 *
 * Rather than diff against a per-Windows-version baseline (brittle), Kestrel
 * parses each class's defaultSecurityDescriptor and flags the actual attack: an
 * ACE that grants a dangerous right to a low-privilege principal (Everyone /
 * Authenticated Users / Domain Users / Users). Flagged classes get
 * defaultSecurityDescriptor provenance (when it changed, from which DSA).
 *
 * Read-only, ordinary user: one rootDSE read + one classSchema enumeration in
 * the Schema NC.
 */

#include "../include/Kestrel.h"
#include <sddl.h>

/* dangerous rights: full/write control, or object-level write/extended/create */
#define KESTREL_SCHEMA_DANGEROUS \
    (GENERIC_ALL | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER | \
     ADS_RIGHT_DS_WRITE_PROP | ADS_RIGHT_DS_CONTROL_ACCESS | ADS_RIGHT_DS_CREATE_CHILD)

static BOOL
_IsLowPrivSid(_In_opt_z_ LPCWSTR sid)
{
    LPCWSTR r;
    if (!sid || !sid[0]) return FALSE;
    if (_wcsicmp(sid, L"S-1-1-0")      == 0) return TRUE;  /* Everyone */
    if (_wcsicmp(sid, L"S-1-5-11")     == 0) return TRUE;  /* Authenticated Users */
    if (_wcsicmp(sid, L"S-1-5-32-545") == 0) return TRUE;  /* BUILTIN\Users */
    r = wcsrchr(sid, L'-');
    if (r && _wcsicmp(r + 1, L"513") == 0) return TRUE;    /* Domain Users */
    return FALSE;
}

static PSID
_AceSid(_In_ ACE_HEADER *pAce)
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

/* Parse one defaultSecurityDescriptor SDDL; return TRUE + print if it grants a
 * dangerous right to a low-priv principal. */
static BOOL
_SddlGrantsLowPriv(_In_z_ LPCWSTR pwszSddl, _In_z_ LPCWSTR pwszClass)
{
    PSECURITY_DESCRIPTOR pSD = 0;
    PACL   pDacl = 0;
    BOOL   bPresent = FALSE, bDefault = FALSE, bHit = FALSE;
    WORD   i = 0;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            pwszSddl, SDDL_REVISION_1, &pSD, 0))
        return FALSE;

    if (GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefault) &&
        bPresent && pDacl) {
        for (i = 0; i < pDacl->AceCount; i++) {
            ACE_HEADER *pAce = 0;
            ACCESS_MASK mask = { 0 };
            PSID        pSid = 0;
            LPWSTR      s = 0;

            if (!GetAce(pDacl, i, (LPVOID *)&pAce) || !pAce) continue;
            if (pAce->AceType != ACCESS_ALLOWED_ACE_TYPE &&
                pAce->AceType != ACCESS_ALLOWED_OBJECT_ACE_TYPE) continue;

            mask = ((ACCESS_ALLOWED_ACE *)pAce)->Mask;
            if (!(mask & KESTREL_SCHEMA_DANGEROUS)) continue;

            pSid = _AceSid(pAce);
            if (!pSid || !IsValidSid(pSid)) continue;
            if (!ConvertSidToStringSidW(pSid, &s) || !s) continue;

            if (_IsLowPrivSid(s)) {
                if (!bHit)
                    wprintf(L"  [SCHEMA] class \"%s\" — defaultSecurityDescriptor grants:\n", pwszClass);
                    KestrelAddFinding(KESTREL_SEV_CRITICAL, L"Schema", pwszClass,
                        L"defaultSecurityDescriptor grants control to a low-privilege principal");
                wprintf(L"        %s : 0x%08lX  (new %s objects born controllable)\n",
                        s, (unsigned long)mask, pwszClass);
                bHit = TRUE;
            }
            LocalFree(s);
        }
    }
    LocalFree(pSD);
    return bHit;
}

_Must_inspect_result_
HRESULT
KestrelRunSchemaAuditScan(_In_z_ LPCWSTR pwszDomainNC)
{
    HRESULT             hr = 0;
    IADs               *pRootDSE = 0;
    IDirectorySearch   *pS = 0;
    ADS_SEARCH_HANDLE   h = 0;
    VARIANT             vSchema;
    WCHAR               wszSchemaPath[600] = { 0 };
    ADS_SEARCHPREF_INFO prefs[2] = { 0 } ;
    DWORD               cClasses = 0, cFlagged = 0;
    LPWSTR rgAttrs[] = {
        (LPWSTR)L"lDAPDisplayName",
        (LPWSTR)L"distinguishedName",
        (LPWSTR)L"defaultSecurityDescriptor"
    };

    UNREFERENCED_PARAMETER(pwszDomainNC);
    VariantInit(&vSchema);

    wprintf(L"\n[*] Schema defaultSecurityDescriptor audit\n");

    /* rootDSE → schemaNamingContext */
    hr = ADsGetObject((LPWSTR)L"LDAP://RootDSE", &IID_IADs, (void **)&pRootDSE);
    if (FAILED(hr)) { wprintf(L"  [!] RootDSE bind 0x%08X\n", hr); return hr; }
    hr = pRootDSE->lpVtbl->Get(pRootDSE, (LPWSTR)L"schemaNamingContext", &vSchema);
    if (FAILED(hr) || vSchema.vt != VT_BSTR || !vSchema.bstrVal) {
        wprintf(L"  [!] could not read schemaNamingContext 0x%08X\n", hr);
        pRootDSE->lpVtbl->Release(pRootDSE);
        return FAILED(hr) ? hr : E_FAIL;
    }
    StringCchPrintfW(wszSchemaPath, ARRAYSIZE(wszSchemaPath), L"LDAP://%s", vSchema.bstrVal);
    VariantClear(&vSchema);
    pRootDSE->lpVtbl->Release(pRootDSE);

    hr = ADsGetObject(wszSchemaPath, &IID_IDirectorySearch, (void **)&pS);
    if (FAILED(hr)) { wprintf(L"  [!] schema bind 0x%08X\n", hr); return hr; }

    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_ONELEVEL;
    prefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;
    pS->lpVtbl->SetSearchPreference(pS, prefs, ARRAYSIZE(prefs));

    hr = pS->lpVtbl->ExecuteSearch(pS, (LPWSTR)L"(objectClass=classSchema)",
            rgAttrs, ARRAYSIZE(rgAttrs), &h);
    if (FAILED(hr)) { wprintf(L"  [!] ExecuteSearch 0x%08X\n", hr); goto Cleanup; }

    for (;;) {
        ADS_SEARCH_COLUMN col;
        WCHAR wszClass[128] = L"", wszDN[600] = L"", wszSddl[2048] = L"";

        hr = pS->lpVtbl->GetNextRow(pS, h);
        if (hr == S_ADS_NOMORE_ROWS) { hr = S_OK; break; }
        if (FAILED(hr)) break;

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"defaultSecurityDescriptor", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszSddl, ARRAYSIZE(wszSddl), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        cClasses++;
        if (!wszSddl[0]) continue;

        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"lDAPDisplayName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszClass, ARRAYSIZE(wszClass), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }
        if (SUCCEEDED(pS->lpVtbl->GetColumn(pS, h, (LPWSTR)L"distinguishedName", &col))) {
            if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING && col.dwNumValues)
                StringCchCopyW(wszDN, ARRAYSIZE(wszDN), col.pADsValues[0].CaseIgnoreString);
            pS->lpVtbl->FreeColumn(pS, &col);
        }

        if (_SddlGrantsLowPriv(wszSddl, wszClass[0] ? wszClass : L"?")) {
            cFlagged++;
            if (wszDN[0]) {
                static const LPCWSTR rgSd[] = { L"defaultSecurityDescriptor" };
                KestrelPrintAttrProvenance(wszDN, L"schema-defaultSD", rgSd, 1, FALSE);
            }
        }
    }

    wprintf(L"\n  [=] %lu schema class(es) scanned, %lu with a low-priv grant in the default SD\n",
            cClasses, cFlagged);
    if (cFlagged == 0)
        wprintf(L"  [=] No dangerous schema default security descriptors\n");

Cleanup:
    if (h)  pS->lpVtbl->CloseSearchHandle(pS, h);
    if (pS) pS->lpVtbl->Release(pS);
    return hr;
}
