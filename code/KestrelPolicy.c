/*
 * KestrelPolicy.c — v0.5 (Part 1)
 * Passive GPO/SYSVOL security policy audit.
 *
 * Checks domain-wide security policies via:
 *   - LDAP queries to GPO objects in AD
 *   - Registry.pol parsing from SYSVOL
 *
 * Zero packets to target hosts.
 * SYSVOL reads are indistinguishable from normal Group Policy processing.
 *
 * Checks implemented:
 *   1. LLMNR          — EnableMulticast GPO setting
 *   2. NBT-NS         — NetBT node type GPO setting
 *   3. WDigest        — UseLogonCredential (plaintext creds in LSASS)
 *   4. NTLMv1         — LMCompatibilityLevel < 3
 *   5. LDAP Signing   — ldapServerIntegrity on DC objects
 *
 * Registry.pol binary format (MS-GPEF):
 *   Header:  52 65 67 66 01 00 00 00  ("Regf" + version)
 *   Entries: [keypath;valuename;type;size;data]
 *   Each field delimited by 0x00 0x00 (null wchar)
 * UPD: must to be
 * static const BYTE g_rgbPolMagic[] =
 *             { 0x50, 0x52, 0x65, 0x67, 0x01, 0x00, 0x00, 0x00 };
 */

#include "../include/Kestrel.h"

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Constants                                                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

/* Registry.pol magic header */
static const BYTE g_rgbPolMagic[] = { 0x52, 0x65, 0x67, 0x66, 0x01, 0x00, 0x00, 0x00 };

/* GPO registry paths and values we check */
#define POL_KEY_DNSCLIENT   L"Software\\Policies\\Microsoft\\Windows NT\\DNSClient"
#define POL_VAL_LLMNR       L"EnableMulticast"          /* 0 = disabled  */

#define POL_KEY_NETBT       L"System\\CurrentControlSet\\Services\\NetBT\\Parameters"
#define POL_VAL_NODETYPE    L"NodeType"                 /* 2 = P-node (no broadcast) */

#define POL_KEY_WDIGEST     L"System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
#define POL_VAL_WDIGEST     L"UseLogonCredential"       /* 0 = disabled  */

#define POL_KEY_LM          L"System\\CurrentControlSet\\Control\\Lsa"
#define POL_VAL_LM          L"LmCompatibilityLevel"    /* >= 3 = NTLMv2 only */


#define POL_KEY_LDAP  L"System\\CurrentControlSet\\Services\\NTDS\\Parameters"
#define POL_VAL_LDAP  L"LDAPServerIntegrity"


/* LDAP signing — read from DC object attributes, not Registry.pol */
#define LDAP_INTEGRITY_NONE    0
#define LDAP_INTEGRITY_SIGN    1
#define LDAP_INTEGRITY_ENCRYPT 2

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Data structures                                                            */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * KESTREL_POLICY_STATUS
 * Status of a single policy check.
 */
typedef enum _KESTREL_POLICY_STATUS {
    POLICY_SECURE    = 0,   /* Setting is hardened                          */
    POLICY_INSECURE  = 1,   /* Setting is vulnerable (or missing = default) */
    POLICY_UNKNOWN   = 2,   /* Could not determine (GPO not found/readable) */
} KESTREL_POLICY_STATUS;

/*
 * KESTREL_POLICY_CHECK
 * Result of one policy check.
 */
typedef struct _KESTREL_POLICY_CHECK {
    WCHAR                 wszName[64];      /* Check name                   */
    KESTREL_POLICY_STATUS Status;
    WCHAR                 wszGPOName[256];  /* GPO that sets this, if found */
    WCHAR                 wszDetail[256];   /* Current value / finding      */
    WCHAR                 wszAttack[256];   /* Attack vector hint (Pro)     */
    WCHAR                 wszRemediation[256]; /* Fix                       */
} KESTREL_POLICY_CHECK;

/*
 * KESTREL_POLICY_RESULT
 * Full result of KestrelRunPolicyAudit.
 */
typedef struct _KESTREL_POLICY_RESULT {
    KESTREL_POLICY_CHECK  LLMNR;
    KESTREL_POLICY_CHECK  NBTNS;
    KESTREL_POLICY_CHECK  WDigest;
    KESTREL_POLICY_CHECK  NTLMv1;
    KESTREL_POLICY_CHECK  LDAPSigning;
    DWORD                 cInsecure;    /* total insecure findings  */
    DWORD                 cUnknown;     /* total unknown            */
    DWORD                 cGPOsScanned;
} KESTREL_POLICY_RESULT;

/*
 * KESTREL_POL_ENTRY
 * One parsed entry from Registry.pol.
 */
typedef struct _KESTREL_POL_ENTRY {
    WCHAR  wszKey[512];
    WCHAR  wszValue[256];
    DWORD  dwType;
    DWORD  dwData;          /* simplified: store as DWORD for REG_DWORD */
    struct _KESTREL_POL_ENTRY *pNext;
} KESTREL_POL_ENTRY;

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Cleanup forward declarations                                               */
/* ─────────────────────────────────────────────────────────────────────────── */

VOID KestrelFreePolicyResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_POLICY_RESULT *pResult);

static VOID
KestrelFreePolEntries(
    _In_opt_ _Post_ptr_invalid_ KESTREL_POL_ENTRY *pHead);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Internal forward declarations                                              */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * Enumerate all GPO objects from AD.
 * Returns linked list of gPCFileSysPath values.
 * Caller must free each path via HeapFree.
 */
_Must_inspect_result_
static HRESULT
KestrelEnumGPOs(
    _In_z_   LPCWSTR   pwszDomainNC,
    _Outptr_ LPWSTR  **prgpwszPaths,
    _Out_    DWORD    *pcPaths);

/*
 * Parse Registry.pol file at pwszPolPath.
 * Returns linked list of KESTREL_POL_ENTRY.
 * Caller must free via KestrelFreePolEntries.
 */
_Must_inspect_result_
static HRESULT
KestrelParseRegistryPol(
    _In_z_   LPCWSTR          pwszPolPath,
    _Outptr_result_maybenull_ KESTREL_POL_ENTRY** ppEntries);

/*
 * Search parsed pol entries for a specific key/value.
 * Returns pointer to matching entry or NULL.
 */
_Ret_maybenull_
static const KESTREL_POL_ENTRY *
KestrelFindPolEntry(
    _In_     const KESTREL_POL_ENTRY *pHead,
    _In_z_   LPCWSTR                  pwszKey,
    _In_z_   LPCWSTR                  pwszValue);

/*
 * Check LDAP signing via DC object ldapServerIntegrity attribute.
 * This comes from AD directly, not from Registry.pol.
 */
_Must_inspect_result_
static HRESULT
KestrelCheckLDAPSigning(
    _In_z_  LPCWSTR               pwszDomainNC,
    _Inout_ KESTREL_POLICY_CHECK *pCheck);

/*
 * Initialize one KESTREL_POLICY_CHECK with default insecure state.
 * (Absence of a hardening policy = insecure by default)
 */
static VOID
KestrelInitCheck(
    _Out_   KESTREL_POLICY_CHECK *pCheck,
    _In_z_  LPCWSTR               pwszName,
    _In_z_  LPCWSTR               pwszAttack,
    _In_z_  LPCWSTR               pwszRemediation);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public entry point                                                         */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * KestrelRunPolicyAudit
 * Enumerates all GPOs, parses Registry.pol from SYSVOL for each,
 * checks five security settings. Fully passive.
 *
 * Parameters:
 *   pwszDomainNC — defaultNamingContext
 *   ppResult     — receives allocated result; free via KestrelFreePolicyResult
 */
_Must_inspect_result_
HRESULT
KestrelRunPolicyAudit(
    _In_z_   LPCWSTR                 pwszDomainNC,
    _Outptr_ KESTREL_POLICY_RESULT **ppResult)
{
    HRESULT               hr      = S_OK;
    KESTREL_POLICY_RESULT *pResult = 0;
    LPWSTR               *rgPaths = 0;
    DWORD                 cPaths  = 0;

    if (!pwszDomainNC || !ppResult) return E_INVALIDARG;
    *ppResult = 0;

    pResult = (KESTREL_POLICY_RESULT *)HeapAlloc(GetProcessHeap(),
                                                  HEAP_ZERO_MEMORY,
                                                  sizeof(*pResult));
    if (!pResult) return E_OUTOFMEMORY;

    wprintf(L"\n═══ Kestrel v0.5 — Policy Audit ═══\n\n");

    /* Initialize all checks as INSECURE by default
       (missing GPO = Windows default = insecure) */
    KestrelInitCheck(&pResult->LLMNR,
        L"LLMNR",
        L"NTLM hash capture via multicast poisoning (Responder)",
        L"GPO: Computer Config → Admin Templates → Network → DNS Client → "
        L"Turn off multicast name resolution = Enabled");

    KestrelInitCheck(&pResult->NBTNS,
        L"NBT-NS",
        L"NTLM hash capture via NetBIOS poisoning (Responder/Inveigh)",
        L"GPO: Set NodeType=2 via registry policy or disable NetBIOS on all adapters");

    KestrelInitCheck(&pResult->WDigest,
        L"WDigest",
        L"Plaintext credentials extractable from LSASS (Mimikatz sekurlsa::wdigest)",
        L"GPO: HKLM\\System\\...\\WDigest\\UseLogonCredential = 0");

    KestrelInitCheck(&pResult->NTLMv1,
        L"NTLMv1",
        L"NTLMv1 hashes crackable offline, downgrade attacks possible",
        L"GPO: Network Security: LAN Manager authentication level = "
        L"Send NTLMv2 response only (level 5)");

    KestrelInitCheck(&pResult->LDAPSigning,
        L"LDAP Signing",
        L"LDAP relay attacks (ntlmrelayx --escalate-user)",
        L"GPO: Domain Controller: LDAP server signing requirements = Require signing");

    /* ── Enumerate GPOs from AD ──────────────────────────────────── */
    wprintf(L"  [*] Enumerating GPOs...\n");
    hr = KestrelEnumGPOs(pwszDomainNC, &rgPaths, &cPaths);
    if (FAILED(hr)) {
        wprintf(L"  [!] GPO enumeration failed: 0x%08X\n", hr);
        goto Cleanup;
    }

    wprintf(L"  [*] GPOs found: %lu\n\n", cPaths);
    pResult->cGPOsScanned = cPaths;

    /* ── Parse each GPO's Registry.pol ──────────────────────────── */
    for (DWORD i = 0; i < cPaths; i++) {
        WCHAR wszPolPath[600] = { 0 };
        StringCchPrintfW(wszPolPath, ARRAYSIZE(wszPolPath),
                L"%s\\Machine\\Registry.pol", rgPaths[i]);

        KTRACE(L"Parsing: %s", wszPolPath);

        KESTREL_POL_ENTRY *pEntries = 0;
        HRESULT hrPol = KestrelParseRegistryPol(wszPolPath, &pEntries);
        if (FAILED(hrPol)) {
            KTRACE(L"  Registry.pol not found or unreadable: 0x%08X", hrPol);
            KestrelFreePolEntries(pEntries);
            continue;
        }

        /* ── Check each setting ──────────────────────────────────── */

        /* LLMNR: EnableMulticast = 0 */
        if (pResult->LLMNR.Status != POLICY_SECURE) {
            const KESTREL_POL_ENTRY *pE = KestrelFindPolEntry(pEntries,
                    POL_KEY_DNSCLIENT, POL_VAL_LLMNR);
            if (pE && pE->dwData == 0) {
                pResult->LLMNR.Status = POLICY_SECURE;
                StringCchCopyW(pResult->LLMNR.wszGPOName,
                        ARRAYSIZE(pResult->LLMNR.wszGPOName), rgPaths[i]);
                StringCchCopyW(pResult->LLMNR.wszDetail,
                        ARRAYSIZE(pResult->LLMNR.wszDetail),
                        L"EnableMulticast = 0 (disabled by GPO)");
            }
        }
        /* LDAPSigning: LDAPServerIntegrity >= 1 */
        if (pResult->LDAPSigning.Status != POLICY_SECURE) {
            const KESTREL_POL_ENTRY* pE = KestrelFindPolEntry(pEntries,
                POL_KEY_LDAP, POL_VAL_LDAP);
            if (pE && pE->dwData >= 1) {
                pResult->LDAPSigning.Status = POLICY_SECURE;
                StringCchCopyW(pResult->LDAPSigning.wszGPOName,
                    ARRAYSIZE(pResult->LDAPSigning.wszGPOName), rgPaths[i]);
                StringCchPrintfW(pResult->LDAPSigning.wszDetail,
                    ARRAYSIZE(pResult->LDAPSigning.wszDetail),
                    L"LDAPServerIntegrity = %lu (signing required)",
                    pE->dwData);
            }
        }

        /* NBT-NS: NodeType = 2 (P-node, no broadcast) */
        if (pResult->NBTNS.Status != POLICY_SECURE) {
            const KESTREL_POL_ENTRY *pE = KestrelFindPolEntry(pEntries,
                    POL_KEY_NETBT, POL_VAL_NODETYPE);
            if (pE && pE->dwData == 2) {
                pResult->NBTNS.Status = POLICY_SECURE;
                StringCchCopyW(pResult->NBTNS.wszGPOName,
                        ARRAYSIZE(pResult->NBTNS.wszGPOName), rgPaths[i]);
                StringCchCopyW(pResult->NBTNS.wszDetail,
                        ARRAYSIZE(pResult->NBTNS.wszDetail),
                        L"NodeType = 2 (P-node, broadcast disabled)");
            }
        }

        /* WDigest: UseLogonCredential = 0 */
        if (pResult->WDigest.Status != POLICY_SECURE) {
            const KESTREL_POL_ENTRY *pE = KestrelFindPolEntry(pEntries,
                    POL_KEY_WDIGEST, POL_VAL_WDIGEST);
            if (pE && pE->dwData == 0) {
                pResult->WDigest.Status = POLICY_SECURE;
                StringCchCopyW(pResult->WDigest.wszGPOName,
                        ARRAYSIZE(pResult->WDigest.wszGPOName), rgPaths[i]);
                StringCchCopyW(pResult->WDigest.wszDetail,
                        ARRAYSIZE(pResult->WDigest.wszDetail),
                        L"UseLogonCredential = 0 (WDigest disabled)");
            }
        }

        /* NTLMv1: LmCompatibilityLevel >= 3 */
        if (pResult->NTLMv1.Status != POLICY_SECURE) {
            const KESTREL_POL_ENTRY *pE = KestrelFindPolEntry(pEntries,
                    POL_KEY_LM, POL_VAL_LM);
            if (pE && pE->dwData >= 3) {
                pResult->NTLMv1.Status = POLICY_SECURE;
                StringCchCopyW(pResult->NTLMv1.wszGPOName,
                        ARRAYSIZE(pResult->NTLMv1.wszGPOName), rgPaths[i]);
                StringCchPrintfW(pResult->NTLMv1.wszDetail,
                        ARRAYSIZE(pResult->NTLMv1.wszDetail),
                        L"LmCompatibilityLevel = %lu (NTLMv2 enforced)",
                        pE->dwData);
            }
        }

        KestrelFreePolEntries(pEntries);
    }

    /* ── LDAP Signing — from AD directly, not Registry.pol ──────── */
    hr = KestrelCheckLDAPSigning(pwszDomainNC, &pResult->LDAPSigning);
    if ( FAILED ( hr ) )
        wprintf(L"  [!] LDAPSigning check failed: 0x%08X\n", hr);
    hr = S_OK;  /* non-fatal, continue */

    /* ── Count results ───────────────────────────────────────────── */
    KESTREL_POLICY_CHECK *rgChecks[] = {
        &pResult->LLMNR, &pResult->NBTNS, &pResult->WDigest,
        &pResult->NTLMv1, &pResult->LDAPSigning
    };

    wprintf(L"  %-20s %-10s %s\n", L"Check", L"Status", L"Detail");
    wprintf(L"  %s\n",
            L"----------------------------------------------------------------");

    for (SIZE_T c = 0; c < ARRAYSIZE(rgChecks); c++) {
        KESTREL_POLICY_CHECK *pC = rgChecks[c];

        LPCWSTR pwszStatus;
        switch (pC->Status) {
            case POLICY_SECURE:   pwszStatus = L"[OK]";      break;
            case POLICY_INSECURE: pwszStatus = L"[VULN]";    pResult->cInsecure++; break;
            default:              pwszStatus = L"[UNKNOWN]";  pResult->cUnknown++;  break;
        }

        wprintf(L"  %-20s %-10s %s\n",
                pC->wszName, pwszStatus,
                pC->wszDetail[0] ? pC->wszDetail : L"No hardening GPO found");

        if (pC->Status == POLICY_INSECURE) {
            wprintf(L"    → %s\n", pC->wszAttack);
        }
    }

    wprintf(L"\n  [*] Insecure: %lu  Unknown: %lu  GPOs scanned: %lu\n",
            pResult->cInsecure, pResult->cUnknown, pResult->cGPOsScanned);

    *ppResult = pResult;
    pResult   = 0;

Cleanup:
    for (DWORD i = 0; i < cPaths; i++)
        if (rgPaths[i]) HeapFree(GetProcessHeap(), 0, rgPaths[i]);
    if (rgPaths) HeapFree(GetProcessHeap(), 0, rgPaths);
    if (pResult) KestrelFreePolicyResult(pResult);
    return hr;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Internal implementations                                                   */
/* ─────────────────────────────────────────────────────────────────────────── */

static VOID
KestrelInitCheck(
    _Out_   KESTREL_POLICY_CHECK *pCheck,
    _In_z_  LPCWSTR               pwszName,
    _In_z_  LPCWSTR               pwszAttack,
    _In_z_  LPCWSTR               pwszRemediation)
{
    SecureZeroMemory(pCheck, sizeof(*pCheck));
    pCheck->Status = POLICY_INSECURE;   /* default = vulnerable */
    StringCchCopyW(pCheck->wszName,        ARRAYSIZE(pCheck->wszName),        pwszName);
    StringCchCopyW(pCheck->wszAttack,      ARRAYSIZE(pCheck->wszAttack),      pwszAttack);
    StringCchCopyW(pCheck->wszRemediation, ARRAYSIZE(pCheck->wszRemediation), pwszRemediation);
}

_Must_inspect_result_
static HRESULT
KestrelEnumGPOs(
    _In_z_   LPCWSTR   pwszDomainNC,
    _Outptr_ LPWSTR  **prgpwszPaths,
    _Out_    DWORD    *pcPaths)
{
    HRESULT           hr      = S_OK;
    IDirectorySearch *pSearch = 0;
    ADS_SEARCH_HANDLE hSearch = 0;
    WCHAR             wszPath[512];
    LPWSTR           *rgPaths = 0;
    DWORD             cPaths  = 0;
    DWORD             cCap    = 64;

    if (!pwszDomainNC || !prgpwszPaths || !pcPaths) return E_INVALIDARG;
    *prgpwszPaths = 0;
    *pcPaths      = 0;

    rgPaths = (LPWSTR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                   cCap * sizeof(LPWSTR));
    if (!rgPaths) return E_OUTOFMEMORY;

    hr = StringCchPrintfW(wszPath, ARRAYSIZE(wszPath),
            L"LDAP://CN=Policies,CN=System,%s", pwszDomainNC);
    if (FAILED(hr)) goto Cleanup;

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void **)&pSearch);
    if (FAILED(hr)) goto Cleanup;

    ADS_SEARCHPREF_INFO prefs[2] = { 0 };
    prefs[0].dwSearchPref   = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_ONELEVEL;
    prefs[1].dwSearchPref   = ADS_SEARCHPREF_PAGESIZE;
    prefs[1].vValue.dwType  = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer = KESTREL_LDAP_PAGESIZE;

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);
    if (FAILED(hr)) goto Cleanup;

    LPWSTR attrs[] = { L"gPCFileSysPath", L"displayName" };
    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
            L"(objectClass=groupPolicyContainer)",
            attrs, ARRAYSIZE(attrs), &hSearch);
    if (FAILED(hr)) goto Cleanup;

    while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {
        ADS_SEARCH_COLUMN colPath = { 0 };
        ADS_SEARCH_COLUMN colName = { 0 };

        BOOL bGotPath = FALSE;

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"gPCFileSysPath", &colPath)) &&
            colPath.dwNumValues > 0 &&
            colPath.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING) {
            bGotPath = TRUE;
        }

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
                        L"displayName", &colName)) &&
            colName.dwNumValues > 0 &&
            colName.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING) {
            KTRACE(L"GPO: %s", colName.pADsValues[0].CaseIgnoreString);
        }

        if (bGotPath) {
            /* Grow array if needed */
            if (cPaths == cCap) {
                cCap *= 2;
                LPWSTR *pNew = (LPWSTR *)HeapReAlloc(GetProcessHeap(),
                        HEAP_ZERO_MEMORY, rgPaths, cCap * sizeof(LPWSTR));
                if (!pNew) { hr = E_OUTOFMEMORY; goto NextGPO; }
                rgPaths = pNew;
            }

            LPCWSTR pwszSysPath = colPath.pADsValues[0].CaseIgnoreString;
            SIZE_T  cch         = wcslen(pwszSysPath) + 1;
            rgPaths[cPaths] = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                cch * sizeof(WCHAR));
            if (rgPaths[cPaths]) {
                StringCchCopyW( rgPaths[cPaths], cch, pwszSysPath) ;
                rgPaths [cPaths] [cch - 1] = L'\0';  /* гарантируем null terminator */
                cPaths++;                                                                       
            }
        }

NextGPO:
        pSearch->lpVtbl->FreeColumn(pSearch, &colPath);
        pSearch->lpVtbl->FreeColumn(pSearch, &colName);
    }

    *prgpwszPaths = rgPaths;
    *pcPaths      = cPaths;
    rgPaths       = 0;  /* ownership transferred */

Cleanup:
    if (hSearch && pSearch)
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    if (rgPaths) {
        for (DWORD i = 0; i < cPaths; i++)
            if (rgPaths[i]) HeapFree(GetProcessHeap(), 0, rgPaths[i]);
        HeapFree(GetProcessHeap(), 0, rgPaths);
    }
    return hr;
}

/*
 * KestrelParseRegistryPol — corrected implementation.
 *
 * Drop-in replacement for the existing KestrelParseRegistryPol in
 * KestrelPolicy.c (currently ~lines 554–746). Two corrections vs. the
 * previous version:
 *
 *   FIX 1 — Signature.
 *     Registry.pol uses the PReg format (MS-GPEF 2.2.1): the file begins
 *     with "PReg" (0x50 0x52 0x65 0x67) + version DWORD 0x00000001.
 *     The old magic was "Regf" (0x52 0x65 0x67 0x66), which is the
 *     registry HIVE signature — a different format. With the wrong magic
 *     the memcmp failed on every real .pol file, so the SYSVOL path
 *     silently parsed nothing and every check fell through to
 *     INSECURE-by-default.
 *
 *     => Update the file-scope constant in KestrelPolicy.c (line ~32) to:
 *
 *         static const BYTE g_rgbPolMagic[] =
 *             { 0x50, 0x52, 0x65, 0x67, 0x01, 0x00, 0x00, 0x00 };
 *
 *     and fix the two header comments that quote "Regf" (lines ~20, ~532).
 *
 *   FIX 2 — String termination.
 *     In PReg each entry is  [ key\0 ; value\0 ; type ; size ; data ]
 *     where '[' ']' ';' are literal UTF-16 chars (2 bytes each), key and
 *     value are SINGLE-null-terminated UTF-16LE strings, and type/size are
 *     raw little-endian DWORDs. The old loop searched for a DOUBLE null,
 *     so it never terminated at "key\0" — it swallowed the ';' separator
 *     into the key and ran into the value field, after which the ';' check
 *     failed and the entry was discarded.
 *
 *     => Terminate each string on the FIRST null; the ';' follows it.
 *        Handled here by the KestrelReadPolWStr helper.
 *
 * Verify on a real file: `xxd machine\Registry.pol | head` — first four
 * bytes must be 50 52 65 67 ("PReg").
 */

#include "../include/Kestrel.h"

 /* ─────────────────────────────────────────────────────────────────────────── */
 /*  Helper: read one single-null-terminated UTF-16LE string                    */
 /* ─────────────────────────────────────────────────────────────────────────── */

 /*
  * KestrelReadPolWStr
  * Reads a single-null-terminated UTF-16LE string from pBuf starting at
  * *ppos, copying up to cchMax-1 chars into pwszOut (always null-terminated).
  * If the string is longer than the buffer it still consumes the full string
  * so *ppos stays byte-aligned for the caller. Advances *ppos past the
  * terminating null.
  *
  * Returns TRUE if a null terminator was found within the buffer,
  * FALSE if the buffer ended first (truncated / malformed tail).
  */
static BOOL
KestrelReadPolWStr(
    _In_reads_bytes_(cbBuf) const BYTE* pBuf,
    _In_                    DWORD        cbBuf,
    _Inout_                 DWORD* ppos,
    _Out_writes_z_(cchMax)  LPWSTR       pwszOut,
    _In_                    DWORD        cchMax)
{
    DWORD pos = *ppos;
    DWORD cch = 0;

    pwszOut[0] = L'\0';

    while (pos + 2 <= cbBuf) {
        WCHAR wch = (WCHAR)(pBuf[pos] | ((WORD)pBuf[pos + 1] << 8));
        pos += 2;

        if (wch == L'\0') {              /* single-null = end of string */
            *ppos = pos;
            return TRUE;
        }

        if (cch < cchMax - 1) {
            pwszOut[cch++] = wch;
            pwszOut[cch] = L'\0';
        }
        /* if truncated, keep scanning to stay aligned, just stop copying */
    }

    return FALSE;                        /* ran off the end, no terminator */
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  KestrelParseRegistryPol                                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
KestrelParseRegistryPol(
    _In_z_                     LPCWSTR              pwszPolPath,
    _Outptr_result_maybenull_  KESTREL_POL_ENTRY** ppEntries)
{
    HRESULT             hr = S_OK;
    HANDLE              hFile = INVALID_HANDLE_VALUE;
    BYTE* pBuf = 0;
    DWORD               cbFile = 0;
    DWORD               cbRead = 0;
    KESTREL_POL_ENTRY* pHead = 0;
    KESTREL_POL_ENTRY** ppTail = &pHead;
    DWORD               cEntries = 0;
    DWORD               pos = 0;

    if (!pwszPolPath || !ppEntries) return E_INVALIDARG;
    *ppEntries = 0;

    /* ── 1. Open Registry.pol from SYSVOL ─────────────────────────── */
    hFile = CreateFileW(pwszPolPath,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0);
    if (hFile == INVALID_HANDLE_VALUE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        KTRACE(L"  CreateFileW failed: 0x%08X", hr);
        return hr;
    }

    /* ── 2. Read entire file into a heap buffer ───────────────────── */
    cbFile = GetFileSize(hFile, 0);
    if (cbFile == INVALID_FILE_SIZE || cbFile < sizeof(g_rgbPolMagic)) {
        hr = E_UNEXPECTED;
        goto Cleanup;
    }

    pBuf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, cbFile);
    if (!pBuf) { hr = E_OUTOFMEMORY; goto Cleanup; }

    if (!ReadFile(hFile, pBuf, cbFile, &cbRead, 0) || cbRead != cbFile) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    /* ── 3. Validate PReg signature ("PReg" + version 1) ──────────── */
    if (memcmp(pBuf, g_rgbPolMagic, sizeof(g_rgbPolMagic)) != 0) {
        KTRACE(L"  Invalid Registry.pol signature (expected PReg)");
        hr = E_UNEXPECTED;
        goto Cleanup;
    }

    /* ── 4. Walk entries ──────────────────────────────────────────── *
     *   [ key\0 ; value\0 ; type ; size ; data ]
     *   '[' ']' ';'  are literal UTF-16 chars (2 bytes).
     *   key, value   are single-null-terminated UTF-16LE.
     *   type, size   are raw little-endian DWORDs.
     *   data         is `size` bytes.
     * On any structural mismatch we resync by scanning forward to the
     * next '[' (PReg is 2-byte aligned throughout).                    */
    pos = sizeof(g_rgbPolMagic);

    while (pos + 2 <= cbRead) {

        /* Entry start marker '[' (0x5B 0x00); else resync 2 bytes. */
        if (pBuf[pos] != 0x5B || pBuf[pos + 1] != 0x00) {
            pos += 2;
            continue;
        }
        pos += 2;

        WCHAR wszKey[512];
        WCHAR wszValue[256];
        DWORD dwType = 0;
        DWORD dwSize = 0;
        DWORD dwData = 0;

        /* ── key + ';' ────────────────────────────────────────────── */
        if (!KestrelReadPolWStr(pBuf, cbRead, &pos, wszKey, ARRAYSIZE(wszKey)))
            break;
        if (pos + 2 > cbRead || pBuf[pos] != 0x3B || pBuf[pos + 1] != 0x00)
            continue;
        pos += 2;

        /* ── value + ';' ──────────────────────────────────────────── */
        if (!KestrelReadPolWStr(pBuf, cbRead, &pos, wszValue, ARRAYSIZE(wszValue)))
            break;
        if (pos + 2 > cbRead || pBuf[pos] != 0x3B || pBuf[pos + 1] != 0x00)
            continue;
        pos += 2;

        /* ── type (raw DWORD) + ';' ───────────────────────────────── */
        if (pos + 4 > cbRead) break;
        dwType = (DWORD)pBuf[pos]
            | ((DWORD)pBuf[pos + 1] << 8)
            | ((DWORD)pBuf[pos + 2] << 16)
            | ((DWORD)pBuf[pos + 3] << 24);
        pos += 4;
        if (pos + 2 > cbRead || pBuf[pos] != 0x3B || pBuf[pos + 1] != 0x00)
            continue;
        pos += 2;

        /* ── size (raw DWORD) + ';' ───────────────────────────────── */
        if (pos + 4 > cbRead) break;
        dwSize = (DWORD)pBuf[pos]
            | ((DWORD)pBuf[pos + 1] << 8)
            | ((DWORD)pBuf[pos + 2] << 16)
            | ((DWORD)pBuf[pos + 3] << 24);
        pos += 4;
        if (pos + 2 > cbRead || pBuf[pos] != 0x3B || pBuf[pos + 1] != 0x00)
            continue;
        pos += 2;

        /* ── data (size bytes), bounds-checked ────────────────────── */
        if (dwSize > cbRead - pos) break;
        if (dwType == REG_DWORD && dwSize == 4) {
            dwData = (DWORD)pBuf[pos]
                | ((DWORD)pBuf[pos + 1] << 8)
                | ((DWORD)pBuf[pos + 2] << 16)
                | ((DWORD)pBuf[pos + 3] << 24);
        }
        pos += dwSize;

        /* Optional entry-end ']' (0x5D 0x00). */
        if (pos + 2 <= cbRead && pBuf[pos] == 0x5D && pBuf[pos + 1] == 0x00)
            pos += 2;

        /* ── Store REG_DWORD entries with a non-empty key only ────── */
        if (dwType != REG_DWORD || wszKey[0] == L'\0')
            continue;

        KESTREL_POL_ENTRY* pEntry = (KESTREL_POL_ENTRY*)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*pEntry));
        if (!pEntry) { hr = E_OUTOFMEMORY; goto Cleanup; }

        StringCchCopyW(pEntry->wszKey, ARRAYSIZE(pEntry->wszKey), wszKey);
        StringCchCopyW(pEntry->wszValue, ARRAYSIZE(pEntry->wszValue), wszValue);
        pEntry->dwType = dwType;
        pEntry->dwData = dwData;
        pEntry->pNext = 0;

        KTRACE(L"  POL: [%s] %s = %lu", wszKey, wszValue, dwData);

        *ppTail = pEntry;
        ppTail = &pEntry->pNext;
        cEntries++;
    }

    KTRACE(L"  Parsed %lu REG_DWORD entries", cEntries);

    *ppEntries = pHead;
    pHead = 0;     /* ownership transferred */

Cleanup:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (pBuf)  HeapFree(GetProcessHeap(), 0, pBuf);
    KestrelFreePolEntries(pHead);   /* frees only on the error path */
    return hr;
}

_Ret_maybenull_
static const KESTREL_POL_ENTRY *
KestrelFindPolEntry(
    _In_     const KESTREL_POL_ENTRY *pHead,
    _In_z_   LPCWSTR                  pwszKey,
    _In_z_   LPCWSTR                  pwszValue)
{
    for (const KESTREL_POL_ENTRY *p = pHead; p; p = p->pNext) {
        if (_wcsicmp(p->wszKey,   pwszKey)   == 0 &&
            _wcsicmp(p->wszValue, pwszValue) == 0)
            return p;
    }
    return 0;
}

/*
 * KestrelCheckLDAPSigning — implementation.
 *
 * Replace the stub in KestrelPolicy.c with this function.
 *
 * Two passive sources checked in order:
 *
 *   Source A — Registry.pol (GPO):
 *     Key:   SYSTEM\CurrentControlSet\Services\NTDS\Parameters
 *     Value: LDAPServerIntegrity
 *     0 = None (insecure), 1 = Require Signing (secure)
 *
 *   Source B — msDS-Other-Settings on NTDS Settings objects:
 *     Each DC has CN=NTDS Settings under its computer object.
 *     Attribute msDS-Other-Settings may contain "RequireSigning".
 *     Less common but authoritative for per-DC configuration.
 *
 * Also add to KestrelRunPolicyAudit's Registry.pol loop:
 *
 *   #define POL_KEY_LDAP   L"System\\CurrentControlSet\\Services\\NTDS\\Parameters"
 *   #define POL_VAL_LDAP   L"LDAPServerIntegrity"
 *
 * And check it alongside LLMNR/WDigest:
 *
 *   if (pResult->LDAPSigning.Status != POLICY_SECURE) {
 *       const KESTREL_POL_ENTRY *pE = KestrelFindPolEntry(pEntries,
 *               POL_KEY_LDAP, POL_VAL_LDAP);
 *       if (pE && pE->dwData >= 1) {
 *           pResult->LDAPSigning.Status = POLICY_SECURE;
 *           StringCchCopyW(pResult->LDAPSigning.wszGPOName, ...);
 *           StringCchPrintfW(pResult->LDAPSigning.wszDetail, ...,
 *               L"LDAPServerIntegrity = %lu (signing required)", pE->dwData);
 *       }
 *   }
 */

_Must_inspect_result_
static HRESULT
KestrelCheckLDAPSigning(
    _In_z_  LPCWSTR               pwszDomainNC,
    _Inout_ KESTREL_POLICY_CHECK* pCheck)
{
    HRESULT           hr = S_OK;
    IDirectorySearch* pSearch = 0;
    ADS_SEARCH_HANDLE hSearch = 0;
    WCHAR             wszPath[512];
    BOOL              bFoundAny = FALSE;
    BOOL              bAllSecure = TRUE;
    DWORD             cDCs = 0;

    if (!pwszDomainNC || !pCheck) return E_INVALIDARG;

    /*
     * Query all NTDS Settings objects under DC computer objects.
     * CN=NTDS Settings lives under each DC's server object in Sites.
     * Filter: (objectClass=nTDSDSA)
     * Attribute: msDS-Other-Settings (multi-valued string)
     *
     * Path: CN=Configuration,<domain> → CN=Sites → ... → CN=NTDS Settings
     * We search from configNC which isn't passed here.
     *
     * Fallback: query DC computer objects for userAccountControl
     * and check dSHeuristics on the directory service object.
     */

     /* ── Source B: dSHeuristics on Directory Service object ──────── */
     /*
      * CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,<domain>
      * Attribute: dSHeuristics — a string where character at position 3
      * (0-indexed) controls LDAP signing:
      *   '1' at position 3 = signing not required
      *   '2' at position 3 = signing required
      *
      * Note: dSHeuristics is rarely set explicitly for LDAP signing —
      * the GPO approach (Source A, Registry.pol) is more common.
      * We check it as a secondary indicator.
      */

    hr = StringCchPrintfW(wszPath, ARRAYSIZE(wszPath),
        L"LDAP://CN=Directory Service,CN=Windows NT,"
        L"CN=Services,CN=Configuration,%s", pwszDomainNC);
    if (FAILED(hr)) goto Cleanup;

    hr = ADsGetObject(wszPath, &IID_IDirectorySearch, (void**)&pSearch);
    if (FAILED(hr)) {
        KTRACE(L"  LDAP signing: cannot reach Directory Service object: 0x%08X", hr);
        pCheck->Status = POLICY_UNKNOWN;
        StringCchCopyW(pCheck->wszDetail, ARRAYSIZE(pCheck->wszDetail),
            L"Could not read Directory Service object");
        hr = S_OK;  /* non-fatal */
        goto Cleanup;
    }

    ADS_SEARCHPREF_INFO prefs[1];
    prefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[0].vValue.dwType = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer = ADS_SCOPE_BASE;

    hr = pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 1);
    if (FAILED(hr)) goto Cleanup;

    LPWSTR attrs[] = { L"dSHeuristics" };
    hr = pSearch->lpVtbl->ExecuteSearch(pSearch,
        L"(objectClass=nTDSService)",
        attrs, ARRAYSIZE(attrs), &hSearch);
    if (FAILED(hr)) goto Cleanup;

    if (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) != S_ADS_NOMORE_ROWS) {

        ADS_SEARCH_COLUMN col = { 0 };

        if (SUCCEEDED(pSearch->lpVtbl->GetColumn(pSearch, hSearch,
            L"dSHeuristics", &col)) &&
            col.dwNumValues > 0 &&
            col.pADsValues[0].dwType == ADSTYPE_CASE_IGNORE_STRING) {

            LPCWSTR pwszHeur = col.pADsValues[0].CaseIgnoreString;
            KTRACE(L"  dSHeuristics: %s", pwszHeur);
            bFoundAny = TRUE;

            /*
             * dSHeuristics position 3 (4th character, 0-indexed):
             * Not present or '0'/'1' = default (no explicit signing req.)
             * '2' = signing required
             *
             * This is an indirect signal — GPO (Registry.pol) is the
             * primary authoritative source for LDAPServerIntegrity.
             * dSHeuristics is a supplementary check.
             */
            if (wcslen(pwszHeur) >= 4 && pwszHeur[3] == L'2') {
                pCheck->Status = POLICY_SECURE;
                StringCchCopyW(pCheck->wszDetail, ARRAYSIZE(pCheck->wszDetail),
                    L"dSHeuristics position 3 = 2 (signing configured)");
                StringCchCopyW(pCheck->wszGPOName, ARRAYSIZE(pCheck->wszGPOName),
                    L"dSHeuristics attribute");
            }

            pSearch->lpVtbl->FreeColumn(pSearch, &col);
        }
    }

    /* ── If dSHeuristics didn't confirm — mark as needing GPO check ── */
    if (!bFoundAny || pCheck->Status != POLICY_SECURE) {
        /*
         * Primary check is via Registry.pol (LDAPServerIntegrity).
         * That check runs in KestrelRunPolicyAudit's main GPO loop.
         * If we reach here without SECURE status, it means:
         *   - dSHeuristics not set explicitly, AND
         *   - Registry.pol check hasn't run yet (or found nothing)
         *
         * Status remains INSECURE (default) — will be updated by
         * the Registry.pol loop if a hardening GPO is found.
         */
        if (pCheck->Status != POLICY_SECURE) {
            StringCchCopyW(pCheck->wszDetail, ARRAYSIZE(pCheck->wszDetail),
                L"No explicit signing requirement found via dSHeuristics");
            KTRACE(L"  LDAP signing: not confirmed via dSHeuristics, "
                L"Registry.pol check pending");
        }
    }

    (void)bAllSecure; (void)cDCs;

Cleanup:
    if (hSearch && pSearch)
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    if (pSearch)
        pSearch->lpVtbl->Release(pSearch);
    return hr;
}
/* ─────────────────────────────────────────────────────────────────────────── */
/*  Cleanup                                                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

static VOID
KestrelFreePolEntries(
    _In_opt_ _Post_ptr_invalid_ KESTREL_POL_ENTRY *pHead)
{
    while (pHead) {
        KESTREL_POL_ENTRY *pNext = pHead->pNext;
        HeapFree(GetProcessHeap(), 0, pHead);
        pHead = pNext;
    }
}

VOID
KestrelFreePolicyResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_POLICY_RESULT *pResult)
{
    if (!pResult) return;
    HeapFree(GetProcessHeap(), 0, pResult);
}
