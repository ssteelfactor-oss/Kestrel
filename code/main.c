/*
 * main.c — Kestrel entry point.
 *
 * Usage:
 *   Kestrel.exe [modules] [output] [options]
 *
 * Modules (default: all):
 *   --all          Run all modules (default when none specified)
 *   --adws         ADWS endpoint detection
 *   --topology     Computer topology via SPN
 *   --delegation   Delegation risks
 *   --laps         LAPS coverage
 *   --stale        Stale computers
 *   --acl          ACL edge extraction
 *   --groups       Transitive group membership
 *   --policy       GPO security policy audit
 *   --paths        Attack-path analysis
 *   --roast        Kerberoastable + AS-REP Roastable
 *   --trust        Domain/forest trust posture
 *   --gmsa         gMSA password reader enumeration
 *   --adcs         ADCS certificate-template / CA audit (ESC1-5/9)
 *   --adfs         AD FS DKM key ACL audit (Golden SAML precondition)
 *   --machines     Machine accounts created via MachineAccountQuota (mS-DS-CreatorSID)
 *   --gpp          SYSVOL secret sweep — GPP cpassword + unattend + script creds
 *
 *   Service posture (passive, opt-in — not part of --all):
 *   --services     Run all service-posture modules
 *   --exchange     Exchange posture from AD (inventory + Exchange-to-DA escalation)
 *   --sql          SQL Server SPN map (manual; not in --services - overlaps --roast)
 *   --sccm         SCCM/MECM posture from AD (System Management container ACL + MP/site map)
 *   --dns          ADIDNS posture from AD (zone CreateChild ACL + wpad/isatap + DnsAdmins)
 *
 * Output:
 *   --report <path>  Generate report (.html / .json / .yaml)
 *
 * Options:
 *   --verbose / -v   Enable trace output
 *   --acl-raw        Disable default-ACL baseline filtering (raw ACL edges)
 *   --version        Show version and exit
 *   --help / -h      Show this help and exit
 */

#include "../include/Kestrel.h"

BOOL g_bVerbose = FALSE;
BOOL g_bAclRaw  = FALSE;

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Help and version                                                           */
/* ─────────────────────────────────────────────────────────────────────────── */

static VOID
KestrelPrintVersion(VOID)
{
    wprintf(L"\nKestrel %s — Passive AD Security Enumeration\n", KESTREL_VERSION);
    wprintf(L"github.com/ssteelfactor-oss/Kestrel\n\n");
}

static VOID
KestrelPrintHelp(VOID)
{
    KestrelPrintVersion();
    wprintf(
        L"USAGE:\n"
        L"  Kestrel.exe [modules] [output] [options]\n\n"
        L"MODULES (default: all):\n"
        L"  --all          Run all core AD modules (service posture is opt-in; see below)\n"
        L"  --adws         ADWS endpoint detection (port 9389/TCP per DC)\n"
        L"  --topology     Computer topology via SPN decoding\n"
        L"  --delegation   Delegation risks (unconstrained/constrained/S4U2Self)\n"
        L"  --laps         LAPS coverage (legacy + Windows LAPS 2023+)\n"
        L"  --stale        Stale computers via lastLogonTimestamp\n"
        L"  --acl          ACL edge extraction via IDirectoryObject\n"
        L"  --groups       Transitive group membership via LDAP_MATCHING_RULE_IN_CHAIN\n"
        L"  --policy       GPO security policy audit (LLMNR/NBT-NS/WDigest/NTLMv1)\n"
        L"  --paths        Attack-path analysis over the graph (to tier-0)\n"
        L"  --from <prin>  Paths FROM a principal (SID/name); implies --paths\n"
        L"  --roast        Kerberoastable + AS-REP Roastable detection\n"
        L"  --shadowcreds  Shadow credentials (msDS-KeyCredentialLink) detection\n"
        L"  --sidhistory   sIDHistory enumeration (privileged / foreign SID injection)\n"
        L"  --adminsdholder  Orphaned adminCount=1 objects (AdminSDHolder)\n"
        L"  --pwdpolicy    Password policy + PSO · krbtgt age · MachineAccountQuota\n"
        L"  --hygiene      Credential hygiene (PASSWD_NOTREQD / DONT_EXPIRE / reversible / desc)\n"
        L"  --gpolateral   GPO local-group → lateral edges (AdminTo/CanRDP/CanPSRemote/ExecuteDCOM)\n"
        L"  --schema       Schema defaultSecurityDescriptor audit (schema-level backdoor)\n"
        L"  --hardening    Domain hardening flags (dSHeuristics anon access + Pre-Win2000 compat)\n"
        L"  --trust        Domain/forest trust posture audit\n"
        L"  --gmsa         gMSA password reader enumeration\n"
        L"  --adcs         ADCS certificate-template / CA audit (ESC1-5/9)\n"
        L"  --adfs         AD FS DKM key ACL audit (Golden SAML precondition)\n"
        L"  --machines     Machine accounts created via MachineAccountQuota (mS-DS-CreatorSID)\n"
        L"  --gpp          SYSVOL secret sweep (GPP cpassword + unattend + script creds)\n\n"
        L"SERVICE POSTURE (passive, opt-in \u2014 NOT included in --all):\n"
        L"  --services     Run all service-posture modules\n"
        L"  --exchange     Exchange posture from AD (inventory + Exchange-to-DA escalation)\n"
        L"  --sql          SQL Server SPN map (manual; not in --services - overlaps --roast)\n"
        L"  --sccm         SCCM/MECM posture from AD (System Management container ACL + MP/site map)\n"
        L"  --dns          ADIDNS posture from AD (zone CreateChild ACL + wpad/isatap + DnsAdmins)\n\n"
        L"OUTPUT:\n"
        L"  --report <path>  Generate report (.html / .json / .yaml by extension)\n"
        L"  --opengraph <path>  Export BloodHound CE OpenGraph JSON\n"
        L"  --diff <path>  Diff current run against a previous .json snapshot\n\n"
        L"OPTIONS:\n"
        L"  --verbose / -v   Enable trace output\n"
        L"  --acl-raw        Disable default-ACL baseline (show raw ACL edges)\n"
        L"  --version        Show version and exit\n"
        L"  --help / -h      Show this help and exit\n\n"
        L"EXAMPLES:\n"
        L"  Kestrel.exe\n"
        L"  Kestrel.exe --report C:\\out\\report.html\n"
        L"  Kestrel.exe --acl --groups --report C:\\out\\report.html\n"
        L"  Kestrel.exe --trust --gmsa --adcs --verbose\n"
        L"  Kestrel.exe --report %%USERPROFILE%%\\Desktop\\report.html\n\n"
    );
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Enable every module — shared by --all and the no-args default              */
/* ─────────────────────────────────────────────────────────────────────────── */

static VOID
KestrelEnableAllModules(_Inout_ KESTREL_CONFIG *pCfg)
{
    pCfg->bRunADWS       = TRUE;
    pCfg->bRunTopology   = TRUE;
    pCfg->bRunDelegation = TRUE;
    pCfg->bRunLAPS       = TRUE;
    pCfg->bRunStale      = TRUE;
    pCfg->bRunACL        = TRUE;
    pCfg->bRunGroups     = TRUE;
    pCfg->bRunPolicy     = TRUE;
    pCfg->bRunPaths      = TRUE;
    pCfg->bRunRoast      = TRUE;
    pCfg->bRunShadowCreds = TRUE;
    pCfg->bRunSidHistory  = TRUE;
    pCfg->bRunAdminSDHolder = TRUE;
    pCfg->bRunPwdPolicy   = TRUE;
    pCfg->bRunHygiene     = TRUE;
    pCfg->bRunGpoLateral  = TRUE;
    pCfg->bRunSchemaAudit = TRUE;
    pCfg->bRunTrust      = TRUE;
    pCfg->bRunGMSA       = TRUE;
    pCfg->bRunADCS       = TRUE;
    pCfg->bRunADFS       = TRUE;
    pCfg->bRunMachineAcct = TRUE;
    pCfg->bRunGPP        = TRUE;
    pCfg->bRunHardening  = TRUE;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Enable every service-posture module — shared by --services                 */
/*  (passive audit of services AD knows about; opt-in, NOT part of --all)       */
/* ─────────────────────────────────────────────────────────────────────────── */

static VOID
KestrelEnableAllServices(_Inout_ KESTREL_CONFIG *pCfg)
{
    pCfg->bRunExchange   = TRUE;
    pCfg->bRunSccm       = TRUE;
    pCfg->bRunDns        = TRUE;
    /* --sql is intentionally NOT in the umbrella: its passive AD footprint is
       only the MSSQLSvc SPN, which --roast already surfaces. Kept as a manual
       flag until it grows a distinct passive signal. */
    /* future service-posture modules land here: DNS, hybrid seam */
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Argument parser                                                            */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL
KestrelParseArgs(
    _In_  int             argc,
    _In_  wchar_t        *argv[],
    _Out_ KESTREL_CONFIG *pCfg)
{
    /* Zero-init */
    SecureZeroMemory(pCfg, sizeof(*pCfg));

    for (int i = 1; i < argc; i++) {
        LPCWSTR arg = argv[i];

        /* ── Help / version ──────────────────────────────────────── */
        if (_wcsicmp(arg, L"--help") == 0 || _wcsicmp(arg, L"-h") == 0) {
            KestrelPrintHelp();
            return FALSE;   /* caller should exit with 0 */
        }
        if (_wcsicmp(arg, L"--version") == 0) {
            KestrelPrintVersion();
            return FALSE;
        }

        /* ── Options ─────────────────────────────────────────────── */
        if (_wcsicmp(arg, L"--verbose") == 0 ||
            _wcsicmp(arg, L"-v") == 0) {
            pCfg->bVerbose = TRUE;
            g_bVerbose = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--acl-raw") == 0) {
            g_bAclRaw = TRUE;
            continue;
        }

        /* ── Output ──────────────────────────────────────────────── */
        if (_wcsicmp(arg, L"--report") == 0) {
            if (i + 1 >= argc) {
                wprintf(L"[!] --report requires a path argument\n");
                return FALSE;
            }
            StringCchCopyW(pCfg->wszReportPath,
                ARRAYSIZE(pCfg->wszReportPath),
                argv[++i]);
            continue;
        }

        if (_wcsicmp(arg, L"--opengraph") == 0) {
            if (i + 1 >= argc) {
                wprintf(L"[!] --opengraph requires a path argument\n");
                return FALSE;
            }
            StringCchCopyW(pCfg->wszOpenGraphPath,
                ARRAYSIZE(pCfg->wszOpenGraphPath),
                argv[++i]);
            continue;
        }

        if (_wcsicmp(arg, L"--diff") == 0) {
            if (i + 1 >= argc) {
                wprintf(L"[!] --diff requires a path argument\n");
                return FALSE;
            }
            StringCchCopyW(pCfg->wszDiffPath,
                ARRAYSIZE(pCfg->wszDiffPath),
                argv[++i]);
            continue;
        }

        /* ── Modules ─────────────────────────────────────────────── */
        if (_wcsicmp(arg, L"--all") == 0) {
            KestrelEnableAllModules(pCfg);
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--services") == 0) {
            KestrelEnableAllServices(pCfg);
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--adws") == 0) {
            pCfg->bRunADWS = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--topology") == 0) {
            pCfg->bRunTopology = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--delegation") == 0) {
            pCfg->bRunDelegation = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--laps") == 0) {
            pCfg->bRunLAPS = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--stale") == 0) {
            pCfg->bRunStale = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--acl") == 0) {
            pCfg->bRunACL = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--groups") == 0) {
            pCfg->bRunGroups = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--policy") == 0) {
            pCfg->bRunPolicy = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--paths") == 0) {
            pCfg->bRunPaths = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--from") == 0) {
            if (i + 1 >= argc) {
                wprintf(L"[!] --from requires a principal (SID or name)\n");
                return FALSE;
            }
            StringCchCopyW(pCfg->wszFrom, ARRAYSIZE(pCfg->wszFrom), argv[++i]);
            pCfg->bRunPaths = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--roast") == 0) {
            pCfg->bRunRoast = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--shadowcreds") == 0) {
            pCfg->bRunShadowCreds = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--sidhistory") == 0) {
            pCfg->bRunSidHistory = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--adminsdholder") == 0) {
            pCfg->bRunAdminSDHolder = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--pwdpolicy") == 0) {
            pCfg->bRunPwdPolicy = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--hygiene") == 0) {
            pCfg->bRunHygiene = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--gpolateral") == 0) {
            pCfg->bRunGpoLateral = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--schema") == 0) {
            pCfg->bRunSchemaAudit = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--hardening") == 0) {
            pCfg->bRunHardening = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--trust") == 0) {
            pCfg->bRunTrust = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--gmsa") == 0) {
            pCfg->bRunGMSA = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--adcs") == 0) {
            pCfg->bRunADCS = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--adfs") == 0) {
            pCfg->bRunADFS = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--exchange") == 0) {
            pCfg->bRunExchange = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--sql") == 0) {
            pCfg->bRunSql = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--sccm") == 0) {
            pCfg->bRunSccm = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--dns") == 0) {
            pCfg->bRunDns = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
        if (_wcsicmp(arg, L"--machines") == 0) {
            pCfg->bRunMachineAcct = TRUE;
            pCfg->bExplicitModules = TRUE;
            continue;
        }
		if (_wcsicmp(arg, L"--gpp") == 0) {
			pCfg->bRunGPP = TRUE;
			pCfg->bExplicitModules = TRUE;
			continue;
		}

        /* ── Unknown argument ────────────────────────────────────── */
        wprintf(L"[!] Unknown argument: %s\n", arg);
        wprintf(L"    Run Kestrel.exe --help for usage\n");
        return FALSE;
    }

    /* Default: run all CORE AD modules if none specified.
       Service-posture modules are opt-in (--services / --exchange) and are
       never enabled by the no-args default or by --all, so v1.0 pipeline
       behaviour is unchanged. */
    if (!pCfg->bExplicitModules)
        KestrelEnableAllModules(pCfg);

    return TRUE;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Entry point                                                                */
/* ─────────────────────────────────────────────────────────────────────────── */

int wmain(int argc, wchar_t *argv[])
{
    KESTREL_CONFIG cfg = { 0 };

    /* Parse args — exit cleanly on --help/--version or bad args */
    if (!KestrelParseArgs(argc, argv, &cfg))
        return 0;

    KestrelPrintVersion();

    /* ── COM init ─────────────────────────────────────────────────── */
    KTRACE(L"Initializing COM...");
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        wprintf(L"[!] CoInitializeEx failed: 0x%08X\n", hr);
        return (int)hr;
    }

    WCHAR   wszDomainNC[512] = { 0 };
    WCHAR   wszConfigNC[512] = { 0 };
    WCHAR   wszRootPath[512] = { 0 };
    IADs   *pRootDSE = 0;
    KESTREL_ACL_SCAN_RESULT       *pACL    = 0;
    KESTREL_GROUP_SCAN_RESULT     *pGroup  = 0;
    KESTREL_DELEG_SCAN_RESULT     *pDeleg  = 0;
    KESTREL_LAPS_SCAN_RESULT      *pLaps   = 0;
    struct _KESTREL_POLICY_RESULT *pPolicy = 0;
    KESTREL_GRAPH                 *pGraph  = 0;
    KESTREL_PATH_RESULT           *pPaths  = 0;
    KESTREL_ROAST_SCAN_RESULT     *pRoast  = 0;
    KESTREL_TRUST_SCAN_RESULT     *pTrust  = 0;
    KESTREL_SIDHISTORY_SCAN_RESULT *pSidHist = 0;
    KESTREL_GPOLATERAL_SCAN_RESULT *pGpoLat = 0;
    KESTREL_GMSA_SCAN_RESULT      *pGMSA   = 0;
    KESTREL_ADCS_SCAN_RESULT      *pADCS   = 0;
    KESTREL_GPP_SCAN_RESULT       * pGPP   = 0;
    VARIANT varDomain, varConfig = { 0 };
    VariantInit( & varDomain );
    VariantInit( & varConfig );

    /* ── Resolve rootDSE ──────────────────────────────────────────── */
    KTRACE(L"Connecting to LDAP://rootDSE...");
    hr = ADsGetObject(L"LDAP://rootDSE", &IID_IADs, (void**)&pRootDSE);
    if (FAILED(hr)) {
        wprintf(L"[!] rootDSE bind failed: 0x%08X\n", hr);
        KTRACE(L"Not domain-joined or DC unreachable");
        goto Cleanup;
    }

    if (SUCCEEDED(pRootDSE->lpVtbl->Get(pRootDSE,
        L"defaultNamingContext", &varDomain)) &&
        varDomain.vt == VT_BSTR) {
        StringCchCopyW(wszDomainNC, ARRAYSIZE(wszDomainNC), varDomain.bstrVal);
        KTRACE(L"Domain NC: %s", wszDomainNC);
    }

    if (SUCCEEDED(pRootDSE->lpVtbl->Get(pRootDSE,
        L"configurationNamingContext", &varConfig)) &&
        varConfig.vt == VT_BSTR) {
        StringCchCopyW(wszConfigNC, ARRAYSIZE(wszConfigNC), varConfig.bstrVal);
        KTRACE(L"Config NC: %s", wszConfigNC);
    }

    pRootDSE->lpVtbl->Release(pRootDSE);
    VariantClear(&varDomain);
    VariantClear(&varConfig);

    if (wszDomainNC[0] == L'\0') {
        wprintf(L"[!] No domain context — cannot proceed\n");
        goto Cleanup;
    }

    StringCchPrintfW(wszRootPath, ARRAYSIZE(wszRootPath),
        L"LDAP://%s", wszDomainNC);

    wprintf(L"[*] Domain: %s\n", wszDomainNC);

    /* ── v0.1 modules ─────────────────────────────────────────────── */
    if (cfg.bRunADWS || cfg.bRunTopology ||
        cfg.bRunDelegation || cfg.bRunLAPS || cfg.bRunStale) {

        wprintf(L"\n═══ Kestrel v0.1 — AD Passive Scan ═══\n\n");
        hr = RunADWSScan();
        if (FAILED(hr))
            wprintf(L"[!] RunADWSScan reported errors: 0x%08X\n", hr);
        KTRACE(L"v0.1 complete");
    }

    /* ── v0.2: ACL edge extraction ───────────────────────────────── */
    if (cfg.bRunACL) {
        wprintf(L"\n═══ Kestrel v0.2 — ACL Edge Scan ═══\n\n");
        hr = KestrelScanACLEdges(wszDomainNC, wszConfigNC, &pACL);
        if (FAILED(hr))
            wprintf(L"[!] KestrelScanACLEdges failed: 0x%08X\n", hr);
        KTRACE(L"v0.2 complete — edges: %lu", pACL ? pACL->cEdges : 0);
        wprintf(L"\n═══ Kestrel — DCSync Rights Analysis ═══\n\n");
        DWORD cDCSync = KestrelAnalyzeDCSync(pACL);
        KTRACE(L"DCSync analysis complete — critical principals: %lu\n", cDCSync);
        wprintf(L"\n═══ Kestrel — MAQ + RBCD Weaponizability ═══\n\n");
        DWORD cRbcd = KestrelAnalyzeRbcdWeaponizable(pACL, wszDomainNC);
        KTRACE(L"RBCD analysis complete — write-on-computer paths: %lu", cRbcd);
    }

    /* ── v0.3: transitive group membership ───────────────────────── */
    if (cfg.bRunGroups) {
        hr = KestrelRunGroupScan(wszRootPath, pACL, &pGroup);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunGroupScan failed: 0x%08X\n", hr);
        KTRACE(L"v0.3 complete — groups: %lu", pGroup ? pGroup->cGroups : 0);
    }

    /* ── v0.4: delegation + LAPS (graph fed below) ───────────────── */
    if (cfg.bRunDelegation) {
        wprintf(L"\n═══ Kestrel v0.4 — Delegation Surface ═══\n\n");
        hr = KestrelScanDelegation(wszDomainNC, &pDeleg);
        if (FAILED(hr))
            wprintf(L"[!] KestrelScanDelegation failed: 0x%08X\n", hr);
        KTRACE(L"delegation complete — findings: %lu",
            pDeleg ? pDeleg->cFindings : 0);
    }

    if (cfg.bRunLAPS) {
        wprintf(L"\n═══ Kestrel v0.4 — LAPS Readability ═══\n\n");
        hr = KestrelScanLapsReaders(wszDomainNC, wszConfigNC, &pLaps);
        if (FAILED(hr))
            wprintf(L"[!] KestrelScanLapsReaders failed: 0x%08X\n", hr);
        KTRACE(L"LAPS complete — reader grants: %lu",
            pLaps ? pLaps->cReaders : 0);
    }

    /* ── v0.5: GPO policy audit ──────────────────────────────────── */
    if (cfg.bRunPolicy) {
        hr = KestrelRunPolicyAudit(wszDomainNC, &pPolicy);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunPolicyAudit failed: 0x%08X\n", hr);
    }

    /* ── v0.6: Kerberoastable + AS-REP Roastable scan ────────────── */
    if (cfg.bRunRoast) {
        wprintf(L"\n═══ Kestrel v0.6 — Roastable Account Scan ═══\n\n");
        hr = KestrelRunRoastScan(wszDomainNC, &pRoast);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunRoastScan failed: 0x%08X\n", hr);
        KTRACE(L"Roast scan complete — kerberoastable: %lu, asrep: %lu",
            pRoast ? pRoast->cKerberoastable : 0,
            pRoast ? pRoast->cASREP : 0);
    }

    /* ── shadow credentials (msDS-KeyCredentialLink) ──────────────── */
    if (cfg.bRunShadowCreds) {
        wprintf(L"\n═══ Kestrel — Shadow Credential Scan ═══\n\n");
        hr = KestrelRunShadowCredScan(wszDomainNC);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunShadowCredScan failed: 0x%08X\n", hr);
    }

    /* ── SID history (sIDHistory) ─────────────────────────────────── */
    if (cfg.bRunSidHistory) {
        wprintf(L"\n═══ Kestrel — SID History Scan ═══\n\n");
        hr = KestrelRunSidHistoryScan(wszDomainNC, &pSidHist);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunSidHistoryScan failed: 0x%08X\n", hr);
    }

    /* ── GPO local-group membership → lateral edges ───────────────── */
    if (cfg.bRunGpoLateral) {
        wprintf(L"\n═══ Kestrel — GPO Lateral-Movement Edges ═══\n\n");
        hr = KestrelRunGpoLateralScan(wszDomainNC, &pGpoLat);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunGpoLateralScan failed: 0x%08X\n", hr);
    }

    /* ── orphaned adminCount (AdminSDHolder) ──────────────────────── */
    if (cfg.bRunAdminSDHolder) {
        wprintf(L"\n═══ Kestrel — AdminSDHolder Orphan Scan ═══\n\n");
        hr = KestrelRunAdminSDHolderScan(wszDomainNC);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunAdminSDHolderScan failed: 0x%08X\n", hr);
    }

    /* ── entry-condition posture (password policy / PSO / krbtgt / MAQ) ── */
    if (cfg.bRunPwdPolicy) {
        wprintf(L"\n═══ Kestrel — Password Policy & Entry-Condition Posture ═══\n\n");
        hr = KestrelRunPwdPolicyScan(wszDomainNC);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunPwdPolicyScan failed: 0x%08X\n", hr);
    }

    /* ── credential hygiene (UAC flags + description secrets) ──────── */
    if (cfg.bRunHygiene) {
        wprintf(L"\n═══ Kestrel — Credential Hygiene ═══\n\n");
        hr = KestrelRunHygieneScan(wszDomainNC);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunHygieneScan failed: 0x%08X\n", hr);
    }

    /* ── schema defaultSecurityDescriptor audit ───────────────────── */
    if (cfg.bRunSchemaAudit) {
        wprintf(L"\n═══ Kestrel — Schema Default-SD Audit ═══\n\n");
        hr = KestrelRunSchemaAuditScan(wszDomainNC);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunSchemaAuditScan failed: 0x%08X\n", hr);
    }

    if (cfg.bRunHardening) {
        wprintf(L"\n═══ Kestrel — Domain Hardening Flags ═══\n");
        hr = KestrelRunHardeningScan(wszConfigNC, wszDomainNC);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunHardeningScan failed: 0x%08X\n", hr);
    }

    /* ── v0.7: domain trust posture audit ────────────────────────── */
    if (cfg.bRunTrust) {
        wprintf(L"\n═══ Kestrel v0.7 — Domain Trust Posture ═══\n\n");
        hr = KestrelRunTrustScan(wszDomainNC, &pTrust);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunTrustScan failed: 0x%08X\n", hr);
        KTRACE(L"trust scan complete — objects: %lu, risky: %lu",
            pTrust ? pTrust->cObjectsScanned : 0,
            pTrust ? pTrust->cRisky : 0);
    }

    if (cfg.bRunGPP) {
        wprintf(L"\n═══ Kestrel — SYSVOL Secret Sweep ═══\n\n");
        hr = KestrelRunGPPScan(wszDomainNC, &pGPP);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunGPPScan failed: 0x%08X\n", hr);
        KTRACE(L"GPP scan complete — files: %lu, findings: %lu",
            pGPP ? pGPP->cFilesScanned : 0,
            pGPP ? pGPP->cFindings : 0);
    }

   

    /* ── v0.7: AD CS posture audit (ESC1-5/9) ────────────────────── */
    if (cfg.bRunADCS) {
        wprintf(L"\n═══ Kestrel v0.7 — AD CS Posture (ESC1-5/9) ═══\n\n");
        hr = KestrelRunADCSScan(wszConfigNC, &pADCS);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunADCSScan failed: 0x%08X\n", hr);
        KTRACE(L"ADCS scan complete — templates: %lu, findings: %lu",
            pADCS ? pADCS->cTemplates : 0,
            pADCS ? pADCS->cVulnerable : 0);
    }

    /* ── v0.17: AD FS DKM key ACL audit (Golden SAML precondition) ── */
    if (cfg.bRunADFS) {
        wprintf(L"\n═══ Kestrel — AD FS DKM Key ACL ═══\n");
        hr = KestrelRunADFSDkmScan(wszDomainNC);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunADFSDkmScan failed: 0x%08X\n", hr);
    }

    if (cfg.bRunExchange) {
        wprintf(L"\n═══ Kestrel — Exchange Posture ═══\n");
        hr = KestrelRunExchangeScan(wszConfigNC, wszDomainNC);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunExchangeScan failed: 0x%08X\n", hr);
    }

    if (cfg.bRunSql) {
        wprintf(L"\n═══ Kestrel — SQL Server Posture ═══\n");
        hr = KestrelRunSqlScan(wszDomainNC);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunSqlScan failed: 0x%08X\n", hr);
    }

    if (cfg.bRunSccm) {
        wprintf(L"\n═══ Kestrel — SCCM / MECM Posture ═══\n");
        hr = KestrelRunSccmScan(wszDomainNC);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunSccmScan failed: 0x%08X\n", hr);
    }

    if (cfg.bRunDns) {
        wprintf(L"\n═══ Kestrel — DNS (ADIDNS) Posture ═══\n");
        hr = KestrelRunDnsScan(wszDomainNC);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunDnsScan failed: 0x%08X\n", hr);
    }

    /* ── machine accounts created through MachineAccountQuota ────── */
    if (cfg.bRunMachineAcct) {
        wprintf(L"\n═══ Kestrel — Machine Accounts (quota footprint) ═══\n");
        hr = KestrelRunMachineAcctScan(wszDomainNC);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunMachineAcctScan failed: 0x%08X\n", hr);
    }

    /* ── v0.7: gMSA password reader enumeration ──────────────────── */
    if (cfg.bRunGMSA) {
        wprintf(L"\n═══ Kestrel v0.7 — gMSA Password Reader Scan ═══\n\n");
        hr = KestrelRunGMSAScan(wszDomainNC, &pGMSA);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunGMSAScan failed: 0x%08X\n", hr);
        KTRACE(L"gMSA scan complete — objects: %lu, readers: %lu",
            pGMSA ? pGMSA->cGmsaScanned : 0,
            pGMSA ? pGMSA->cReaders : 0);
    }

    /* ── v0.4: build graph + report (HTML / JSON / YAML by extension) ── */
    if (cfg.bRunACL || cfg.bRunGroups || cfg.bRunDelegation ||
        cfg.bRunLAPS || cfg.bRunPaths || cfg.bRunGMSA || cfg.bRunRoast ||
        cfg.bRunTrust || cfg.bRunADCS || cfg.bRunSidHistory || cfg.bRunGpoLateral) {
        hr = KestrelBuildGraph(pACL, pGroup, pDeleg, pLaps, pGMSA, pRoast,
                               pTrust, pADCS, wszDomainNC, &pGraph);
        if (FAILED(hr)) {
            wprintf(L"[!] KestrelBuildGraph failed: 0x%08X\n", hr);
        }
        else {
            /* tag tier-0 (also enriches the report's high-value rings) */
            KestrelTagHighValue(pGraph);

            /* fold sIDHistory findings in as HasSIDHistory edges */
            if (pSidHist) {
                hr = KestrelGraphAddSidHistoryEdges(pGraph, pSidHist);
                if (FAILED(hr))
                    wprintf(L"[!] KestrelGraphAddSidHistoryEdges failed: 0x%08X\n", hr);
            }

            /* fold GPO local-group grants in as AdminTo/CanRDP/… edges */
            if (pGpoLat) {
                hr = KestrelGraphAddGpoLateralEdges(pGraph, pGpoLat);
                if (FAILED(hr))
                    wprintf(L"[!] KestrelGraphAddGpoLateralEdges failed: 0x%08X\n", hr);
            }

            /* ADeleg-class: low-privilege trustee → Tier-0 resource */
            KestrelGraphReportLowToHigh(pGraph);

            /* v0.5: attack-path analysis */
            if (cfg.bRunPaths) {
                hr = KestrelFindPaths(pGraph,
                        cfg.wszFrom[0] ? cfg.wszFrom : NULL, &pPaths);
                if (FAILED(hr))
                    wprintf(L"[!] KestrelFindPaths failed: 0x%08X\n", hr);
            }

            if (cfg.wszReportPath[0] != L'\0') {
                hr = KestrelWriteReportAuto(pGraph, cfg.wszReportPath);
                if (FAILED(hr))
                    wprintf(L"[!] KestrelWriteReportAuto failed: 0x%08X\n", hr);
            }
            else {
                wprintf(L"\n[*] Graph: %lu nodes, %lu edges\n",
                    pGraph ? pGraph->cNodes : 0,
                    pGraph ? pGraph->cEdges : 0);
                wprintf(L"[*] Use --report <path.html|.json|.yaml> to generate a report\n");
            }

            if (cfg.wszOpenGraphPath[0] != L'\0') {
                hr = KestrelWriteOpenGraph(pGraph, cfg.wszOpenGraphPath);
                if (FAILED(hr))
                    wprintf(L"[!] KestrelWriteOpenGraph failed: 0x%08X\n", hr);
            }

            if (cfg.wszDiffPath[0] != L'\0')
                KestrelRunDiff(pGraph, cfg.wszDiffPath);
        }
    }

    /* One severity-sorted triage table across every scan that ran. */
    KestrelPrintFindingSummary();

Cleanup:
    KTRACE(L"Cleanup...");
    KestrelFreeFindings();
    KestrelFreeACLScanResult(pACL);
    KestrelFreeGroupScanResult(pGroup);
    KestrelFreeDelegScanResult(pDeleg);
    KestrelFreeLapsScanResult(pLaps);
    KestrelFreePolicyResult(pPolicy);
    KestrelFreePathResult(pPaths);
    KestrelFreeRoastScanResult(pRoast);
    KestrelFreeSidHistoryScanResult(pSidHist);
    KestrelFreeGpoLateralScanResult(pGpoLat);
    KestrelFreeTrustScanResult(pTrust);
    KestrelFreeGMSAScanResult(pGMSA);
    KestrelFreeADCSScanResult(pADCS);
    KestrelFreeGPPScanResult(pGPP);
    KestrelFreeGraph(pGraph);
    CoUninitialize();
    return HRESULT_CODE(hr);
}
