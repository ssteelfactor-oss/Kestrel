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
 *
 * Output:
 *   --report <path>  Generate HTML report
 *
 * Options:
 *   --verbose / -v   Enable trace output
 *   --version        Show version and exit
 *   --help / -h      Show this help and exit
 */

#include "../include/Kestrel.h"

BOOL g_bVerbose = FALSE;

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
        L"  --all          Run all modules\n"
        L"  --adws         ADWS endpoint detection (port 9389/TCP per DC)\n"
        L"  --topology     Computer topology via SPN decoding\n"
        L"  --delegation   Delegation risks (unconstrained/constrained/S4U2Self)\n"
        L"  --laps         LAPS coverage (legacy + Windows LAPS 2023+)\n"
        L"  --stale        Stale computers via lastLogonTimestamp\n"
        L"  --acl          ACL edge extraction via IDirectoryObject\n"
        L"  --groups       Transitive group membership via LDAP_MATCHING_RULE_IN_CHAIN\n"
        L"  --policy       GPO security policy audit (LLMNR/NBT-NS/WDigest/NTLMv1)\n"
        L"  --paths        Attack-path analysis over the graph (to tier-0)\n"
        L"  --from <prin>  Paths FROM a principal (SID/name); implies --paths\n\n"
        L"OUTPUT:\n"
        L"  --report <path>  Generate report (.html / .json / .yaml by extension)\n\n"
        L"OPTIONS:\n"
        L"  --verbose / -v   Enable trace output\n"
        L"  --version        Show version and exit\n"
        L"  --help / -h      Show this help and exit\n\n"
        L"EXAMPLES:\n"
        L"  Kestrel.exe\n"
        L"  Kestrel.exe --report C:\\out\\report.html\n"
        L"  Kestrel.exe --acl --groups --report C:\\out\\report.html\n"
        L"  Kestrel.exe --delegation --verbose\n"
        L"  Kestrel.exe --report %%USERPROFILE%%\\Desktop\\report.html\n\n"
    );
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Argument parser                                                            */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL
KestrelParseArgs(
    _In_  int             argc,
    _In_  wchar_t* argv[],
    _Out_ KESTREL_CONFIG* pCfg)
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

        /* ── Modules ─────────────────────────────────────────────── */
        if (_wcsicmp(arg, L"--all") == 0) {
            pCfg->bRunADWS = TRUE;
            pCfg->bRunTopology = TRUE;
            pCfg->bRunDelegation = TRUE;
            pCfg->bRunLAPS = TRUE;
            pCfg->bRunStale = TRUE;
            pCfg->bRunACL = TRUE;
            pCfg->bRunGroups = TRUE;
            pCfg->bRunPolicy = TRUE;
            pCfg->bRunPaths = TRUE;
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

        /* ── Unknown argument ────────────────────────────────────── */
        wprintf(L"[!] Unknown argument: %s\n", arg);
        wprintf(L"    Run Kestrel.exe --help for usage\n");
        return FALSE;
    }

    /* Default: run all modules if none specified */
    if (!pCfg->bExplicitModules) {
        pCfg->bRunADWS = TRUE;
        pCfg->bRunTopology = TRUE;
        pCfg->bRunDelegation = TRUE;
        pCfg->bRunLAPS = TRUE;
        pCfg->bRunStale = TRUE;
        pCfg->bRunACL = TRUE;
        pCfg->bRunGroups = TRUE;
        pCfg->bRunPolicy = TRUE;
        pCfg->bRunPaths = TRUE;
    }

    return TRUE;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Entry point                                                                */
/* ─────────────────────────────────────────────────────────────────────────── */

int wmain(int argc, wchar_t* argv[])
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
    IADs* pRootDSE = 0;
    KESTREL_ACL_SCAN_RESULT* pACL = 0;
    KESTREL_GROUP_SCAN_RESULT* pGroup = 0;
    KESTREL_DELEG_SCAN_RESULT* pDeleg = 0;
    KESTREL_LAPS_SCAN_RESULT*  pLaps  = 0;
    struct _KESTREL_POLICY_RESULT* pPolicy = 0;
    KESTREL_GRAPH* pGraph = 0;
    KESTREL_PATH_RESULT* pPaths = 0;
    VARIANT varDomain, varConfig;
    VariantInit(&varDomain);
    VariantInit(&varConfig);

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
    }

    /* ── v0.3: transitive group membership ───────────────────────── */
    if (cfg.bRunGroups) {
        hr = KestrelRunGroupScan(wszRootPath, pACL, &pGroup);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunGroupScan failed: 0x%08X\n", hr);
        KTRACE(L"v0.3 complete — groups: %lu", pGroup ? pGroup->cGroups : 0);
    }

    /* ── v0.4: build graph + report (HTML / JSON / YAML by extension) ── */
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

    /* ── v0.5: GPO policy audit (LLMNR / NBT-NS / WDigest / NTLMv1 / LDAP signing) ── */
    if (cfg.bRunPolicy) {
        hr = KestrelRunPolicyAudit(wszDomainNC, &pPolicy);
        if (FAILED(hr))
            wprintf(L"[!] KestrelRunPolicyAudit failed: 0x%08X\n", hr);
    }

    if (cfg.bRunACL || cfg.bRunGroups || cfg.bRunDelegation || cfg.bRunLAPS || cfg.bRunPaths) {
        hr = KestrelBuildGraph(pACL, pGroup, pDeleg, pLaps, &pGraph);
        if (FAILED(hr)) {
            wprintf(L"[!] KestrelBuildGraph failed: 0x%08X\n", hr);
        }
        else {
            /* tag tier-0 (also enriches the report's high-value rings) */
            KestrelTagHighValue(pGraph);

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
        }
    }

Cleanup:
    KTRACE(L"Cleanup...");
    KestrelFreeACLScanResult(pACL);
    KestrelFreeGroupScanResult(pGroup);
    KestrelFreeDelegScanResult(pDeleg);
    KestrelFreeLapsScanResult(pLaps);
    KestrelFreePolicyResult(pPolicy);
    KestrelFreePathResult(pPaths);
    KestrelFreeGraph(pGraph);
    CoUninitialize();
    return HRESULT_CODE(hr);
}
