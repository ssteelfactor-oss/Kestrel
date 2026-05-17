/*
 * Kestrel.h
 * Public API — forward declarations for all Kestrel modules.
 *
 * Every .c file includes this header.
 * Internal (static) functions are NOT declared here.
 *
 * Module map:
 *   adws_scan.c   — v0.1  five passive AD scans
 *   KestrelACL.c  — v0.2  ACL edge extraction
 *   KestrelGraph.c — v0.4  in-memory graph (planned)
 *   KestrelPath.c  — v0.5  BFS path finder (planned)
 */

#pragma once

#define COBJMACROS
#define CINTERFACE
/* ── winsock2.h MUST precede windows.h everywhere ──────────────────────── */
#include <winsock2.h>
#include <ws2tcpip.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <activeds.h>
#include <adshlp.h>
#include <iads.h>
#include <adserr.h>
#include <stdio.h>
#include <strsafe.h>
#include <sddl.h>       /* ConvertSidToStringSidW / ConvertStringSidToSidW */
#include <sal.h>

#pragma comment(lib, "activeds.lib")
#pragma comment(lib, "adsiid.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

/* ═══════════════════════════════════════════════════════════════════════════
 * adws_scan.c — v0.1
 * ═══════════════════════════════════════════════════════════════════════════ */
#define KESTREL_LDAP_PAGESIZE       200
#define KESTREL_ADWS_PORT           9389
#define KESTREL_PROBE_TIMEOUT_MS    2000
#define KESTREL_STALE_DAYS          90
#define KESTREL_FT_PER_DAY          (10000000ULL * 86400ULL)


/*
 * RunADWSScan
 * Resolves rootDSE once, then runs all five passive scan modules.
 * Returns S_OK if all scans succeeded, E_FAIL if any scan reported an error.
 * Caller must have called CoInitializeEx before invoking this.
 */
_Must_inspect_result_
HRESULT RunADWSScan(void);

/* ═══════════════════════════════════════════════════════════════════════════
 * KestrelACL.c — v0.2
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * KESTREL_ACL_SCAN_RESULT
 * Output of KestrelScanACLEdges.
 * Flat array of edges; free via KestrelFreeACLScanResult.
 */
typedef struct _KESTREL_ACL_SCAN_RESULT KESTREL_ACL_SCAN_RESULT;

/*
 * KestrelScanACLEdges
 * Enumerates all AD objects, extracts DACL edges via IDirectoryObject.
 * Builds Extended Rights table from CN=Extended-Rights,CN=Configuration.
 *
 * Parameters:
 *   pwszDomainNC  — defaultNamingContext  (e.g. "DC=corp,DC=example,DC=com")
 *   pwszConfigNC  — configurationNamingContext
 *   ppResult      — receives allocated result; free via KestrelFreeACLScanResult
 */
_Must_inspect_result_
HRESULT KestrelScanACLEdges(
    _In_z_   LPCWSTR                  pwszDomainNC,
    _In_z_   LPCWSTR                  pwszConfigNC,
    _Outptr_ KESTREL_ACL_SCAN_RESULT **ppResult);

/*
 * KestrelFreeACLScanResult
 * Frees result allocated by KestrelScanACLEdges. Safe to call with NULL.
 */
VOID KestrelFreeACLScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_ACL_SCAN_RESULT *pResult);

/* ═══════════════════════════════════════════════════════════════════════════
 * KestrelGraph.c — v0.4 (planned)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Reserved — declarations added when module is implemented */

/* ═══════════════════════════════════════════════════════════════════════════
 * KestrelPath.c — v0.5 (planned)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Reserved — declarations added when module is implemented */
