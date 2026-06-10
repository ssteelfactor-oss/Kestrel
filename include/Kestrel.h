/*
 * Kestrel.h
 * Public API — shared types and forward declarations for all Kestrel modules.
 *
 * Module map:
 *   adws_scan.c     — v0.1  five passive AD scans
 *   KestrelACL.C    — v0.2  ACL edge extraction
 *   KestrelGroup.c  — v0.3  transitive group membership
 *   KestrelReport.c — v0.4  in-memory graph + HTML report
 *   KestrelPath.c   — v0.5  BFS path finder
 *   KestrelRoast.c  — v0.6  Kerberoastable + AS-REP Roastable detection
 */

#pragma once

#define COBJMACROS
#define CINTERFACE

/* winsock2.h MUST precede windows.h */
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
#include <wchar.h>
#include <stdint.h>
#include <sddl.h>
#include <strsafe.h>
#include <sal.h>

#pragma comment(lib, "activeds.lib")
#pragma comment(lib, "adsiid.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

/* ════════════════════════════════════════════════════════════════════════════
 * Shared constants
 * ════════════════════════════════════════════════════════════════════════════ */

#define KESTREL_LDAP_PAGESIZE       200
#define KESTREL_ADWS_PORT           9389
#define KESTREL_PROBE_TIMEOUT_MS    2000
#define KESTREL_STALE_DAYS          90
#define KESTREL_FT_PER_DAY          (10000000ULL * 86400ULL)

#define KESTREL_VERSION L"0.6-dev"

typedef struct _KESTREL_CONFIG {
    /* Modules */
    BOOL bRunADWS;
    BOOL bRunTopology;
    BOOL bRunDelegation;
    BOOL bRunLAPS;
    BOOL bRunStale;
    BOOL bRunACL;
    BOOL bRunGroups;
    BOOL bRunPolicy;    /* v0.5 GPO policy audit   */
    BOOL bRunPaths;     /* v0.5 attack-path finder */
    BOOL bRunRPC;       /* v0.5                    */
    BOOL bRunRoast;     /* v0.6 Kerberoast / AS-REP Roast scan */
    BOOL bRunTrust;     /* v0.7 trust posture audit */
    /* Output */
    WCHAR wszReportPath[512];
    WCHAR wszFrom[256];        /* path finder source; empty = to-tier-0 */

    /* Options */
    BOOL bVerbose;
    BOOL bExplicitModules; /* TRUE если хоть один модуль задан явно */
} KESTREL_CONFIG;


/* Logging */
extern BOOL g_bVerbose;
#define KTRACE(fmt, ...) \
    if (g_bVerbose) wprintf(L"[TRACE] " fmt L"\n", ##__VA_ARGS__)

/* ════════════════════════════════════════════════════════════════════════════
 * Shared types — KestrelACL.C
 * ════════════════════════════════════════════════════════════════════════════ */

typedef enum _KESTREL_ACL_EDGE_TYPE {
    EDGE_UNKNOWN        = 0,
    EDGE_GENERIC_ALL    = 1,
    EDGE_WRITE_DACL     = 2,
    EDGE_WRITE_OWNER    = 3,
    EDGE_GENERIC_WRITE  = 4,
    EDGE_EXTENDED_RIGHT = 5,
    EDGE_WRITE_PROPERTY = 6,
    EDGE_CREATE_CHILD   = 7,
    EDGE_DELETE_CHILD   = 8,
    EDGE_SELF           = 9,
} KESTREL_ACL_EDGE_TYPE;

typedef struct _KESTREL_ACL_EDGE {
    WCHAR                  wszTrusteeSid[128];
    WCHAR                  wszTargetDN[512];
    WCHAR                  wszObjectClass[64];
    KESTREL_ACL_EDGE_TYPE  EdgeType;
    WCHAR                  wszRightName[128];
    WCHAR                  wszRightGuid[64];
    BOOL                   bInherited;
    BOOL                   bDeny;
} KESTREL_ACL_EDGE;

typedef struct _KESTREL_ACL_SCAN_RESULT {
    KESTREL_ACL_EDGE  *rgEdges;
    DWORD              cEdges;
    DWORD              cCapacity;
    DWORD              cObjectsScanned;
    DWORD              cObjectsErrored;
} KESTREL_ACL_SCAN_RESULT;

/* ── Delegation ──────────────────────────────────────────────────────────── */
typedef enum _KESTREL_DELEG_KIND {
    DELEG_UNCONSTRAINED = 0,
    DELEG_CONSTRAINED,             /* Kerberos-only                    */
    DELEG_CONSTRAINED_PROTOTRANS,  /* + TRUSTED_TO_AUTH (S4U2Self)     */
    DELEG_RBCD                     /* resource-based, allowed principal */
} KESTREL_DELEG_KIND;

typedef struct _KESTREL_DELEG_FINDING {
    WCHAR              wszDN[512];
    WCHAR              wszSam[64];
    WCHAR              wszObjectClass[64];
    KESTREL_DELEG_KIND Kind;
    WCHAR              wszDetail[512];  /* SPN, allowed-SID, or marker */
} KESTREL_DELEG_FINDING;

typedef struct _KESTREL_DELEG_SCAN_RESULT {
    KESTREL_DELEG_FINDING* rgFindings;
    DWORD                  cFindings;
    DWORD                  cCapacity;
    DWORD                  cObjectsScanned;
    DWORD                  cObjectsErrored;
} KESTREL_DELEG_SCAN_RESULT;

typedef struct _KESTREL_LAPS_READER {
    WCHAR wszComputerDN[512];
    WCHAR wszTrusteeSid[64];
    WCHAR wszAttr[64];
    BOOL  bAllProperties;
} KESTREL_LAPS_READER;

typedef struct _KESTREL_LAPS_SCAN_RESULT {
    KESTREL_LAPS_READER* rgReaders;
    DWORD                cReaders;
    DWORD                cCapacity;
    DWORD                cComputersScanned;
    DWORD                cComputersErrored;
    BOOL                 bLegacyLapsPresent;
    BOOL                 bWindowsLapsPresent;
} KESTREL_LAPS_SCAN_RESULT;

/* ════════════════════════════════════════════════════════════════════════════
 * Shared types — KestrelGroup.c
 * ════════════════════════════════════════════════════════════════════════════ */

typedef struct _KESTREL_MEMBER {
    WCHAR   wszDN[512];
    WCHAR   wszSAM[128];
    WCHAR   wszSid[128];
    WCHAR   wszClass[64];
    BOOL    bEnabled;
    struct _KESTREL_MEMBER *pNext;
} KESTREL_MEMBER;

typedef struct _KESTREL_GROUP_RESULT {
    WCHAR             wszGroupDN[512];
    WCHAR             wszGroupName[128];
    KESTREL_MEMBER   *pMembers;
    DWORD             cMembers;
    DWORD             cEnabled;
    struct _KESTREL_GROUP_RESULT *pNext;
} KESTREL_GROUP_RESULT;

typedef struct _KESTREL_GROUP_SCAN_RESULT {
    KESTREL_GROUP_RESULT *pGroups;
    DWORD                 cGroups;
    DWORD                 cErrors;
} KESTREL_GROUP_SCAN_RESULT;

/* ════════════════════════════════════════════════════════════════════════════
 * Shared types — KestrelReport.c (v0.4)
 * ════════════════════════════════════════════════════════════════════════════ */

#define KESTREL_GRAPH_HASH_SIZE  4096
#define KESTREL_GRAPH_HASH_MASK  (KESTREL_GRAPH_HASH_SIZE - 1)
#define KESTREL_EDGE_INITIAL_CAP 8192

typedef enum _KESTREL_NODE_CLASS {
    NODE_CLASS_UNKNOWN   = 0,
    NODE_CLASS_USER      = 1,
    NODE_CLASS_GROUP     = 2,
    NODE_CLASS_COMPUTER  = 3,
    NODE_CLASS_OU        = 4,
    NODE_CLASS_DOMAIN    = 5,
    NODE_CLASS_GPO       = 6,
    NODE_CLASS_CONTAINER = 7,
} KESTREL_NODE_CLASS;

typedef enum _KESTREL_GRAPH_EDGE_TYPE {
    GEDGE_ACL_GENERIC_ALL = 0,
    GEDGE_ACL_WRITE_DACL,
    GEDGE_ACL_WRITE_OWNER,
    GEDGE_ACL_GENERIC_WRITE,
    GEDGE_ACL_EXTENDED_RIGHT,
    GEDGE_ACL_WRITE_PROP,
    GEDGE_MEMBER_OF,
    GEDGE_DELEG_UNCONSTRAINED,   /* 7  "Delegation_Unconstrained" */
    GEDGE_DELEG_CONSTRAINED,     /* 8  "Delegation_Constrained"   */
    GEDGE_DELEG_S4U2SELF,        /* 9  "Delegation_S4U2Self"      */
    GEDGE_DELEG_RBCD,            /* 10 "Delegation_RBCD"          */
    GEDGE_CAN_READ_LAPS          /* 11 "CanReadLAPS"              */
} KESTREL_GRAPH_EDGE_TYPE;

typedef struct _KESTREL_GRAPH_NODE {
    WCHAR               wszSid[128];
    WCHAR               wszDN[512];
    WCHAR               wszLabel[128];
    KESTREL_NODE_CLASS  Class;
    BOOL                bEnabled;
    BOOL                bHighValue;
    BOOL                bUnconstrainedDeleg;
} KESTREL_GRAPH_NODE;

typedef struct _KESTREL_GRAPH_EDGE {
    DWORD                   iFrom;
    DWORD                   iTo;
    KESTREL_GRAPH_EDGE_TYPE Type;
    WCHAR                   wszDetail[128];
    BOOL                    bDeny;
} KESTREL_GRAPH_EDGE;

typedef struct _KESTREL_GRAPH_HASH_ENTRY {
    WCHAR wszSid[128];
    DWORD iNode;
} KESTREL_GRAPH_HASH_ENTRY;

typedef struct _KESTREL_GRAPH {
    KESTREL_GRAPH_NODE       *pNodes;
    DWORD                     cNodes;
    DWORD                     cNodesCapacity;
    KESTREL_GRAPH_EDGE       *pEdges;
    DWORD                     cEdges;
    DWORD                     cEdgesCapacity;
    KESTREL_GRAPH_HASH_ENTRY  rgHash[KESTREL_GRAPH_HASH_SIZE];
    DWORD                     cACLEdges;
    DWORD                     cMemberEdges;
    DWORD                     cDelegEdges;
    DWORD                     cLapsEdges;
} KESTREL_GRAPH;

typedef enum _KESTREL_REPORT_FORMAT {
    KESTREL_REPORT_HTML = 0,
    KESTREL_REPORT_JSON,
    KESTREL_REPORT_YAML
} KESTREL_REPORT_FORMAT;

/* ════════════════════════════════════════════════════════════════════════════
 * Shared types — KestrelRoast.c (v0.6)
 * ════════════════════════════════════════════════════════════════════════════ */

typedef enum _KESTREL_ROAST_KIND {
    ROAST_KERBEROASTABLE = 0,
    ROAST_ASREPROASTABLE = 1,
} KESTREL_ROAST_KIND;

typedef enum _KESTREL_ROAST_RISK {
    ROAST_RISK_LOW    = 0,
    ROAST_RISK_MEDIUM = 1,
    ROAST_RISK_HIGH   = 2,
} KESTREL_ROAST_RISK;

typedef struct _KESTREL_ROAST_FINDING {
    KESTREL_ROAST_KIND Kind;
    KESTREL_ROAST_RISK Risk;
    WCHAR    wszSAM[128];
    WCHAR    wszDN[512];
    WCHAR    wszSid[128];
    WCHAR    wszSPNs[512];   /* Kerberoastable only; values joined with "; " */
    LONGLONG llPwdLastSet;   /* FILETIME 64-bit; 0 = not set                 */
    LONGLONG llLastLogon;    /* FILETIME 64-bit; 0 = not set                 */
    DWORD    dwUAC;
} KESTREL_ROAST_FINDING;

typedef struct _KESTREL_ROAST_SCAN_RESULT {
    KESTREL_ROAST_FINDING *rgFindings;
    DWORD                  cFindings;
    DWORD                  cCapacity;
    DWORD                  cKerberoastable;
    DWORD                  cASREP;
    DWORD                  cObjectsScanned;
} KESTREL_ROAST_SCAN_RESULT;

/* ════════════════════════════════════════════════════════════════════════════
 * adws_scan.c — v0.1
 * ════════════════════════════════════════════════════════════════════════════ */

_Must_inspect_result_
HRESULT RunADWSScan(void);

/* ════════════════════════════════════════════════════════════════════════════
 * KestrelACL.C — v0.2
 * ════════════════════════════════════════════════════════════════════════════ */

_Must_inspect_result_ HRESULT KestrelScanDelegation(
    _In_z_   LPCWSTR                    pwszDomainNC,
    _Outptr_ KESTREL_DELEG_SCAN_RESULT **ppResult);

VOID KestrelFreeDelegScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_DELEG_SCAN_RESULT *pResult);

_Must_inspect_result_ HRESULT KestrelScanLapsReaders(
    _In_z_   LPCWSTR                   pwszDomainNC,
    _In_z_   LPCWSTR                   pwszConfigNC,
    _Outptr_ KESTREL_LAPS_SCAN_RESULT **ppResult);

VOID KestrelFreeLapsScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_LAPS_SCAN_RESULT *pResult);

_Must_inspect_result_
HRESULT KestrelScanACLEdges(
    _In_z_   LPCWSTR                  pwszDomainNC,
    _In_z_   LPCWSTR                  pwszConfigNC,
    _Outptr_ KESTREL_ACL_SCAN_RESULT **ppResult);

VOID KestrelFreeACLScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_ACL_SCAN_RESULT *pResult);

/* ════════════════════════════════════════════════════════════════════════════
 * KestrelGroup.c — v0.3
 * ════════════════════════════════════════════════════════════════════════════ */

_Must_inspect_result_
HRESULT KestrelRunGroupScan(
    _In_z_   LPCWSTR                    pwszRootPath,
    _In_opt_ KESTREL_ACL_SCAN_RESULT   *pACLResult,
    _Outptr_ KESTREL_GROUP_SCAN_RESULT **ppResult);

VOID KestrelFreeGroupScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GROUP_SCAN_RESULT *pResult);

/* ════════════════════════════════════════════════════════════════════════════
 * KestrelReport.c — v0.4
 * ════════════════════════════════════════════════════════════════════════════ */

_Must_inspect_result_ HRESULT KestrelBuildGraph(
    _In_opt_ KESTREL_ACL_SCAN_RESULT   *pACLResult,
    _In_opt_ KESTREL_GROUP_SCAN_RESULT *pGroupResult,
    _In_opt_ KESTREL_DELEG_SCAN_RESULT *pDelegResult,
    _In_opt_ KESTREL_LAPS_SCAN_RESULT  *pLapsResult,
    _Outptr_ KESTREL_GRAPH            **ppGraph);

_Must_inspect_result_
HRESULT KestrelWriteHTMLReport(
    _In_   const KESTREL_GRAPH *pGraph,
    _In_z_ LPCWSTR              pwszOutputPath);

VOID KestrelFreeGraph(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GRAPH *pGraph);

_Must_inspect_result_ HRESULT
KestrelWriteReport(
    _In_   const KESTREL_GRAPH  *pGraph,
    _In_z_ LPCWSTR               pwszOutputPath,
    _In_   KESTREL_REPORT_FORMAT eFormat);

_Must_inspect_result_ HRESULT
KestrelWriteReportAuto(
    _In_   const KESTREL_GRAPH *pGraph,
    _In_z_ LPCWSTR              pwszOutputPath);

/* ════════════════════════════════════════════════════════════════════════════
 * KestrelPolicy.c — v0.5 GPO security policy audit
 * ════════════════════════════════════════════════════════════════════════════ */



/* ════════════════════════════════════════════════════════════════════════════
 * KestrelPath.c — v0.5
 * ════════════════════════════════════════════════════════════════════════════ */

typedef struct _KESTREL_PATH {
    DWORD                   *rgNodes;   /* node indices, source..target          */
    KESTREL_GRAPH_EDGE_TYPE *rgEdges;   /* cHops entries; edge i links node i->i+1 */
    DWORD                    cHops;     /* number of edges; nodes = cHops + 1   */
} KESTREL_PATH;

typedef struct _KESTREL_PATH_RESULT {
    KESTREL_PATH *rgPaths;
    DWORD         cPaths;
    DWORD         cCapacity;
    DWORD         cTargets;     /* high-value targets considered */
    DWORD         cReachable;   /* targets with >= 1 path        */
    BOOL          bCapped;      /* output truncated by cap       */
} KESTREL_PATH_RESULT;

DWORD KestrelTagHighValue(_Inout_ KESTREL_GRAPH *pGraph);

_Must_inspect_result_ HRESULT KestrelFindPaths(
    _In_       const KESTREL_GRAPH  *pGraph,
    _In_opt_z_ LPCWSTR               pwszFrom,
    _Outptr_   KESTREL_PATH_RESULT **ppResult);

VOID KestrelFreePathResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_PATH_RESULT *pResult);

//struct _KESTREL_POLICY_RESULT;   /* defined in KestrelPolicy.c */

_Must_inspect_result_ HRESULT
KestrelRunPolicyAudit(
    _In_z_   LPCWSTR                         pwszDomainNC,
    _Outptr_ struct _KESTREL_POLICY_RESULT** ppResult);

VOID KestrelFreePolicyResult(
    _In_opt_ _Post_ptr_invalid_ struct _KESTREL_POLICY_RESULT* pResult);

/* ════════════════════════════════════════════════════════════════════════════
 * KestrelRoast.c — v0.6
 * ════════════════════════════════════════════════════════════════════════════ */

_Must_inspect_result_
HRESULT KestrelRunRoastScan(
    _In_z_   LPCWSTR                    pwszDomainNC,
    _Outptr_ KESTREL_ROAST_SCAN_RESULT **ppResult);

VOID KestrelFreeRoastScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_ROAST_SCAN_RESULT *pResult);

/*
 * Post-process pACL to find principals with DS-Replication rights.
 * No LDAP traffic. Returns count of non-default principals with full
 * DCSync capability (GetChanges + GetChangesAll on domainDNS object).
 */
_Must_inspect_result_
DWORD KestrelAnalyzeDCSync(
    _In_opt_ const KESTREL_ACL_SCAN_RESULT* pACL);

/* ════════════════════════════════════════════════════════════════════════════
 * Shared types — KestrelTrust.c (v0.7)
 * ════════════════════════════════════════════════════════════════════════════ */

typedef enum _KESTREL_TRUST_DIRECTION {
    TRUST_DIR_DISABLED = 0,
    TRUST_DIR_INBOUND = 1,
    TRUST_DIR_OUTBOUND = 2,
    TRUST_DIR_BIDIRECTIONAL = 3,
} KESTREL_TRUST_DIRECTION;

typedef enum _KESTREL_TRUST_TYPE {
    TRUST_TYPE_DOWNLEVEL = 1,   /* NT4            */
    TRUST_TYPE_UPLEVEL = 2,   /* AD             */
    TRUST_TYPE_MIT = 3,   /* Kerberos realm */
    TRUST_TYPE_DCE = 4,
} KESTREL_TRUST_TYPE;

typedef struct _KESTREL_TRUST_FINDING {
    WCHAR                   wszPartner[256];   /* trustPartner (DNS) */
    WCHAR                   wszFlatName[64];   /* NetBIOS            */
    WCHAR                   wszSid[128];       /* trusted domain SID */
    KESTREL_TRUST_DIRECTION Direction;
    KESTREL_TRUST_TYPE      Type;
    DWORD                   dwAttributes;      /* raw trustAttributes */
    BOOL                    bSidFiltering;     /* QUARANTINED_DOMAIN  */
    BOOL                    bWithinForest;
    BOOL                    bForestTransitive;
    BOOL                    bTransitive;
    BOOL                    bRC4;
    BOOL                    bTgtDelegEnabled;
    BOOL                    bTreatAsExternal;
    WCHAR                   wszRisk[256];      /* joined posture notes */
} KESTREL_TRUST_FINDING;

typedef struct _KESTREL_TRUST_SCAN_RESULT {
    KESTREL_TRUST_FINDING* rgFindings;
    DWORD                  cFindings;
    DWORD                  cCapacity;
    DWORD                  cInbound;
    DWORD                  cRisky;
    DWORD                  cObjectsScanned;
} KESTREL_TRUST_SCAN_RESULT;

_Must_inspect_result_
HRESULT KestrelRunTrustScan(
    _In_z_   LPCWSTR                     pwszDomainNC,
    _Outptr_ KESTREL_TRUST_SCAN_RESULT** ppResult);

VOID KestrelFreeTrustScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_TRUST_SCAN_RESULT* pResult);
