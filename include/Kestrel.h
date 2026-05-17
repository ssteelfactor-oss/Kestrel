/*
 * Kestrel.h
 * Public API — shared types and forward declarations for all Kestrel modules.
 *
 * Module map:
 *   adws_scan.c    — v0.1  five passive AD scans
 *   KestrelACL.C   — v0.2  ACL edge extraction
 *   KestrelGroup.c — v0.3  transitive group membership
 *   KestrelGraph.c — v0.4  in-memory graph (planned)
 *   KestrelPath.c  — v0.5  BFS path finder (planned)
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
#include <sddl.h>
#include <strsafe.h>
#include <sal.h>

#pragma comment(lib, "activeds.lib")
#pragma comment(lib, "adsiid.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

/* ═══════════════════════════════════════════════════════════════════════════
 * Shared constants
 * ═══════════════════════════════════════════════════════════════════════════ */

#define KESTREL_LDAP_PAGESIZE       200
#define KESTREL_ADWS_PORT           9389
#define KESTREL_PROBE_TIMEOUT_MS    2000
#define KESTREL_STALE_DAYS          90
#define KESTREL_FT_PER_DAY          (10000000ULL * 86400ULL)

/* ═══════════════════════════════════════════════════════════════════════════
 * Shared types — KestrelACL.C
 * ═══════════════════════════════════════════════════════════════════════════ */

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

/* ═══════════════════════════════════════════════════════════════════════════
 * Shared types — KestrelGroup.c
 * ═══════════════════════════════════════════════════════════════════════════ */

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

/* ═══════════════════════════════════════════════════════════════════════════
 * adws_scan.c — v0.1
 * ═══════════════════════════════════════════════════════════════════════════ */

_Must_inspect_result_
HRESULT RunADWSScan(void);

/* ═══════════════════════════════════════════════════════════════════════════
 * KestrelACL.C — v0.2
 * ═══════════════════════════════════════════════════════════════════════════ */

_Must_inspect_result_
HRESULT KestrelScanACLEdges(
    _In_z_   LPCWSTR                  pwszDomainNC,
    _In_z_   LPCWSTR                  pwszConfigNC,
    _Outptr_ KESTREL_ACL_SCAN_RESULT **ppResult);

VOID KestrelFreeACLScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_ACL_SCAN_RESULT *pResult);

/* ═══════════════════════════════════════════════════════════════════════════
 * KestrelGroup.c — v0.3
 * ═══════════════════════════════════════════════════════════════════════════ */

_Must_inspect_result_
HRESULT KestrelRunGroupScan(
    _In_z_   LPCWSTR                    pwszRootPath,
    _In_opt_ KESTREL_ACL_SCAN_RESULT   *pACLResult,
    _Outptr_ KESTREL_GROUP_SCAN_RESULT **ppResult);

VOID KestrelFreeGroupScanResult(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GROUP_SCAN_RESULT *pResult);
