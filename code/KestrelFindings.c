/*
 * KestrelFindings.c — prioritized findings registry
 *
 * Kestrel's per-module output is deliberately verbose: each scan prints
 * everything it sees, in context. On a full run that is a wall of text where a
 * critical finding (a rogue CA in the NTAuth store) sits next to an
 * informational one (a spray-safe lockout policy).
 *
 * This registry gives every module a second, lightweight channel: alongside its
 * normal printout, a module calls KestrelAddFinding() for the things that matter.
 * At the end of the run main calls KestrelPrintFindingSummary(), which sorts by
 * severity and prints one triage table — the "read this first" view.
 *
 * Single-threaded by design (Kestrel runs its scans sequentially), so the
 * registry is a plain global grown on demand; no locking.
 */

#include "../include/Kestrel.h"
#include <stdlib.h>   /* qsort */

typedef struct _KESTREL_FINDING_ROW {
    KESTREL_SEVERITY sev;
    WCHAR            wszCategory[48];
    WCHAR            wszObject[200];
    WCHAR            wszDetail[200];
    WCHAR            wszRemediation[256];
} KESTREL_FINDING_ROW;

static KESTREL_FINDING_ROW *g_rgFindings = NULL;
static DWORD                g_cFindings   = 0;
static DWORD                g_cCapacity   = 0;

VOID
KestrelAddFinding(
    _In_   KESTREL_SEVERITY sev,
    _In_z_ LPCWSTR          pwszCategory,
    _In_z_ LPCWSTR          pwszObject,
    _In_z_ LPCWSTR          pwszDetail,
    _In_opt_z_ LPCWSTR      pwszRemediation)
{
    KESTREL_FINDING_ROW *pRow;

    if (g_cFindings == g_cCapacity) {
        DWORD                cNew = g_cCapacity ? g_cCapacity * 2 : 64;
        KESTREL_FINDING_ROW *pTmp = (KESTREL_FINDING_ROW *)(g_rgFindings
            ? HeapReAlloc(GetProcessHeap(), 0, g_rgFindings,
                          (SIZE_T)cNew * sizeof(KESTREL_FINDING_ROW))
            : HeapAlloc(GetProcessHeap(), 0,
                          (SIZE_T)cNew * sizeof(KESTREL_FINDING_ROW)));
        if (!pTmp) return;   /* out of memory: drop the summary row, never crash */
        g_rgFindings = pTmp;
        g_cCapacity  = cNew;
    }

    pRow = &g_rgFindings[g_cFindings++];
    pRow->sev = sev;
    StringCchCopyW(pRow->wszCategory, ARRAYSIZE(pRow->wszCategory),
                   pwszCategory ? pwszCategory : L"");
    StringCchCopyW(pRow->wszObject, ARRAYSIZE(pRow->wszObject),
                   pwszObject ? pwszObject : L"");
    StringCchCopyW(pRow->wszDetail, ARRAYSIZE(pRow->wszDetail),
                   pwszDetail ? pwszDetail : L"");
    StringCchCopyW(pRow->wszRemediation, ARRAYSIZE(pRow->wszRemediation),
                   pwszRemediation ? pwszRemediation : L"");
}

static LPCWSTR
_SevName(_In_ KESTREL_SEVERITY s)
{
    switch (s) {
    case KESTREL_SEV_CRITICAL: return L"CRITICAL";
    case KESTREL_SEV_HIGH:     return L"HIGH";
    case KESTREL_SEV_MEDIUM:   return L"MEDIUM";
    case KESTREL_SEV_LOW:      return L"LOW";
    default:                   return L"INFO";
    }
}

/* Severity descending; within a severity, group by category. */
static int __cdecl
_CmpFinding(const void *a, const void *b)
{
    const KESTREL_FINDING_ROW *x = (const KESTREL_FINDING_ROW *)a;
    const KESTREL_FINDING_ROW *y = (const KESTREL_FINDING_ROW *)b;
    if (x->sev != y->sev)
        return (int)y->sev - (int)x->sev;
    return _wcsicmp(x->wszCategory, y->wszCategory);
}

VOID
KestrelPrintFindingSummary(VOID)
{
    DWORD i;
    DWORD rgCount[5] = { 0, 0, 0, 0, 0 };

    if (g_cFindings == 0)
        return;   /* nothing worth surfacing — stay quiet */

    qsort(g_rgFindings, g_cFindings, sizeof(KESTREL_FINDING_ROW), _CmpFinding);

    wprintf(L"\n═══ Kestrel — Prioritized Findings ═══\n\n");
    for (i = 0; i < g_cFindings; i++) {
        const KESTREL_FINDING_ROW *r = &g_rgFindings[i];
        if (r->sev <= KESTREL_SEV_CRITICAL) rgCount[r->sev]++;
        wprintf(L"  %-9s %-14s %s%s%s\n",
            _SevName(r->sev),
            r->wszCategory,
            r->wszObject,
            (r->wszObject[0] && r->wszDetail[0]) ? L" — " : L"",
            r->wszDetail);
        if (r->wszRemediation[0])
            wprintf(L"                          → fix: %s\n", r->wszRemediation);
    }

    wprintf(L"\n  [=] %lu critical · %lu high · %lu medium · %lu low · %lu info\n",
        rgCount[KESTREL_SEV_CRITICAL], rgCount[KESTREL_SEV_HIGH],
        rgCount[KESTREL_SEV_MEDIUM],   rgCount[KESTREL_SEV_LOW],
        rgCount[KESTREL_SEV_INFO]);
}

VOID
KestrelFreeFindings(VOID)
{
    if (g_rgFindings) {
        HeapFree(GetProcessHeap(), 0, g_rgFindings);
        g_rgFindings = NULL;
    }
    g_cFindings = 0;
    g_cCapacity = 0;
}
