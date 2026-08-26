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
    WCHAR            wszTechnique[24];   /* MITRE ATT&CK technique ID, or "" */
} KESTREL_FINDING_ROW;

static KESTREL_FINDING_ROW *g_rgFindings = NULL;
static DWORD                g_cFindings   = 0;
static DWORD                g_cCapacity   = 0;


/* Map a finding to its MITRE ATT&CK technique from the module category, using
 * the detail string to disambiguate modules that raise more than one kind of
 * finding. Returns NULL when there is no clean, defensible mapping (better an
 * honest gap than a wrong tag). */
static LPCWSTR
_TechniqueFor(_In_z_ LPCWSTR cat, _In_opt_z_ LPCWSTR detail)
{
    if (_wcsicmp(cat, L"Kerberoast")      == 0) return L"T1558.003"; /* Kerberoasting            */
    if (_wcsicmp(cat, L"AS-REP")          == 0) return L"T1558.004"; /* AS-REP Roasting          */
    if (_wcsicmp(cat, L"GPP")             == 0) return L"T1552.006"; /* GPP passwords            */
    if (_wcsicmp(cat, L"SID History")     == 0) return L"T1134.005"; /* SID-History Injection    */
    if (_wcsicmp(cat, L"FSP")             == 0) return L"T1134.005"; /* foreign SID in priv group*/
    if (_wcsicmp(cat, L"AD FS")           == 0) return L"T1606.002"; /* Forge SAML (Golden SAML) */
    if (_wcsicmp(cat, L"AD CS")           == 0) return L"T1649";     /* Steal/Forge Auth Certs   */
    if (_wcsicmp(cat, L"Shadow Creds")    == 0) return L"T1556";     /* Modify Auth Process      */
    if (_wcsicmp(cat, L"Entra Sync")      == 0) return L"T1003.006"; /* DCSync (sync account)    */
    if (_wcsicmp(cat, L"Password Policy") == 0) return L"T1110";     /* Brute Force              */
    if (_wcsicmp(cat, L"SCCM")            == 0) return L"T1072";     /* Software Deployment Tools*/
    if (_wcsicmp(cat, L"AdminSDHolder")   == 0) return L"T1098";     /* Account Manipulation     */
    if (_wcsicmp(cat, L"Schema")          == 0) return L"T1098";     /* Account Manipulation     */
    if (_wcsicmp(cat, L"SQL")             == 0) return L"T1558.003"; /* roastable SQL SPN acct   */

    if (_wcsicmp(cat, L"Archaeology") == 0)
        return (detail && wcsstr(detail, L"password")) ? L"T1078"   /* stale valid account  */
                                                       : L"T1098"; /* orphaned ACE manip   */

    if (_wcsicmp(cat, L"Hardening") == 0)
        return (detail && wcsstr(detail, L"AdminSDHolder")) ? L"T1098"      /* SDProp exclusion     */
                                                            : L"T1087.002"; /* anon domain discovery*/

    if (_wcsicmp(cat, L"DNS") == 0)
        return (detail && wcsstr(detail, L"DnsAdmins")) ? L"T1098"      /* priv group           */
                                                        : L"T1557";     /* ADIDNS / AiTM        */
    if (_wcsicmp(cat, L"Exchange") == 0) {
        if (detail && (wcsstr(detail, L"WriteDACL") || wcsstr(detail, L"DCSync") ||
                       wcsstr(detail, L"privesc")))
            return L"T1003.006";                                        /* Exchange-to-DA        */
        return NULL;   /* EOL exposure is not an ATT&CK technique */
    }
    if (_wcsicmp(cat, L"Machine Acct") == 0)
        return (detail && wcsstr(detail, L"Domain Controller")) ? L"T1207"  /* Rogue DC          */
                                                                : L"T1136"; /* Create Account    */
    return NULL;
}

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
    {
        LPCWSTR t = _TechniqueFor(pRow->wszCategory, pRow->wszDetail);
        StringCchCopyW(pRow->wszTechnique, ARRAYSIZE(pRow->wszTechnique), t ? t : L"");
    }
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
        wprintf(L"  %-9s %-14s %-11s %s%s%s\n",
            _SevName(r->sev),
            r->wszCategory,
            r->wszTechnique[0] ? r->wszTechnique : L"-",
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
