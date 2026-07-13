/*
 * KestrelDiff.c — diff over time
 *
 * Compares the current in-memory graph against a previous Kestrel JSON snapshot
 * (produced by `--report <file>.json`) and surfaces the security-relevant delta:
 * NEW attack-path edges appearing since the last run, and edges that have been
 * REMOVED. New edges into Tier-0 are the high-signal case (a fresh GenericAll on
 * Domain Admins, a new RBCD, a new ADCS_ESC, a new privileged membership).
 *
 * This is an add-on over existing output — no new directory reads, scan skeleton
 * untouched. Edges are keyed by (sourceSID | type | targetSID): node indices are
 * per-run and not stable, but SIDs are, so the snapshot's index->SID map is
 * rebuilt from its "nodes" array and every edge resolved to a SID-based key.
 *
 * The snapshot is Kestrel's own line-oriented JSON (one node/edge object per
 * line), so a small field scanner is enough; no JSON dependency is pulled in.
 */

#include "../include/Kestrel.h"
#include <stdlib.h>
#include <string.h>

/* Edge-type names — MUST stay in sync with g_rgszEdgeType[] in KestrelReport.c.
 * Indexed by GEDGE_*. Used to render the current edge's type into the same
 * string the snapshot stored, so keys match. */
static const char *g_rgszDiffEdgeType[] = {
    "GenericAll", "WriteDACL", "WriteOwner", "GenericWrite",
    "ExtendedRight", "WriteProperty",
    "MemberOf",
    "Delegation_Unconstrained", "Delegation_Constrained", "Delegation_S4U2Self",
    "Delegation_RBCD", "CanReadLAPS", "CanReadGMSAPassword",
    "Trusts", "ADCS_ESC", "HasSIDHistory"
};

typedef struct { char *sid; char *label; } DIFF_NODE;
typedef struct { char *key;  char *disp;  } DIFF_EDGE;

/* ── small helpers ──────────────────────────────────────────────────────── */

static char *_Dup(_In_z_ const char *s)
{
    size_t n = strlen(s) + 1;
    char  *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static VOID _W2A(_In_opt_z_ const WCHAR *w, _Out_writes_z_(cch) char *out, _In_ int cch)
{
    if (cch <= 0) return;
    out[0] = '\0';
    if (w) WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cch, NULL, NULL);
    out[cch - 1] = '\0';
}

/* Extract "key": "value" from a line (value copied verbatim up to the closing
 * quote; escapes are left as-is, which is fine for SIDs/types that contain none). */
static BOOL _JsonStr(_In_z_ const char *line, _In_z_ const char *key,
                     _Out_writes_z_(cch) char *out, _In_ int cch)
{
    char        pat[64];
    const char *p, *e;
    int         n;

    if (cch > 0) out[0] = '\0';
    if (FAILED(StringCchPrintfA(pat, ARRAYSIZE(pat), "\"%s\": \"", key))) return FALSE;
    p = strstr(line, pat);
    if (!p) return FALSE;
    p += strlen(pat);
    e = p;
    while (*e && *e != '"') { if (*e == '\\' && e[1]) e++; e++; }
    n = (int)(e - p);
    if (n >= cch) n = cch - 1;
    if (n > 0) memcpy(out, p, (size_t)n);
    out[n < 0 ? 0 : n] = '\0';
    return TRUE;
}

static BOOL _JsonInt(_In_z_ const char *line, _In_z_ const char *key, _Out_ long *out)
{
    char        pat[64];
    const char *p;

    *out = 0;
    if (FAILED(StringCchPrintfA(pat, ARRAYSIZE(pat), "\"%s\": ", key))) return FALSE;
    p = strstr(line, pat);
    if (!p) return FALSE;
    *out = strtol(p + strlen(pat), NULL, 10);
    return TRUE;
}

static int _CmpEdge(const void *a, const void *b)
{
    return strcmp(((const DIFF_EDGE *)a)->key, ((const DIFF_EDGE *)b)->key);
}
static int _CmpKey(const void *k, const void *e)
{
    return strcmp((const char *)k, ((const DIFF_EDGE *)e)->key);
}

/* ── snapshot loader ────────────────────────────────────────────────────── */

VOID
KestrelRunDiff(
    _In_ const KESTREL_GRAPH *pGraph,
    _In_z_ LPCWSTR            pwszPrevPath)
{
    FILE       *pf;
    char        line[4096];
    DIFF_NODE  *pn      = NULL;   /* index -> {sid,label} from snapshot */
    DWORD       pnCap   = 0;
    DIFF_EDGE  *pePrev  = NULL;   /* snapshot edges */
    DWORD       pePrevN = 0, pePrevCap = 0;
    DIFF_EDGE  *peCurr  = NULL;   /* current edges */
    DWORD       peCurrN = 0;
    int         inNodes = 0, inEdges = 0;
    DWORD       cNew = 0, cRemoved = 0;

    if (!pGraph || !pwszPrevPath) return;

    pf = _wfopen(pwszPrevPath, L"rb");
    if (!pf) {
        wprintf(L"\n[!] Diff: cannot open previous snapshot: %s\n", pwszPrevPath);
        return;
    }

    wprintf(L"\n[*] Diff against previous snapshot: %s\n", pwszPrevPath);

    /* Parse the snapshot line by line. */
    while (fgets(line, ARRAYSIZE(line), pf)) {
        if (strstr(line, "\"nodes\"")) { inNodes = 1; inEdges = 0; continue; }
        if (strstr(line, "\"edges\"")) { inNodes = 0; inEdges = 1; continue; }

        if (inNodes && strstr(line, "\"sid\"")) {
            long id;
            char sid[96], label[256];
            if (!_JsonInt(line, "id", &id) || id < 0) continue;
            _JsonStr(line, "sid",   sid,   ARRAYSIZE(sid));
            _JsonStr(line, "label", label, ARRAYSIZE(label));
            if ((DWORD)id >= pnCap) {
                DWORD nc = (DWORD)id + 64;
                DIFF_NODE *np = (DIFF_NODE *)realloc(pn, nc * sizeof(DIFF_NODE));
                if (!np) goto cleanup;
                for (DWORD k = pnCap; k < nc; k++) { np[k].sid = NULL; np[k].label = NULL; }
                pn = np; pnCap = nc;
            }
            free(pn[id].sid); free(pn[id].label);
            pn[id].sid   = _Dup(sid);
            pn[id].label = _Dup(label);
        }
        else if (inEdges && strstr(line, "\"type\"")) {
            long src, tgt;
            char type[64], key[320], disp[640];
            const char *fs, *ts, *fl, *tl;

            if (!_JsonInt(line, "source", &src) || !_JsonInt(line, "target", &tgt)) continue;
            if (!_JsonStr(line, "type", type, ARRAYSIZE(type))) continue;
            if (src < 0 || tgt < 0 || (DWORD)src >= pnCap || (DWORD)tgt >= pnCap) continue;
            if (!pn[src].sid || !pn[tgt].sid) continue;

            fs = pn[src].sid;   ts = pn[tgt].sid;
            fl = pn[src].label ? pn[src].label : fs;
            tl = pn[tgt].label ? pn[tgt].label : ts;

            if (FAILED(StringCchPrintfA(key,  ARRAYSIZE(key),  "%s|%s|%s", fs, type, ts))) continue;
            StringCchPrintfA(disp, ARRAYSIZE(disp), "%s  -%s->  %s", fl, type, tl);

            if (pePrevN == pePrevCap) {
                DWORD nc = pePrevCap ? pePrevCap * 2 : 128;
                DIFF_EDGE *ne = (DIFF_EDGE *)realloc(pePrev, nc * sizeof(DIFF_EDGE));
                if (!ne) goto cleanup;
                pePrev = ne; pePrevCap = nc;
            }
            pePrev[pePrevN].key  = _Dup(key);
            pePrev[pePrevN].disp = _Dup(disp);
            pePrevN++;
        }
    }
    fclose(pf);
    pf = NULL;

    /* Build the current edge set from the in-memory graph. */
    if (pGraph->cEdges) {
        peCurr = (DIFF_EDGE *)malloc(pGraph->cEdges * sizeof(DIFF_EDGE));
        if (!peCurr) goto cleanup;
    }
    for (DWORD i = 0; i < pGraph->cEdges; i++) {
        const KESTREL_GRAPH_EDGE *pE = &pGraph->pEdges[i];
        const KESTREL_GRAPH_NODE *pF = &pGraph->pNodes[pE->iFrom];
        const KESTREL_GRAPH_NODE *pT = &pGraph->pNodes[pE->iTo];
        const char *pszType = (pE->Type < ARRAYSIZE(g_rgszDiffEdgeType))
            ? g_rgszDiffEdgeType[pE->Type] : "Unknown";
        char fs[96], ts[96], fl[256], tl[256], key[320], disp[640];
        BOOL bTier0 = (pF->bHighValue || pT->bHighValue);

        _W2A(pF->wszSid,   fs, ARRAYSIZE(fs));
        _W2A(pT->wszSid,   ts, ARRAYSIZE(ts));
        _W2A(pF->wszLabel, fl, ARRAYSIZE(fl));
        _W2A(pT->wszLabel, tl, ARRAYSIZE(tl));

        StringCchPrintfA(key,  ARRAYSIZE(key),  "%s|%s|%s", fs, pszType, ts);
        StringCchPrintfA(disp, ARRAYSIZE(disp), "%s  -%s->  %s%s",
                         fl[0] ? fl : fs, pszType, tl[0] ? tl : ts,
                         bTier0 ? "   [TIER-0]" : "");

        peCurr[peCurrN].key  = _Dup(key);
        peCurr[peCurrN].disp = _Dup(disp);
        peCurrN++;
    }

    /* Sort both, then set-difference via binary search. */
    if (pePrevN) qsort(pePrev, pePrevN, sizeof(DIFF_EDGE), _CmpEdge);
    if (peCurrN) qsort(peCurr, peCurrN, sizeof(DIFF_EDGE), _CmpEdge);

    /* NEW: current edges absent from the snapshot. */
    for (DWORD i = 0; i < peCurrN; i++) {
        if (!pePrevN ||
            !bsearch(peCurr[i].key, pePrev, pePrevN, sizeof(DIFF_EDGE), _CmpKey)) {
            if (cNew == 0) wprintf(L"\n  [+] NEW edges since last run:\n");
            wprintf(L"      + %hs\n", peCurr[i].disp);
            cNew++;
        }
    }

    /* REMOVED: snapshot edges absent from the current run. */
    for (DWORD i = 0; i < pePrevN; i++) {
        if (!peCurrN ||
            !bsearch(pePrev[i].key, peCurr, peCurrN, sizeof(DIFF_EDGE), _CmpKey)) {
            if (cRemoved == 0) wprintf(L"\n  [-] REMOVED edges since last run:\n");
            wprintf(L"      - %hs\n", pePrev[i].disp);
            cRemoved++;
        }
    }

    wprintf(L"\n  [=] Diff summary: %lu new, %lu removed, %lu current / %lu previous edges\n",
            cNew, cRemoved, peCurrN, pePrevN);
    if (cNew == 0 && cRemoved == 0)
        wprintf(L"  [=] No change in the attack-path graph since the snapshot\n");

cleanup:
    if (pf) fclose(pf);
    for (DWORD i = 0; i < pnCap; i++) { free(pn[i].sid); free(pn[i].label); }
    free(pn);
    for (DWORD i = 0; i < pePrevN; i++) { free(pePrev[i].key); free(pePrev[i].disp); }
    free(pePrev);
    for (DWORD i = 0; i < peCurrN; i++) { free(peCurr[i].key); free(peCurr[i].disp); }
    free(peCurr);
}
