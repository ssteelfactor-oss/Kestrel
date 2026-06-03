/*
 * KestrelPath.c — v0.5
 * In-memory attack-path finder over the graph built by KestrelReport.c.
 *
 * Two query modes, one symmetric BFS engine:
 *   - "to tier-0"  (pwszFrom == NULL): for each high-value target, reverse-BFS
 *     to enumerate principals that can reach it, with the shortest path.
 *   - "from X"     (pwszFrom set):     forward-BFS from one principal to every
 *     high-value target it can ultimately compromise.
 *
 * Edge orientation is uniform across the graph — "controller → controlled"
 * (ACL trustee→object, member→group, attacker→target for delegation/RBCD/LAPS),
 * so forward BFS = "what can this node compromise". DENY edges grant no control
 * and are excluded from traversal.
 *
 * Fully in-memory: no LDAP, no I/O. Consumes the graph; changes nothing on the
 * wire. (KestrelTagHighValue does mutate node flags in memory.)
 */

#include "../include/Kestrel.h"

#define KP_INF                 MAXDWORD
#define KP_MAX_PATHS           1000   /* global output cap                  */
#define KP_MAX_PATHS_PER_TGT   100    /* per high-value target cap          */

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Internal CSR adjacency                                                     */
/* ─────────────────────────────────────────────────────────────────────────── */

typedef struct _KP_ADJ {
    DWORD *pOff;     /* size cNodes + 1 — CSR row offsets         */
    DWORD *pEdge;    /* size cLive      — edge indices, grouped   */
    BOOL   bReverse; /* FALSE: grouped by iFrom; TRUE: by iTo      */
} KP_ADJ;

static VOID
KpFreeAdj(_Inout_ KP_ADJ *pA)
{
    if (pA->pOff)  HeapFree(GetProcessHeap(), 0, pA->pOff);
    if (pA->pEdge) HeapFree(GetProcessHeap(), 0, pA->pEdge);
    pA->pOff = NULL;
    pA->pEdge = NULL;
}

/*
 * Build a CSR adjacency over non-DENY edges, grouped by source (forward) or
 * by target (reverse).
 */
_Must_inspect_result_
static HRESULT
KpBuildAdj(
    _In_  const KESTREL_GRAPH *pGraph,
    _In_  BOOL                 bReverse,
    _Out_ KP_ADJ              *pA)
{
    DWORD n = pGraph->cNodes;

    pA->bReverse = bReverse;
    pA->pOff  = NULL;
    pA->pEdge = NULL;

    pA->pOff = (DWORD *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                  (SIZE_T)(n + 1) * sizeof(DWORD));
    if (!pA->pOff) return E_OUTOFMEMORY;

    /* Count out/in degree (skip DENY edges and out-of-range endpoints) */
    DWORD cLive = 0;
    for (DWORD e = 0; e < pGraph->cEdges; e++) {
        const KESTREL_GRAPH_EDGE *pE = &pGraph->pEdges[e];
        if (pE->bDeny) continue;
        DWORD key = bReverse ? pE->iTo : pE->iFrom;
        if (key >= n) continue;
        pA->pOff[key + 1]++;
        cLive++;
    }

    /* Prefix sum → row offsets */
    for (DWORD i = 0; i < n; i++)
        pA->pOff[i + 1] += pA->pOff[i];

    if (cLive > 0) {
        pA->pEdge = (DWORD *)HeapAlloc(GetProcessHeap(), 0,
                                       (SIZE_T)cLive * sizeof(DWORD));
        if (!pA->pEdge) { KpFreeAdj(pA); return E_OUTOFMEMORY; }

        /* Cursor copy of offsets for the fill pass */
        DWORD *pCur = (DWORD *)HeapAlloc(GetProcessHeap(), 0,
                                         (SIZE_T)n * sizeof(DWORD));
        if (!pCur) { KpFreeAdj(pA); return E_OUTOFMEMORY; }
        for (DWORD i = 0; i < n; i++) pCur[i] = pA->pOff[i];

        for (DWORD e = 0; e < pGraph->cEdges; e++) {
            const KESTREL_GRAPH_EDGE *pE = &pGraph->pEdges[e];
            if (pE->bDeny) continue;
            DWORD key = bReverse ? pE->iTo : pE->iFrom;
            if (key >= n) continue;
            pA->pEdge[pCur[key]++] = e;
        }
        HeapFree(GetProcessHeap(), 0, pCur);
    }

    return S_OK;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  BFS                                                                        */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * Single-source BFS over the given adjacency. Fills dist/parent/parentEdge
 * (all sized cNodes; caller-owned and reused across calls). parentEdge[v] is
 * the graph edge index linking v to its BFS parent; the edge is always read in
 * its native (forward) orientation regardless of adjacency direction.
 */
static VOID
KpBfs(
    _In_                  const KESTREL_GRAPH *pGraph,
    _In_                  const KP_ADJ        *pA,
    _In_                  DWORD                iStart,
    _Out_writes_(pGraph->cNodes) DWORD        *pDist,
    _Out_writes_(pGraph->cNodes) DWORD        *pParent,
    _Out_writes_(pGraph->cNodes) DWORD        *pParentEdge,
    _Inout_updates_(pGraph->cNodes) DWORD     *pQueue)
{
    DWORD n = pGraph->cNodes;

    for (DWORD i = 0; i < n; i++) {
        pDist[i]       = KP_INF;
        pParent[i]     = KP_INF;
        pParentEdge[i] = KP_INF;
    }

    DWORD head = 0, tail = 0;
    pDist[iStart] = 0;
    pQueue[tail++] = iStart;

    while (head < tail) {
        DWORD u = pQueue[head++];
        for (DWORD idx = pA->pOff[u]; idx < pA->pOff[u + 1]; idx++) {
            DWORD e = pA->pEdge[idx];
            DWORD v = pA->bReverse ? pGraph->pEdges[e].iFrom
                                   : pGraph->pEdges[e].iTo;
            if (v >= n) continue;
            if (pDist[v] == KP_INF) {
                pDist[v]       = pDist[u] + 1;
                pParent[v]     = u;
                pParentEdge[v] = e;
                pQueue[tail++] = v;
            }
        }
    }
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Result assembly                                                            */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
static HRESULT
KpAppendPath(
    _Inout_ KESTREL_PATH_RESULT *pResult,
    _In_reads_(cNodes) const DWORD *pNodes,
    _In_reads_(cNodes - 1) const KESTREL_GRAPH_EDGE_TYPE *pEdges,
    _In_ DWORD cNodes)
{
    if (cNodes < 2) return S_OK;   /* nothing meaningful to record */

    if (pResult->cPaths == pResult->cCapacity) {
        DWORD cNew = pResult->cCapacity ? pResult->cCapacity * 2 : 128;
        KESTREL_PATH *pNew = (KESTREL_PATH *)HeapReAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY,
            pResult->rgPaths, (SIZE_T)cNew * sizeof(KESTREL_PATH));
        if (!pNew) return E_OUTOFMEMORY;
        pResult->rgPaths = pNew;
        pResult->cCapacity = cNew;
    }

    DWORD cHops = cNodes - 1;
    KESTREL_PATH *pP = &pResult->rgPaths[pResult->cPaths];

    pP->rgNodes = (DWORD *)HeapAlloc(GetProcessHeap(), 0,
                                     (SIZE_T)cNodes * sizeof(DWORD));
    pP->rgEdges = (KESTREL_GRAPH_EDGE_TYPE *)HeapAlloc(GetProcessHeap(), 0,
                  (SIZE_T)cHops * sizeof(KESTREL_GRAPH_EDGE_TYPE));
    if (!pP->rgNodes || !pP->rgEdges) {
        if (pP->rgNodes) HeapFree(GetProcessHeap(), 0, pP->rgNodes);
        if (pP->rgEdges) HeapFree(GetProcessHeap(), 0, pP->rgEdges);
        pP->rgNodes = NULL; pP->rgEdges = NULL;
        return E_OUTOFMEMORY;
    }

    for (DWORD i = 0; i < cNodes; i++) pP->rgNodes[i] = pNodes[i];
    for (DWORD i = 0; i < cHops;  i++) pP->rgEdges[i] = pEdges[i];
    pP->cHops = cHops;

    pResult->cPaths++;
    return S_OK;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Helpers                                                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

static BOOL
KpSidEndsWith(_In_z_ LPCWSTR pwszSid, _In_z_ LPCWSTR pwszSuffix)
{
    size_t ls = wcslen(pwszSid);
    size_t lf = wcslen(pwszSuffix);
    return (ls >= lf) && (_wcsicmp(pwszSid + (ls - lf), pwszSuffix) == 0);
}

/* Resolve a node by exact SID, else case-insensitive label, else DN. */
static DWORD
KpResolveNode(_In_ const KESTREL_GRAPH *pGraph, _In_z_ LPCWSTR pwszSpec)
{
    for (DWORD i = 0; i < pGraph->cNodes; i++)
        if (_wcsicmp(pGraph->pNodes[i].wszSid, pwszSpec) == 0) return i;
    for (DWORD i = 0; i < pGraph->cNodes; i++)
        if (_wcsicmp(pGraph->pNodes[i].wszLabel, pwszSpec) == 0) return i;
    for (DWORD i = 0; i < pGraph->cNodes; i++)
        if (_wcsicmp(pGraph->pNodes[i].wszDN, pwszSpec) == 0) return i;
    return KP_INF;
}

static LPCWSTR
KpEdgeName(_In_ KESTREL_GRAPH_EDGE_TYPE t)
{
    switch (t) {
    case GEDGE_ACL_GENERIC_ALL:     return L"GenericAll";
    case GEDGE_ACL_WRITE_DACL:      return L"WriteDACL";
    case GEDGE_ACL_WRITE_OWNER:     return L"WriteOwner";
    case GEDGE_ACL_GENERIC_WRITE:   return L"GenericWrite";
    case GEDGE_ACL_EXTENDED_RIGHT:  return L"ExtendedRight";
    case GEDGE_ACL_WRITE_PROP:      return L"WriteProperty";
    case GEDGE_MEMBER_OF:           return L"MemberOf";
    case GEDGE_DELEG_UNCONSTRAINED: return L"Unconstrained";
    case GEDGE_DELEG_CONSTRAINED:   return L"Constrained";
    case GEDGE_DELEG_S4U2SELF:      return L"S4U2Self";
    case GEDGE_DELEG_RBCD:          return L"RBCD";
    case GEDGE_CAN_READ_LAPS:       return L"CanReadLAPS";
    default:                        return L"?";
    }
}

static VOID
KpPrintPath(_In_ const KESTREL_GRAPH *pGraph, _In_ const KESTREL_PATH *pP)
{
    wprintf(L"  ");
    for (DWORD i = 0; i <= pP->cHops; i++) {
        DWORD ni = pP->rgNodes[i];
        LPCWSTR lbl = pGraph->pNodes[ni].wszLabel[0]
                    ? pGraph->pNodes[ni].wszLabel
                    : pGraph->pNodes[ni].wszSid;
        wprintf(L"%s", lbl);
        if (i < pP->cHops)
            wprintf(L" =[%s]=> ", KpEdgeName(pP->rgEdges[i]));
    }
    wprintf(L"\n");
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public: high-value tagging                                                 */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * KestrelTagHighValue
 * Marks well-known tier-0 principals (by SID) and the domain object as
 * bHighValue. Idempotent. Returns the number of high-value nodes after tagging.
 * Note: DC computer objects are not auto-detected here (no membership data in
 * the node) — a known first-cut limitation.
 */
DWORD
KestrelTagHighValue(_Inout_ KESTREL_GRAPH *pGraph)
{
    /* Relative RIDs appended to the domain SID */
    static const WCHAR *rgRelRid[] = {
        L"-512",  /* Domain Admins        */
        L"-516",  /* Domain Controllers   */
        L"-518",  /* Schema Admins        */
        L"-519",  /* Enterprise Admins    */
        L"-520",  /* Group Policy Creators*/
        L"-500",  /* Administrator        */
        L"-502"   /* krbtgt               */
    };
    /* Absolute BUILTIN SIDs */
    static const WCHAR *rgAbsSid[] = {
        L"S-1-5-32-544",  /* Administrators     */
        L"S-1-5-32-548",  /* Account Operators  */
        L"S-1-5-32-549",  /* Server Operators   */
        L"S-1-5-32-551"   /* Backup Operators   */
    };

    DWORD cHigh = 0;
    if (!pGraph) return 0;

    for (DWORD i = 0; i < pGraph->cNodes; i++) {
        KESTREL_GRAPH_NODE *pN = &pGraph->pNodes[i];
        BOOL bHV = (pN->Class == NODE_CLASS_DOMAIN);

        for (DWORD k = 0; !bHV && k < ARRAYSIZE(rgRelRid); k++)
            if (KpSidEndsWith(pN->wszSid, rgRelRid[k])) bHV = TRUE;
        for (DWORD k = 0; !bHV && k < ARRAYSIZE(rgAbsSid); k++)
            if (_wcsicmp(pN->wszSid, rgAbsSid[k]) == 0) bHV = TRUE;

        if (bHV) {
            pN->bHighValue = TRUE;
            cHigh++;
        }
    }
    return cHigh;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public: path finder                                                        */
/* ─────────────────────────────────────────────────────────────────────────── */

_Must_inspect_result_
HRESULT
KestrelFindPaths(
    _In_       const KESTREL_GRAPH  *pGraph,
    _In_opt_z_ LPCWSTR               pwszFrom,
    _Outptr_   KESTREL_PATH_RESULT **ppResult)
{
    HRESULT              hr      = S_OK;
    KESTREL_PATH_RESULT *pResult = NULL;
    KP_ADJ               adj     = { 0 };
    DWORD               *pDist = NULL, *pParent = NULL, *pParentEdge = NULL, *pQueue = NULL;
    DWORD               *pScratch = NULL;       /* node-id scratch for reconstruction */
    KESTREL_GRAPH_EDGE_TYPE *pScratchE = NULL;  /* edge scratch                       */
    BOOL                 bFromMode = (pwszFrom && pwszFrom[0] != L'\0');

    if (!pGraph || !ppResult) return E_INVALIDARG;
    *ppResult = NULL;

    pResult = (KESTREL_PATH_RESULT *)HeapAlloc(GetProcessHeap(),
                  HEAP_ZERO_MEMORY, sizeof(*pResult));
    if (!pResult) return E_OUTOFMEMORY;

    DWORD n = pGraph->cNodes;
    if (n == 0) {                       /* empty graph — nothing to do */
        wprintf(L"  [*] Graph is empty — no paths to compute.\n");
        *ppResult = pResult;
        return S_OK;
    }

    /* Per-BFS working buffers (reused across roots) */
    pDist       = (DWORD *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)n * sizeof(DWORD));
    pParent     = (DWORD *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)n * sizeof(DWORD));
    pParentEdge = (DWORD *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)n * sizeof(DWORD));
    pQueue      = (DWORD *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)n * sizeof(DWORD));
    pScratch    = (DWORD *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)n * sizeof(DWORD));
    pScratchE   = (KESTREL_GRAPH_EDGE_TYPE *)HeapAlloc(GetProcessHeap(), 0,
                      (SIZE_T)n * sizeof(KESTREL_GRAPH_EDGE_TYPE));
    if (!pDist || !pParent || !pParentEdge || !pQueue || !pScratch || !pScratchE) {
        hr = E_OUTOFMEMORY; goto Cleanup;
    }

    if (bFromMode) {
        /* ── FROM mode: forward BFS from one source ─────────────────── */
        DWORD iSrc = KpResolveNode(pGraph, pwszFrom);
        if (iSrc == KP_INF) {
            wprintf(L"  [!] Source principal not found in graph: %s\n", pwszFrom);
            *ppResult = pResult; pResult = NULL;   /* empty result, not an error */
            goto Cleanup;
        }

        hr = KpBuildAdj(pGraph, FALSE /* forward */, &adj);
        if (FAILED(hr)) goto Cleanup;

        KpBfs(pGraph, &adj, iSrc, pDist, pParent, pParentEdge, pQueue);

        wprintf(L"\n  [*] Paths from \"%s\" to high-value targets:\n\n",
            pGraph->pNodes[iSrc].wszLabel[0] ? pGraph->pNodes[iSrc].wszLabel
                                             : pGraph->pNodes[iSrc].wszSid);

        for (DWORD t = 0; t < n; t++) {
            if (t == iSrc || !pGraph->pNodes[t].bHighValue) continue;
            pResult->cTargets++;
            if (pDist[t] == KP_INF) continue;
            pResult->cReachable++;

            /* reconstruct t → ... → iSrc via parent, then reverse to src→t */
            DWORD cN = 0, cur = t;
            while (cur != KP_INF) { pScratch[cN++] = cur; if (cur == iSrc) break; cur = pParent[cur]; }
            /* reverse node order in-place */
            for (DWORD a = 0, b = cN - 1; a < b; a++, b--) {
                DWORD tmp = pScratch[a]; pScratch[a] = pScratch[b]; pScratch[b] = tmp;
            }
            /* edges: pScratch now src..t; edge i links node[i]→node[i+1] = parentEdge[node[i+1]] */
            for (DWORD i = 0; i + 1 < cN; i++)
                pScratchE[i] = pGraph->pEdges[ pParentEdge[ pScratch[i + 1] ] ].Type;

            if (pResult->cPaths < KP_MAX_PATHS) {
                hr = KpAppendPath(pResult, pScratch, pScratchE, cN);
                if (FAILED(hr)) goto Cleanup;
            } else {
                pResult->bCapped = TRUE;
            }
        }
    }
    else {
        /* ── TO tier-0 mode: reverse BFS rooted at each target ──────── */
        hr = KpBuildAdj(pGraph, TRUE /* reverse */, &adj);
        if (FAILED(hr)) goto Cleanup;

        wprintf(L"\n  [*] Paths to high-value (tier-0) targets:\n\n");

        for (DWORD t = 0; t < n; t++) {
            if (!pGraph->pNodes[t].bHighValue) continue;
            pResult->cTargets++;

            KpBfs(pGraph, &adj, t, pDist, pParent, pParentEdge, pQueue);

            DWORD cForTgt = 0;
            BOOL  bAny = FALSE;
            for (DWORD s = 0; s < n; s++) {
                if (s == t || pDist[s] == KP_INF) continue;
                if (pGraph->pNodes[s].bHighValue) continue;   /* skip tier-0 → tier-0 */
                bAny = TRUE;

                if (pResult->cPaths >= KP_MAX_PATHS ||
                    cForTgt >= KP_MAX_PATHS_PER_TGT) {
                    pResult->bCapped = TRUE;
                    break;
                }

                /* reverse-BFS parent[u] is one hop closer to t, and
                   parentEdge[u] is the native forward edge u→parent[u].
                   Walk s → parent → ... → t (already forward order). */
                DWORD cN = 0, cur = s;
                while (cur != KP_INF) {
                    pScratch[cN] = cur;
                    if (cur != t) pScratchE[cN] = pGraph->pEdges[ pParentEdge[cur] ].Type;
                    cN++;
                    if (cur == t) break;
                    cur = pParent[cur];
                }

                hr = KpAppendPath(pResult, pScratch, pScratchE, cN);
                if (FAILED(hr)) goto Cleanup;
                cForTgt++;
            }
            if (bAny) pResult->cReachable++;
        }
    }

    /* ── Print ──────────────────────────────────────────────────────── */
    for (DWORD i = 0; i < pResult->cPaths; i++)
        KpPrintPath(pGraph, &pResult->rgPaths[i]);

    wprintf(L"\n  [*] High-value targets: %lu  |  reachable: %lu  |  paths: %lu%s\n",
        pResult->cTargets, pResult->cReachable, pResult->cPaths,
        pResult->bCapped ? L"  (output capped)" : L"");

    *ppResult = pResult;
    pResult = NULL;

Cleanup:
    KpFreeAdj(&adj);
    if (pDist)       HeapFree(GetProcessHeap(), 0, pDist);
    if (pParent)     HeapFree(GetProcessHeap(), 0, pParent);
    if (pParentEdge) HeapFree(GetProcessHeap(), 0, pParentEdge);
    if (pQueue)      HeapFree(GetProcessHeap(), 0, pQueue);
    if (pScratch)    HeapFree(GetProcessHeap(), 0, pScratch);
    if (pScratchE)   HeapFree(GetProcessHeap(), 0, pScratchE);
    if (pResult)     KestrelFreePathResult(pResult);
    return hr;
}

VOID
KestrelFreePathResult(_In_opt_ _Post_ptr_invalid_ KESTREL_PATH_RESULT *pResult)
{
    if (!pResult) return;
    if (pResult->rgPaths) {
        for (DWORD i = 0; i < pResult->cPaths; i++) {
            if (pResult->rgPaths[i].rgNodes) HeapFree(GetProcessHeap(), 0, pResult->rgPaths[i].rgNodes);
            if (pResult->rgPaths[i].rgEdges) HeapFree(GetProcessHeap(), 0, pResult->rgPaths[i].rgEdges);
        }
        HeapFree(GetProcessHeap(), 0, pResult->rgPaths);
    }
    HeapFree(GetProcessHeap(), 0, pResult);
}
