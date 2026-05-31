/*
 * KestrelReport.c — v0.4
 * In-memory graph construction + HTML report generation.
 *
 * Consumes output from v0.1/v0.2/v0.3, builds a typed graph,
 * exports a self-contained HTML file with embedded D3.js visualization.
 *
 * No new LDAP queries — all data comes from previous scan results.
 * Output: single .html file, no external dependencies.
 *
 * Usage:
 *   Kestrel.exe --report report.html
 *
 * Graph model:
 *   Nodes — AD objects identified by SID
 *   Edges — typed relationships: ACL rights, memberOf, delegation
 *
 * Node lookup: open-addressing hash table keyed by SID string.
 * O(1) average insert/lookup — necessary for large domains.
 */

#include "../include/Kestrel.h"

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Cleanup forward declarations                                               */
/* ─────────────────────────────────────────────────────────────────────────── */

VOID KestrelFreeGraph(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GRAPH *pGraph);

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Internal forward declarations                                              */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * Hash a SID string to a slot index.
 * Simple djb2 variant — fast, good distribution for SID strings.
 */
static DWORD
KestrelGraphHash(
    _In_z_ LPCWSTR pwszSid);

/*
 * Find or insert a node by SID.
 * Returns node index. If not found and bCreate=TRUE, allocates new node.
 * Returns DWORD_MAX on error.
 */
static DWORD
KestrelGraphGetOrAddNode(
    _Inout_ KESTREL_GRAPH *pGraph,
    _In_z_  LPCWSTR        pwszSid,
    _In_z_  LPCWSTR        pwszDN,
    _In_z_  LPCWSTR        pwszLabel,
    _In_    KESTREL_NODE_CLASS Class,
    _In_    BOOL           bEnabled,
    _In_    BOOL           bCreate);

/*
 * Append one edge to pGraph->pEdges. Grows array if needed.
 */
_Must_inspect_result_
static HRESULT
KestrelGraphAddEdge(
    _Inout_       KESTREL_GRAPH          *pGraph,
    _In_          DWORD                   iFrom,
    _In_          DWORD                   iTo,
    _In_          KESTREL_GRAPH_EDGE_TYPE Type,
    _In_z_        LPCWSTR                 pwszDetail,
    _In_          BOOL                    bDeny);

/*
 * Classify objectClass string to KESTREL_NODE_CLASS enum.
 */
static KESTREL_NODE_CLASS
KestrelClassifyNodeClass(
    _In_z_ LPCWSTR pwszClass);

/*
 * Phase 1 of graph build: populate nodes and edges from ACL scan.
 */
_Must_inspect_result_
static HRESULT
KestrelGraphAddACLEdges(
    _Inout_  KESTREL_GRAPH          *pGraph,
    _In_     KESTREL_ACL_SCAN_RESULT *pACLResult);

/*
 * Phase 2 of graph build: add memberOf edges from group scan.
 */
_Must_inspect_result_
static HRESULT
KestrelGraphAddMemberEdges(
    _Inout_  KESTREL_GRAPH            *pGraph,
    _In_     KESTREL_GROUP_SCAN_RESULT *pGroupResult);

/*
 * Write the complete graph as JSON embedded in HTML to a file.
 */
_Must_inspect_result_
static HRESULT
KestrelWriteGraphJSON(
    _In_     const KESTREL_GRAPH *pGraph,
    _In_     FILE                *pFile);


/* ─────────────────────────────────────────────────────────────────────────── */
/*  Public API                                                                 */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * KestrelBuildGraph
 * Constructs in-memory graph from v0.2 + v0.3 scan results.
 * No LDAP queries — pure in-memory construction.
 *
 * Parameters:
 *   pACLResult    — output of KestrelScanACLEdges (may be NULL)
 *   pGroupResult  — output of KestrelRunGroupScan (may be NULL)
 *   ppGraph       — receives allocated graph; free via KestrelFreeGraph
 */
_Must_inspect_result_
HRESULT
KestrelBuildGraph(
    _In_opt_ KESTREL_ACL_SCAN_RESULT    *pACLResult,
    _In_opt_ KESTREL_GROUP_SCAN_RESULT  *pGroupResult,
    _Outptr_ KESTREL_GRAPH             **ppGraph)
{
    HRESULT        hr     = S_OK;
    KESTREL_GRAPH *pGraph = NULL;

    if (!ppGraph) return E_INVALIDARG;
    *ppGraph = NULL;

    /* Allocate graph — hash table is zero-initialized (free slots)  */
    pGraph = (KESTREL_GRAPH *)HeapAlloc(GetProcessHeap(),
                                         HEAP_ZERO_MEMORY, sizeof(*pGraph));
    if (!pGraph) return E_OUTOFMEMORY;

    /* Pre-allocate node and edge arrays */
    pGraph->cNodesCapacity = 1024;
    pGraph->pNodes = (KESTREL_GRAPH_NODE *)HeapAlloc(GetProcessHeap(),
                        HEAP_ZERO_MEMORY,
                        pGraph->cNodesCapacity * sizeof(KESTREL_GRAPH_NODE));
    if (!pGraph->pNodes) { hr = E_OUTOFMEMORY; goto Cleanup; }

    pGraph->cEdgesCapacity = KESTREL_EDGE_INITIAL_CAP;
    pGraph->pEdges = (KESTREL_GRAPH_EDGE *)HeapAlloc(GetProcessHeap(),
                        HEAP_ZERO_MEMORY,
                        pGraph->cEdgesCapacity * sizeof(KESTREL_GRAPH_EDGE));
    if (!pGraph->pEdges) { hr = E_OUTOFMEMORY; goto Cleanup; }

    wprintf(L"\n[*] Building graph...\n");

    /* Phase 1: ACL edges → nodes + edges */
    if (pACLResult && pACLResult->cEdges > 0) {
        hr = KestrelGraphAddACLEdges(pGraph, pACLResult);
        if (FAILED(hr)) goto Cleanup;
        wprintf(L"  [*] ACL edges:        %lu\n", pGraph->cACLEdges);
    }

    /* Phase 2: memberOf edges */
    if (pGroupResult && pGroupResult->cGroups > 0) {
        hr = KestrelGraphAddMemberEdges(pGraph, pGroupResult);
        if (FAILED(hr)) goto Cleanup;
        wprintf(L"  [*] Member edges:     %lu\n", pGraph->cMemberEdges);
    }

    wprintf(L"  [*] Total nodes:      %lu\n", pGraph->cNodes);
    wprintf(L"  [*] Total edges:      %lu\n", pGraph->cEdges);

    *ppGraph = pGraph;
    pGraph   = NULL;

Cleanup:
    if (pGraph) KestrelFreeGraph(pGraph);
    return hr;
}

/*
 * KestrelWriteHTMLReport
 * Writes self-contained HTML report to pwszOutputPath.
 * The file embeds D3.js from cdnjs and all graph data as inline JSON.
 */
 /*
  * KestrelWriteHTMLReport — исправленная версия.
  *
  * Замени функцию KestrelWriteHTMLReport в KestrelReport.c целиком.
  *
  * Правило: fprintf только там где есть %lu/%s с аргументами.
  * Всё остальное — fputs. Причина: MSVC C4477 — видит "50%" в CSS
  * и интерпретирует % как начало format specifier.
  */

_Must_inspect_result_
HRESULT
KestrelWriteHTMLReport(
    _In_     const KESTREL_GRAPH* pGraph,
    _In_z_   LPCWSTR              pwszOutputPath)
{

    HRESULT hr = S_OK;   /* ← добавить */
    if (!pGraph || !pwszOutputPath) return E_INVALIDARG;

    wprintf(L"\n[*] Writing HTML report: %s\n", pwszOutputPath);

    FILE* pFile = _wfopen(pwszOutputPath, L"w, ccs=UTF-8");
    if (!pFile) {
        wprintf(L"[!] Failed to open output file\n");
        return HRESULT_FROM_WIN32(ERROR_OPEN_FAILED);
    }

    /* ── HTML header + CSS ─────────────────────────────────────────── */
    fputs("<!DOCTYPE html>\n", pFile);
    fputs("<html lang=\"en\">\n", pFile);
    fputs("<head>\n", pFile);
    fputs("  <meta charset=\"UTF-8\">\n", pFile);
    fputs("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n", pFile);
    fputs("  <title>Kestrel — AD Security Graph</title>\n", pFile);
    fputs("  <script src=\"https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js\"></script>\n", pFile);
    fputs("  <style>\n", pFile);
    fputs("    * { margin: 0; padding: 0; box-sizing: border-box; }\n", pFile);
    fputs("    body { background: #1a1a2e; color: #e0e0e0; font-family: 'Consolas', monospace; }\n", pFile);
    fputs("    #header { padding: 12px 20px; background: #16213e; border-bottom: 1px solid #0f3460; display: flex; align-items: center; gap: 20px; }\n", pFile);
    fputs("    #header h1 { font-size: 16px; color: #4A90D9; letter-spacing: 2px; }\n", pFile);
    fputs("    #header .stats { font-size: 12px; color: #888; }\n", pFile);
    fputs("    #header .stats span { color: #e0e0e0; margin-right: 16px; }\n", pFile);
    fputs("    #container { display: flex; height: calc(100vh - 44px); }\n", pFile);
    fputs("    #graph { flex: 1; overflow: hidden; }\n", pFile);
    fputs("    #panel { width: 300px; background: #16213e; border-left: 1px solid #0f3460; padding: 16px; overflow-y: auto; display: none; }\n", pFile);
    fputs("    #panel.visible { display: block; }\n", pFile);
    fputs("    #panel h2 { font-size: 13px; color: #4A90D9; margin-bottom: 12px; border-bottom: 1px solid #0f3460; padding-bottom: 8px; }\n", pFile);
    fputs("    #panel .field { margin-bottom: 8px; }\n", pFile);
    fputs("    #panel .field label { font-size: 10px; color: #888; display: block; }\n", pFile);
    fputs("    #panel .field value { font-size: 12px; word-break: break-all; }\n", pFile);
    fputs("    #panel .close-btn { float: right; cursor: pointer; color: #888; font-size: 14px; }\n", pFile);
    fputs("    #legend { position: absolute; bottom: 20px; left: 20px; background: rgba(22,33,62,0.9); padding: 12px; border: 1px solid #0f3460; border-radius: 4px; }\n", pFile);
    fputs("    #legend h3 { font-size: 11px; color: #888; margin-bottom: 8px; }\n", pFile);
    fputs("    #legend .item { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; font-size: 11px; }\n", pFile);
    fputs("    #legend .dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }\n", pFile);
    fputs("    #legend .line { width: 20px; height: 2px; flex-shrink: 0; }\n", pFile);
    fputs("    .tooltip { position: absolute; background: rgba(22,33,62,0.95); border: 1px solid #4A90D9; padding: 8px 12px; border-radius: 4px; font-size: 11px; pointer-events: none; display: none; max-width: 250px; }\n", pFile);
    fputs("    #filters { position: absolute; top: 54px; right: 310px; background: rgba(22,33,62,0.9); padding: 10px; border: 1px solid #0f3460; border-radius: 4px; font-size: 11px; }\n", pFile);
    fputs("    #filters.panel-open { right: 320px; }\n", pFile);
    fputs("    #filters label { display: flex; align-items: center; gap: 6px; margin-bottom: 4px; cursor: pointer; }\n", pFile);
    fputs("    #filters input[type=checkbox] { accent-color: #4A90D9; }\n", pFile);
    fputs("  </style>\n", pFile);
    fputs("</head>\n", pFile);
    fputs("<body>\n", pFile);

    /* ── Stats header — единственный fprintf с аргументами ────────── */
    fprintf(pFile,
        "<div id=\"header\">\n"
        "  <h1>KESTREL</h1>\n"
        "  <div class=\"stats\">\n"
        "    <span>Nodes: <b>%lu</b></span>\n"
        "    <span>Edges: <b>%lu</b></span>\n"
        "    <span>ACL: <b>%lu</b></span>\n"
        "    <span>Membership: <b>%lu</b></span>\n"
        "  </div>\n"
        "</div>\n",
        pGraph->cNodes, pGraph->cEdges,
        pGraph->cACLEdges, pGraph->cMemberEdges);

    /* ── Main layout ───────────────────────────────────────────────── */
    fputs("<div id=\"container\">\n", pFile);
    fputs("  <div id=\"graph\"></div>\n", pFile);
    fputs("  <div id=\"panel\">\n", pFile);
    fputs("    <span class=\"close-btn\" onclick=\"closePanel()\">X</span>\n", pFile);
    fputs("    <h2 id=\"panel-title\">Node Details</h2>\n", pFile);
    fputs("    <div id=\"panel-content\"></div>\n", pFile);
    fputs("  </div>\n", pFile);
    fputs("</div>\n", pFile);
    fputs("<div class=\"tooltip\" id=\"tooltip\"></div>\n", pFile);

    /* ── Legend ────────────────────────────────────────────────────── */
    fputs("<div id=\"legend\">\n", pFile);
    fputs("  <h3>NODES</h3>\n", pFile);
    fputs("  <div class=\"item\"><div class=\"dot\" style=\"background:#4A90D9\"></div>User</div>\n", pFile);
    fputs("  <div class=\"item\"><div class=\"dot\" style=\"background:#E8A838\"></div>Group</div>\n", pFile);
    fputs("  <div class=\"item\"><div class=\"dot\" style=\"background:#5CB85C\"></div>Computer</div>\n", pFile);
    fputs("  <div class=\"item\"><div class=\"dot\" style=\"background:#9B59B6\"></div>OU</div>\n", pFile);
    fputs("  <div class=\"item\"><div class=\"dot\" style=\"background:#E74C3C\"></div>Domain</div>\n", pFile);
    fputs("  <div class=\"item\"><div class=\"dot\" style=\"background:#1ABC9C\"></div>GPO</div>\n", pFile);
    fputs("  <h3 style=\"margin-top:10px\">EDGES</h3>\n", pFile);
    fputs("  <div class=\"item\"><div class=\"line\" style=\"background:#E74C3C\"></div>High severity</div>\n", pFile);
    fputs("  <div class=\"item\"><div class=\"line\" style=\"background:#E8A838\"></div>Medium</div>\n", pFile);
    fputs("  <div class=\"item\"><div class=\"line\" style=\"background:#4A90D9\"></div>MemberOf</div>\n", pFile);
    fputs("  <div class=\"item\"><div class=\"line\" style=\"background:#9B59B6\"></div>Delegation</div>\n", pFile);
    fputs("</div>\n", pFile);

    /* ── Edge type filters ─────────────────────────────────────────── */
    fputs("<div id=\"filters\">\n", pFile);
    fputs("  <label><input type=\"checkbox\" id=\"f-acl\" checked onchange=\"updateFilter()\"> ACL edges</label>\n", pFile);
    fputs("  <label><input type=\"checkbox\" id=\"f-member\" checked onchange=\"updateFilter()\"> MemberOf</label>\n", pFile);
    fputs("  <label><input type=\"checkbox\" id=\"f-deleg\" checked onchange=\"updateFilter()\"> Delegation</label>\n", pFile);
    fputs("  <label><input type=\"checkbox\" id=\"f-deny\" onchange=\"updateFilter()\"> Show DENY</label>\n", pFile);
    fputs("</div>\n", pFile);

    /* ── Embedded graph data + D3.js ───────────────────────────────── */
    fputs("<script>\n", pFile);
    hr = KestrelWriteGraphJSON(pGraph, pFile);
    if (FAILED(hr)) {
        fclose(pFile);
        return hr;
    }       

    /* D3.js visualization — все через fputs (см. KestrelJS_block.c) */
    fputs("const NODE_COLORS = {\n", pFile);
    fputs("  user: '#4A90D9', group: '#E8A838', computer: '#5CB85C',\n", pFile);
    fputs("  ou: '#9B59B6', domain: '#E74C3C', gpo: '#1ABC9C',\n", pFile);
    fputs("  container: '#7F8C8D', unknown: '#95A5A6'\n", pFile);
    fputs("};\n\n", pFile);
    fputs("const EDGE_COLORS = {\n", pFile);
    fputs("  GenericAll: '#E74C3C', WriteDACL: '#E74C3C', WriteOwner: '#E74C3C',\n", pFile);
    fputs("  GenericWrite: '#E8A838', ExtendedRight: '#E8A838',\n", pFile);
    fputs("  WriteProperty: '#F39C12',\n", pFile);
    fputs("  MemberOf: '#4A90D9',\n", pFile);
    fputs("  Delegation_Unconstrained: '#9B59B6',\n", pFile);
    fputs("  Delegation_Constrained: '#8E44AD',\n", pFile);
    fputs("  Delegation_S4U2Self: '#6C3483'\n", pFile);
    fputs("};\n\n", pFile);
    fputs("const EDGE_SEVERITY = {\n", pFile);
    fputs("  GenericAll: 3, WriteDACL: 3, WriteOwner: 3,\n", pFile);
    fputs("  GenericWrite: 2, ExtendedRight: 2,\n", pFile);
    fputs("  WriteProperty: 1, MemberOf: 0,\n", pFile);
    fputs("  Delegation_Unconstrained: 2, Delegation_Constrained: 1,\n", pFile);
    fputs("  Delegation_S4U2Self: 1\n", pFile);
    fputs("};\n\n", pFile);
    fputs("let activeFilters = { acl: true, member: true, deleg: true, deny: false };\n", pFile);
    fputs("let simulation, svg, linkGroup, nodeGroup;\n\n", pFile);
    fputs("function isEdgeVisible(e) {\n", pFile);
    fputs("  if (e.deny && !activeFilters.deny) return false;\n", pFile);
    fputs("  if (e.type === 'MemberOf') return activeFilters.member;\n", pFile);
    fputs("  if (e.type.startsWith('Delegation')) return activeFilters.deleg;\n", pFile);
    fputs("  return activeFilters.acl;\n", pFile);
    fputs("}\n\n", pFile);
    fputs("function updateFilter() {\n", pFile);
    fputs("  activeFilters.acl    = document.getElementById('f-acl').checked;\n", pFile);
    fputs("  activeFilters.member = document.getElementById('f-member').checked;\n", pFile);
    fputs("  activeFilters.deleg  = document.getElementById('f-deleg').checked;\n", pFile);
    fputs("  activeFilters.deny   = document.getElementById('f-deny').checked;\n", pFile);
    fputs("  linkGroup.selectAll('line')\n", pFile);
    fputs("    .style('display', d => isEdgeVisible(d) ? null : 'none');\n", pFile);
    fputs("}\n\n", pFile);
    fputs("function closePanel() {\n", pFile);
    fputs("  document.getElementById('panel').classList.remove('visible');\n", pFile);
    fputs("}\n\n", pFile);
    fputs("function showNodePanel(d) {\n", pFile);
    fputs("  const panel = document.getElementById('panel');\n", pFile);
    fputs("  panel.classList.add('visible');\n", pFile);
    fputs("  document.getElementById('panel-title').textContent = d.label;\n", pFile);
    fputs("  document.getElementById('panel-content').innerHTML = `\n", pFile);
    fputs("    <div class='field'><label>CLASS</label><value>${d.class}</value></div>\n", pFile);
    fputs("    <div class='field'><label>SID</label><value>${d.sid}</value></div>\n", pFile);
    fputs("    <div class='field'><label>STATUS</label><value>${d.enabled ? 'Enabled' : 'DISABLED'}</value></div>\n", pFile);
    fputs("    ${d.highValue ? \"<div class='field'><label>HIGH VALUE TARGET</label></div>\" : ''}\n", pFile);
    fputs("  `;\n", pFile);
    fputs("}\n\n", pFile);
    fputs("function initGraph() {\n", pFile);
    fputs("  const nodes = KESTREL_GRAPH.nodes.map(n => ({...n}));\n", pFile);
    fputs("  const edges = KESTREL_GRAPH.edges.map(e => ({...e,\n", pFile);
    fputs("    source: e.source, target: e.target }));\n\n", pFile);
    fputs("  const container = document.getElementById('graph');\n", pFile);
    fputs("  const W = container.clientWidth;\n", pFile);
    fputs("  const H = container.clientHeight;\n\n", pFile);
    fputs("  svg = d3.select('#graph').append('svg')\n", pFile);
    fputs("    .attr('width', W).attr('height', H)\n", pFile);
    fputs("    .call(d3.zoom().on('zoom', e => g.attr('transform', e.transform)));\n\n", pFile);
    fputs("  const g = svg.append('g');\n\n", pFile);
    fputs("  const markerTypes = [...new Set(edges.map(e => e.type))];\n", pFile);
    fputs("  svg.append('defs').selectAll('marker')\n", pFile);
    fputs("    .data(markerTypes).enter().append('marker')\n", pFile);
    fputs("    .attr('id', d => 'arrow-' + d)\n", pFile);
    fputs("    .attr('viewBox', '0 -4 8 8')\n", pFile);
    fputs("    .attr('refX', 18).attr('refY', 0)\n", pFile);
    fputs("    .attr('markerWidth', 6).attr('markerHeight', 6)\n", pFile);
    fputs("    .attr('orient', 'auto')\n", pFile);
    fputs("    .append('path')\n", pFile);
    fputs("    .attr('d', 'M0,-4L8,0L0,4')\n", pFile);
    fputs("    .attr('fill', d => EDGE_COLORS[d] || '#888');\n\n", pFile);
    fputs("  simulation = d3.forceSimulation(nodes)\n", pFile);
    fputs("    .force('link', d3.forceLink(edges).id(d => d.id).distance(80))\n", pFile);
    fputs("    .force('charge', d3.forceManyBody().strength(-200))\n", pFile);
    fputs("    .force('center', d3.forceCenter(W / 2, H / 2))\n", pFile);
    fputs("    .force('collision', d3.forceCollide(20));\n\n", pFile);
    fputs("  linkGroup = g.append('g').attr('class', 'links');\n", pFile);
    fputs("  linkGroup.selectAll('line')\n", pFile);
    fputs("    .data(edges).enter().append('line')\n", pFile);
    fputs("    .attr('stroke', d => EDGE_COLORS[d.type] || '#888')\n", pFile);
    fputs("    .attr('stroke-width', d => 0.5 + (EDGE_SEVERITY[d.type] || 0) * 0.5)\n", pFile);
    fputs("    .attr('stroke-opacity', 0.7)\n", pFile);
    fputs("    .attr('marker-end', d => `url(#arrow-${d.type})`)\n", pFile);
    fputs("    .style('display', d => isEdgeVisible(d) ? null : 'none')\n", pFile);
    fputs("    .append('title').text(d => `${d.type}${d.detail ? ': ' + d.detail : ''}`);\n\n", pFile);
    fputs("  nodeGroup = g.append('g').attr('class', 'nodes');\n", pFile);
    fputs("  const node = nodeGroup.selectAll('circle')\n", pFile);
    fputs("    .data(nodes).enter().append('circle')\n", pFile);
    fputs("    .attr('r', d => d.highValue ? 12 : d.class === 'group' ? 9 : 7)\n", pFile);
    fputs("    .attr('fill', d => NODE_COLORS[d.class] || '#95A5A6')\n", pFile);
    fputs("    .attr('stroke', d => d.highValue ? '#fff' : 'rgba(255,255,255,0.15)')\n", pFile);
    fputs("    .attr('stroke-width', d => d.highValue ? 2 : 0.5)\n", pFile);
    fputs("    .style('cursor', 'pointer')\n", pFile);
    fputs("    .on('click', (event, d) => { event.stopPropagation(); showNodePanel(d); })\n", pFile);
    fputs("    .on('mouseover', (event, d) => {\n", pFile);
    fputs("      const tt = document.getElementById('tooltip');\n", pFile);
    fputs("      tt.innerHTML = `<b>${d.label}</b><br>${d.class}`;\n", pFile);
    fputs("      tt.style.display = 'block';\n", pFile);
    fputs("      tt.style.left = (event.pageX + 12) + 'px';\n", pFile);
    fputs("      tt.style.top  = (event.pageY - 8)  + 'px';\n", pFile);
    fputs("    })\n", pFile);
    fputs("    .on('mouseout', () => {\n", pFile);
    fputs("      document.getElementById('tooltip').style.display = 'none';\n", pFile);
    fputs("    })\n", pFile);
    fputs("    .call(d3.drag()\n", pFile);
    fputs("      .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })\n", pFile);
    fputs("      .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })\n", pFile);
    fputs("      .on('end',   (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }));\n\n", pFile);
    fputs("  const label = nodeGroup.selectAll('text')\n", pFile);
    fputs("    .data(nodes.filter(n => n.highValue || n.class === 'domain'))\n", pFile);
    fputs("    .enter().append('text')\n", pFile);
    fputs("    .text(d => d.label)\n", pFile);
    fputs("    .attr('font-size', '9px')\n", pFile);
    fputs("    .attr('fill', '#ccc')\n", pFile);
    fputs("    .attr('dx', 14).attr('dy', 4);\n\n", pFile);
    fputs("  simulation.on('tick', () => {\n", pFile);
    fputs("    linkGroup.selectAll('line')\n", pFile);
    fputs("      .attr('x1', d => d.source.x).attr('y1', d => d.source.y)\n", pFile);
    fputs("      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);\n", pFile);
    fputs("    node.attr('cx', d => d.x).attr('cy', d => d.y);\n", pFile);
    fputs("    label.attr('x', d => d.x).attr('y', d => d.y);\n", pFile);
    fputs("  });\n\n", pFile);
    fputs("  svg.on('click', closePanel);\n", pFile);
    fputs("}\n\n", pFile);
    fputs("document.addEventListener('DOMContentLoaded', initGraph);\n", pFile);

    /* ── Close HTML ────────────────────────────────────────────────── */
    fputs("</script>\n</body>\n</html>\n", pFile);

    fclose(pFile);

    wprintf(L"  [+] Report written — %lu nodes, %lu edges\n",
        pGraph->cNodes, pGraph->cEdges);
    wprintf(L"  [+] Open in any browser to view the graph\n");

    return S_OK;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Internal implementations                                                   */
/* ─────────────────────────────────────────────────────────────────────────── */

static DWORD
KestrelGraphHash(
    _In_z_ LPCWSTR pwszSid)
{
    DWORD hash = 5381;
    while (*pwszSid)
        hash = ((hash << 5) + hash) ^ (DWORD)*pwszSid++;
    return hash & KESTREL_GRAPH_HASH_MASK;
}

static DWORD
KestrelGraphGetOrAddNode(
    _Inout_ KESTREL_GRAPH     *pGraph,
    _In_z_  LPCWSTR            pwszSid,
    _In_z_  LPCWSTR            pwszDN,
    _In_z_  LPCWSTR            pwszLabel,
    _In_    KESTREL_NODE_CLASS Class,
    _In_    BOOL               bEnabled,
    _In_    BOOL               bCreate)
{
    if (!pwszSid || !pwszSid[0]) return MAXDWORD;

    DWORD slot = KestrelGraphHash(pwszSid);

    /* Linear probing */
    for (DWORD i = 0; i < KESTREL_GRAPH_HASH_SIZE; i++) {
        DWORD s = (slot + i) & KESTREL_GRAPH_HASH_MASK;

        if (pGraph->rgHash[s].wszSid[0] == L'\0') {
            /* Free slot — insert if requested */
            if (!bCreate) return MAXDWORD;

            /* Grow node array if needed */
            if (pGraph->cNodes == pGraph->cNodesCapacity) {
                DWORD cNew = pGraph->cNodesCapacity * 2;
                KESTREL_GRAPH_NODE *pNew = (KESTREL_GRAPH_NODE *)HeapReAlloc(
                        GetProcessHeap(), HEAP_ZERO_MEMORY,
                        pGraph->pNodes,
                        cNew * sizeof(KESTREL_GRAPH_NODE));
                if (!pNew) return MAXDWORD;
                pGraph->pNodes         = pNew;
                pGraph->cNodesCapacity = cNew;
            }

            DWORD iNode = pGraph->cNodes++;
            KESTREL_GRAPH_NODE *pNode = &pGraph->pNodes[iNode];

            StringCchCopyW(pNode->wszSid,   ARRAYSIZE(pNode->wszSid),   pwszSid);
            StringCchCopyW(pNode->wszDN,    ARRAYSIZE(pNode->wszDN),    pwszDN);
            StringCchCopyW(pNode->wszLabel, ARRAYSIZE(pNode->wszLabel), pwszLabel);
            pNode->Class    = Class;
            pNode->bEnabled = bEnabled;

            StringCchCopyW(pGraph->rgHash[s].wszSid,
                           ARRAYSIZE(pGraph->rgHash[s].wszSid), pwszSid);
            pGraph->rgHash[s].iNode = iNode;

            return iNode;

        } else if (_wcsicmp(pGraph->rgHash[s].wszSid, pwszSid) == 0) {
            /* Found existing node */
            return pGraph->rgHash[s].iNode;
        }
    }

    return MAXDWORD; /* hash table full — shouldn't happen */
}

_Must_inspect_result_
static HRESULT
KestrelGraphAddEdge(
    _Inout_  KESTREL_GRAPH          *pGraph,
    _In_     DWORD                   iFrom,
    _In_     DWORD                   iTo,
    _In_     KESTREL_GRAPH_EDGE_TYPE Type,
    _In_z_   LPCWSTR                 pwszDetail,
    _In_     BOOL                    bDeny)
{
    if (iFrom == MAXDWORD || iTo == MAXDWORD) return E_INVALIDARG;

    /* Grow edge array if needed */
    if (pGraph->cEdges == pGraph->cEdgesCapacity) {
        DWORD cNew = pGraph->cEdgesCapacity * 2;
        KESTREL_GRAPH_EDGE *pNew = (KESTREL_GRAPH_EDGE *)HeapReAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY,
                pGraph->pEdges,
                cNew * sizeof(KESTREL_GRAPH_EDGE));
        if (!pNew) return E_OUTOFMEMORY;
        pGraph->pEdges         = pNew;
        pGraph->cEdgesCapacity = cNew;
    }

    KESTREL_GRAPH_EDGE *pEdge = &pGraph->pEdges[pGraph->cEdges++];
    pEdge->iFrom = iFrom;
    pEdge->iTo   = iTo;
    pEdge->Type  = Type;
    pEdge->bDeny = bDeny;

    if (pwszDetail)
        StringCchCopyW(pEdge->wszDetail, ARRAYSIZE(pEdge->wszDetail), pwszDetail);

    return S_OK;
}

static KESTREL_NODE_CLASS
KestrelClassifyNodeClass(
    _In_z_ LPCWSTR pwszClass)
{
    if (!pwszClass) return NODE_CLASS_UNKNOWN;
    if (_wcsicmp(pwszClass, L"user")                 == 0) return NODE_CLASS_USER;
    if (_wcsicmp(pwszClass, L"group")                == 0) return NODE_CLASS_GROUP;
    if (_wcsicmp(pwszClass, L"computer")             == 0) return NODE_CLASS_COMPUTER;
    if (_wcsicmp(pwszClass, L"organizationalUnit")   == 0) return NODE_CLASS_OU;
    if (_wcsicmp(pwszClass, L"domainDNS")            == 0) return NODE_CLASS_DOMAIN;
    if (_wcsicmp(pwszClass, L"groupPolicyContainer") == 0) return NODE_CLASS_GPO;
    if (_wcsicmp(pwszClass, L"container")            == 0) return NODE_CLASS_CONTAINER;
    return NODE_CLASS_UNKNOWN;
}

_Must_inspect_result_
static HRESULT
KestrelGraphAddACLEdges(
    _Inout_  KESTREL_GRAPH           *pGraph,
    _In_     KESTREL_ACL_SCAN_RESULT *pACLResult)
{
    /* Map KESTREL_ACL_EDGE_TYPE → KESTREL_GRAPH_EDGE_TYPE */
    static const KESTREL_GRAPH_EDGE_TYPE rgTypeMap[] = {
        GEDGE_ACL_GENERIC_ALL,    /* EDGE_UNKNOWN        → fallback */
        GEDGE_ACL_GENERIC_ALL,    /* EDGE_GENERIC_ALL                */
        GEDGE_ACL_WRITE_DACL,     /* EDGE_WRITE_DACL                 */
        GEDGE_ACL_WRITE_OWNER,    /* EDGE_WRITE_OWNER                */
        GEDGE_ACL_GENERIC_WRITE,  /* EDGE_GENERIC_WRITE              */
        GEDGE_ACL_EXTENDED_RIGHT, /* EDGE_EXTENDED_RIGHT             */
        GEDGE_ACL_WRITE_PROP,     /* EDGE_WRITE_PROPERTY             */
        GEDGE_ACL_GENERIC_WRITE,  /* EDGE_CREATE_CHILD               */
        GEDGE_ACL_GENERIC_WRITE,  /* EDGE_DELETE_CHILD               */
        GEDGE_ACL_GENERIC_WRITE,  /* EDGE_SELF                       */
    };

    for (DWORD i = 0; i < pACLResult->cEdges; i++) {
        KESTREL_ACL_EDGE *pE = &pACLResult->rgEdges[i];

        /* Trustee node — we only have SID, no DN/label yet */
        DWORD iFrom = KestrelGraphGetOrAddNode(pGraph,
                pE->wszTrusteeSid, L"", pE->wszTrusteeSid,
                NODE_CLASS_UNKNOWN, TRUE, TRUE);

        /* Target node */
        DWORD iTo = KestrelGraphGetOrAddNode(pGraph,
                pE->wszTrusteeSid, /* placeholder — target has no SID in edge */
                pE->wszTargetDN, pE->wszTargetDN,
                KestrelClassifyNodeClass(pE->wszObjectClass),
                TRUE, TRUE);

        /* TODO: target node should be keyed by DN not SID
                 once we have SID for target objects, update key */

        KESTREL_GRAPH_EDGE_TYPE eType =
            (pE->EdgeType < ARRAYSIZE(rgTypeMap))
            ? rgTypeMap[pE->EdgeType] : GEDGE_ACL_GENERIC_ALL;

        LPCWSTR pwszDetail = pE->wszRightName[0]
                           ? pE->wszRightName : pE->wszRightGuid;

        HRESULT hr = KestrelGraphAddEdge(pGraph, iFrom, iTo,
                                          eType, pwszDetail, pE->bDeny);
        if (FAILED(hr)) return hr;

        pGraph->cACLEdges++;
    }

    return S_OK;
}

_Must_inspect_result_
static HRESULT
KestrelGraphAddMemberEdges(
    _Inout_  KESTREL_GRAPH             *pGraph,
    _In_     KESTREL_GROUP_SCAN_RESULT *pGroupResult)
{
    for (KESTREL_GROUP_RESULT *pGroup = pGroupResult->pGroups;
         pGroup; pGroup = pGroup->pNext) {

        /* Group node */
        DWORD iGroup = KestrelGraphGetOrAddNode(pGraph,
                pGroup->wszGroupDN, /* use DN as key if no SID */
                pGroup->wszGroupDN,
                pGroup->wszGroupName,
                NODE_CLASS_GROUP, TRUE, TRUE);

        /* Member nodes */
        for (KESTREL_MEMBER *pMember = pGroup->pMembers;
             pMember; pMember = pMember->pNext) {

            DWORD iMember = KestrelGraphGetOrAddNode(pGraph,
                    pMember->wszSid,
                    pMember->wszDN,
                    pMember->wszSAM[0] ? pMember->wszSAM : pMember->wszDN,
                    KestrelClassifyNodeClass(pMember->wszClass),
                    pMember->bEnabled, TRUE);

            /* member → memberOf → group */
            HRESULT hr = KestrelGraphAddEdge(pGraph, iMember, iGroup,
                                              GEDGE_MEMBER_OF, L"", FALSE);
            if (FAILED(hr)) return hr;

            pGraph->cMemberEdges++;
        }
    }

    return S_OK;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/*  Cleanup                                                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

VOID
KestrelFreeGraph(
    _In_opt_ _Post_ptr_invalid_ KESTREL_GRAPH *pGraph)
{
    if (!pGraph) return;
    if (pGraph->pNodes) HeapFree(GetProcessHeap(), 0, pGraph->pNodes);
    if (pGraph->pEdges) HeapFree(GetProcessHeap(), 0, pGraph->pEdges);
    HeapFree(GetProcessHeap(), 0, pGraph);
}
_Must_inspect_result_
static HRESULT
KestrelWriteGraphJSON(
    _In_ const KESTREL_GRAPH* pGraph,
    _In_ FILE* pFile)
{
    static const char* rgszNodeClass[] = {
        "unknown", "user", "group", "computer",
        "ou", "domain", "gpo", "container"
    };

    static const char* rgszEdgeType[] = {
        "GenericAll", "WriteDACL", "WriteOwner", "GenericWrite",
        "ExtendedRight", "WriteProperty",
        "MemberOf",
        "Delegation_Unconstrained", "Delegation_Constrained", "Delegation_S4U2Self"
    };

    fprintf(pFile, "const KESTREL_GRAPH = {\n");

    /* ── Nodes ─────────────────────────────────────────────────────── */
    fprintf(pFile, "  nodes: [\n");
    for (DWORD i = 0; i < pGraph->cNodes; i++) {
        const KESTREL_GRAPH_NODE* pN = &pGraph->pNodes[i];

        const char* pszClass = (pN->Class < ARRAYSIZE(rgszNodeClass))
            ? rgszNodeClass[pN->Class] : "unknown";

        /* Escape backslashes in DN for JSON */
        fprintf(pFile, "    { \"id\": %lu, ", i);
        fprintf(pFile, "\"sid\": \"");

        /* Write SID — safe, no special chars */
        for (const WCHAR* p = pN->wszSid; *p; p++)
            fputc((char)*p, pFile);

        fprintf(pFile, "\", \"label\": \"");

        /* Write label — escape quotes */
        for (const WCHAR* p = pN->wszLabel; *p; p++) {
            if (*p == L'"')  fputs("\\\"", pFile);
            else if (*p == L'\\') fputs("\\\\", pFile);
            else fputc((char)*p, pFile);
        }

        fprintf(pFile, "\", \"class\": \"%s\", ", pszClass);
        fprintf(pFile, "\"enabled\": %s, ", pN->bEnabled ? "true" : "false");
        fprintf(pFile, "\"highValue\": %s }%s\n",
            pN->bHighValue ? "true" : "false",
            i < pGraph->cNodes - 1 ? "," : "");
    }
    fprintf(pFile, "  ],\n");

    /* ── Edges ─────────────────────────────────────────────────────── */
    fprintf(pFile, "  edges: [\n");
    for (DWORD i = 0; i < pGraph->cEdges; i++) {
        const KESTREL_GRAPH_EDGE* pE = &pGraph->pEdges[i];

        const char* pszType = (pE->Type < ARRAYSIZE(rgszEdgeType))
            ? rgszEdgeType[pE->Type] : "Unknown";

        fprintf(pFile, "    { \"source\": %lu, \"target\": %lu, ",
            pE->iFrom, pE->iTo);
        fprintf(pFile, "\"type\": \"%s\", ", pszType);
        fprintf(pFile, "\"detail\": \"");

        for (const WCHAR* p = pE->wszDetail; *p; p++) {
            if (*p == L'"')  fputs("\\\"", pFile);
            else if (*p == L'\\') fputs("\\\\", pFile);
            else fputc((char)*p, pFile);
        }

        fprintf(pFile, "\", \"deny\": %s }%s\n",
            pE->bDeny ? "true" : "false",
            i < pGraph->cEdges - 1 ? "," : "");
    }
    fprintf(pFile, "  ]\n");
    fprintf(pFile, "};\n\n");

    return S_OK;
}
