import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import type { Finding, MapNode, NodeKind, SystemGraph } from "../api/schemas";
import { NODE_KINDS } from "../api/schemas";
import { append, clear, h } from "../lib/dom";
import { SEVERITY_BADGE, SEVERITY_LABEL, bySeverityDesc } from "../lib/severity";
import { location } from "./findings";

export const KIND_LABEL: Record<NodeKind, string> = {
  component: "Component",
  entry_point: "Entry point",
  route: "Route",
  data_store: "Data store",
  external_service: "External service",
  secret: "Secret",
  dependency: "Dependency",
};

export const KIND_COLOR: Record<NodeKind, string> = {
  component: "#64748b",
  entry_point: "#059669",
  route: "#7c3aed",
  data_store: "#2563eb",
  external_service: "#0d9488",
  secret: "#c026d3",
  dependency: "#d97706",
};

// ── Data transforms (pure, unit-tested) ─────────────────────────────────────

export const nodeKey = (id: number): string => `n${id}`;

/** Graph → Cytoscape elements. Nodes with findings get the `risky` class and grow with their count. */
export function toElements(graph: SystemGraph): ElementDefinition[] {
  const nodes: ElementDefinition[] = graph.nodes.map((n) => ({
    group: "nodes",
    data: {
      id: nodeKey(n.id),
      label: n.label,
      kind: n.kind,
      color: KIND_COLOR[n.kind],
      findings: n.finding_count,
      size: 28 + Math.min(n.finding_count, 6) * 6,
    },
    classes: [`kind-${n.kind}`, n.finding_count > 0 ? "risky" : ""].filter(Boolean).join(" "),
  }));
  const seen = new Set<string>();
  const edges: ElementDefinition[] = [];
  for (const e of graph.edges) {
    const id = `e${e.source}-${e.target}-${e.kind}`;
    if (seen.has(id)) continue; // the API dedupes too; this keeps the graph valid if it ever doesn't
    seen.add(id);
    edges.push({ group: "edges", data: { id, source: nodeKey(e.source), target: nodeKey(e.target), kind: e.kind } });
  }
  return [...nodes, ...edges];
}

function lineOf(n: MapNode): number | undefined {
  const line = n.meta["line"];
  return typeof line === "number" ? line : undefined;
}

/** The findings that belong to a node: same file, and for line-anchored nodes, the lines it owns. */
export function findingsForNode(graph: SystemGraph, findings: readonly Finding[], node: MapNode): Finding[] {
  if (!node.rel_path) return [];
  const inFile = findings.filter((f) => f.rel_path === node.rel_path);
  const start = lineOf(node);
  let matched: Finding[];
  if (node.kind === "dependency") {
    const pkg = node.label.split("@")[0]?.toLowerCase() ?? "";
    matched = inFile.filter((f) => pkg !== "" && f.title.toLowerCase().includes(pkg));
  } else if (start === undefined) {
    matched = inFile;
  } else {
    // A route or secret owns its lines: up to meta.line_end when the mapper knows it, otherwise up to
    // the next node of the same kind in the same file (a secret owns just its own line).
    const next = graph.nodes
      .filter((o) => o.kind === node.kind && o.rel_path === node.rel_path && (lineOf(o) ?? 0) > start)
      .map((o) => lineOf(o) ?? Infinity)
      .reduce((a, b) => Math.min(a, b), Infinity);
    const declaredEnd = node.meta["line_end"];
    const end = typeof declaredEnd === "number" ? declaredEnd + 1 : node.kind === "secret" ? start + 1 : next;
    matched = inFile.filter((f) => f.line_start !== null && f.line_start >= start && f.line_start < end);
  }
  return [...matched].sort(bySeverityDesc);
}

export function neighbours(graph: SystemGraph, nodeId: number): { node: MapNode; kind: string; outgoing: boolean }[] {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const out: { node: MapNode; kind: string; outgoing: boolean }[] = [];
  for (const e of graph.edges) {
    const other = e.source === nodeId ? byId.get(e.target) : e.target === nodeId ? byId.get(e.source) : undefined;
    if (other) out.push({ node: other, kind: e.kind, outgoing: e.source === nodeId });
  }
  return out;
}

export function countByKind(graph: SystemGraph): Record<NodeKind, number> {
  const counts = Object.fromEntries(NODE_KINDS.map((k) => [k, 0])) as Record<NodeKind, number>;
  for (const n of graph.nodes) counts[n.kind] += 1;
  return counts;
}

/** A large synthetic graph for checking the map stays usable (open the viewer with `?big=300`). */
export function syntheticGraph(size: number): SystemGraph {
  const nodes: MapNode[] = [];
  const edges: SystemGraph["edges"] = [];
  for (let i = 1; i <= size; i++) {
    const kind = NODE_KINDS[i === 1 ? 1 : i % NODE_KINDS.length] ?? "component";
    nodes.push({
      id: i,
      kind,
      label: `${KIND_LABEL[kind]} ${i}`,
      rel_path: `src/module_${i % 40}.ts`,
      meta: {},
      finding_count: i % 9 === 0 ? (i % 4) + 1 : 0,
    });
    if (i > 1) edges.push({ source: Math.max(1, Math.floor(i / 3)), target: i, kind: "imports" });
  }
  return { nodes, edges };
}

// ── Rendering ───────────────────────────────────────────────────────────────

export function renderMap(root: HTMLElement, graph: SystemGraph, findings: readonly Finding[]): () => void {
  const byKey = new Map(graph.nodes.map((n) => [nodeKey(n.id), n]));
  const counts = countByKind(graph);
  const risky = graph.nodes.filter((n) => n.finding_count > 0).length;

  const legend = h(
    "div",
    { class: "flex flex-wrap gap-x-4 gap-y-1 text-xs" },
    ...NODE_KINDS.filter((k) => counts[k] > 0).map((k) =>
      h(
        "span",
        { class: "inline-flex items-center gap-1.5" },
        h("span", { class: "inline-block h-2.5 w-2.5 rounded-full", style: `background:${KIND_COLOR[k]}` }),
        `${KIND_LABEL[k]} (${counts[k]})`,
      ),
    ),
    h(
      "span",
      { class: "inline-flex items-center gap-1.5" },
      h("span", { class: "inline-block h-2.5 w-2.5 rounded-full border-2 border-red-600" }),
      `Has problems (${risky})`,
    ),
  );
  const graphHost = h("div", {
    id: "graph",
    role: "img",
    "aria-label": `Map of the app: ${graph.nodes.length} parts, ${risky} with problems`,
    class: "h-[560px] w-full rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900",
  });
  const side = h("div");

  const showNode = (node: MapNode | undefined) => {
    clear(side);
    const box = h("section", {
      class: "rounded-xl border border-slate-200 bg-white p-4 text-sm shadow-sm dark:border-slate-800 dark:bg-slate-900",
    });
    side.append(box);
    if (!node) {
      box.append(
        h("h2", { class: "font-semibold" }, "How to read this map"),
        h(
          "p",
          { class: "mt-2 text-slate-600 dark:text-slate-300" },
          "Each dot is a part of your app: where it starts, the web addresses it answers, where it keeps data, the secrets it uses and the packages it depends on. Red rings mark parts with security problems. Click a dot for details.",
        ),
        h("p", { class: "mt-2 text-slate-500 dark:text-slate-400" }, "Scroll to zoom, drag to move around."),
      );
      return;
    }
    const own = findingsForNode(graph, findings, node);
    const links = neighbours(graph, node.id);
    append(box, [
      h(
        "div",
        { class: "flex items-center gap-2" },
        h("span", { class: "inline-block h-3 w-3 rounded-full", style: `background:${KIND_COLOR[node.kind]}` }),
        h("span", { class: "text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400" }, KIND_LABEL[node.kind]),
      ),
      h("h2", { class: "mt-1 break-words text-base font-semibold" }, node.label),
      node.rel_path ? h("div", { class: "mt-1 font-mono text-xs text-slate-500 dark:text-slate-400" }, node.rel_path) : null,
      h("h3", { class: "mt-4 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400" }, `Problems (${own.length})`),
      own.length
        ? h(
            "ul",
            { class: "mt-1 space-y-1" },
            ...own.map((f) =>
              h(
                "li",
                { class: "flex items-start gap-2" },
                h("span", { class: `rounded px-1 text-[10px] font-semibold uppercase ${SEVERITY_BADGE[f.severity]}` }, SEVERITY_LABEL[f.severity]),
                h("a", { href: "#/findings", class: "hover:underline" }, f.title),
                h("span", { class: "ml-auto font-mono text-[11px] text-slate-400" }, location(f).split(":")[1] ?? ""),
              ),
            ),
          )
        : h("p", { class: "mt-1 text-slate-500 dark:text-slate-400" }, "None found."),
      h("h3", { class: "mt-4 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400" }, `Connected to (${links.length})`),
      h(
        "ul",
        { class: "mt-1 space-y-0.5" },
        ...links.map((l) =>
          h("li", {}, h("span", { class: "text-slate-500 dark:text-slate-400" }, `${l.outgoing ? "→" : "←"} ${l.kind.replace("_", " ")} `), l.node.label),
        ),
      ),
    ]);
  };

  clear(root);
  root.append(
    legend,
    h("div", { class: "mt-3 grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_320px]" }, graphHost, side),
  );
  showNode(undefined);

  const theme = document.documentElement.dataset["theme"];
  const dark = theme ? theme === "dark" : (window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false);
  const big = graph.nodes.length > 120;
  const cy: Core = cytoscape({
    container: graphHost,
    elements: toElements(graph),
    wheelSensitivity: 0.3,
    minZoom: 0.1,
    maxZoom: 3,
    style: [
      {
        selector: "node",
        style: {
          "background-color": "data(color)",
          label: big ? "" : "data(label)",
          width: "data(size)",
          height: "data(size)",
          "font-size": 11,
          color: dark ? "#e2e8f0" : "#0f172a",
          "text-valign": "bottom",
          "text-margin-y": 4,
          "text-wrap": "ellipsis",
          "text-max-width": "140px",
        },
      },
      { selector: "node.risky", style: { "border-width": 4, "border-color": "#dc2626" } },
      { selector: "node:selected", style: { "overlay-color": "#10b981", "overlay-opacity": 0.25, label: "data(label)" } },
      {
        selector: "edge",
        style: {
          width: 1.5,
          "line-color": dark ? "#475569" : "#cbd5e1",
          "target-arrow-color": dark ? "#475569" : "#cbd5e1",
          "target-arrow-shape": "triangle",
          "curve-style": big ? "haystack" : "bezier",
        },
      },
    ],
    layout: big
      ? { name: "cose", animate: false, nodeRepulsion: () => 8000, idealEdgeLength: () => 60, numIter: 600 }
      : { name: "cose", animate: false, padding: 30, nodeRepulsion: () => 12000 },
  });
  cy.on("tap", "node", (evt) => showNode(byKey.get(evt.target.id())));
  cy.on("tap", (evt) => {
    if (evt.target === cy) showNode(undefined);
  });
  return () => cy.destroy();
}
