import cytoscape from "cytoscape";
import type { Api } from "../api/client";
import { nodeKinds, type ScanSummary } from "../api/schemas";
import { h, severityBadge } from "../dom";
import { findingsForNode, KIND_COLORS, KIND_LABELS, toElements } from "./transforms";

const LARGE_GRAPH = 150;

export async function renderMap(root: HTMLElement, api: Api, scan: ScanSummary): Promise<void> {
  const [graph, findings] = await Promise.all([api.map(scan.scan_id), api.findings(scan.scan_id)]);
  const container = h("div", { class: "h-[65vh] w-full rounded border border-slate-200 bg-white", "aria-label": "System map graph" });
  const panel = h("aside", { class: "card", "aria-live": "polite" }, h("p", { class: "text-sm text-slate-500" }, "Click a node to see its files and findings. Red borders mark risky spots."));
  const toggle = h("input", { type: "checkbox", id: "show-deps" });
  const legend = h("div", { class: "flex flex-wrap items-center gap-3 text-xs" },
    ...nodeKinds.map((kind) => h("span", { class: "flex items-center gap-1" },
      h("span", { class: "inline-block h-3 w-3 rounded-full", style: `background:${KIND_COLORS[kind]}` }), KIND_LABELS[kind])),
    h("label", { class: "ml-auto flex items-center gap-1", for: "show-deps" }, toggle, "Show all dependencies"));

  root.replaceChildren(
    h("div", { class: "grid gap-6 lg:grid-cols-[3fr_1fr]" },
      h("section", { class: "card space-y-3" }, legend, container), panel));

  let cy: cytoscape.Core | null = null;
  const draw = (): void => {
    cy?.destroy();
    const elements = toElements(graph, toggle.checked);
    cy = cytoscape({
      container,
      elements,
      wheelSensitivity: 0.3,
      layout: { name: elements.length > LARGE_GRAPH ? "concentric" : "cose", animate: false },
      style: [
        { selector: "node", style: { "background-color": "data(color)", label: "data(label)", "font-size": 9, color: "#0f172a", "text-valign": "bottom", "text-margin-y": 3, width: 18, height: 18 } },
        { selector: "node[?risky]", style: { "border-width": 3, "border-color": "#dc2626", width: 26, height: 26 } },
        { selector: "edge", style: { width: 1, "line-color": "#cbd5e1", "target-arrow-color": "#cbd5e1", "target-arrow-shape": "triangle", "curve-style": "bezier" } },
        { selector: ":selected", style: { "overlay-opacity": 0.15, "overlay-color": "#0f172a" } },
      ],
    });
    cy.on("tap", "node", (event) => {
      const id = Number(String(event.target.id()).slice(1));
      const node = graph.nodes.find((n) => n.id === id);
      if (!node) return;
      const related = findingsForNode(node, findings.items);
      panel.replaceChildren(
        h("p", { class: "text-xs uppercase text-slate-500" }, KIND_LABELS[node.kind]),
        h("h3", { class: "break-all font-semibold" }, node.label),
        node.rel_path ? h("p", { class: "mt-1 break-all font-mono text-xs text-slate-500" }, node.rel_path) : "",
        ...Object.entries(node.meta).map(([k, v]) => h("p", { class: "text-xs text-slate-600" }, `${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`)),
        h("h4", { class: "mt-3 text-sm font-semibold" }, `Findings (${related.length})`),
        related.length === 0 ? h("p", { class: "text-sm text-slate-500" }, "None here.") :
          h("ul", { class: "mt-1 space-y-2" }, ...related.map((f) => h("li", { class: "text-sm" }, severityBadge(f.severity), " ", f.title,
            h("span", { class: "block font-mono text-xs text-slate-500" }, `${f.rel_path ?? ""}:${f.line_start ?? ""}`)))),
      );
    });
  };
  toggle.addEventListener("change", draw);
  draw();
}
