import type {
  FindingItem,
  LedgerFile,
  MapNode,
  NodeKind,
  Severity,
  SystemGraph,
} from "../api/schemas";
import { severities } from "../api/schemas";

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function atLeast(severity: Severity, minimum: Severity): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[minimum];
}

export function filterFindings(
  items: readonly FindingItem[],
  minimum: Severity,
  query: string,
): FindingItem[] {
  const needle = query.trim().toLowerCase();
  return items.filter(
    (item) =>
      atLeast(item.severity, minimum) &&
      (needle === "" ||
        item.title.toLowerCase().includes(needle) ||
        (item.rel_path ?? "").toLowerCase().includes(needle)),
  );
}

export function countBySeverity(items: readonly FindingItem[]): Record<Severity, number> {
  const counts = Object.fromEntries(severities.map((s) => [s, 0])) as Record<Severity, number>;
  for (const item of items) {
    if (item.status !== "fixed") counts[item.severity] += 1;
  }
  return counts;
}

export const KIND_COLORS: Record<NodeKind, string> = {
  component: "#64748b",
  entry_point: "#7c3aed",
  route: "#2563eb",
  data_store: "#059669",
  external_service: "#d97706",
  secret: "#dc2626",
  dependency: "#94a3b8",
};

export const KIND_LABELS: Record<NodeKind, string> = {
  component: "Component",
  entry_point: "Entry point",
  route: "Route",
  data_store: "Data store",
  external_service: "External service",
  secret: "Secret",
  dependency: "Dependency",
};

export interface GraphElement {
  data: Record<string, string | number | boolean>;
}

/** Turns the API graph into Cytoscape elements; hides dependencies unless asked. */
export function toElements(graph: SystemGraph, showDependencies: boolean): GraphElement[] {
  const visible = new Set<number>();
  const nodes: GraphElement[] = [];
  for (const node of graph.nodes) {
    if (!showDependencies && node.kind === "dependency" && node.finding_count === 0) continue;
    visible.add(node.id);
    nodes.push({
      data: {
        id: `n${node.id}`,
        label: shorten(node.label),
        kind: node.kind,
        color: KIND_COLORS[node.kind],
        risky: node.finding_count > 0,
        findings: node.finding_count,
      },
    });
  }
  const edges = graph.edges
    .filter((e) => visible.has(e.source) && visible.has(e.target))
    .map((e) => ({
      data: { id: `e${e.source}-${e.target}-${e.kind}`, source: `n${e.source}`, target: `n${e.target}`, kind: e.kind },
    }));
  return [...nodes, ...edges];
}

export function shorten(label: string, max = 32): string {
  return label.length <= max ? label : `…${label.slice(label.length - max + 1)}`;
}

/** Findings that belong to a map node (same file, or inside a component folder). */
export function findingsForNode(node: MapNode, items: readonly FindingItem[]): FindingItem[] {
  const open = items.filter((f) => f.status !== "fixed" && f.rel_path !== null);
  if (node.kind === "component") {
    const folder = node.rel_path ?? "";
    return open.filter((f) => parentOf(f.rel_path ?? "") === folder);
  }
  if (node.kind === "secret") {
    return open.filter((f) => `${f.rel_path}:${f.line_start ?? 1}` === node.label);
  }
  if (node.rel_path) return open.filter((f) => f.rel_path === node.rel_path);
  return [];
}

function parentOf(path: string): string {
  const index = path.lastIndexOf("/");
  return index === -1 ? "" : path.slice(0, index);
}

export function pageCount(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / pageSize));
}

export function describeSkip(file: LedgerFile): string {
  const reasons: Record<string, string> = {
    gitignored: "Ignored by .gitignore",
    too_large: "Larger than the size limit",
    binary: "Binary file",
    excluded_dir: "Dependency/build folder",
    symlink_outside_root: "Link pointing outside the project",
    symlink_dir: "Linked folder (not followed)",
    unreadable: "Could not be read",
  };
  return file.skip_reason ? (reasons[file.skip_reason] ?? file.skip_reason) : "";
}
