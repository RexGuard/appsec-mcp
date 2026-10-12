import { describe, expect, it } from "vitest";
import { MockScan, SystemGraph } from "../api/schemas";
import mockMap from "../mock/map.json";
import mockScan from "../mock/scan.json";
import { countByKind, findingsForNode, neighbours, syntheticGraph, toElements } from "./map";

const graph = SystemGraph.parse(mockMap);
const findings = MockScan.parse(mockScan).findings.items;
const byLabel = (label: string) => graph.nodes.find((n) => n.label === label)!;

describe("toElements", () => {
  it("emits one element per node and edge, marking risky nodes", () => {
    const els = toElements(graph);
    expect(els.filter((e) => e.group === "nodes").length).toBe(graph.nodes.length);
    expect(els.filter((e) => e.group === "edges").length).toBe(graph.edges.length);
    const risky = els.filter((e) => e.classes?.includes("risky")).length;
    expect(risky).toBe(graph.nodes.filter((n) => n.finding_count > 0).length);
  });

  it("drops duplicate edges", () => {
    const dup = { ...graph, edges: [...graph.edges, graph.edges[0]!] };
    expect(toElements(dup).filter((e) => e.group === "edges").length).toBe(graph.edges.length);
  });

  it("handles 200+ nodes quickly", () => {
    const big = SystemGraph.parse(syntheticGraph(500));
    const t0 = performance.now();
    const els = toElements(big);
    expect(els.filter((e) => e.group === "nodes").length).toBe(500);
    expect(performance.now() - t0).toBeLessThan(200);
  });
});

describe("findingsForNode", () => {
  it("assigns a route the findings in its own handler only", () => {
    expect(findingsForNode(graph, findings, byLabel("GET /api/users")).map((f) => f.id)).toEqual([1]);
    expect(findingsForNode(graph, findings, byLabel("GET /hello")).map((f) => f.id)).toEqual([4]);
    expect(findingsForNode(graph, findings, byLabel("POST /api/orders"))).toEqual([]);
  });

  it("assigns a secret only its own line", () => {
    expect(findingsForNode(graph, findings, byLabel("apiSecretKey")).map((f) => f.id)).toEqual([2]);
    expect(findingsForNode(graph, findings, byLabel("paymentsApiToken")).map((f) => f.id)).toEqual([3]);
  });

  it("matches a dependency by package name", () => {
    expect(findingsForNode(graph, findings, byLabel("lodash@4.17.15")).map((f) => f.id)).toEqual([5]);
    expect(findingsForNode(graph, findings, byLabel("express@4.18.2"))).toEqual([]);
  });

  it("gives a file-level node every finding in its file, most severe first", () => {
    const out = findingsForNode(graph, findings, byLabel("server.ts (app.listen)"));
    expect(out[0]!.severity).toBe("critical");
    expect(out.every((f) => f.rel_path === "src/server.ts")).toBe(true);
  });
});

describe("graph helpers", () => {
  it("lists neighbours in both directions", () => {
    const users = byLabel("GET /api/users");
    const n = neighbours(graph, users.id);
    expect(n.some((x) => x.node.kind === "entry_point" && !x.outgoing)).toBe(true);
    expect(n.some((x) => x.node.kind === "data_store" && x.outgoing)).toBe(true);
  });

  it("counts nodes by kind", () => {
    const c = countByKind(graph);
    expect(c.route).toBe(3);
    expect(c.dependency).toBe(4);
    expect(Object.values(c).reduce((a, b) => a + b, 0)).toBe(graph.nodes.length);
  });

  it("builds a valid synthetic graph", () => {
    expect(SystemGraph.safeParse(syntheticGraph(300)).success).toBe(true);
  });
});
