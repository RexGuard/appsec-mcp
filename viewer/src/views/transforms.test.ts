import { describe, expect, it } from "vitest";
import mapMock from "../mock/map.json";
import scanMock from "../mock/scan.json";
import { FindingListSchema, SystemGraphSchema, type SystemGraph } from "../api/schemas";
import { currentView, viewUrl } from "../router";
import {
  countBySeverity,
  describeSkip,
  filterFindings,
  findingsForNode,
  pageCount,
  shorten,
  toElements,
} from "./transforms";

const findings = FindingListSchema.parse(scanMock.findings).items;
const graph = SystemGraphSchema.parse(mapMock);

describe("findings transforms", () => {
  it("filters by minimum severity and text", () => {
    expect(filterFindings(findings, "critical", "").every((f) => f.severity === "critical")).toBe(true);
    expect(filterFindings(findings, "info", "SQL").length).toBeGreaterThan(0);
    expect(filterFindings(findings, "info", "no-such-thing")).toHaveLength(0);
  });

  it("counts open findings per severity", () => {
    const counts = countBySeverity(findings);
    expect(Object.values(counts).reduce((a, b) => a + b, 0)).toBe(findings.length);
  });
});

describe("map transforms", () => {
  it("builds nodes and edges and highlights risky nodes", () => {
    const elements = toElements(graph, true);
    const nodes = elements.filter((e) => !("source" in e.data));
    expect(nodes).toHaveLength(graph.nodes.length);
    expect(nodes.some((n) => n.data["risky"] === true)).toBe(true);
  });

  it("hides clean dependencies unless asked", () => {
    expect(toElements(graph, false).length).toBeLessThan(toElements(graph, true).length);
  });

  it("handles 300 nodes", () => {
    const big: SystemGraph = {
      nodes: Array.from({ length: 300 }, (_, i) => ({ id: i + 1, kind: "route" as const, label: `GET /r${i}`, rel_path: "a.js", meta: {}, finding_count: 0 })),
      edges: Array.from({ length: 299 }, (_, i) => ({ source: 1, target: i + 2, kind: "handles" as const })),
    };
    expect(toElements(big, false)).toHaveLength(599);
  });

  it("links nodes to their findings", () => {
    const secret = graph.nodes.find((n) => n.kind === "secret");
    expect(secret).toBeDefined();
    expect(findingsForNode(secret!, findings)).toHaveLength(1);
  });

  it("shortens long labels from the left", () => {
    expect(shorten("a".repeat(40), 10)).toHaveLength(10);
    expect(shorten("short")).toBe("short");
  });
});

describe("ledger and router", () => {
  it("paginates and explains skips", () => {
    expect(pageCount(0, 200)).toBe(1);
    expect(pageCount(401, 200)).toBe(3);
    expect(describeSkip({ rel_path: "x", language: null, size_bytes: null, sha256: null, status: "skipped", skip_reason: "binary" })).toBe("Binary file");
  });

  it("routes by ?view=", () => {
    expect(currentView("?view=map")).toBe("map");
    expect(currentView("?view=evil")).toBe("findings");
    expect(viewUrl("ledger", "?view=map")).toBe("?view=ledger");
  });
});
