import { describe, expect, it } from "vitest";
import mockLedger from "../mock/ledger.json";
import mockMap from "../mock/map.json";
import mockScan from "../mock/scan.json";
import { Finding, FindingDetail, Ledger, LedgerFile, MockScan, ScanSummary, SystemGraph } from "./schemas";

describe("mock data matches the API contract", () => {
  it("parses the scan bundle", () => {
    const scan = MockScan.parse(mockScan);
    expect(scan.findings.items.length).toBe(scan.findings.total);
    const sum = Object.values(scan.summary.counts).reduce((a, b) => a + b, 0);
    expect(sum).toBe(scan.findings.total);
    for (const f of scan.findings.items) expect(scan.details.some((d) => d.id === f.id)).toBe(true);
  });

  it("parses the map and the ledger", () => {
    expect(SystemGraph.parse(mockMap).nodes.length).toBeGreaterThan(5);
    const ledger = Ledger.parse(mockLedger);
    expect(ledger.files.items.filter((f) => f.status === "read").length).toBe(ledger.files.read);
    expect(ledger.files.items.filter((f) => f.status === "skipped").length).toBe(ledger.files.skipped);
  });
});

describe("schemas reject malformed responses", () => {
  const finding = MockScan.parse(mockScan).findings.items[0]!;

  it("rejects unknown severities, bad ids and extra fields", () => {
    expect(Finding.safeParse({ ...finding, severity: "urgent" }).success).toBe(false);
    expect(Finding.safeParse({ ...finding, id: 0 }).success).toBe(false);
    expect(Finding.safeParse({ ...finding, id: -3 }).success).toBe(false);
    expect(Finding.safeParse({ ...finding, surprise: true }).success).toBe(false);
  });

  it("rejects a score above 100", () => {
    const summary = MockScan.parse(mockScan).summary;
    expect(ScanSummary.safeParse({ ...summary, score: 140 }).success).toBe(false);
  });

  it("rejects non-http reference links (no javascript: URLs in the page)", () => {
    const detail = MockScan.parse(mockScan).details[0]!;
    expect(FindingDetail.safeParse({ ...detail, references: ["javascript:alert(1)"] }).success).toBe(false);
  });

  it("rejects edges to missing nodes", () => {
    const graph = SystemGraph.parse(mockMap);
    const bad = { ...graph, edges: [...graph.edges, { source: 1, target: 999, kind: "calls" }] };
    expect(SystemGraph.safeParse(bad).success).toBe(false);
  });

  it("requires a skip reason exactly when a file was skipped", () => {
    const base = { rel_path: "a.py", language: "python", size_bytes: 3, sha256: "a".repeat(64) };
    expect(LedgerFile.safeParse({ ...base, status: "read", skip_reason: null }).success).toBe(true);
    expect(LedgerFile.safeParse({ ...base, status: "skipped", skip_reason: null }).success).toBe(false);
    expect(LedgerFile.safeParse({ ...base, status: "read", skip_reason: "binary" }).success).toBe(false);
  });
});
