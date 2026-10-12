import { describe, expect, it } from "vitest";
import ledgerMock from "../mock/ledger.json";
import mapMock from "../mock/map.json";
import scanMock from "../mock/scan.json";
import { ApiError, createLiveApi, createMockApi } from "./client";
import {
  FindingDetailSchema,
  FindingListSchema,
  LedgerSchema,
  ScanListSchema,
  SystemGraphSchema,
} from "./schemas";

describe("schemas", () => {
  it("parse the mock data produced by a real scan", () => {
    expect(ScanListSchema.parse(scanMock.scans).items).toHaveLength(1);
    expect(FindingListSchema.parse(scanMock.findings).total).toBeGreaterThan(0);
    for (const detail of Object.values(scanMock.details)) FindingDetailSchema.parse(detail);
    expect(SystemGraphSchema.parse(mapMock).nodes.length).toBeGreaterThan(0);
    expect(LedgerSchema.parse(ledgerMock).scanners[0]?.name).toBe("builtin");
  });

  it("reject bad severities and negative ids", () => {
    const item = scanMock.findings.items[0];
    expect(FindingListSchema.safeParse({ total: 1, items: [{ ...item, severity: "urgent" }] }).success).toBe(false);
    expect(FindingListSchema.safeParse({ total: 1, items: [{ ...item, id: -1 }] }).success).toBe(false);
  });
});

describe("api client", () => {
  it("mock api serves all views", async () => {
    const api = createMockApi();
    const [scan] = await api.scans();
    expect(scan).toBeDefined();
    const findings = await api.findings(scan!.scan_id);
    const detail = await api.finding(findings.items[0]!.id);
    expect(detail.how_to_fix.length).toBeGreaterThan(0);
  });

  it("live api sends the token and rejects malformed data", async () => {
    const seen: string[] = [];
    const fetcher = (async (_url: string, init?: RequestInit) => {
      seen.push(String((init?.headers as Record<string, string>)["X-AppSec-Token"]));
      return new Response(JSON.stringify({ items: [{ scan_id: "oops" }] }), { status: 200 });
    }) as typeof fetch;
    await expect(createLiveApi("tok", fetcher).scans()).rejects.toBeInstanceOf(ApiError);
    expect(seen).toEqual(["tok"]);
  });

  it("live api explains an expired token", async () => {
    const fetcher = (async () => new Response("{}", { status: 401 })) as typeof fetch;
    await expect(createLiveApi("x", fetcher).scans()).rejects.toThrow(/expired/);
  });
});
