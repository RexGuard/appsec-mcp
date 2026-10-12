import type { z } from "zod";
import ledgerMock from "../mock/ledger.json";
import mapMock from "../mock/map.json";
import scanMock from "../mock/scan.json";
import {
  FindingDetailSchema,
  FindingListSchema,
  LedgerSchema,
  ScanListSchema,
  SystemGraphSchema,
  type FindingDetail,
  type FindingList,
  type Ledger,
  type ScanSummary,
  type SystemGraph,
} from "./schemas";

const TOKEN_HEADER = "X-AppSec-Token";
const TOKEN_KEY = "appsec-token";
export const LEDGER_PAGE_SIZE = 200;

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export interface Api {
  readonly source: "live" | "mock";
  scans(): Promise<ScanSummary[]>;
  findings(scanId: number): Promise<FindingList>;
  finding(id: number): Promise<FindingDetail>;
  map(scanId: number): Promise<SystemGraph>;
  ledger(scanId: number, offset: number): Promise<Ledger>;
}

/** Reads the token from the URL fragment once, then keeps it only for this tab. */
export function takeToken(location: Location, storage: Storage): string | null {
  const match = /token=([A-Za-z0-9_-]+)/.exec(location.hash);
  if (match?.[1]) {
    storage.setItem(TOKEN_KEY, match[1]);
    history.replaceState(null, "", location.pathname + location.search);
    return match[1];
  }
  return storage.getItem(TOKEN_KEY);
}

function parse<T>(schema: z.ZodType<T>, data: unknown, what: string): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    throw new ApiError(`The ${what} data from the server was not in the expected shape.`, 0);
  }
  return result.data;
}

export function createLiveApi(token: string, fetcher: typeof fetch = fetch): Api {
  const get = async <T>(path: string, schema: z.ZodType<T>, what: string): Promise<T> => {
    const response = await fetcher(path, { headers: { [TOKEN_HEADER]: token } });
    if (response.status === 401) {
      throw new ApiError("The viewer link has expired. Run `appsec-mcp view` again.", 401);
    }
    if (!response.ok) {
      throw new ApiError(`The server answered ${response.status} for ${what}.`, response.status);
    }
    return parse(schema, (await response.json()) as unknown, what);
  };
  return {
    source: "live",
    scans: async () => (await get("/api/scans", ScanListSchema, "scan list")).items,
    findings: (id) =>
      get(`/api/scans/${id}/findings?min_severity=info&limit=500`, FindingListSchema, "findings"),
    finding: (id) => get(`/api/findings/${id}`, FindingDetailSchema, "finding"),
    map: (id) => get(`/api/scans/${id}/map`, SystemGraphSchema, "map"),
    ledger: (id, offset) =>
      get(
        `/api/scans/${id}/ledger?limit=${LEDGER_PAGE_SIZE}&offset=${offset}`,
        LedgerSchema,
        "ledger",
      ),
  };
}

export function createMockApi(): Api {
  const details = scanMock.details as Record<string, unknown>;
  return {
    source: "mock",
    scans: async () => parse(ScanListSchema, scanMock.scans, "scan list").items,
    findings: async () => parse(FindingListSchema, scanMock.findings, "findings"),
    finding: async (id) => parse(FindingDetailSchema, details[String(id)], "finding"),
    map: async () => parse(SystemGraphSchema, mapMock, "map"),
    ledger: async () => parse(LedgerSchema, ledgerMock, "ledger"),
  };
}
