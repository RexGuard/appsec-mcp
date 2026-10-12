// Zod mirrors of the Pydantic models in src/appsec_mcp/models (docs/plan/SPEC.md, "API contract").
// Everything the viewer shows is parsed through these first, so a malformed response becomes a
// visible error instead of a broken page.
import { z } from "zod";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const Severity = z.enum(SEVERITIES);
export type Severity = z.infer<typeof Severity>;

export const ScannerName = z.enum(["semgrep", "gitleaks", "osv", "builtin"]);
export type ScannerName = z.infer<typeof ScannerName>;

const Id = z.number().int().min(1);
const Count = z.number().int().min(0);
const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);

export const SeverityCounts = z.strictObject({
  critical: Count,
  high: Count,
  medium: Count,
  low: Count,
  info: Count,
});
export type SeverityCounts = z.infer<typeof SeverityCounts>;

export const ScanSummary = z.strictObject({
  scan_id: Id,
  project: z.string().min(1),
  started_at: z.string(),
  status: z.enum(["running", "completed", "failed", "partial"]),
  score: z.number().int().min(0).max(100),
  counts: SeverityCounts,
  new: Count,
  fixed: Count,
  scanners_run: z.array(ScannerName),
  scanners_skipped: z.array(
    z.strictObject({ name: ScannerName, reason: z.string().min(1), install_hint: z.string() }),
  ),
  files_read: Count,
  files_skipped: Count,
  duration_s: z.number().min(0),
});
export type ScanSummary = z.infer<typeof ScanSummary>;

export const Finding = z.strictObject({
  id: Id,
  severity: Severity,
  title: z.string().min(1),
  rel_path: z.string().min(1).nullable(),
  line_start: z.number().int().min(1).nullable(),
  plain_explanation: z.string().min(1),
  patchable: z.boolean(),
  status: z.enum(["new", "existing", "fixed"]),
});
export type Finding = z.infer<typeof Finding>;

export const FindingsPage = z.strictObject({ total: Count, items: z.array(Finding) });
export type FindingsPage = z.infer<typeof FindingsPage>;

export const FindingDetail = z.strictObject({
  id: Id,
  title: z.string().min(1),
  severity: Severity,
  cwe: z.string().regex(/^CWE-\d+$/).nullable(),
  what: z.string().min(1),
  why_it_matters: z.string().min(1),
  how_to_fix: z.string().min(1),
  snippet_redacted: z.string().nullable(),
  references: z.array(z.url({ protocol: /^https?$/ })),
});
export type FindingDetail = z.infer<typeof FindingDetail>;

export const NODE_KINDS = [
  "component",
  "entry_point",
  "route",
  "data_store",
  "external_service",
  "secret",
  "dependency",
] as const;
export const NodeKind = z.enum(NODE_KINDS);
export type NodeKind = z.infer<typeof NodeKind>;

export const MapNode = z.strictObject({
  id: Id,
  kind: NodeKind,
  label: z.string().min(1),
  rel_path: z.string().min(1).nullable(),
  meta: z.record(z.string(), z.unknown()),
  finding_count: Count,
});
export type MapNode = z.infer<typeof MapNode>;

export const MapEdge = z.strictObject({
  source: Id,
  target: Id,
  kind: z.enum(["imports", "calls", "handles", "reads", "depends_on"]),
});
export type MapEdge = z.infer<typeof MapEdge>;

export const SystemGraph = z
  .strictObject({ nodes: z.array(MapNode), edges: z.array(MapEdge) })
  .superRefine((g, ctx) => {
    const ids = new Set(g.nodes.map((n) => n.id));
    if (ids.size !== g.nodes.length) ctx.addIssue({ code: "custom", message: "node ids must be unique" });
    for (const e of g.edges) {
      if (!ids.has(e.source) || !ids.has(e.target)) {
        ctx.addIssue({ code: "custom", message: `edge ${e.source}->${e.target} references a missing node` });
      }
    }
  });
export type SystemGraph = z.infer<typeof SystemGraph>;

export const SKIP_REASONS = ["gitignored", "too_large", "binary", "excluded_dir", "symlink_outside_root"] as const;

export const LedgerFile = z
  .strictObject({
    rel_path: z.string().min(1),
    language: z.string().nullable(),
    size_bytes: Count.nullable(),
    sha256: Sha256.nullable(),
    status: z.enum(["read", "skipped"]),
    skip_reason: z.enum(SKIP_REASONS).nullable(),
  })
  .refine((f) => (f.status === "skipped") === (f.skip_reason !== null), {
    message: "skipped files need a skip_reason; read files must not have one",
  });
export type LedgerFile = z.infer<typeof LedgerFile>;

export const Ledger = z.strictObject({
  files: z.strictObject({ read: Count, skipped: Count, items: z.array(LedgerFile) }),
  rules: z.array(z.strictObject({ scanner: ScannerName, rule_id: z.string().min(1), files_matched: Count })),
  scanners: z.array(
    z.strictObject({ name: ScannerName, version: z.string().nullable(), duration_s: z.number().min(0) }),
  ),
});
export type Ledger = z.infer<typeof Ledger>;

/** The mock bundle: one scan's summary, findings and finding details, as the API will serve them. */
export const MockScan = z.strictObject({
  summary: ScanSummary,
  findings: FindingsPage,
  details: z.array(FindingDetail),
});
export type MockScan = z.infer<typeof MockScan>;
