import { z } from "zod";

export const severities = ["critical", "high", "medium", "low", "info"] as const;
export const SeveritySchema = z.enum(severities);
export type Severity = z.infer<typeof SeveritySchema>;

export const SeverityCountsSchema = z.object({
  critical: z.number().int().nonnegative(),
  high: z.number().int().nonnegative(),
  medium: z.number().int().nonnegative(),
  low: z.number().int().nonnegative(),
  info: z.number().int().nonnegative(),
});

export const ScanSummarySchema = z.object({
  scan_id: z.number().int().positive(),
  project: z.string(),
  root_path: z.string(),
  started_at: z.string(),
  status: z.enum(["running", "completed", "failed", "partial"]),
  score: z.number().int().min(0).max(100).nullable(),
  counts: SeverityCountsSchema,
});
export type ScanSummary = z.infer<typeof ScanSummarySchema>;

export const ScanListSchema = z.object({ items: z.array(ScanSummarySchema) });

export const FindingItemSchema = z.object({
  id: z.number().int().positive(),
  severity: SeveritySchema,
  title: z.string(),
  rel_path: z.string().nullable(),
  line_start: z.number().int().nullable(),
  plain_explanation: z.string(),
  patchable: z.boolean(),
  status: z.enum(["new", "existing", "fixed"]),
  scanner: z.string(),
  cwe: z.string().nullable(),
});
export type FindingItem = z.infer<typeof FindingItemSchema>;

export const FindingListSchema = z.object({
  total: z.number().int().nonnegative(),
  items: z.array(FindingItemSchema),
});
export type FindingList = z.infer<typeof FindingListSchema>;

export const FindingDetailSchema = z.object({
  id: z.number().int().positive(),
  title: z.string(),
  severity: SeveritySchema,
  cwe: z.string().nullable(),
  rel_path: z.string().nullable(),
  line_start: z.number().int().nullable(),
  scanner: z.string(),
  rule_id: z.string(),
  what: z.string(),
  why_it_matters: z.string(),
  how_to_fix: z.string(),
  snippet_redacted: z.string(),
  patchable: z.boolean(),
  references: z.array(z.string()),
});
export type FindingDetail = z.infer<typeof FindingDetailSchema>;

export const nodeKinds = [
  "component",
  "entry_point",
  "route",
  "data_store",
  "external_service",
  "secret",
  "dependency",
] as const;
export const NodeKindSchema = z.enum(nodeKinds);
export type NodeKind = z.infer<typeof NodeKindSchema>;

export const MapNodeSchema = z.object({
  id: z.number().int().positive(),
  kind: NodeKindSchema,
  label: z.string(),
  rel_path: z.string().nullable(),
  meta: z.record(z.unknown()),
  finding_count: z.number().int().nonnegative(),
});
export type MapNode = z.infer<typeof MapNodeSchema>;

export const MapEdgeSchema = z.object({
  source: z.number().int().positive(),
  target: z.number().int().positive(),
  kind: z.enum(["imports", "calls", "handles", "reads", "depends_on"]),
});

export const SystemGraphSchema = z.object({
  nodes: z.array(MapNodeSchema),
  edges: z.array(MapEdgeSchema),
});
export type SystemGraph = z.infer<typeof SystemGraphSchema>;

export const LedgerFileSchema = z.object({
  rel_path: z.string(),
  language: z.string().nullable(),
  size_bytes: z.number().int().nullable(),
  sha256: z.string().nullable(),
  status: z.enum(["read", "skipped"]),
  skip_reason: z.string().nullable(),
});
export type LedgerFile = z.infer<typeof LedgerFileSchema>;

export const LedgerSchema = z.object({
  files: z
    .object({
      read: z.number().int().nonnegative(),
      skipped: z.number().int().nonnegative(),
      items: z.array(LedgerFileSchema),
    })
    .nullable(),
  rules: z
    .array(
      z.object({
        scanner: z.string(),
        rule_id: z.string(),
        scanner_version: z.string().nullable(),
        files_matched: z.number().int().nonnegative(),
      }),
    )
    .nullable(),
  scanners: z.array(
    z.object({
      name: z.string(),
      version: z.string(),
      duration_s: z.number(),
      findings: z.number().int(),
    }),
  ),
  scanners_skipped: z.array(
    z.object({ name: z.string(), reason: z.string(), install_hint: z.string() }),
  ),
});
export type Ledger = z.infer<typeof LedgerSchema>;
