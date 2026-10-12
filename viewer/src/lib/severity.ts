import { SEVERITIES, type Severity } from "../api/schemas";

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** Badge classes per severity (light and dark). */
export const SEVERITY_BADGE: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-300 text-amber-950",
  low: "bg-sky-200 text-sky-950 dark:bg-sky-800 dark:text-sky-50",
  info: "bg-slate-200 text-slate-800 dark:bg-slate-700 dark:text-slate-100",
};

/** Hex colours for places Tailwind classes can't reach (the graph canvas). */
export const SEVERITY_HEX: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#0ea5e9",
  info: "#94a3b8",
};

export function bySeverityDesc<T extends { severity: Severity }>(a: T, b: T): number {
  return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
}

export { SEVERITIES };

/** Plain-language grade for a 0-100 score. */
export function scoreGrade(score: number): { label: string; tone: "good" | "fair" | "poor" } {
  if (score >= 80) return { label: "Looking good", tone: "good" };
  if (score >= 50) return { label: "Needs attention", tone: "fair" };
  return { label: "At risk", tone: "poor" };
}
