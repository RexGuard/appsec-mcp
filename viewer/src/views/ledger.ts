import type { Ledger, LedgerFile, ScannerName } from "../api/schemas";
import { clear, h } from "../lib/dom";

export const SKIP_REASON_TEXT: Record<NonNullable<LedgerFile["skip_reason"]>, string> = {
  gitignored: "Listed in .gitignore",
  too_large: "Larger than the size limit",
  binary: "Not a text file (image, archive, compiled file…)",
  excluded_dir: "Dependency or build folder, skipped by default",
  symlink_outside_root: "Shortcut pointing outside the project",
};

export const SCANNER_TEXT: Record<ScannerName, string> = {
  semgrep: "Semgrep: looks for risky code patterns",
  gitleaks: "gitleaks: looks for leaked passwords and keys",
  osv: "OSV-Scanner: looks for packages with known security bugs",
  builtin: "Built-in checks: risky settings such as debug mode or open CORS",
};

// ── Data transforms (pure, unit-tested) ─────────────────────────────────────

export type FileStatusFilter = "all" | "read" | "skipped";

export function filterLedgerFiles(items: readonly LedgerFile[], status: FileStatusFilter, query: string): LedgerFile[] {
  const q = query.trim().toLowerCase();
  return items.filter((f) => (status === "all" || f.status === status) && (q === "" || f.rel_path.toLowerCase().includes(q)));
}

export interface Page<T> {
  items: T[];
  page: number;
  pages: number;
  from: number;
  to: number;
  total: number;
}

/** 1-based pagination; out-of-range pages clamp to the nearest valid page. */
export function paginate<T>(items: readonly T[], page: number, size: number): Page<T> {
  const total = items.length;
  const pages = Math.max(1, Math.ceil(total / size));
  const p = Math.min(Math.max(1, Math.floor(page) || 1), pages);
  const start = (p - 1) * size;
  const slice = items.slice(start, start + size);
  return { items: slice, page: p, pages, from: total ? start + 1 : 0, to: start + slice.length, total };
}

export function rulesByScanner(rules: Ledger["rules"]): Map<ScannerName, Ledger["rules"]> {
  const out = new Map<ScannerName, Ledger["rules"]>();
  for (const r of rules) out.set(r.scanner, [...(out.get(r.scanner) ?? []), r]);
  for (const [k, list] of out) out.set(k, [...list].sort((a, b) => b.files_matched - a.files_matched || a.rule_id.localeCompare(b.rule_id)));
  return out;
}

export function formatBytes(n: number | null): string {
  if (n === null) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// ── Rendering ───────────────────────────────────────────────────────────────

const PAGE_SIZE = 25;
const panel = "rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900";
const th = "px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400";
const td = "px-3 py-2 align-top";

export function renderLedger(root: HTMLElement, ledger: Ledger): void {
  let status: FileStatusFilter = "all";
  let query = "";
  let page = 1;

  const filesHost = h("div");
  const pager = h("div", { class: "flex items-center gap-2 border-t border-slate-200 px-3 py-2 text-xs dark:border-slate-800" });

  const statusButtons = (["all", "read", "skipped"] as const).map((s) =>
    h(
      "button",
      {
        type: "button",
        "data-status": s,
        class: "rounded-md px-2.5 py-1 text-xs font-medium",
        onclick: () => {
          status = s;
          page = 1;
          draw();
        },
      },
      s === "all" ? `All (${ledger.files.read + ledger.files.skipped})` : s === "read" ? `Read (${ledger.files.read})` : `Skipped (${ledger.files.skipped})`,
    ),
  );
  const search = h("input", {
    type: "search",
    placeholder: "Filter by path…",
    "aria-label": "Filter files by path",
    class: "ml-auto w-48 rounded-md border border-slate-300 bg-white px-2 py-1 text-xs dark:border-slate-700 dark:bg-slate-900",
  });
  search.addEventListener("input", () => {
    query = search.value;
    page = 1;
    draw();
  });

  const draw = () => {
    for (const b of statusButtons) {
      const on = b.dataset["status"] === status;
      b.className = `rounded-md px-2.5 py-1 text-xs font-medium ${on ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900" : "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"}`;
      b.setAttribute("aria-pressed", String(on));
    }
    const view = paginate(filterLedgerFiles(ledger.files.items, status, query), page, PAGE_SIZE);
    page = view.page;
    clear(filesHost);
    filesHost.append(
      h(
        "div",
        { class: "overflow-x-auto" },
        h(
          "table",
          { class: "w-full text-sm" },
          h("thead", {}, h("tr", {}, h("th", { class: th }, "File"), h("th", { class: th }, "Result"), h("th", { class: th }, "Language"), h("th", { class: th }, "Size"), h("th", { class: th }, "SHA-256"))),
          h(
            "tbody",
            { class: "divide-y divide-slate-100 dark:divide-slate-800" },
            ...view.items.map((f) =>
              h(
                "tr",
                {},
                h("td", { class: `${td} font-mono text-xs` }, f.rel_path),
                h(
                  "td",
                  { class: td },
                  f.status === "read"
                    ? h("span", { class: "text-emerald-700 dark:text-emerald-400" }, "Read")
                    : h("span", { class: "text-slate-500 dark:text-slate-400" }, `Skipped: ${f.skip_reason ? SKIP_REASON_TEXT[f.skip_reason] : ""}`),
                ),
                h("td", { class: `${td} text-xs` }, f.language ?? ""),
                h("td", { class: `${td} whitespace-nowrap text-xs tabular-nums` }, formatBytes(f.size_bytes)),
                h("td", { class: `${td} font-mono text-[11px] text-slate-500 dark:text-slate-400`, title: f.sha256 ?? "" }, f.sha256 ? `${f.sha256.slice(0, 12)}…` : ""),
              ),
            ),
          ),
        ),
      ),
    );
    if (view.total === 0) filesHost.append(h("p", { class: "p-4 text-sm text-slate-500" }, "No files match."));
    clear(pager);
    pager.append(
      h("span", { class: "text-slate-500 dark:text-slate-400" }, view.total ? `${view.from}–${view.to} of ${view.total}` : "0 files"),
      h("button", { type: "button", class: "ml-auto rounded px-2 py-1 hover:bg-slate-100 disabled:opacity-40 dark:hover:bg-slate-800", disabled: view.page <= 1, onclick: () => { page -= 1; draw(); } }, "← Previous"),
      h("span", { class: "tabular-nums" }, `Page ${view.page} of ${view.pages}`),
      h("button", { type: "button", class: "rounded px-2 py-1 hover:bg-slate-100 disabled:opacity-40 dark:hover:bg-slate-800", disabled: view.page >= view.pages, onclick: () => { page += 1; draw(); } }, "Next →"),
    );
  };

  const groups = rulesByScanner(ledger.rules);
  const rulesPanel = h(
    "section",
    { class: `${panel} p-4` },
    h("h2", { class: "font-semibold" }, "Checks that ran"),
    ...ledger.scanners.map((s) =>
      h(
        "div",
        { class: "mt-3" },
        h(
          "div",
          { class: "flex items-baseline gap-2 text-sm" },
          h("span", { class: "font-medium" }, SCANNER_TEXT[s.name]),
          h("span", { class: "ml-auto whitespace-nowrap text-xs text-slate-500 dark:text-slate-400" }, `${s.version ? `v${s.version} · ` : ""}${s.duration_s.toFixed(1)} s`),
        ),
        h(
          "ul",
          { class: "mt-1 space-y-0.5 text-xs" },
          ...(groups.get(s.name) ?? []).map((r) =>
            h(
              "li",
              { class: "flex gap-2" },
              h("span", { class: "font-mono" }, r.rule_id),
              h("span", { class: `ml-auto tabular-nums ${r.files_matched ? "font-semibold text-red-600 dark:text-red-400" : "text-slate-400"}` }, r.files_matched ? `matched ${r.files_matched} file${r.files_matched > 1 ? "s" : ""}` : "no match"),
            ),
          ),
        ),
      ),
    ),
  );

  clear(root);
  root.append(
    h(
      "p",
      { class: "mb-4 max-w-3xl text-sm text-slate-600 dark:text-slate-300" },
      "This is the full record of the scan: every file AppSec MCP read (with a fingerprint so you can verify it), every file it skipped and why, and every check it ran.",
    ),
    h(
      "div",
      { class: "grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]" },
      h(
        "section",
        { class: panel },
        h("div", { class: "flex flex-wrap items-center gap-1 border-b border-slate-200 px-3 py-2 dark:border-slate-800" }, h("h2", { class: "mr-2 text-sm font-semibold" }, "Files"), ...statusButtons, search),
        filesHost,
        pager,
      ),
      rulesPanel,
    ),
  );
  draw();
}
