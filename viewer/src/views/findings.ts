import type { Finding, FindingDetail, MockScan, ScanSummary, Severity } from "../api/schemas";
import { clear, h } from "../lib/dom";
import { SEVERITIES, SEVERITY_BADGE, SEVERITY_LABEL, bySeverityDesc, scoreGrade } from "../lib/severity";

// ── Data transforms (pure, unit-tested) ─────────────────────────────────────

export interface FindingFilter {
  severities: ReadonlySet<Severity>;
  query: string;
}

/** Findings matching the filter, most severe first, then by file and line. */
export function filterFindings(items: readonly Finding[], filter: FindingFilter): Finding[] {
  const q = filter.query.trim().toLowerCase();
  return items
    .filter((f) => filter.severities.has(f.severity))
    .filter(
      (f) =>
        q === "" ||
        f.title.toLowerCase().includes(q) ||
        (f.rel_path ?? "").toLowerCase().includes(q) ||
        f.plain_explanation.toLowerCase().includes(q),
    )
    .sort(
      (a, b) =>
        bySeverityDesc(a, b) ||
        (a.rel_path ?? "").localeCompare(b.rel_path ?? "") ||
        (a.line_start ?? 0) - (b.line_start ?? 0),
    );
}

export function location(f: Pick<Finding, "rel_path" | "line_start">): string {
  if (!f.rel_path) return "Project-wide";
  return f.line_start ? `${f.rel_path}:${f.line_start}` : f.rel_path;
}

const STATUS_LABEL: Record<Finding["status"], string> = { new: "New", existing: "Seen before", fixed: "Fixed" };

// ── Rendering ───────────────────────────────────────────────────────────────

function badge(severity: Severity): HTMLElement {
  return h(
    "span",
    { class: `inline-flex shrink-0 rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${SEVERITY_BADGE[severity]}` },
    SEVERITY_LABEL[severity],
  );
}

function card(...children: (Node | string | null)[]): HTMLElement {
  return h(
    "section",
    { class: "rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900" },
    ...children,
  );
}

function summaryRow(s: ScanSummary, filter: Set<Severity>, onToggle: (sev: Severity) => void): HTMLElement {
  const grade = scoreGrade(s.score);
  const tone = {
    good: "text-emerald-600 dark:text-emerald-400",
    fair: "text-amber-600 dark:text-amber-400",
    poor: "text-red-600 dark:text-red-400",
  }[grade.tone];

  const scoreCard = card(
    h("div", { class: "text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400" }, "Security score"),
    h(
      "div",
      { class: "mt-1 flex items-baseline gap-2" },
      h("span", { class: `text-4xl font-bold tabular-nums ${tone}` }, String(s.score)),
      h("span", { class: "text-sm text-slate-500 dark:text-slate-400" }, "/ 100"),
    ),
    h("div", { class: `text-sm font-medium ${tone}` }, grade.label),
    h(
      "div",
      { class: "mt-2 text-xs text-slate-500 dark:text-slate-400" },
      `${s.new} new · ${s.fixed} fixed since last scan`,
    ),
  );

  const chips = h("div", { class: "mt-2 flex flex-wrap gap-2", role: "group", "aria-label": "Filter by severity" });
  for (const sev of SEVERITIES) {
    const on = filter.has(sev);
    chips.append(
      h(
        "button",
        {
          type: "button",
          "aria-pressed": String(on),
          class: `flex items-center gap-2 rounded-lg border px-3 py-2 text-left transition ${
            on
              ? "border-slate-300 bg-white dark:border-slate-600 dark:bg-slate-800"
              : "border-transparent bg-slate-100 opacity-50 dark:bg-slate-800/40"
          }`,
          onclick: () => onToggle(sev),
        },
        badge(sev),
        h("span", { class: "text-lg font-semibold tabular-nums" }, String(s.counts[sev])),
      ),
    );
  }
  const countsCard = card(
    h("div", { class: "text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400" }, "Problems found"),
    chips,
    h("div", { class: "mt-2 text-xs text-slate-500 dark:text-slate-400" }, "Click a severity to show or hide it."),
  );

  const scanners = card(
    h("div", { class: "text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400" }, "This scan"),
    h(
      "ul",
      { class: "mt-2 space-y-1 text-sm" },
      h("li", {}, `${s.files_read} files read, ${s.files_skipped} skipped`),
      h("li", {}, `Ran: ${s.scanners_run.join(", ") || "none"}`),
      h("li", {}, `Took ${s.duration_s.toFixed(1)} s`),
    ),
    ...s.scanners_skipped.map((sk) =>
      h(
        "div",
        {
          class:
            "mt-2 rounded-lg bg-amber-50 p-2 text-xs text-amber-900 dark:bg-amber-950/40 dark:text-amber-200",
        },
        h("strong", {}, `${sk.name} skipped: `),
        sk.reason,
        sk.install_hint ? h("div", { class: "mt-1 font-mono" }, sk.install_hint) : null,
      ),
    ),
  );

  return h("div", { class: "grid grid-cols-1 gap-4 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)_minmax(0,1.3fr)]" }, scoreCard, countsCard, scanners);
}

function detailPanel(f: Finding | undefined, detail: FindingDetail | undefined): HTMLElement {
  if (!f) {
    return card(h("p", { class: "text-sm text-slate-500 dark:text-slate-400" }, "Pick a finding to see what it means and how to fix it."));
  }
  const section = (title: string, body: string) =>
    h(
      "div",
      { class: "mt-4" },
      h("h3", { class: "text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400" }, title),
      h("p", { class: "mt-1 text-sm leading-relaxed" }, body),
    );
  return card(
    h("div", { class: "flex items-start gap-2" }, badge(f.severity), h("h2", { class: "text-base font-semibold leading-snug" }, f.title)),
    h(
      "div",
      { class: "mt-1 flex flex-wrap gap-x-3 text-xs text-slate-500 dark:text-slate-400" },
      h("span", { class: "font-mono" }, location(f)),
      detail?.cwe ? h("span", {}, detail.cwe) : null,
      h("span", {}, STATUS_LABEL[f.status]),
    ),
    h("p", { class: "mt-3 rounded-lg bg-slate-50 p-3 text-sm leading-relaxed dark:bg-slate-800/60" }, f.plain_explanation),
    detail ? section("What it is", detail.what) : null,
    detail ? section("Why it matters", detail.why_it_matters) : null,
    detail ? section("How to fix it", detail.how_to_fix) : null,
    detail?.snippet_redacted
      ? h(
          "pre",
          { class: "mt-4 overflow-x-auto rounded-lg bg-slate-900 p-3 text-xs text-slate-100" },
          h("code", {}, detail.snippet_redacted),
        )
      : null,
    f.patchable
      ? h(
          "p",
          { class: "mt-4 rounded-lg bg-emerald-50 p-3 text-sm text-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200" },
          "AppSec MCP can fix this for you. Ask your AI assistant to “fix finding ",
          String(f.id),
          "”. It will show you the change before anything is written.",
        )
      : null,
    detail && detail.references.length
      ? h(
          "div",
          { class: "mt-4 text-xs" },
          ...detail.references.map((r) =>
            h("a", { href: r, target: "_blank", rel: "noopener noreferrer", class: "text-emerald-700 underline dark:text-emerald-400" }, r),
          ),
        )
      : null,
  );
}

export function renderFindings(root: HTMLElement, data: MockScan): void {
  const filter: FindingFilter & { severities: Set<Severity> } = { severities: new Set(SEVERITIES), query: "" };
  const details = new Map(data.details.map((d) => [d.id, d]));
  let selectedId: number | undefined = filterFindings(data.findings.items, filter)[0]?.id;

  const summaryHost = h("div");
  const search = h("input", {
    type: "search",
    placeholder: "Search findings or files…",
    "aria-label": "Search findings",
    class:
      "w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/30 dark:border-slate-700 dark:bg-slate-900",
  });
  const list = h("ul", { class: "mt-3 space-y-2", "aria-label": "Findings" });
  const count = h("div", { class: "mt-2 text-xs text-slate-500 dark:text-slate-400" });
  const detailHost = h("div", { class: "lg:sticky lg:top-4" });

  const draw = () => {
    clear(summaryHost);
    summaryHost.append(
      summaryRow(data.summary, filter.severities, (sev) => {
        if (filter.severities.has(sev)) filter.severities.delete(sev);
        else filter.severities.add(sev);
        draw();
      }),
    );
    const visible = filterFindings(data.findings.items, filter);
    if (selectedId !== undefined && !visible.some((f) => f.id === selectedId)) selectedId = visible[0]?.id;
    count.textContent = `Showing ${visible.length} of ${data.findings.total}`;
    clear(list);
    if (visible.length === 0) {
      list.append(h("li", { class: "rounded-lg p-4 text-sm text-slate-500 dark:text-slate-400" }, "Nothing matches this filter."));
    }
    for (const f of visible) {
      const active = f.id === selectedId;
      list.append(
        h(
          "li",
          {},
          h(
            "button",
            {
              type: "button",
              "aria-current": active ? "true" : null,
              class: `w-full rounded-xl border p-3 text-left transition ${
                active
                  ? "border-emerald-500 bg-emerald-50/60 ring-1 ring-emerald-500 dark:bg-emerald-950/30"
                  : "border-slate-200 bg-white hover:border-slate-300 dark:border-slate-800 dark:bg-slate-900 dark:hover:border-slate-700"
              }`,
              onclick: () => {
                selectedId = f.id;
                draw();
              },
            },
            h(
              "div",
              { class: "flex items-start gap-2" },
              badge(f.severity),
              h("span", { class: "text-sm font-medium leading-snug" }, f.title),
              f.status === "new"
                ? h("span", { class: "ml-auto shrink-0 text-[11px] font-medium text-emerald-700 dark:text-emerald-400" }, "NEW")
                : null,
            ),
            h("div", { class: "mt-1 font-mono text-xs text-slate-500 dark:text-slate-400" }, location(f)),
            h("p", { class: "mt-1 line-clamp-2 text-sm text-slate-600 dark:text-slate-300" }, f.plain_explanation),
          ),
        ),
      );
    }
    clear(detailHost);
    const sel = visible.find((f) => f.id === selectedId);
    detailHost.append(detailPanel(sel, sel ? details.get(sel.id) : undefined));
  };

  search.addEventListener("input", () => {
    filter.query = search.value;
    draw();
  });

  clear(root);
  root.append(
    summaryHost,
    h(
      "div",
      { class: "mt-6 grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]" },
      h("div", {}, search, count, list),
      detailHost,
    ),
  );
  draw();
}
