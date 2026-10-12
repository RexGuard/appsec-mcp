import type { Api } from "../api/client";
import { severities, type FindingItem, type ScanSummary, type Severity } from "../api/schemas";
import { errorBox, h, messageOf, severityBadge } from "../dom";
import { filterFindings } from "./transforms";

export async function renderFindings(root: HTMLElement, api: Api, scan: ScanSummary): Promise<void> {
  const list = await api.findings(scan.scan_id);
  let minimum: Severity = "info";
  let query = "";

  const listEl = h("ul", { class: "divide-y divide-slate-100", "aria-label": "Findings" });
  const detailEl = h("aside", { class: "card lg:sticky lg:top-4", "aria-live": "polite" },
    h("p", { class: "text-sm text-slate-500" }, "Select a finding to see what it means and how to fix it."));

  const select = h("select", { class: "rounded border border-slate-300 px-2 py-1 text-sm", "aria-label": "Minimum severity" });
  for (const s of severities) select.append(h("option", { value: s }, `${s} and above`));
  select.value = minimum;
  const search = h("input", { type: "search", placeholder: "Filter by title or file", class: "rounded border border-slate-300 px-2 py-1 text-sm", "aria-label": "Filter" });

  const redraw = (): void => {
    listEl.replaceChildren();
    const shown = filterFindings(list.items, minimum, query);
    if (shown.length === 0) listEl.append(h("li", { class: "py-6 text-center text-sm text-slate-500" }, "No findings match."));
    for (const item of shown) listEl.append(row(item, () => void showDetail(item)));
  };
  const showDetail = async (item: FindingItem): Promise<void> => {
    try {
      const d = await api.finding(item.id);
      detailEl.replaceChildren(
        h("div", { class: "mb-2 flex items-center gap-2" }, severityBadge(d.severity), h("span", { class: "text-xs text-slate-500" }, d.cwe ?? "")),
        h("h3", { class: "text-lg font-semibold" }, d.title),
        h("p", { class: "mt-1 font-mono text-xs text-slate-500" }, `${d.rel_path ?? ""}${d.line_start ? `:${d.line_start}` : ""}`),
        h("h4", { class: "mt-4 text-sm font-semibold" }, "What it is"),
        h("p", { class: "text-sm" }, d.what),
        h("h4", { class: "mt-3 text-sm font-semibold" }, "Why it matters"),
        h("p", { class: "text-sm" }, d.why_it_matters),
        h("h4", { class: "mt-3 text-sm font-semibold" }, "How to fix it"),
        h("p", { class: "text-sm" }, d.how_to_fix),
        d.snippet_redacted ? h("pre", { class: "mt-3 overflow-x-auto rounded bg-slate-900 p-2 text-xs text-slate-100" }, d.snippet_redacted) : "",
        d.patchable ? h("p", { class: "mt-3 rounded bg-emerald-50 p-2 text-sm text-emerald-900" }, "An automatic fix is available: ask your AI assistant to “fix this finding”.") : "",
        h("p", { class: "mt-3 text-xs text-slate-500" }, `Found by ${d.scanner} (${d.rule_id})`),
      );
    } catch (error: unknown) {
      detailEl.replaceChildren(errorBox(messageOf(error)));
    }
  };

  select.addEventListener("change", () => { minimum = select.value as Severity; redraw(); });
  search.addEventListener("input", () => { query = search.value; redraw(); });

  root.replaceChildren(
    summary(scan),
    h("div", { class: "mt-6 grid gap-6 lg:grid-cols-[3fr_2fr]" },
      h("section", { class: "card" }, h("div", { class: "mb-3 flex flex-wrap gap-2" }, select, search), listEl),
      detailEl),
  );
  redraw();
}

function row(item: FindingItem, onSelect: () => void): HTMLLIElement {
  const button = h("button", { type: "button", class: "w-full py-3 text-left hover:bg-slate-50 focus:bg-slate-50 focus:outline-none" },
    h("div", { class: "flex items-center gap-2" }, severityBadge(item.severity),
      h("span", { class: "font-medium" }, item.title),
      item.status === "new" && h("span", { class: "text-xs text-emerald-700" }, "new"),
      item.status === "fixed" && h("span", { class: "text-xs text-slate-500 line-through" }, "fixed")),
    h("p", { class: "mt-1 font-mono text-xs text-slate-500" }, `${item.rel_path ?? ""}${item.line_start ? `:${item.line_start}` : ""}`),
    h("p", { class: "mt-1 text-sm text-slate-700" }, item.plain_explanation));
  button.addEventListener("click", onSelect);
  return h("li", {}, button);
}

function summary(scan: ScanSummary): HTMLElement {
  const score = scan.score ?? 0;
  const tone = score >= 80 ? "text-emerald-600" : score >= 50 ? "text-amber-600" : "text-red-600";
  return h("section", { class: "card flex flex-wrap items-center gap-6" },
    h("div", {}, h("p", { class: "text-xs uppercase text-slate-500" }, "Security score"),
      h("p", { class: `text-4xl font-bold ${tone}` }, `${score}`)),
    h("div", {}, h("p", { class: "font-semibold" }, scan.project),
      h("p", { class: "text-xs text-slate-500" }, `${scan.root_path} · ${new Date(scan.started_at).toLocaleString()} · ${scan.status}`)),
    h("div", { class: "ml-auto flex gap-2" }, ...severities.map((s) =>
      h("div", { class: "text-center" }, severityBadge(s), h("p", { class: "mt-1 text-lg font-semibold" }, String(scan.counts[s]))))),
  );
}
