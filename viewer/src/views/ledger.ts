import { LEDGER_PAGE_SIZE, type Api } from "../api/client";
import type { Ledger, ScanSummary } from "../api/schemas";
import { errorBox, h, messageOf } from "../dom";
import { describeSkip, pageCount } from "./transforms";

export async function renderLedger(root: HTMLElement, api: Api, scan: ScanSummary): Promise<void> {
  let offset = 0;
  const filesEl = h("section", { class: "card" });
  const rulesEl = h("section", { class: "card" });
  const scannersEl = h("section", { class: "card" });
  root.replaceChildren(
    h("p", { class: "mb-4 text-sm text-slate-600" }, "Everything the scan looked at: every file read (with its SHA-256), every path skipped and why, and every rule and scanner that ran."),
    h("div", { class: "grid gap-6 lg:grid-cols-2" }, scannersEl, rulesEl),
    h("div", { class: "mt-6" }, filesEl),
  );

  const load = async (): Promise<void> => {
    try {
      const ledger = await api.ledger(scan.scan_id, offset);
      drawScanners(scannersEl, ledger);
      drawRules(rulesEl, ledger);
      drawFiles(filesEl, ledger, offset, (next) => { offset = next; void load(); });
    } catch (error: unknown) {
      filesEl.replaceChildren(errorBox(messageOf(error)));
    }
  };
  await load();
}

function drawScanners(el: HTMLElement, ledger: Ledger): void {
  el.replaceChildren(
    h("h3", { class: "mb-2 font-semibold" }, "Scanners"),
    h("ul", { class: "space-y-1 text-sm" },
      ...ledger.scanners.map((s) => h("li", {}, `✔ ${s.name} ${s.version} · ${s.findings} finding(s) · ${s.duration_s.toFixed(2)} s`)),
      ...ledger.scanners_skipped.map((s) => h("li", { class: "text-amber-800" }, `✖ ${s.name}: ${s.reason}`,
        h("span", { class: "block text-xs text-slate-500" }, s.install_hint)))),
  );
}

function drawRules(el: HTMLElement, ledger: Ledger): void {
  const rules = ledger.rules ?? [];
  const matched = rules.filter((r) => r.files_matched > 0).length;
  el.replaceChildren(
    h("h3", { class: "mb-2 font-semibold" }, `Rules applied (${rules.length}, ${matched} matched)`),
    h("div", { class: "max-h-64 overflow-y-auto" },
      h("table", { class: "w-full text-left text-xs" },
        h("thead", {}, h("tr", {}, h("th", {}, "Scanner"), h("th", {}, "Rule"), h("th", { class: "text-right" }, "Files matched"))),
        h("tbody", {}, ...rules.map((r) => h("tr", { class: r.files_matched ? "font-semibold" : "text-slate-500" },
          h("td", {}, r.scanner), h("td", { class: "font-mono" }, r.rule_id), h("td", { class: "text-right" }, String(r.files_matched))))))),
  );
}

function drawFiles(el: HTMLElement, ledger: Ledger, offset: number, go: (offset: number) => void): void {
  const files = ledger.files;
  if (!files) { el.replaceChildren(); return; }
  const total = files.read + files.skipped;
  const page = Math.floor(offset / LEDGER_PAGE_SIZE) + 1;
  const pages = pageCount(total, LEDGER_PAGE_SIZE);
  const prev = h("button", { type: "button", class: "tab", "aria-label": "Previous page" }, "←");
  const next = h("button", { type: "button", class: "tab", "aria-label": "Next page" }, "→");
  prev.disabled = page <= 1;
  next.disabled = page >= pages;
  prev.addEventListener("click", () => go(offset - LEDGER_PAGE_SIZE));
  next.addEventListener("click", () => go(offset + LEDGER_PAGE_SIZE));
  el.replaceChildren(
    h("div", { class: "mb-2 flex items-center gap-2" },
      h("h3", { class: "font-semibold" }, `Files: ${files.read} read, ${files.skipped} skipped`),
      h("span", { class: "ml-auto text-xs text-slate-500" }, `Page ${page} of ${pages}`), prev, next),
    h("div", { class: "overflow-x-auto" },
      h("table", { class: "w-full text-left text-xs" },
        h("thead", {}, h("tr", {}, h("th", {}, "Path"), h("th", {}, "Status"), h("th", {}, "Language"), h("th", {}, "Size"), h("th", {}, "SHA-256 / reason"))),
        h("tbody", {}, ...files.items.map((f) => h("tr", { class: f.status === "skipped" ? "text-slate-500" : "" },
          h("td", { class: "font-mono" }, f.rel_path), h("td", {}, f.status), h("td", {}, f.language ?? ""),
          h("td", {}, f.size_bytes === null ? "" : `${f.size_bytes} B`),
          h("td", { class: "font-mono" }, f.status === "read" ? (f.sha256 ?? "").slice(0, 16) + "…" : describeSkip(f))))))),
  );
}
