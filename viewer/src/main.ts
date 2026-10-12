import "./style.css";
import { type Ledger as LedgerT, Ledger, MockScan, SystemGraph } from "./api/schemas";
import mockLedger from "./mock/ledger.json";
import mockMap from "./mock/map.json";
import mockScan from "./mock/scan.json";
import { clear, h } from "./lib/dom";
import { TABS, type TabId, parseRoute, routeHref } from "./router";
import { renderFindings } from "./views/findings";
import { renderLedger } from "./views/ledger";
import { renderMap, syntheticGraph } from "./views/map";

interface Data {
  scan: MockScan;
  graph: SystemGraph;
  ledger: LedgerT;
}

/** Parse everything up front; a schema mismatch shows an error page instead of a half-broken view. */
export function loadMockData(search: string): Data {
  const big = Number(new URLSearchParams(search).get("big") ?? 0);
  return {
    scan: MockScan.parse(mockScan),
    graph: big > 0 ? SystemGraph.parse(syntheticGraph(Math.min(big, 5000))) : SystemGraph.parse(mockMap),
    ledger: Ledger.parse(mockLedger),
  };
}

function showError(app: HTMLElement, err: unknown): void {
  clear(app);
  app.append(
    h(
      "div",
      { role: "alert", class: "rounded-xl border border-red-300 bg-red-50 p-4 text-sm text-red-900 dark:border-red-800 dark:bg-red-950/40 dark:text-red-200" },
      h("strong", {}, "The scan data couldn't be read. "),
      "It doesn't match what the viewer expects.",
      h("pre", { class: "mt-2 overflow-x-auto whitespace-pre-wrap text-xs" }, err instanceof Error ? err.message : String(err)),
    ),
  );
}

function start(): void {
  const app = document.getElementById("app");
  const tabs = document.getElementById("tabs");
  const projectName = document.getElementById("project-name");
  const badge = document.getElementById("data-badge");
  if (!app || !tabs || !projectName || !badge) return;

  let data: Data;
  try {
    data = loadMockData(location.search);
  } catch (err) {
    showError(app, err);
    return;
  }
  projectName.textContent = `${data.scan.summary.project} · scan #${data.scan.summary.scan_id}`;
  badge.textContent = "Sample data";
  badge.title = "The viewer is showing built-in sample data. Real scans arrive once the scan engine is connected.";

  let teardown: (() => void) | undefined;
  const show = (tab: TabId) => {
    teardown?.();
    teardown = undefined;
    clear(tabs);
    for (const t of TABS) {
      const active = t.id === tab;
      tabs.append(
        h(
          "a",
          {
            href: routeHref(t.id),
            "aria-current": active ? "page" : null,
            class: `rounded-md px-3 py-1.5 font-medium ${active ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900" : "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"}`,
          },
          t.label,
        ),
      );
    }
    if (tab === "findings") renderFindings(app, data.scan);
    else if (tab === "map") teardown = renderMap(app, data.graph, data.scan.findings.items);
    else renderLedger(app, data.ledger);
  };

  window.addEventListener("hashchange", () => show(parseRoute(location.hash)));
  show(parseRoute(location.hash));
}

start();
