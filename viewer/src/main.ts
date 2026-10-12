import "./style.css";
import { createLiveApi, createMockApi, takeToken, type Api } from "./api/client";
import type { ScanSummary } from "./api/schemas";
import { errorBox, h, messageOf } from "./dom";
import { currentView, viewUrl, type View } from "./router";
import { renderFindings } from "./views/findings";
import { renderLedger } from "./views/ledger";
import { renderMap } from "./views/map";

const renderers: Record<View, (root: HTMLElement, api: Api, scan: ScanSummary) => Promise<void>> = {
  findings: renderFindings,
  map: renderMap,
  ledger: renderLedger,
};

function chooseApi(): Api {
  const token = takeToken(window.location, window.sessionStorage);
  return token ? createLiveApi(token) : createMockApi();
}

async function start(): Promise<void> {
  const app = document.getElementById("app");
  const picker = document.getElementById("scan-picker") as HTMLSelectElement | null;
  const badge = document.getElementById("source-badge");
  if (!app || !picker || !badge) return;
  const api = chooseApi();
  badge.textContent = api.source === "mock" ? "Showing sample data (open the link from `appsec-mcp view`)" : "Live data from this computer";

  let scans: ScanSummary[];
  try {
    scans = await api.scans();
  } catch (error: unknown) {
    app.replaceChildren(errorBox(messageOf(error)));
    return;
  }
  if (scans.length === 0) {
    app.replaceChildren(h("div", { class: "card" }, "No scans yet. Ask your AI assistant to “scan my project for security problems”."));
    return;
  }
  for (const scan of scans) {
    picker.append(h("option", { value: String(scan.scan_id) }, `#${scan.scan_id} ${scan.project} (score ${scan.score ?? "?"})`));
  }

  const render = async (): Promise<void> => {
    const view = currentView(window.location.search);
    document.querySelectorAll<HTMLAnchorElement>("[data-view]").forEach((link) => {
      const linkView = link.dataset["view"] as View;
      link.href = viewUrl(linkView, window.location.search);
      if (linkView === view) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    const scan = scans.find((s) => String(s.scan_id) === picker.value) ?? scans[0];
    if (!scan) return;
    app.replaceChildren(h("p", { class: "text-sm text-slate-500" }, "Loading…"));
    try {
      await renderers[view](app, api, scan);
    } catch (error: unknown) {
      app.replaceChildren(errorBox(messageOf(error)));
    }
  };

  document.querySelectorAll<HTMLAnchorElement>("[data-view]").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      history.pushState(null, "", link.href);
      void render();
    });
  });
  window.addEventListener("popstate", () => void render());
  picker.addEventListener("change", () => void render());
  await render();
}

void start();
