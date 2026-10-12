export const TABS = [
  { id: "findings", label: "Findings" },
  { id: "map", label: "System map" },
  { id: "ledger", label: "Audit ledger" },
] as const;

export type TabId = (typeof TABS)[number]["id"];

/** `#/map` → "map". Anything unknown falls back to the findings tab. */
export function parseRoute(hash: string): TabId {
  const id = hash.replace(/^#\/?/, "").split(/[/?]/)[0] ?? "";
  return TABS.some((t) => t.id === id) ? (id as TabId) : "findings";
}

export function routeHref(tab: TabId): string {
  return `#/${tab}`;
}
