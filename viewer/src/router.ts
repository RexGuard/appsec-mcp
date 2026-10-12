export const views = ["findings", "map", "ledger"] as const;
export type View = (typeof views)[number];

export function currentView(search: string): View {
  const requested = new URLSearchParams(search).get("view");
  return views.find((v) => v === requested) ?? "findings";
}

export function viewUrl(view: View, search: string): string {
  const params = new URLSearchParams(search);
  params.set("view", view);
  return `?${params.toString()}`;
}
