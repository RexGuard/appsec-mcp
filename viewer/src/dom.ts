type Child = Node | string | null | undefined | false;

/** Small element builder. Text is always set via text nodes, never innerHTML. */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) element.setAttribute(name, value);
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    element.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return element;
}

export function severityBadge(severity: string): HTMLSpanElement {
  return h("span", { class: `sev sev-${severity}` }, severity);
}

export function errorBox(message: string): HTMLDivElement {
  return h(
    "div",
    { class: "card border-red-300 bg-red-50 text-red-900", role: "alert" },
    h("p", { class: "font-semibold" }, "Something went wrong"),
    h("p", { class: "text-sm" }, message),
  );
}

export function messageOf(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}
