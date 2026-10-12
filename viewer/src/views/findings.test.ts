import { describe, expect, it } from "vitest";
import { MockScan, SEVERITIES, type Severity } from "../api/schemas";
import mockScan from "../mock/scan.json";
import { filterFindings, location, renderFindings } from "./findings";

const scan = MockScan.parse(mockScan);
const all = new Set<Severity>(SEVERITIES);

describe("filterFindings", () => {
  it("sorts most severe first", () => {
    const out = filterFindings(scan.findings.items, { severities: all, query: "" });
    expect(out[0]!.severity).toBe("critical");
    expect(out.at(-1)!.severity).toBe("info");
  });

  it("filters by severity", () => {
    const out = filterFindings(scan.findings.items, { severities: new Set(["high"]), query: "" });
    expect(out.length).toBe(scan.summary.counts.high);
    expect(out.every((f) => f.severity === "high")).toBe(true);
  });

  it("searches title, path and explanation case-insensitively", () => {
    expect(filterFindings(scan.findings.items, { severities: all, query: "CONFIG.TS" }).length).toBe(2);
    expect(filterFindings(scan.findings.items, { severities: all, query: "sql" })[0]!.id).toBe(1);
    expect(filterFindings(scan.findings.items, { severities: all, query: "nothing-like-this" })).toEqual([]);
  });
});

describe("location", () => {
  it("formats path and line", () => {
    expect(location({ rel_path: "a.ts", line_start: 3 })).toBe("a.ts:3");
    expect(location({ rel_path: "a.ts", line_start: null })).toBe("a.ts");
    expect(location({ rel_path: null, line_start: null })).toBe("Project-wide");
  });
});

describe("renderFindings", () => {
  it("renders every finding and never interprets text as HTML", () => {
    const root = document.createElement("div");
    const evil = structuredClone(scan);
    evil.findings.items[0]!.title = '<img src=x onerror="alert(1)">';
    renderFindings(root, evil);
    expect(root.querySelectorAll('ul[aria-label="Findings"] > li').length).toBe(scan.findings.total);
    expect(root.querySelector("img")).toBeNull();
    expect(root.textContent).toContain('<img src=x onerror="alert(1)">');
  });

  it("hides a severity when its chip is clicked", () => {
    const root = document.createElement("div");
    renderFindings(root, scan);
    const chip = [...root.querySelectorAll<HTMLButtonElement>('[aria-label="Filter by severity"] button')][0]!;
    chip.click();
    const shown = root.querySelectorAll('ul[aria-label="Findings"] > li').length;
    expect(shown).toBe(scan.findings.total - scan.summary.counts.critical);
  });
});
