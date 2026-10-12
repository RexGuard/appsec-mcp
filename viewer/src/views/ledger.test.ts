import { describe, expect, it } from "vitest";
import { Ledger } from "../api/schemas";
import mockLedger from "../mock/ledger.json";
import { filterLedgerFiles, formatBytes, paginate, renderLedger, rulesByScanner } from "./ledger";

const ledger = Ledger.parse(mockLedger);

describe("paginate", () => {
  const items = Array.from({ length: 53 }, (_, i) => i + 1);

  it("slices pages with 1-based numbering", () => {
    expect(paginate(items, 1, 25)).toMatchObject({ page: 1, pages: 3, from: 1, to: 25, total: 53 });
    expect(paginate(items, 3, 25).items).toEqual([51, 52, 53]);
  });

  it("clamps out-of-range pages", () => {
    expect(paginate(items, 99, 25).page).toBe(3);
    expect(paginate(items, -4, 25).page).toBe(1);
    expect(paginate(items, Number.NaN, 25).page).toBe(1);
  });

  it("handles an empty list", () => {
    expect(paginate([], 1, 25)).toMatchObject({ items: [], page: 1, pages: 1, from: 0, to: 0, total: 0 });
  });
});

describe("ledger transforms", () => {
  it("filters files by status and path", () => {
    expect(filterLedgerFiles(ledger.files.items, "read", "").length).toBe(ledger.files.read);
    expect(filterLedgerFiles(ledger.files.items, "skipped", "").length).toBe(ledger.files.skipped);
    expect(filterLedgerFiles(ledger.files.items, "all", "SRC/").map((f) => f.rel_path)).toEqual([
      "src/config.ts",
      "src/server.ts",
    ]);
  });

  it("groups rules by scanner, matched rules first", () => {
    const g = rulesByScanner(ledger.rules);
    expect([...g.keys()].sort()).toEqual(["builtin", "gitleaks", "osv"]);
    const builtin = g.get("builtin")!;
    expect(builtin[0]!.files_matched).toBeGreaterThan(0);
    expect(builtin.at(-1)!.files_matched).toBe(0);
  });

  it("formats sizes", () => {
    expect(formatBytes(null)).toBe("");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.0 KB");
    expect(formatBytes(3 * 1024 * 1024)).toBe("3.0 MB");
  });
});

describe("renderLedger", () => {
  it("pages through a long file list", () => {
    const many = {
      ...ledger,
      files: {
        read: 60,
        skipped: 0,
        items: Array.from({ length: 60 }, (_, i) => ({
          rel_path: `src/f${i}.ts`,
          language: "typescript",
          size_bytes: 10,
          sha256: "b".repeat(64),
          status: "read" as const,
          skip_reason: null,
        })),
      },
    };
    const root = document.createElement("div");
    renderLedger(root, many);
    expect(root.querySelectorAll("tbody tr").length).toBe(25);
    const next = [...root.querySelectorAll("button")].find((b) => b.textContent === "Next →")!;
    next.click();
    next.click();
    expect(root.querySelectorAll("tbody tr").length).toBe(10);
    expect(root.textContent).toContain("Page 3 of 3");
  });
});
