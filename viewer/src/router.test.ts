import { describe, expect, it } from "vitest";
import { parseRoute, routeHref } from "./router";

describe("router", () => {
  it("maps hashes to tabs, defaulting to findings", () => {
    expect(parseRoute("#/map")).toBe("map");
    expect(parseRoute("#/ledger?x=1")).toBe("ledger");
    expect(parseRoute("")).toBe("findings");
    expect(parseRoute("#/nope")).toBe("findings");
    expect(routeHref("ledger")).toBe("#/ledger");
  });
});
