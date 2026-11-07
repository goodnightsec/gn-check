import { describe, expect, it } from "vitest";
import { createMemoryRouter } from "react-router-dom";
import { scanListSearch, type ScanListChange, type ScanListUrlState } from "./scansListParams";

const empty: ScanListUrlState = { q: "", started_from: "", started_to: "", offset: 0 };

function stateOf(search: string): ScanListUrlState {
  const p = new URLSearchParams(search);
  return {
    q: p.get("q") ?? "",
    started_from: p.get("started_from") ?? "",
    started_to: p.get("started_to") ?? "",
    offset: Number(p.get("offset")) || 0,
  };
}

describe("scanListSearch", () => {
  it("keeps current filters and drops a zero offset", () => {
    const { params } = scanListSearch(
      { q: "alpha", started_from: "2026-01-01T00:00:00Z", started_to: "", offset: 50 },
      { offset: 0 },
      "page"
    );
    expect(params.toString()).toBe("q=alpha&started_from=2026-01-01T00%3A00%3A00Z");
  });

  it("clear removes every parameter", () => {
    const { params } = scanListSearch({ q: "a", started_from: "x", started_to: "y", offset: 25 }, {}, "clear");
    expect(params.toString()).toBe("");
  });

  it("replaces history only for debounced typing", () => {
    const modes: ScanListChange[] = ["typing", "page", "remove", "clear"];
    expect(modes.map((m) => scanListSearch(empty, {}, m).replace)).toEqual([true, false, false, false]);
  });
});

describe("scans list history", () => {
  it("back undoes pagination, chip removal and clear; filter edits replace in place", async () => {
    const router = createMemoryRouter([{ path: "/scans", element: null }], { initialEntries: ["/scans"] });
    const apply = async (next: Partial<ScanListUrlState>, change: ScanListChange) => {
      const { params, replace } = scanListSearch(stateOf(router.state.location.search), next, change);
      await router.navigate({ pathname: "/scans", search: params.toString() ? `?${params}` : "" }, { replace });
    };

    await apply({ q: "alp", offset: 0 }, "typing");
    await apply({ q: "alpha", offset: 0 }, "typing");
    expect(router.state.location.search).toBe("?q=alpha");
    await apply({ offset: 25 }, "page");
    await apply({ offset: 50 }, "page");
    await apply({ started_from: "2026-01-01T00:00:00Z", offset: 0 }, "typing");
    await apply({ q: "", offset: 0 }, "remove");
    await apply({}, "clear");
    expect(router.state.location.search).toBe("");

    const back = async () => {
      await router.navigate(-1);
      return router.state.location.search;
    };
    expect(await back()).toBe("?started_from=2026-01-01T00%3A00%3A00Z");
    // The time edit replaced the page-50 entry in place.
    expect(await back()).toBe("?q=alpha&started_from=2026-01-01T00%3A00%3A00Z");
    expect(await back()).toBe("?q=alpha&offset=25");
    // Both typing steps replaced the first entry in place, so no entry exists for "alp".
    expect(await back()).toBe("?q=alpha");
    router.dispose();
  });
});
