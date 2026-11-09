import { describe, expect, it } from "vitest";
import { createMemoryRouter } from "react-router-dom";
import { makeRow } from "../components/ConditionBuilder";
import { nextScanFilter, rowsToScanFilter, scanFilterToRows, type ScanFilter } from "./scansFilterRows";
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

describe("scans filter rows and deep links", () => {
  const url = (o: Partial<ScanFilter>): ScanFilter => ({ q: "", started_from: "", started_to: "", ...o });
  // Rows rebuilt from the URL, as the page does when it opens a link.
  const open = (f: ScanFilter) => scanFilterToRows(f);

  it("maps Name and Started rows to q and the inclusive started bounds", () => {
    const rows = [
      makeRow({ field: "name", op: "contains", values: [" alpha "] }),
      makeRow({ field: "started", op: "between", values: ["2026-01-01", "2026-01-31"] }),
    ];
    expect(rowsToScanFilter(rows)).toEqual({
      q: "alpha",
      started_from: "2026-01-01T00:00:00Z",
      started_to: "2026-01-31T23:59:59.999999Z",
    });
    expect(rowsToScanFilter([makeRow({ field: "started", op: "after", values: ["2026-02-03"] })])).toEqual(
      url({ started_from: "2026-02-03T00:00:00Z" })
    );
    expect(rowsToScanFilter([makeRow({ field: "started", op: "before", values: ["2026-02-03"] })])).toEqual(
      url({ started_to: "2026-02-03T23:59:59.999999Z" })
    );
  });

  it("incomplete rows filter nothing", () => {
    const rows = [
      makeRow({ field: "name", op: "contains", values: [] }),
      makeRow({ field: "started", op: "between", values: ["2026-01-01", ""] }),
    ];
    expect(rowsToScanFilter(rows)).toEqual(url({}));
  });

  it.each([
    "2026-01-01T00:00:00Z",
    "2026-01-01T00:00:00.000Z",
    "2026-01-01T00:00:30Z",
    "2026-01-01T00:00:00.123456Z",
    "2026-01-01T01:00:00+01:00",
  ])("a deep link with started_from=%s is not an edit, so the URL and offset stay", (from) => {
    const u = url({ started_from: from });
    expect(nextScanFilter(open(u), u)).toBeNull();
  });

  it("a deep link with both bounds and a name is not an edit", () => {
    const u = url({ q: "alpha", started_from: "2026-01-01T00:00:00Z", started_to: "2026-01-31T12:30:15+02:00" });
    expect(nextScanFilter(open(u), u)).toBeNull();
  });

  it("an unrelated edit keeps the exact bound from the link (seconds and offset survive)", () => {
    const u = url({ started_from: "2026-01-01T00:00:30Z", started_to: "2026-01-31T12:30:15+02:00" });
    const rows = open(u);
    rows.unshift(makeRow({ field: "name", op: "contains", values: ["beta"] }));
    expect(nextScanFilter(rows, u)).toEqual({ q: "beta", started_from: u.started_from, started_to: u.started_to });
  });

  it("changing a bound to another day is an edit and writes the new bound", () => {
    const u = url({ started_from: "2026-01-01T00:00:30Z" });
    const rows = [makeRow({ field: "started", op: "after", values: ["2026-01-05"] })];
    expect(nextScanFilter(rows, u)).toEqual(url({ started_from: "2026-01-05T00:00:00Z" }));
  });

  it("removing every row clears an existing filter", () => {
    const u = url({ q: "a", started_from: "2026-01-01T00:00:00Z" });
    expect(nextScanFilter([], u)).toEqual(url({}));
  });

  it("an empty URL with no rows is not an edit", () => {
    expect(nextScanFilter([], url({}))).toBeNull();
  });

  it("round trips a link through the router: no navigation, offset kept", async () => {
    const initial = "/scans?started_from=2026-01-01T00%3A00%3A00Z&offset=50";
    const router = createMemoryRouter([{ path: "/scans", element: null }], { initialEntries: [initial] });
    const cur = stateOf(router.state.location.search);
    const u = url({ started_from: cur.started_from });
    if (nextScanFilter(open(u), u) !== null) {
      const { params, replace } = scanListSearch(cur, { offset: 0 }, "typing");
      await router.navigate({ pathname: "/scans", search: `?${params}` }, { replace });
    }
    expect(router.state.location.search).toBe("?started_from=2026-01-01T00%3A00%3A00Z&offset=50");
    router.dispose();
  });
});
