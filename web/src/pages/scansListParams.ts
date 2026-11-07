// URL state of the scans list: which filters and page a change writes, and
// whether it adds a browser history entry or replaces the current one.

export interface ScanListUrlState {
  q: string;
  started_from: string;
  started_to: string;
  offset: number;
}

// "typing" is the debounced name box; every other change is an explicit
// action (pagination, applying the time range, clearing the filters) that the
// back button should be able to undo.
export type ScanListChange = "typing" | "page" | "time" | "clear";

export function scanListSearch(
  current: ScanListUrlState,
  next: Partial<ScanListUrlState>,
  change: ScanListChange
): { params: URLSearchParams; replace: boolean } {
  const params = new URLSearchParams();
  if (change !== "clear") {
    const q = (next.q ?? current.q).trim();
    const from = next.started_from ?? current.started_from;
    const to = next.started_to ?? current.started_to;
    const off = next.offset ?? current.offset;
    if (q) params.set("q", q);
    if (from) params.set("started_from", from);
    if (to) params.set("started_to", to);
    if (off > 0) params.set("offset", String(off));
  }
  return { params, replace: change === "typing" };
}
