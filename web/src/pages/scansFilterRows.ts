// Scans use the Findings ConditionBuilder with a deliberately small field set:
// Name (contains -> `q`) and Started (after / before / between ->
// `started_from` / `started_to`). This module maps between the builder rows and
// the URL filter, and decides when a row edit is a real change to the filter.

import { makeRow, type FieldDef, type Row } from "../components/ConditionBuilder";

export interface ScanFilter {
  q: string;
  started_from: string;
  started_to: string;
}

export const SCAN_FIELDS: FieldDef[] = [
  { value: "name", label: "Name", kind: "text", ops: ["contains"] },
  { value: "started", label: "Started", kind: "time", ops: ["after", "before", "between"] },
];

const DAY = /^\d{4}-\d{2}-\d{2}$/;

/** UTC calendar day (YYYY-MM-DD) of an RFC 3339 instant, or "" if it does not parse. */
function utcDay(rfc: string): string {
  if (!rfc) return "";
  const d = new Date(rfc);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 10);
}

const startOfDay = (day: string) => `${day}T00:00:00Z`;
const endOfDay = (day: string) => `${day}T23:59:59.999999Z`;

/** The builder rows that represent a URL filter. Bounds show at day precision. */
export function scanFilterToRows(f: ScanFilter): Row[] {
  const rows: Row[] = [];
  const q = f.q.trim();
  if (q) rows.push(makeRow({ field: "name", op: "contains", values: [q] }));
  const from = utcDay(f.started_from);
  const to = utcDay(f.started_to);
  if (from && to) rows.push(makeRow({ field: "started", op: "between", values: [from, to] }));
  else if (from) rows.push(makeRow({ field: "started", op: "after", values: [from] }));
  else if (to) rows.push(makeRow({ field: "started", op: "before", values: [to] }));
  return rows;
}

/** The filter the complete builder rows describe; incomplete rows filter nothing. */
export function rowsToScanFilter(rows: Row[]): ScanFilter {
  const f: ScanFilter = { q: "", started_from: "", started_to: "" };
  for (const r of rows) {
    const v0 = r.values[0]?.trim() ?? "";
    const v1 = r.values[1]?.trim() ?? "";
    if (r.field === "name") {
      if (r.op === "contains" && v0) f.q = v0;
    } else if (r.field === "started") {
      if (r.op === "after" && DAY.test(v0)) f.started_from = startOfDay(v0);
      else if (r.op === "before" && DAY.test(v0)) f.started_to = endOfDay(v0);
      else if (r.op === "between" && DAY.test(v0) && DAY.test(v1)) {
        f.started_from = startOfDay(v0);
        f.started_to = endOfDay(v1);
      }
    }
  }
  return f;
}

/** A URL filter at the precision the builder can show: same instants compare equal. */
export function canonicalScanFilter(f: ScanFilter): ScanFilter {
  return rowsToScanFilter(scanFilterToRows(f));
}

export function sameScanFilter(a: ScanFilter, b: ScanFilter): boolean {
  return a.q === b.q && a.started_from === b.started_from && a.started_to === b.started_to;
}

/**
 * The filter to write when the rows were edited, or null when they still
 * describe the URL's filter (so the URL and its offset stay untouched). A bound
 * the user did not change keeps its exact URL value, so seconds or a non-UTC
 * offset in a shared link are never dropped by an unrelated edit.
 */
export function nextScanFilter(rows: Row[], url: ScanFilter): ScanFilter | null {
  const fromRows = rowsToScanFilter(rows);
  const canon = canonicalScanFilter(url);
  if (sameScanFilter(fromRows, canon)) return null;
  return {
    q: fromRows.q,
    started_from: fromRows.started_from === canon.started_from ? url.started_from : fromRows.started_from,
    started_to: fromRows.started_to === canon.started_to ? url.started_to : fromRows.started_to,
  };
}
