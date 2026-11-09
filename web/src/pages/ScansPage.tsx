import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Filter } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { scanListSearch, type ScanListChange, type ScanListUrlState } from "./scansListParams";
import { SCAN_FIELDS, nextScanFilter, scanFilterToRows } from "./scansFilterRows";
import { api } from "../api";
import { hasRole, useMe } from "../auth";
import { ConditionBuilder, type Row } from "../components/ConditionBuilder";
import {
  Button,
  Card,
  ErrorText,
  Field,
  FormHint,
  linkClass,
  Modal,
  ModalActions,
  Muted,
  OffsetPager,
  Page,
  PageHeader,
  ProgressBar,
  RowActions,
  Select,
  Spinner,
  StateBadge,
  Table,
  TableEmpty,
  Td,
  Th,
  THead,
  TRow,
  useConfirm,
} from "../components/ui";
import { ImportBundleModal } from "./ImportBundleModal";

const PAGE_SIZE = 50;

function RunScanModal({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const scanPolicies = useQuery({ queryKey: ["scan-policies"], queryFn: () => api.listScanPolicies() });
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const [scanPolicyId, setScanPolicyId] = useState("");
  const [targetId, setTargetId] = useState("");

  const targetName = (id: string) => targets.data?.find((t) => t.id === id)?.name ?? id.slice(0, 8);
  const selectedPolicy = (scanPolicies.data ?? []).find((p) => p.id === scanPolicyId);
  const policies = scanPolicies.data ?? [];

  const run = useMutation({
    mutationFn: () => api.createScan({ scan_policy_id: scanPolicyId, target_id: targetId }),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ["scans"] });
      onClose();
      navigate(`/scans/${res.scan_id}`);
    },
  });

  return (
    <Modal open onOpenChange={(v) => !v && onClose()} title="Run scan">
      <div className="space-y-4">
        <Field label="Scan policy">
          <Select value={scanPolicyId} onChange={(e) => setScanPolicyId(e.target.value)} className="w-full">
            <option value="">Select a scan policy…</option>
            {policies.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Target (approved scope)">
          <Select value={targetId} onChange={(e) => setTargetId(e.target.value)} className="w-full">
            <option value="">Select a target…</option>
            {(targets.data ?? []).map((target) => (
              <option key={target.id} value={target.id}>
                {target.name} ({target.host_count} host{target.host_count === 1 ? "" : "s"})
              </option>
            ))}
          </Select>
        </Field>
        {selectedPolicy && (
          <div className="space-y-1 text-xs text-neutral-500">
            <p>
              Runs the <span className="font-medium">{selectedPolicy.name}</span> policy
              {targetId ? (
                <>
                  {" "}
                  against <span className="font-medium">{targetName(targetId)}</span>
                </>
              ) : null}
              .
            </p>
            <p>Confirm its discovery mode, rate, and timeouts are appropriate for the selected target.</p>
          </div>
        )}
        {!scanPolicies.isLoading && policies.length === 0 && (
          <FormHint tone="warning">No scan policies yet — create one under Scan policies first.</FormHint>
        )}
        {!targets.isLoading && (targets.data ?? []).length === 0 && (
          <FormHint tone="warning">No approved targets yet — create one under Targets before running a scan.</FormHint>
        )}
        {run.isError && <ErrorText error={run.error} />}
        <ModalActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!scanPolicyId || !targetId || run.isPending} onClick={() => run.mutate()}>
            {run.isPending ? "Starting…" : "Run scan"}
          </Button>
        </ModalActions>
      </div>
    </Modal>
  );
}

/** A chip label for a bound: a whole UTC day shows as a date, anything else as the exact UTC instant. */
function boundLabel(rfc: string): string {
  const d = new Date(rfc);
  if (Number.isNaN(d.getTime())) return rfc;
  const iso = d.toISOString();
  if (iso.endsWith("T00:00:00.000Z") || iso.endsWith("T23:59:59.999Z")) return iso.slice(0, 10);
  return `${iso.slice(0, 19).replace("T", " ")} UTC`;
}

export function ScansPage() {
  const me = useMe();
  const canRun = hasRole(me.data ?? undefined, "operator");
  const canCancel = canRun;
  const canDelete = hasRole(me.data ?? undefined, "admin");
  const showActions = canCancel || canDelete;
  const [runOpen, setRunOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [searchParams, setSearchParams] = useSearchParams();

  const qParam = searchParams.get("q") ?? "";
  const fromParam = searchParams.get("started_from") ?? "";
  const toParam = searchParams.get("started_to") ?? "";
  const offset = Math.max(0, Number(searchParams.get("offset")) || 0);

  // The builder rows are the draft; the URL holds the applied filter. The rows
  // are rebuilt from the URL only when the URL filter really changes (Back,
  // a pasted link), so half-built rows survive the page's own applies.
  const urlFilter = useMemo(
    () => ({ q: qParam, started_from: fromParam, started_to: toParam }),
    [qParam, fromParam, toParam]
  );
  const [rows, setRows] = useState<Row[]>(() => scanFilterToRows(urlFilter));
  useEffect(() => {
    setRows((prev) => (nextScanFilter(prev, urlFilter) === null ? prev : scanFilterToRows(urlFilter)));
  }, [urlFilter]);

  const [filterOpen, setFilterOpen] = useState(false);

  const applyFilters = useCallback(
    (next: Partial<ScanListUrlState>, change: ScanListChange) => {
      const { params, replace } = scanListSearch(
        { q: qParam, started_from: fromParam, started_to: toParam, offset },
        next,
        change
      );
      setSearchParams(params, { replace });
    },
    [qParam, fromParam, toParam, offset, setSearchParams]
  );

  // One apply model for every field, as on Findings: edits apply after a short
  // debounce and reset the page. Rows that still describe the URL's filter (the
  // same instants at the builder's precision) change nothing, so a valid deep
  // link keeps its exact bounds and its offset.
  useEffect(() => {
    const t = setTimeout(() => {
      const next = nextScanFilter(rows, urlFilter);
      if (next === null) return;
      applyFilters({ ...next, offset: 0 }, "typing");
    }, 300);
    return () => clearTimeout(t);
  }, [rows, urlFilter, applyFilters]);

  const listQuery = useMemo(
    () => ({
      q: qParam.trim() || undefined,
      started_from: fromParam || undefined,
      started_to: toParam || undefined,
      limit: PAGE_SIZE,
      offset,
    }),
    [qParam, fromParam, toParam, offset]
  );

  const scans = useQuery({
    queryKey: ["scans", listQuery],
    queryFn: () => api.listScans(listQuery),
    // Re-poll the current page only; filters and offset stay put.
    refetchInterval: (q) => {
      const active = (q.state.data?.items ?? []).some((s) => s.state === "queued" || s.state === "running");
      return active ? 2000 : false;
    },
  });

  const items = scans.data?.items ?? [];
  const total = scans.data?.total ?? 0;

  const invalidate = () => void qc.invalidateQueries({ queryKey: ["scans"] });
  const cancel = useMutation({ mutationFn: (id: string) => api.cancelScan(id), onSuccess: invalidate });
  const del = useMutation({ mutationFn: (id: string) => api.deleteScan(id), onSuccess: invalidate });
  const colCount = 7 + (showActions ? 1 : 0);

  const onClearFilters = () => {
    setRows([]);
    applyFilters({}, "clear");
  };

  const hasFilters = !!(qParam || fromParam || toParam);
  const chips = [
    qParam && { key: "q" as const, label: "Name", value: qParam },
    fromParam && { key: "started_from" as const, label: "Started from", value: boundLabel(fromParam) },
    toParam && { key: "started_to" as const, label: "Started to", value: boundLabel(toParam) },
  ].filter((c): c is { key: "q" | "started_from" | "started_to"; label: string; value: string } => !!c);

  return (
    <Page>
      <PageHeader
        title="Scans"
        description="On-demand and scheduled scan runs, newest first."
        actions={
          canRun && (
            <>
              <Button onClick={() => setImportOpen(true)}>Import bundle</Button>
              <Button variant="primary" onClick={() => setRunOpen(true)}>
                Run scan
              </Button>
            </>
          )
        }
      />

      <div className="flex flex-wrap items-center gap-2">
        <Button
          onClick={() => setFilterOpen((v) => !v)}
          aria-expanded={filterOpen}
          title={filterOpen ? "Hide filter" : "Show filter"}
          selected={filterOpen || chips.length > 0}
        >
          <Filter className="h-4 w-4" aria-hidden />
          Filter
          {chips.length > 0 && (
            <span className="rounded bg-indigo-600 px-1.5 text-xs font-semibold text-white">{chips.length}</span>
          )}
        </Button>
        {!filterOpen &&
          (chips.length > 0 ? (
            <div className="flex flex-wrap items-center gap-1.5 text-sm text-neutral-500">
              {chips.map((c) => (
                <span
                  key={c.key}
                  className="inline-flex items-center gap-1 rounded bg-indigo-50 px-1.5 py-0.5 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300"
                >
                  <span className="font-medium">{c.label}</span> {c.value}
                  <button
                    type="button"
                    onClick={() => applyFilters({ [c.key]: "", offset: 0 }, "remove")}
                    className="rounded-sm text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-200"
                    aria-label={`Remove ${c.label} filter`}
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          ) : (
            <span className="text-sm text-neutral-400">No filter — showing all scans</span>
          ))}
        {hasFilters && (
          <Button variant="link" onClick={onClearFilters} title="Remove every scan filter">
            Clear
          </Button>
        )}
      </div>

      {filterOpen && (
        <Card className="space-y-3 p-3">
          <ConditionBuilder
            rows={rows}
            onChange={setRows}
            targetOptions={[]}
            fields={SCAN_FIELDS}
            unique
            hideClearAll
          />
          <FormHint>
            Name matches target, scan policy, and schedule names, or a scan-ID prefix. Started dates are UTC days and
            inclusive; queued scans without a start time use their queue time.
          </FormHint>
        </Card>
      )}

      {(cancel.isError || del.isError) && <ErrorText error={cancel.error ?? del.error} />}

      {scans.isLoading ? (
        <Spinner />
      ) : scans.isError ? (
        <ErrorText error={scans.error} />
      ) : (
        <div className="space-y-3">
          <Card>
            <Table>
              <THead>
                <Th>Scan</Th>
                <Th>Target</Th>
                <Th>Node</Th>
                <Th>State</Th>
                <Th>Created</Th>
                <Th>Finished</Th>
                <Th>Nuclei</Th>
                {showActions && <Th aria-label="Actions" />}
              </THead>
              <tbody>
                {items.map((s) => {
                  const active = s.state === "queued" || s.state === "running";
                  const short = s.id.slice(0, 8);
                  return (
                    <TRow key={s.id}>
                      <Td>
                        <Link to={`/scans/${s.id}`} className={`font-mono text-xs ${linkClass}`}>
                          {short}
                        </Link>
                      </Td>
                      <Td>
                        {s.target_name ? (
                          <span>
                            {s.target_name}
                            {s.target_host_count ? (
                              <span className="text-neutral-400">
                                {" "}
                                ({s.target_host_count} host{s.target_host_count === 1 ? "" : "s"})
                              </span>
                            ) : null}
                          </span>
                        ) : (
                          <Muted>ad-hoc</Muted>
                        )}
                      </Td>
                      <Td className="text-neutral-600 dark:text-neutral-300">{s.node_name || <Muted />}</Td>
                      <Td>
                        <StateBadge state={s.state} />
                        {s.state === "running" && s.progress && (
                          <div className="mt-1 w-40">
                            <ProgressBar percent={s.progress.percent} />
                          </div>
                        )}
                      </Td>
                      <Td className="whitespace-nowrap text-neutral-500">{new Date(s.created_at).toLocaleString()}</Td>
                      <Td className="whitespace-nowrap text-neutral-500">
                        {s.finished_at ? new Date(s.finished_at).toLocaleString() : <Muted />}
                      </Td>
                      <Td className="font-mono text-xs text-neutral-500">{s.nuclei_version || <Muted />}</Td>
                      {showActions && (
                        <RowActions
                          label={`scan ${short}`}
                          actions={[
                            {
                              label: "Stop",
                              primary: true,
                              hidden: !canCancel || !active,
                              disabled: cancel.isPending,
                              onSelect: async () => {
                                if (
                                  await confirm({
                                    title: `Stop scan ${short}?`,
                                    description:
                                      "The scanner node cancels the run. Results collected so far are not ingested.",
                                    confirmLabel: "Stop scan",
                                  })
                                )
                                  cancel.mutate(s.id);
                              },
                            },
                            {
                              label: "Delete",
                              danger: true,
                              hidden: !canDelete || active,
                              disabled: del.isPending,
                              onSelect: async () => {
                                if (
                                  await confirm({
                                    title: `Delete scan ${short}?`,
                                    description:
                                      "This removes its finding occurrences and archived output. Finding lifecycles are recomputed from the scans that remain.",
                                    confirmLabel: "Delete scan",
                                  })
                                )
                                  del.mutate(s.id);
                              },
                            },
                          ]}
                        />
                      )}
                    </TRow>
                  );
                })}
                {items.length === 0 && (
                  <TableEmpty colSpan={colCount}>
                    {hasFilters ? "No scans match these filters." : "No scans yet."}
                  </TableEmpty>
                )}
              </tbody>
            </Table>
          </Card>
          <OffsetPager
            offset={offset}
            total={total}
            pageSize={PAGE_SIZE}
            onChange={(o) => applyFilters({ offset: o }, "page")}
          />
        </div>
      )}

      {runOpen && <RunScanModal onClose={() => setRunOpen(false)} />}
      {importOpen && <ImportBundleModal onClose={() => setImportOpen(false)} />}
    </Page>
  );
}
