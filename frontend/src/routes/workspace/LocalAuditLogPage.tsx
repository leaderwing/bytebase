import { Download, X } from "lucide-react";
import { type SyntheticEvent, useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { HumanizeTs } from "@/components/HumanizeTs";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  WorkspacePageContent,
  WorkspacePageLayout,
} from "@/components/WorkspacePageLayout";
import {
  EXPORT_MAX_ROWS,
  EXPORT_PAGE_SIZE,
  exportFileName,
  saveTextFile,
  toCsv,
  toJson,
} from "./localAuditLogExport";

const ENDPOINT = "/api/local-audit-logs";
const PAGE_SIZE = 50;

type LocalAuditLogPayload = {
  method?: string;
  resource?: string;
  user?: string;
  severity?: string;
  request?: string;
  response?: string;
  status?: { code?: number; message?: string };
  latency?: string;
  requestMetadata?: { callerIp?: string };
};

type LocalAuditLogEntry = {
  name: string;
  createTime: string;
  log: LocalAuditLogPayload;
};

type SearchResponse = {
  logs: LocalAuditLogEntry[];
  nextOffset?: number;
};

type Filters = { actor: string; method: string; from: string; to: string };

const EMPTY_FILTERS: Filters = { actor: "", method: "", from: "", to: "" };

// The endpoint's filter is CEL; quote values and keep them from closing the string.
const quote = (value: string) =>
  `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

export const buildFilter = (f: Filters): string => {
  const terms: string[] = [];
  const actor = f.actor.trim();
  if (actor) {
    terms.push(`actor == ${quote(actor.includes("/") ? actor : `users/${actor}`)}`);
  }
  const method = f.method.trim();
  if (method) {
    terms.push(`method == ${quote(method)}`);
  }
  if (f.from) {
    terms.push(`create_time >= ${quote(new Date(f.from).toISOString())}`);
  }
  if (f.to) {
    terms.push(`create_time <= ${quote(new Date(f.to).toISOString())}`);
  }
  return terms.join(" && ");
};

type LoadError = "forbidden" | "unauthorized" | "failed";

class LoadFailure extends Error {
  constructor(readonly kind: LoadError) {
    super(kind);
  }
}

async function fetchPage(
  filters: Filters,
  offset: number,
  limit = PAGE_SIZE
): Promise<SearchResponse> {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });
  const filter = buildFilter(filters);
  if (filter) {
    params.set("filter", filter);
  }
  const res = await fetch(`${ENDPOINT}?${params}`, {
    credentials: "same-origin",
  });
  if (res.status === 401) throw new LoadFailure("unauthorized");
  if (res.status === 403) throw new LoadFailure("forbidden");
  if (!res.ok) throw new LoadFailure("failed");
  return (await res.json()) as SearchResponse;
}

export function LocalAuditLogPage() {
  const { t } = useTranslation();
  const [draft, setDraft] = useState<Filters>(EMPTY_FILTERS);
  const [applied, setApplied] = useState<Filters>(EMPTY_FILTERS);
  const [logs, setLogs] = useState<LocalAuditLogEntry[]>([]);
  const [nextOffset, setNextOffset] = useState<number | undefined>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<LoadError>();
  const [detail, setDetail] = useState<LocalAuditLogEntry>();
  const [downloading, setDownloading] = useState(false);
  const [truncated, setTruncated] = useState(false);
  // A newer search must win over a slower, older one.
  const requestId = useRef(0);

  const load = useCallback(async (filters: Filters, offset: number) => {
    const id = ++requestId.current;
    setLoading(true);
    setError(undefined);
    try {
      const page = await fetchPage(filters, offset);
      if (id !== requestId.current) return;
      setLogs((prev) => (offset === 0 ? page.logs : [...prev, ...page.logs]));
      setNextOffset(page.nextOffset);
    } catch (e) {
      if (id !== requestId.current) return;
      setError(e instanceof LoadFailure ? e.kind : "failed");
      if (offset === 0) {
        setLogs([]);
        setNextOffset(undefined);
      }
    } finally {
      if (id === requestId.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(applied, 0);
  }, [applied, load]);

  const onSearch = (e: SyntheticEvent) => {
    e.preventDefault();
    setApplied({ ...draft });
  };

  // Downloads everything matching the applied filters, not just the rows on
  // screen, by paging through the same endpoint.
  const download = async (format: "csv" | "json") => {
    setDownloading(true);
    setTruncated(false);
    setError(undefined);
    try {
      const all: LocalAuditLogEntry[] = [];
      let offset: number | undefined = 0;
      while (offset !== undefined && all.length < EXPORT_MAX_ROWS) {
        const page: SearchResponse = await fetchPage(
          applied,
          offset,
          EXPORT_PAGE_SIZE
        );
        all.push(...page.logs);
        offset = page.nextOffset;
      }
      if (offset !== undefined) {
        all.length = Math.min(all.length, EXPORT_MAX_ROWS);
        setTruncated(true);
      }
      if (format === "csv") {
        saveTextFile(toCsv(all), exportFileName("csv"), "text/csv;charset=utf-8");
      } else {
        saveTextFile(
          toJson(all),
          exportFileName("json"),
          "application/json;charset=utf-8"
        );
      }
    } catch (e) {
      setError(e instanceof LoadFailure ? e.kind : "failed");
    } finally {
      setDownloading(false);
    }
  };

  const columnCount = 7;
  const errorMessage: Record<LoadError, string> = {
    failed: t("local-audit-log.error.failed"),
    forbidden: t("local-audit-log.error.forbidden"),
    unauthorized: t("local-audit-log.error.unauthorized"),
  };

  return (
    <WorkspacePageLayout>
      <WorkspacePageContent>
        <div className="flex flex-col gap-y-4">
          <form
            className="flex flex-wrap items-end gap-x-2 gap-y-2"
            onSubmit={onSearch}
          >
            <label className="flex flex-col gap-y-1.5 text-sm text-control">
              {t("local-audit-log.filter.actor")}
              <Input
                value={draft.actor}
                placeholder={t("local-audit-log.filter.actor-placeholder")}
                onChange={(e) => setDraft({ ...draft, actor: e.target.value })}
              />
            </label>
            <label className="flex flex-col gap-y-1.5 text-sm text-control">
              {t("local-audit-log.filter.method")}
              <Input
                value={draft.method}
                placeholder={t("local-audit-log.filter.method-placeholder")}
                onChange={(e) => setDraft({ ...draft, method: e.target.value })}
              />
            </label>
            <label className="flex flex-col gap-y-1.5 text-sm text-control">
              {t("local-audit-log.filter.from")}
              <Input
                type="datetime-local"
                value={draft.from}
                onChange={(e) => setDraft({ ...draft, from: e.target.value })}
              />
            </label>
            <label className="flex flex-col gap-y-1.5 text-sm text-control">
              {t("local-audit-log.filter.to")}
              <Input
                type="datetime-local"
                value={draft.to}
                onChange={(e) => setDraft({ ...draft, to: e.target.value })}
              />
            </label>
            <Button type="submit" disabled={loading}>
              {t("common.search")}
            </Button>
            <Button
              type="button"
              appearance="secondary"
              onClick={() => {
                setDraft(EMPTY_FILTERS);
                setApplied(EMPTY_FILTERS);
              }}
            >
              {t("common.reset")}
            </Button>
            <div className="ml-auto flex items-center gap-x-2">
              <Button
                type="button"
                appearance="secondary"
                disabled={loading || downloading}
                onClick={() => void download("csv")}
              >
                <Download className="size-4" />
                {downloading
                  ? t("local-audit-log.download.preparing")
                  : t("local-audit-log.download.csv")}
              </Button>
              <Button
                type="button"
                appearance="secondary"
                disabled={loading || downloading}
                onClick={() => void download("json")}
              >
                <Download className="size-4" />
                {t("local-audit-log.download.json")}
              </Button>
            </div>
          </form>

          {truncated && (
            <Alert
              variant="warning"
              description={t("local-audit-log.download.truncated", {
                count: EXPORT_MAX_ROWS,
              })}
            />
          )}

          {error && (
            <Alert
              variant="error"
              description={errorMessage[error]}
            />
          )}

          <div className="overflow-x-auto rounded-sm border border-block-border">
            <Table>
              <TableHeader>
                <TableRow className="bg-control-bg">
                  <TableHead>{t("local-audit-log.table.time")}</TableHead>
                  <TableHead>{t("local-audit-log.table.level")}</TableHead>
                  <TableHead>{t("local-audit-log.table.actor")}</TableHead>
                  <TableHead>{t("local-audit-log.table.method")}</TableHead>
                  <TableHead>{t("local-audit-log.table.resource")}</TableHead>
                  <TableHead>{t("local-audit-log.table.status")}</TableHead>
                  <TableHead>{t("local-audit-log.table.ip")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={columnCount}
                      className="py-8 text-center text-control-placeholder"
                    >
                      {loading ? t("common.loading") : t("common.no-data")}
                    </TableCell>
                  </TableRow>
                ) : (
                  logs.map((entry) => (
                    <TableRow
                      key={entry.name}
                      className="cursor-pointer"
                      onClick={() => setDetail(entry)}
                    >
                      <TableCell className="whitespace-nowrap">
                        <HumanizeTs
                          mode="datetime"
                          tsMs={new Date(entry.createTime).getTime()}
                        />
                      </TableCell>
                      <TableCell>{entry.log.severity ?? "-"}</TableCell>
                      <TableCell>{entry.log.user || "-"}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {entry.log.method || "-"}
                      </TableCell>
                      <TableCell>{entry.log.resource || "-"}</TableCell>
                      <TableCell>
                        <StatusBadge status={entry.log.status} />
                      </TableCell>
                      <TableCell>
                        {entry.log.requestMetadata?.callerIp || "-"}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          {nextOffset !== undefined && (
            <div className="flex justify-end">
              <Button
                appearance="secondary"
                size="sm"
                disabled={loading}
                onClick={() => void load(applied, nextOffset)}
              >
                {loading ? t("common.loading") : t("common.load-more")}
              </Button>
            </div>
          )}
        </div>
      </WorkspacePageContent>

      {detail && (
        <Dialog open onOpenChange={(open) => !open && setDetail(undefined)}>
          <DialogContent className="flex h-[calc(100vh-12rem)] w-[calc(100vw-12rem)] max-w-none flex-col p-0">
            <div className="flex items-center justify-between border-b px-4 py-3">
              <DialogTitle className="text-base font-medium">
                {t("common.view-details")}
              </DialogTitle>
              <Button
                appearance="secondary"
                size="sm"
                aria-label={t("common.close")}
                onClick={() => setDetail(undefined)}
              >
                <X className="size-4" />
              </Button>
            </div>
            <div className="flex-1 overflow-auto p-4">
              <pre className="whitespace-pre-wrap break-all font-mono text-sm">
                {JSON.stringify(detail.log, null, 2)}
              </pre>
            </div>
          </DialogContent>
        </Dialog>
      )}
    </WorkspacePageLayout>
  );
}

function StatusBadge({ status }: { status?: LocalAuditLogPayload["status"] }) {
  const { t } = useTranslation();
  if (!status || !status.code) {
    return <Badge variant="success">{t("local-audit-log.status.ok")}</Badge>;
  }
  return <Badge variant="destructive">{status.message || status.code}</Badge>;
}
