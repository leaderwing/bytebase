export type ExportEntry = {
  name: string;
  createTime: string;
  log: {
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
};

// Rows fetched per request; the endpoint caps limit at 1000.
export const EXPORT_PAGE_SIZE = 1000;
// Upper bound for one download so a huge table cannot exhaust browser memory.
export const EXPORT_MAX_ROWS = 50000;

const CSV_HEADER = [
  "time",
  "level",
  "user",
  "method",
  "resource",
  "status_code",
  "status_message",
  "ip",
  "latency",
  "request",
  "response",
];

// Quote a CSV cell and neutralize spreadsheet formulas (CSV injection):
// statements and resources are user-controlled and a cell starting with
// = + - @ would run as a formula when opened in Excel or Sheets.
export const csvCell = (value: string | number | undefined): string => {
  let s = value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(s)) {
    s = `'${s}`;
  }
  return `"${s.replace(/"/g, '""')}"`;
};

export const toCsv = (entries: ExportEntry[]): string => {
  const rows = entries.map((e) =>
    [
      e.createTime,
      e.log.severity,
      e.log.user,
      e.log.method,
      e.log.resource,
      e.log.status?.code ?? 0,
      e.log.status?.message,
      e.log.requestMetadata?.callerIp,
      e.log.latency,
      e.log.request,
      e.log.response,
    ]
      .map(csvCell)
      .join(",")
  );
  return [CSV_HEADER.map(csvCell).join(","), ...rows].join("\r\n") + "\r\n";
};

export const toJson = (entries: ExportEntry[]): string =>
  JSON.stringify(entries, null, 2);

export const exportFileName = (ext: "csv" | "json", now = new Date()) => {
  const p = (n: number) => String(n).padStart(2, "0");
  const stamp =
    `${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}` +
    `-${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}`;
  return `local-audit-log-${stamp}.${ext}`;
};

export const saveTextFile = (
  content: string,
  fileName: string,
  mime: string
) => {
  // BOM so Excel opens UTF-8 CSV correctly.
  const prefix = mime.startsWith("text/csv") ? "﻿" : "";
  const url = URL.createObjectURL(new Blob([prefix + content], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
};
