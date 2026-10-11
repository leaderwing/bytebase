import { describe, expect, it } from "vitest";
import {
  csvCell,
  exportFileName,
  type ExportEntry,
  toCsv,
  toJson,
} from "./localAuditLogExport";

const entry: ExportEntry = {
  name: "workspaces/w/localAuditLogs/1",
  createTime: "2026-10-11T00:00:00Z",
  log: {
    user: "users/a@example.com",
    method: "/bytebase.v1.SQLService/Query",
    request: 'select "x", 1',
    status: { code: 7, message: "denied" },
    requestMetadata: { callerIp: "10.0.0.1" },
  },
};

describe("csvCell", () => {
  it("quotes and doubles embedded quotes", () => {
    expect(csvCell('a"b,c')).toBe('"a""b,c"');
  });

  it("renders undefined as an empty cell", () => {
    expect(csvCell(undefined)).toBe('""');
  });

  it("neutralizes formula prefixes", () => {
    for (const v of ["=1+1", "+1", "-1", "@SUM(A1)"]) {
      expect(csvCell(v)).toBe(`"'${v}"`);
    }
  });
});

describe("toCsv", () => {
  it("writes a header and one row per entry", () => {
    const lines = toCsv([entry]).trimEnd().split("\r\n");
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('"time","level","user"');
    expect(lines[1]).toContain('"users/a@example.com"');
    expect(lines[1]).toContain('"select ""x"", 1"');
    expect(lines[1]).toContain('"7","denied","10.0.0.1"');
  });

  it("writes only the header for no entries", () => {
    expect(toCsv([]).trimEnd().split("\r\n")).toHaveLength(1);
  });
});

describe("toJson", () => {
  it("round-trips entries", () => {
    expect(JSON.parse(toJson([entry]))).toEqual([entry]);
  });
});

describe("exportFileName", () => {
  it("embeds a local timestamp and the extension", () => {
    expect(exportFileName("csv", new Date(2026, 9, 11, 8, 5, 3))).toBe(
      "local-audit-log-20261011-080503.csv"
    );
  });
});
