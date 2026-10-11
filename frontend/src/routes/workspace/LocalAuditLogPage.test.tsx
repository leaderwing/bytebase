import { describe, expect, it } from "vitest";
import { buildFilter } from "./LocalAuditLogPage";

const empty = { actor: "", method: "", from: "", to: "" };

describe("buildFilter", () => {
  it("returns an empty filter when nothing is set", () => {
    expect(buildFilter(empty)).toBe("");
  });

  it("prefixes a bare email with users/", () => {
    expect(buildFilter({ ...empty, actor: " a@example.com " })).toBe(
      'actor == "users/a@example.com"'
    );
  });

  it("keeps a full principal name as typed", () => {
    expect(
      buildFilter({ ...empty, actor: "serviceAccounts/bot@example.com" })
    ).toBe('actor == "serviceAccounts/bot@example.com"');
  });

  it("joins the terms with && and converts local times to RFC 3339", () => {
    const filter = buildFilter({
      actor: "a@example.com",
      method: "/bytebase.v1.SQLService/Query",
      from: "2026-01-02T03:04",
      to: "2026-01-03T03:04",
    });
    expect(filter).toBe(
      [
        'actor == "users/a@example.com"',
        'method == "/bytebase.v1.SQLService/Query"',
        `create_time >= "${new Date("2026-01-02T03:04").toISOString()}"`,
        `create_time <= "${new Date("2026-01-03T03:04").toISOString()}"`,
      ].join(" && ")
    );
  });

  it("escapes quotes and backslashes so a value cannot end the string", () => {
    expect(buildFilter({ ...empty, method: 'a"b\\c' })).toBe(
      'method == "a\\"b\\\\c"'
    );
  });
});
