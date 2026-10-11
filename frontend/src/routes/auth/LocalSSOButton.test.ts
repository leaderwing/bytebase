import { describe, expect, it } from "vitest";
import { parseErrorCode } from "./LocalSSOButton";

describe("parseErrorCode", () => {
  it("accepts the codes the backend sends", () => {
    for (const code of [
      "denied",
      "failed",
      "not_registered",
      "state",
      "unverified",
    ]) {
      expect(parseErrorCode(code)).toBe(code);
    }
  });

  it("ignores anything else so it never reaches a translation key", () => {
    expect(parseErrorCode("../x")).toBeUndefined();
    expect(parseErrorCode(undefined)).toBeUndefined();
    expect(parseErrorCode(["denied"])).toBeUndefined();
  });
});
