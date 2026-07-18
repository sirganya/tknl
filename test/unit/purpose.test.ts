import { describe, expect, it } from "vitest";
import { purposeAllowed, purposeMatches } from "../../src/lib/purpose";

describe("purpose pattern matching", () => {
  it("matches exact codes", () => {
    expect(purposeMatches("COMPUTE.INFERENCE", "COMPUTE.INFERENCE")).toBe(true);
    expect(purposeMatches("COMPUTE.INFERENCE", "COMPUTE.TRAINING")).toBe(false);
  });

  it("matches wildcard suffixes on segment boundaries only", () => {
    expect(purposeMatches("COMPUTE.*", "COMPUTE.INFERENCE")).toBe(true);
    expect(purposeMatches("COMPUTE.*", "COMPUTE.INFERENCE.BATCH")).toBe(true);
    expect(purposeMatches("COMPUTE.*", "COMPUTE")).toBe(true);
    expect(purposeMatches("COMPUTE.*", "COMPUTED.X")).toBe(false);
  });

  it("supports the global wildcard", () => {
    expect(purposeMatches("*", "ANYTHING.AT.ALL")).toBe(true);
  });

  it("requires any-of across a pattern list", () => {
    expect(purposeAllowed(["COMPUTE.*", "DATA.LICENSE"], "DATA.LICENSE")).toBe(true);
    expect(purposeAllowed(["COMPUTE.*", "DATA.LICENSE"], "DATA.EXPORT")).toBe(false);
    expect(purposeAllowed([], "COMPUTE.INFERENCE")).toBe(false);
  });
});
