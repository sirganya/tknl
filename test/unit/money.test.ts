import { describe, expect, it } from "vitest";
import { fromMinor, toMinor } from "../../src/lib/money";

describe("money (integer minor-unit arithmetic)", () => {
  it("round-trips EUR amounts", () => {
    expect(toMinor("40000.00", "EUR")).toBe(4000000n);
    expect(toMinor("0.01", "EUR")).toBe(1n);
    expect(toMinor("112400", "EUR")).toBe(11240000n);
    expect(fromMinor(11240000n, "EUR")).toBe("112400.00");
    expect(fromMinor(1n, "EUR")).toBe("0.01");
    expect(fromMinor(0n, "EUR")).toBe("0.00");
  });

  it("honours zero-exponent currencies", () => {
    expect(toMinor("500", "JPY")).toBe(500n);
    expect(fromMinor(500n, "JPY")).toBe("500");
    expect(() => toMinor("500.5", "JPY")).toThrow();
  });

  it("rejects malformed and over-precise values", () => {
    expect(() => toMinor("1.234", "EUR")).toThrow();
    expect(() => toMinor("-5.00", "EUR")).toThrow();
    expect(() => toMinor("1e3", "EUR")).toThrow();
    expect(() => toMinor("", "EUR")).toThrow();
    expect(() => toMinor("1,000.00", "EUR")).toThrow();
  });

  it("never loses precision on large amounts", () => {
    expect(toMinor("9007199254740993.11", "EUR")).toBe(900719925474099311n);
    expect(fromMinor(900719925474099311n, "EUR")).toBe("9007199254740993.11");
  });
});
