import { describe, expect, it } from "vitest";
import { jcs } from "../../src/lib/jcs";

describe("JCS canonicalisation (RFC 8785)", () => {
  it("sorts object keys by UTF-16 code units", () => {
    expect(jcs({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(jcs({ z: 1, A: 2, a: 3 })).toBe('{"A":2,"a":3,"z":1}');
  });

  it("canonicalises nested structures deterministically", () => {
    const a = { outer: { y: [1, 2], x: "s" }, n: 1.5 };
    const b = { n: 1.5, outer: { x: "s", y: [1, 2] } };
    expect(jcs(a)).toBe(jcs(b));
    expect(jcs(a)).toBe('{"n":1.5,"outer":{"x":"s","y":[1,2]}}');
  });

  it("serialises numbers per ECMAScript rules", () => {
    expect(jcs(10)).toBe("10");
    expect(jcs(1e21)).toBe("1e+21");
    expect(jcs(0.000001)).toBe("0.000001");
    expect(jcs(-0)).toBe("0");
  });

  it("rejects non-finite numbers", () => {
    expect(() => jcs(NaN)).toThrow();
    expect(() => jcs(Infinity)).toThrow();
  });

  it("skips undefined object members and nullifies undefined array slots", () => {
    expect(jcs({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(jcs([1, undefined, 2])).toBe("[1,null,2]");
  });

  it("escapes control characters and preserves unicode", () => {
    expect(jcs("line\nbreak")).toBe('"line\\nbreak"');
    expect(jcs("\u0000")).toBe('"\\u0000"');
    expect(jcs("€")).toBe(JSON.stringify("€"));
  });
});
