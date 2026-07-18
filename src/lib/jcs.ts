/**
 * JSON Canonicalization Scheme (RFC 8785).
 *
 * All signed and hashed structures in UTAP are canonicalised with JCS before
 * signing/hashing. Any ambiguity in canonical form is a signature-forgery
 * vector, so this module is deliberately small and strict:
 *  - object keys sorted by UTF-16 code units (JS default string sort)
 *  - numbers serialised per ECMAScript Number::toString (JSON.stringify)
 *  - non-finite numbers rejected
 *  - undefined object members skipped (as JSON.stringify does)
 */
export function jcs(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new Error("jcs: non-finite number");
      return JSON.stringify(value);
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return "[" + value.map((v) => jcs(v === undefined ? null : v)).join(",") + "]";
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(obj[k])).join(",") + "}";
    }
    default:
      throw new Error(`jcs: unsupported type ${typeof value}`);
  }
}
