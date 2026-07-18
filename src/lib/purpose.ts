/**
 * Purpose codes are dot-separated segments from the purpose registry, e.g.
 * "COMPUTE.INFERENCE". Patterns in delegation scopes and budget policies may
 * end in ".*" (matches the prefix and any deeper code) or be "*" (matches
 * everything). Matching is exact per segment — "COMPUTE.*" matches
 * "COMPUTE.INFERENCE" and "COMPUTE.INFERENCE.BATCH" but not "COMPUTED.X".
 */
export function purposeMatches(pattern: string, code: string): boolean {
  if (pattern === "*") return true;
  if (pattern === code) return true;
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -2);
    return code === prefix || code.startsWith(prefix + ".");
  }
  return false;
}

export function purposeAllowed(patterns: string[], code: string): boolean {
  return patterns.some((p) => purposeMatches(p, code));
}

export function isValidPurposeCode(code: string): boolean {
  return /^[A-Z0-9_]+(\.[A-Z0-9_]+)*$/.test(code);
}
