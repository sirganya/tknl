/**
 * Decimal money handling. All arithmetic is done in integer minor units
 * (bigint) — never floating point. Wire format is a decimal string with the
 * currency's full exponent, e.g. "40000.00" EUR.
 */
const EXPONENTS: Record<string, number> = { EUR: 2, USD: 2, GBP: 2, CHF: 2, JPY: 0 };

export function currencyExponent(ccy: string): number {
  return EXPONENTS[ccy] ?? 2;
}

export function isSupportedCurrency(ccy: string): boolean {
  return /^[A-Z]{3}$/.test(ccy);
}

/** Parse "40000.00" → 4000000n. Rejects malformed values and excess precision. */
export function toMinor(value: string, ccy: string): bigint {
  const exp = currencyExponent(ccy);
  const m = /^(\d+)(?:\.(\d+))?$/.exec(value);
  if (!m) throw new MoneyError(`invalid amount: ${JSON.stringify(value)}`);
  const whole = m[1]!;
  const frac = m[2] ?? "";
  if (frac.length > exp) throw new MoneyError(`too many decimal places for ${ccy}: ${value}`);
  return BigInt(whole) * 10n ** BigInt(exp) + BigInt(frac.padEnd(exp, "0") || "0");
}

export function fromMinor(minor: bigint, ccy: string): string {
  if (minor < 0n) throw new MoneyError("negative amount");
  const exp = currencyExponent(ccy);
  if (exp === 0) return minor.toString();
  const s = minor.toString().padStart(exp + 1, "0");
  return s.slice(0, -exp) + "." + s.slice(-exp);
}

export class MoneyError extends Error {}

export function minBig(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}
