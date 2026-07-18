const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** ULID: 48-bit ms timestamp + 80 bits of CSPRNG randomness, Crockford base32. */
export function ulid(now = Date.now()): string {
  let ts = now;
  const timeChars = new Array<string>(10);
  for (let i = 9; i >= 0; i--) {
    timeChars[i] = CROCKFORD[ts % 32]!;
    ts = Math.floor(ts / 32);
  }
  const rand = crypto.getRandomValues(new Uint8Array(16));
  let out = timeChars.join("");
  for (let i = 0; i < 16; i++) out += CROCKFORD[rand[i]! % 32]!;
  return out;
}

export function newTid(): string {
  return "utap_" + ulid();
}
