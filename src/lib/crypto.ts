import { b64u, b64uDecode, concatBytes, hex, utf8 } from "./encoding";
import { jcs } from "./jcs";

const ED25519 = { name: "Ed25519" };

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

/** "sha256:<hex>" over the JCS form of a JSON value. */
export async function sha256Jcs(value: unknown): Promise<string> {
  return "sha256:" + hex(await sha256(utf8(jcs(value))));
}

export async function importPrivateJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk, ED25519, false, ["sign"]);
}

export async function importPublicJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  const pub: JsonWebKey = { kty: jwk.kty, crv: jwk.crv, x: jwk.x };
  return crypto.subtle.importKey("jwk", pub, ED25519, false, ["verify"]);
}

/**
 * Sign a JSON structure: Ed25519 over utf8(context || JCS(value)).
 * The context string domain-separates signature types (token vs delegation vs
 * auth credential) so a signature over one structure can never be replayed as
 * another. Returns "ed25519:<b64u>".
 */
export async function signJcs(
  privateJwk: JsonWebKey,
  context: string,
  value: unknown,
): Promise<string> {
  const key = await importPrivateJwk(privateJwk);
  const msg = concatBytes(utf8(context), utf8(jcs(value)));
  const sig = new Uint8Array(await crypto.subtle.sign(ED25519, key, msg as BufferSource));
  return "ed25519:" + b64u(sig);
}

export async function verifyJcs(
  publicJwk: JsonWebKey,
  context: string,
  value: unknown,
  signature: string,
): Promise<boolean> {
  if (!signature.startsWith("ed25519:")) return false;
  let sigBytes: Uint8Array;
  try {
    sigBytes = b64uDecode(signature.slice("ed25519:".length));
  } catch {
    return false;
  }
  try {
    const key = await importPublicJwk(publicJwk);
    const msg = concatBytes(utf8(context), utf8(jcs(value)));
    return await crypto.subtle.verify(ED25519, key, sigBytes as BufferSource, msg as BufferSource);
  } catch {
    return false;
  }
}

/** Try a set of candidate public keys; true if any verifies. */
export async function verifyJcsAny(
  publicJwks: JsonWebKey[],
  context: string,
  value: unknown,
  signature: string,
): Promise<boolean> {
  for (const jwk of publicJwks) {
    if (await verifyJcs(jwk, context, value, signature)) return true;
  }
  return false;
}

export async function generateEd25519Jwk(): Promise<{ privateJwk: JsonWebKey; publicJwk: JsonWebKey }> {
  const pair = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
  const privateJwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey;
  const publicJwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  return { privateJwk, publicJwk };
}

/** Signature contexts (domain separation). */
export const SIG_CONTEXT = {
  token: "utap.v0.1.token.",
  delegation: "utap.v0.1.delegation.",
  auth: "utap.v0.1.auth.",
  approval: "utap.v0.1.approval.",
} as const;
