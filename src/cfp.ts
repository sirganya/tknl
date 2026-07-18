import type { Env } from "./env";
import { ApiError } from "./http";

export interface CfpKeys {
  privateJwk: JsonWebKey & { kid?: string };
  publicJwk: JsonWebKey & { kid: string; alg: string; use: string };
  kid: string;
}

/** CFP signing key from Workers Secrets (JSON JWK, OKP/Ed25519, private). */
export function getCfpKeys(env: Env): CfpKeys {
  if (!env.CFP_SIGNING_KEY) {
    throw new ApiError(503, "cfp_key_missing", "CFP_SIGNING_KEY secret is not configured");
  }
  let jwk: JsonWebKey & { kid?: string };
  try {
    jwk = JSON.parse(env.CFP_SIGNING_KEY) as JsonWebKey & { kid?: string };
  } catch {
    throw new ApiError(503, "cfp_key_invalid", "CFP_SIGNING_KEY is not valid JSON");
  }
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof (jwk as { d?: string }).d !== "string") {
    throw new ApiError(503, "cfp_key_invalid", "CFP_SIGNING_KEY must be a private Ed25519 OKP JWK");
  }
  const kid = jwk.kid ?? "cfp-1";
  return {
    privateJwk: jwk,
    publicJwk: { kty: "OKP", crv: "Ed25519", x: jwk.x, kid, alg: "EdDSA", use: "sig" },
    kid,
  };
}
