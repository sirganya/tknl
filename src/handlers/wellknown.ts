import type { Env } from "../env";
import { getCfpKeys } from "../cfp";
import { json } from "../http";

export function handleCfpMetadata(env: Env, url: URL): Response {
  return json({
    cfp: env.CFP_ID,
    utap_versions: ["0.1"],
    jwks_uri: `${url.origin}/.well-known/jwks.json`,
    api_base: `${url.origin}/v1`,
    endpoints: {
      mint: "/v1/tokens",
      token: "/v1/tokens/{tid}",
      reserve: "/v1/tokens/{tid}/reserve",
      redeem: "/v1/tokens/{tid}/redeem",
      void: "/v1/tokens/{tid}/void",
      delegations: "/v1/delegations",
      budgets: "/v1/budgets/{ref}",
      approvals: "/v1/approvals/{id}",
      audit_entries: "/v1/audit/{org}/entries",
      audit_proof: "/v1/audit/{org}/proof/{seq}",
      audit_checkpoints: "/v1/audit/{org}/checkpoints",
    },
    settlement: "mock-ledger", // real rails attach behind the same boundary
  });
}

export function handleJwks(env: Env): Response {
  const { publicJwk } = getCfpKeys(env);
  return json({ keys: [publicJwk] });
}
