import type { Env } from "../env";
import type { AuthContext } from "../auth";
import { errorJson, json, statusForCode } from "../http";
import {
  getOrgCheckpoints,
  getOrgEntries,
  getOrgHead,
  getOrgProof,
} from "../services/audit";

/**
 * GET /v1/audit/{org}/entries?from=&to= — audit entries contain pseudonymous
 * DIDs and purpose data, so reads require an org credential (or the auditor's
 * bootstrap token). Checkpoints and inclusion proofs are public: an external
 * verifier needs only an entry hash and a published root, never entry bodies.
 *
 * All reads route through services/audit.ts, which fans out across the
 * per-period chain segments (and the pre-sharding legacy DO) transparently.
 */
export async function handleAuditEntries(
  env: Env,
  auth: AuthContext | null,
  org: string,
  url: URL,
): Promise<Response> {
  const allowed = auth?.kind === "bootstrap" || (auth?.kind === "did" && auth.org === org);
  if (!allowed) return errorJson(auth ? 403 : 401, "forbidden", "not authorised for this org's audit log");

  const head = await getOrgHead(env, org);
  const from = Math.max(1, Number(url.searchParams.get("from") ?? "1") || 1);
  const to = Math.min(head.seq, Number(url.searchParams.get("to") ?? String(head.seq)) || head.seq);
  const entries = to >= from ? await getOrgEntries(env, org, from, to) : [];
  return json({ org, head_seq: head.seq, head_hash: head.head, entries });
}

export async function handleAuditCheckpoints(env: Env, org: string): Promise<Response> {
  const checkpoints = await getOrgCheckpoints(env, org);
  return json({ org, checkpoints });
}

/** GET /v1/audit/{org}/proof/{seq} — Merkle inclusion proof + checkpoint root,
 * verifiable without trusting the CFP (UTAP §9). Routed to the segment whose
 * global seq range contains the entry. */
export async function handleAuditProof(env: Env, org: string, seqStr: string): Promise<Response> {
  const seq = Number(seqStr);
  if (!Number.isInteger(seq) || seq < 1) return errorJson(400, "bad_seq", "seq must be a positive integer");
  const result = await getOrgProof(env, org, seq);
  if (!result.ok) return errorJson(statusForCode(result.code), result.code, result.error);
  return json({
    org,
    entry: result.entry,
    proof: result.proof,
    checkpoint: result.checkpoint,
    verify:
      "leaf = sha256(0x00 || utf8(entry.entry_hash)); fold proof steps with sha256(0x01 || left || right); compare to checkpoint.merkle_root",
  });
}
