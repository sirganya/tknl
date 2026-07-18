import type { Env } from "../env";
import type { Amount, DelegationCredential, Purpose, Token } from "../types";
import type { TokenRecord } from "../do/token";
import { getCfpKeys } from "../cfp";
import { SIG_CONTEXT, sha256Jcs, signJcs } from "../lib/crypto";
import { b64u } from "../lib/encoding";
import { orgOfDid } from "../lib/did";
import { fromMinor, isSupportedCurrency, toMinor } from "../lib/money";
import { isValidPurposeCode } from "../lib/purpose";
import { newTid, ulid } from "../lib/ulid";
import { verifyChain } from "../lib/chain";
import { doDirectory } from "../services/directory";
import { releaseWalk, reserveWalk, resolveBudgetPath } from "../services/budgetWalk";
import { auditAppend } from "../services/audit";

export interface MintRequest {
  amount: Amount;
  purpose: Purpose;
  budget_ref: string;
  chain: DelegationCredential[];
  ttl_seconds?: number;
}

export type MintOutcome =
  | { kind: "minted"; token: Token; uriQuery: string }
  | { kind: "approval_required"; approvalId: string; threshold: string }
  | { kind: "error"; status: number; code: string; error: string };

const DEFAULT_TTL_S = 86_400;
const MAX_TTL_S = 30 * 86_400;
const MIN_TTL_S = 60;
/** Budget reservations outlive the token slightly so expiry always finds them. */
const RESERVATION_GRACE_S = 300;

function bad(code: string, error: string, status = 400): MintOutcome {
  return { kind: "error", status, code, error };
}

/**
 * Mint flow (UTAP §5.1). Reservation and token creation live in different
 * Durable Objects, so this is a saga, not a transaction: every failure path
 * compensates by releasing the reservation walk, and reservation TTLs are the
 * backstop if this Worker dies mid-flight.
 */
export async function performMint(
  env: Env,
  req: MintRequest,
  agentDid: string,
  opts: { approved?: boolean } = {},
): Promise<MintOutcome> {
  // -- validation ------------------------------------------------------------
  if (!req.amount || typeof req.amount.value !== "string" || typeof req.amount.ccy !== "string") {
    return bad("bad_amount", "amount {value, ccy} is required");
  }
  if (!isSupportedCurrency(req.amount.ccy)) return bad("bad_ccy", "unsupported currency");
  let amountMinor: bigint;
  try {
    amountMinor = toMinor(req.amount.value, req.amount.ccy);
  } catch (e) {
    return bad("bad_amount", String(e));
  }
  if (amountMinor <= 0n) return bad("bad_amount", "amount must be positive");
  if (!req.purpose || !isValidPurposeCode(req.purpose.code ?? "")) {
    return bad("bad_purpose", "purpose.code must be a registry code like COMPUTE.INFERENCE");
  }
  if (typeof req.budget_ref !== "string" || !req.budget_ref) {
    return bad("bad_budget_ref", "budget_ref is required");
  }
  const ttl = req.ttl_seconds ?? DEFAULT_TTL_S;
  if (typeof ttl !== "number" || ttl < MIN_TTL_S || ttl > MAX_TTL_S) {
    return bad("bad_ttl", `ttl_seconds must be between ${MIN_TTL_S} and ${MAX_TTL_S}`);
  }

  // Fail fast on CFP configuration BEFORE taking any reservation: nothing
  // before this point mutates state, so a missing key cannot leak a hold.
  let cfpKeys: ReturnType<typeof getCfpKeys>;
  try {
    cfpKeys = getCfpKeys(env);
  } catch (e) {
    const apiErr = e as { status?: number; code?: string; message?: string };
    return bad(apiErr.code ?? "cfp_key_invalid", apiErr.message ?? String(e), apiErr.status ?? 503);
  }

  const now = Math.floor(Date.now() / 1000);

  // -- delegation chain (UTAP §8) -------------------------------------------
  const verdict = await verifyChain(req.chain, doDirectory(env), {
    amountMinor,
    ccy: req.amount.ccy,
    purposeCode: req.purpose.code,
    budgetRef: req.budget_ref,
    agentDid,
    nowSeconds: now,
  });
  if (!verdict.ok) {
    return bad(verdict.code, `delegation chain rejected: ${verdict.error}`, 403);
  }
  const org = orgOfDid(verdict.principal);

  // -- budget policy & approval gate (UTAP §7) ------------------------------
  const pathResult = await resolveBudgetPath(env, req.budget_ref);
  if (!pathResult.ok) return bad(pathResult.code, pathResult.error, 404);
  const { path, leaf } = pathResult;
  if (leaf.ccy !== req.amount.ccy) return bad("ccy_mismatch", `budget is ${leaf.ccy}`);

  const threshold = leaf.policy.requires_human_approval_above;
  if (!opts.approved && threshold && amountMinor > toMinor(threshold, leaf.ccy)) {
    const approvalId = "apr_" + ulid();
    const approval = env.APPROVAL_DO.get(env.APPROVAL_DO.idFromName(approvalId));
    const put = await approval.put({
      id: approvalId,
      org,
      agent: agentDid,
      principal: verdict.principal,
      budgetRef: req.budget_ref,
      thresholdExceeded: threshold,
      request: req,
      status: "pending",
      createdTs: new Date().toISOString(),
    });
    if (!put.ok) return bad(put.code, put.error, 500);
    const audited = await auditAppend(env, org, {
      event: "APPROVAL_REQUESTED",
      principal: verdict.principal,
      agent: agentDid,
      amount: req.amount,
      purpose_code: req.purpose.code,
      budget_ref: req.budget_ref,
      detail: `approval ${approvalId}: amount exceeds ${threshold}`,
    });
    if (!audited.ok) return bad("audit_failed", audited.error, 503);
    return { kind: "approval_required", approvalId, threshold };
  }

  // -- reserve leaf→root -----------------------------------------------------
  const tid = newTid();
  const exp = now + ttl;
  const reservationExpiryMs = (exp + RESERVATION_GRACE_S) * 1000;
  const reserved = await reserveWalk(env, path, {
    tid,
    amountMinor: amountMinor.toString(),
    ccy: req.amount.ccy,
    purposeCode: req.purpose.code,
    expiresAtMs: reservationExpiryMs,
  });
  if (!reserved.ok) {
    const status = reserved.code === "insufficient_budget" || reserved.code === "per_txn_max" ? 422 : 403;
    return bad(reserved.code, reserved.error, status);
  }

  // -- create + sign token ---------------------------------------------------
  try {
    return await createSignAndAudit(env, req, cfpKeys, {
      tid,
      now,
      exp,
      amountMinor,
      principal: verdict.principal,
      agent: verdict.agent,
      participants: verdict.participants,
      org,
      path,
      leafAvailableAfter: reserved.leafAvailableAfter,
    });
  } catch (e) {
    // Any unexpected throw after the walk must not leak the reservation.
    await releaseWalk(env, path, tid);
    throw e;
  }
}

interface MintContext {
  tid: string;
  now: number;
  exp: number;
  amountMinor: bigint;
  principal: string;
  agent: string;
  participants: string[];
  org: string;
  path: string[];
  leafAvailableAfter: string;
}

async function createSignAndAudit(
  env: Env,
  req: MintRequest,
  cfpKeys: ReturnType<typeof getCfpKeys>,
  ctx: MintContext,
): Promise<MintOutcome> {
  const { tid, now, exp, amountMinor, principal, agent, participants, org, path } = ctx;
  const unsigned: Omit<Token, "sig"> = {
    tid,
    ver: "0.1",
    cfp: env.CFP_ID,
    amt: { value: fromMinor(amountMinor, req.amount.ccy), ccy: req.amount.ccy },
    purpose: req.purpose,
    principal: principal,
    delegation_chain_hash: await sha256Jcs(req.chain),
    budget_ref: req.budget_ref,
    state: "issued",
    nbf: now,
    exp,
    nonce: b64u(crypto.getRandomValues(new Uint8Array(16))),
  };
  const sig = await signJcs(cfpKeys.privateJwk, SIG_CONTEXT.token, unsigned);
  const token: Token = { ...unsigned, sig };

  const rec: TokenRecord = {
    token,
    org,
    agent: agent,
    participants: participants,
    budgetPath: path,
    history: [],
  };
  const created = await env.TOKEN_DO.get(env.TOKEN_DO.idFromName(tid)).create(rec);
  if (!created.ok) {
    await releaseWalk(env, path, tid);
    return bad(created.code, created.error, 500);
  }

  // -- synchronous audit append (fail ⇒ whole operation fails) ---------------
  const audited = await auditAppend(env, org, {
    event: "TOKEN_ISSUED",
    tid,
    principal: principal,
    agent: agent,
    delegation_chain_hash: token.delegation_chain_hash,
    amount: token.amt,
    purpose_code: token.purpose.code,
    budget_ref: token.budget_ref,
    budget_after: ctx.leafAvailableAfter,
  });
  if (!audited.ok) {
    await env.TOKEN_DO.get(env.TOKEN_DO.idFromName(tid)).destroy();
    await releaseWalk(env, path, tid);
    return bad("audit_failed", `audit append failed: ${audited.error}`, 503);
  }

  // The URI is a bearer reference, not the token body (UTAP §4.2): merchants
  // append these params to their own payment URL and fetch state from the CFP.
  const uriQuery = new URLSearchParams({
    utap_v: "0.1",
    utap_tid: tid,
    utap_cfp: env.CFP_ID,
    utap_sig: sig,
  }).toString();

  return { kind: "minted", token, uriQuery };
}
