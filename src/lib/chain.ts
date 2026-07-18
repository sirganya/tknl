import type { DelegationCredential } from "../types";
import { SIG_CONTEXT, verifyJcsAny } from "./crypto";
import { isPersonDid, isValidDid } from "./did";
import { minBig, toMinor } from "./money";
import { purposeAllowed } from "./purpose";

/**
 * Delegation chain verification (UTAP v0.1 §8).
 *
 * A chain is an ordered array of delegation credentials: chain[0] is the root,
 * signed by a human principal; each subsequent credential's `iss` must equal
 * the previous credential's `sub`. The effective scope is the most restrictive
 * intersection at every dimension.
 *
 * Key material and revocation state are looked up through PrincipalDirectory,
 * so the pure verification logic is unit-testable without Durable Objects.
 */
export interface PrincipalDirectory {
  getKeys(did: string): Promise<JsonWebKey[]>;
  /** Revocation list lives with the issuer's PrincipalDO. */
  isRevoked(issuerDid: string, jti: string): Promise<boolean>;
}

export interface ChainRequest {
  amountMinor: bigint;
  ccy: string;
  purposeCode: string;
  budgetRef: string;
  /** DID the caller authenticated as — must be the final delegate. */
  agentDid: string;
  nowSeconds: number;
}

export type ChainVerdict =
  | {
      ok: true;
      principal: string;
      agent: string;
      /** every DID appearing in the chain (for token authorisation checks) */
      participants: string[];
      effectiveMaxAmountMinor: bigint;
    }
  | { ok: false; code: string; error: string; hop?: number };

function fail(code: string, error: string, hop?: number): ChainVerdict {
  return { ok: false, code, error, hop };
}

/** The signed portion of a credential is everything except `sig`. */
export function credentialSigningPayload(cred: DelegationCredential): Omit<DelegationCredential, "sig"> {
  const { sig: _sig, ...payload } = cred;
  return payload;
}

export async function verifyChain(
  chain: DelegationCredential[],
  dir: PrincipalDirectory,
  req: ChainRequest,
): Promise<ChainVerdict> {
  if (!Array.isArray(chain) || chain.length === 0) {
    return fail("chain_empty", "delegation chain is empty");
  }

  const root = chain[0]!;
  // 1. Root credential must be issued by a human principal, not an agent.
  if (!isPersonDid(root.iss)) {
    return fail("root_not_person", `chain root iss must be a person DID, got ${root.iss}`, 0);
  }

  let effectiveMax: bigint | null = null;
  const participants = new Set<string>([root.iss]);

  for (let i = 0; i < chain.length; i++) {
    const cred = chain[i]!;
    if (!isValidDid(cred.iss) || !isValidDid(cred.sub)) {
      return fail("bad_did", `invalid DID at hop ${i}`, i);
    }
    // 2. iss/sub continuity.
    if (i > 0 && cred.iss !== chain[i - 1]!.sub) {
      return fail(
        "chain_discontinuity",
        `hop ${i}: iss ${cred.iss} does not match previous sub ${chain[i - 1]!.sub}`,
        i,
      );
    }
    // 3. Time validity at every hop, for the current time.
    if (req.nowSeconds < cred.nbf) return fail("not_yet_valid", `hop ${i} nbf in the future`, i);
    if (req.nowSeconds >= cred.exp) return fail("expired", `hop ${i} credential expired`, i);

    // 4. Revocation — checked against the issuer's revocation list.
    if (await dir.isRevoked(cred.iss, cred.jti)) {
      return fail("revoked", `hop ${i} credential ${cred.jti} is revoked`, i);
    }

    // Signature: Ed25519 over JCS(credential minus sig), by the issuer's keys.
    const keys = await dir.getKeys(cred.iss);
    if (keys.length === 0) return fail("unknown_issuer", `no keys registered for ${cred.iss}`, i);
    const valid = await verifyJcsAny(keys, SIG_CONTEXT.delegation, credentialSigningPayload(cred), cred.sig);
    if (!valid) return fail("bad_signature", `hop ${i} signature invalid`, i);

    // 5. Scope intersection — most restrictive wins at every dimension.
    if (cred.scope.ccy !== req.ccy) {
      return fail("ccy_mismatch", `hop ${i} scope currency ${cred.scope.ccy} != ${req.ccy}`, i);
    }
    const hopMax = toMinor(cred.scope.max_amount, cred.scope.ccy);
    effectiveMax = effectiveMax === null ? hopMax : minBig(effectiveMax, hopMax);

    if (!purposeAllowed(cred.scope.purposes, req.purposeCode)) {
      return fail("purpose_not_allowed", `hop ${i} scope does not permit purpose ${req.purposeCode}`, i);
    }
    if (cred.scope.budget_refs && !cred.scope.budget_refs.includes(req.budgetRef)) {
      return fail("budget_not_allowed", `hop ${i} scope does not permit budget ${req.budgetRef}`, i);
    }

    // 6. Depth: credential i allows at most max_depth further hops below it.
    const hopsBelow = chain.length - 1 - i;
    if (hopsBelow > cred.scope.max_depth) {
      return fail("depth_exceeded", `hop ${i} allows ${cred.scope.max_depth} further hops, chain has ${hopsBelow}`, i);
    }

    participants.add(cred.sub);
  }

  if (effectiveMax === null || req.amountMinor > effectiveMax) {
    return fail("amount_exceeds_scope", "requested amount exceeds effective delegated maximum");
  }

  const agent = chain[chain.length - 1]!.sub;
  if (agent !== req.agentDid) {
    return fail("agent_mismatch", `caller ${req.agentDid} is not the final delegate ${agent}`);
  }

  return {
    ok: true,
    principal: root.iss,
    agent,
    participants: [...participants],
    effectiveMaxAmountMinor: effectiveMax,
  };
}
