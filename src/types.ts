export interface Amount {
  value: string; // decimal string, full currency exponent, e.g. "40000.00"
  ccy: string; // ISO 4217
}

export interface PurposeConstraints {
  merchant_allow?: string[]; // merchant DIDs
  mcc_allow?: string[]; // merchant category codes
}

export interface Purpose {
  code: string; // machine-readable, from purpose registry, e.g. COMPUTE.INFERENCE
  desc?: string;
  constraints?: PurposeConstraints;
}

export type TokenState = "issued" | "reserved" | "redeemed" | "settled" | "void" | "expired";

export interface Token {
  tid: string; // "utap_" + ULID
  ver: "0.1";
  cfp: string; // issuing CFP identity
  amt: Amount;
  purpose: Purpose;
  principal: string; // human principal DID at the root of the chain
  delegation_chain_hash: string; // sha256:<hex> over JCS(chain)
  budget_ref: string;
  state: TokenState;
  nbf: number; // unix seconds
  exp: number; // unix seconds
  nonce: string; // b64u
  sig?: string; // "ed25519:<b64u>" — CFP signature over canonical form minus sig/state
}

export interface DelegationScope {
  max_amount: string;
  ccy: string;
  purposes: string[]; // patterns, e.g. ["COMPUTE.*", "DATA.LICENSE"]
  budget_refs?: string[]; // absent = unrestricted
  max_depth: number; // further sub-delegations allowed below this credential
}

export interface DelegationCredential {
  iss: string; // delegator DID
  sub: string; // delegate DID
  scope: DelegationScope;
  nbf: number;
  exp: number;
  jti: string; // "dlg_" + ULID
  parent_jti?: string; // link for chain resolution (root credentials omit it)
  sig: string; // signed by iss
}

export type AuditEvent =
  | "TOKEN_ISSUED"
  | "TOKEN_RESERVED"
  | "TOKEN_REDEEMED"
  | "TOKEN_SETTLED"
  | "TOKEN_VOIDED"
  | "TOKEN_EXPIRED"
  | "DELEGATION_ISSUED"
  | "DELEGATION_REVOKED"
  | "BUDGET_CONFIGURED"
  | "BUDGET_POLICY_UPDATED"
  | "APPROVAL_REQUESTED"
  | "APPROVAL_GRANTED"
  | "APPROVAL_DENIED"
  | "PRINCIPAL_KEY_ADDED"
  | "RECONCILIATION_DIVERGENCE";

export interface AuditEntryBody {
  event: AuditEvent;
  tid?: string;
  principal?: string;
  agent?: string;
  delegation_chain_hash?: string;
  amount?: Amount;
  purpose_code?: string;
  budget_ref?: string;
  budget_after?: string; // available at leaf budget after the operation
  merchant?: string;
  detail?: string;
}

export interface AuditEntry extends AuditEntryBody {
  seq: number;
  ts: string; // ISO 8601
  org: string;
  prev_hash: string; // entry_hash of seq-1, or genesis seed hash for seq 1
  entry_hash: string; // sha256( utf8(JCS(entry minus entry_hash)) || utf8(prev_hash) )
}

export interface BudgetPolicy {
  purposes_allow?: string[];
  per_txn_max?: string;
  requires_human_approval_above?: string;
}

export interface BudgetConfig {
  budget_ref: string;
  org: string;
  parent: string | null;
  limit: string;
  ccy: string;
  period: { start: string; end: string };
  policy: BudgetPolicy;
}

export interface BudgetState extends BudgetConfig {
  reserved: string;
  spent: string;
  available: string;
}

export interface Checkpoint {
  org: string;
  seq: number; // last seq covered by this checkpoint
  from_seq: number; // first seq covered
  merkle_root: string;
  ts: string;
  anchor_ref?: string;
}

/** Result envelope used across Durable Object RPC boundaries. */
export type DOResult<T = unknown> =
  | ({ ok: true } & T)
  | { ok: false; error: string; code: string };

export function err(code: string, error: string): { ok: false; error: string; code: string } {
  return { ok: false, error, code };
}
