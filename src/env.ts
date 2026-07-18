import type { TokenDO } from "./do/token";
import type { BudgetDO } from "./do/budget";
import type { PrincipalDO } from "./do/principal";
import type { AuditChainDO } from "./do/audit";
import type { AuditDirectoryDO } from "./do/auditDirectory";
import type { IdempotencyDO } from "./do/idempotency";
import type { ApprovalDO } from "./do/approval";
import type { AuditEntry } from "./types";

export type QueueMessage =
  | { type: "audit.index"; entry: AuditEntry }
  | { type: "settle"; tid: string; org: string }
  | { type: "budget.index"; ref: string; org: string; parent: string | null; ccy: string };

export interface Env {
  TOKEN_DO: DurableObjectNamespace<TokenDO>;
  BUDGET_DO: DurableObjectNamespace<BudgetDO>;
  PRINCIPAL_DO: DurableObjectNamespace<PrincipalDO>;
  AUDIT_DO: DurableObjectNamespace<AuditChainDO>;
  AUDIT_DIR: DurableObjectNamespace<AuditDirectoryDO>;
  IDEMPOTENCY_DO: DurableObjectNamespace<IdempotencyDO>;
  APPROVAL_DO: DurableObjectNamespace<ApprovalDO>;

  DB: D1Database;
  AUDIT_ARCHIVE: R2Bucket;
  AUDIT_QUEUE: Queue<QueueMessage>;
  CONFIG_KV: KVNamespace;

  CFP_ID: string;
  ENVIRONMENT?: string;
  /** Secret: JSON JWK (OKP / Ed25519, private, with kid) for CFP token signing. */
  CFP_SIGNING_KEY?: string;
  /** Secret: bearer token guarding bootstrap/admin endpoints. */
  BOOTSTRAP_TOKEN?: string;
}
