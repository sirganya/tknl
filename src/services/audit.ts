import type { Env } from "../env";
import type { AuditEntry, AuditEntryBody, DOResult } from "../types";

/**
 * Synchronous audit append — in the critical path of every value operation.
 * An unauditable transaction is not a valid transaction under UTAP: callers
 * must treat a failure here as failure of the operation and compensate.
 */
export async function auditAppend(
  env: Env,
  org: string,
  body: AuditEntryBody,
): Promise<DOResult<{ entry: AuditEntry }>> {
  const stub = env.AUDIT_DO.get(env.AUDIT_DO.idFromName(org));
  try {
    return await stub.append(org, body);
  } catch (e) {
    return { ok: false, code: "audit_failed", error: String(e) };
  }
}
