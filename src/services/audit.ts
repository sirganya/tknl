import type { Env } from "../env";
import type { AuditEntry, AuditEntryBody, Checkpoint, DOResult } from "../types";
import { err } from "../types";
import { genesisHash } from "../do/audit";
import type { SegmentRecord } from "../do/auditDirectory";
import type { ProofStep } from "../lib/merkle";

/**
 * Routing layer over the sharded audit chain (see AuditChainDO for the
 * sharding design and boundary protocol).
 *
 * Appends go to the clock-derived active segment `org:YYYY-MM-DD` — no
 * directory lookup on the hot path. Reads fan out across segments via the
 * per-org AuditDirectoryDO. The pre-sharding single DO (addressed by org
 * alone) is surfaced as the "legacy" segment without copying any data.
 */
export function utcPeriod(nowMs = Date.now()): string {
  return new Date(nowMs).toISOString().slice(0, 10);
}

function segmentName(org: string, period: string): string {
  return period === "legacy" ? org : `${org}:${period}`;
}

function segmentStub(env: Env, org: string, period: string) {
  return env.AUDIT_DO.get(env.AUDIT_DO.idFromName(segmentName(org, period)));
}

function directoryStub(env: Env, org: string) {
  return env.AUDIT_DIR.get(env.AUDIT_DIR.idFromName(org));
}

/**
 * Synchronous audit append — in the critical path of every value operation.
 * An unauditable transaction is not a valid transaction under UTAP: callers
 * must treat a failure here as failure of the operation and compensate.
 *
 * `period` is injectable for boundary tests; production callers omit it.
 * If the clock-derived segment has been sealed (period boundary race) the
 * append retries once against the directory's latest segment.
 */
export async function auditAppend(
  env: Env,
  org: string,
  body: AuditEntryBody,
  period?: string,
): Promise<DOResult<{ entry: AuditEntry }>> {
  const p = period ?? utcPeriod();
  try {
    let result = await segmentStub(env, org, p).append(org, body, p);
    if (!result.ok && (result.code === "sealed" || result.code === "stale_period")) {
      const latest = await directoryStub(env, org).latest();
      if (latest && latest.period !== p && latest.period !== "legacy") {
        result = await segmentStub(env, org, latest.period).append(org, body, latest.period);
      }
    }
    return result;
  } catch (e) {
    return { ok: false, code: "audit_failed", error: String(e) };
  }
}

/** All segments in chain order; falls back to the legacy DO when the org has
 * never crossed into sharded operation. */
export async function listSegments(env: Env, org: string): Promise<SegmentRecord[]> {
  const records = await directoryStub(env, org).list();
  if (records.length > 0) return records;
  const legacyHead = await segmentStub(env, org, "legacy").head();
  if (legacyHead.seq > 0) return [{ period: "legacy", firstSeq: 1 }];
  return [];
}

/** Live end of a segment: the directory's sealed lastSeq, else the DO's head. */
async function segmentLastSeq(env: Env, org: string, rec: SegmentRecord): Promise<number> {
  if (rec.lastSeq !== undefined) return rec.lastSeq;
  return (await segmentStub(env, org, rec.period).head()).seq;
}

export async function getOrgHead(env: Env, org: string): Promise<{ seq: number; head: string | null }> {
  const segments = await listSegments(env, org);
  if (segments.length === 0) return { seq: 0, head: null };
  return segmentStub(env, org, segments[segments.length - 1]!.period).head();
}

export async function getOrgEntries(
  env: Env,
  org: string,
  fromSeq: number,
  toSeq: number,
): Promise<AuditEntry[]> {
  const segments = await listSegments(env, org);
  const out: AuditEntry[] = [];
  for (const rec of segments) {
    const last = await segmentLastSeq(env, org, rec);
    if (last < rec.firstSeq) continue; // sealed-empty segment
    const from = Math.max(fromSeq, rec.firstSeq);
    const to = Math.min(toSeq, last);
    if (to < from) continue;
    out.push(...(await segmentStub(env, org, rec.period).getEntries(from, to)));
  }
  return out;
}

export async function getOrgCheckpoints(env: Env, org: string): Promise<Checkpoint[]> {
  const segments = await listSegments(env, org);
  const out: Checkpoint[] = [];
  for (const rec of segments) {
    out.push(...(await segmentStub(env, org, rec.period).getCheckpoints()));
  }
  return out;
}

export async function getOrgProof(
  env: Env,
  org: string,
  seq: number,
): Promise<DOResult<{ entry: AuditEntry; proof: ProofStep[]; checkpoint: Checkpoint }>> {
  const segments = await listSegments(env, org);
  for (const rec of segments) {
    if (seq < rec.firstSeq) break;
    const last = await segmentLastSeq(env, org, rec);
    if (seq <= last) return segmentStub(env, org, rec.period).proof(seq);
  }
  return err("not_found", `no entry with seq ${seq}`);
}

/** Checkpoint every segment with uncheckpointed entries (hourly cron). The
 * segment list grows one per active day, so iterating it stays cheap; sealed,
 * fully-checkpointed segments return immediately. */
export async function checkpointOrg(
  env: Env,
  org: string,
): Promise<{ ok: boolean; checkpoints: Checkpoint[]; errors: string[] }> {
  const segments = await listSegments(env, org);
  const checkpoints: Checkpoint[] = [];
  const errors: string[] = [];
  for (const rec of segments) {
    const result = await segmentStub(env, org, rec.period).checkpoint();
    if (!result.ok) errors.push(`${rec.period}: ${result.error}`);
    else if (result.checkpoint) checkpoints.push(result.checkpoint);
  }
  return { ok: errors.length === 0, checkpoints, errors };
}

/**
 * Full-chain verification: each segment recomputes its own hashes, and the
 * seams are checked — segment N must chain from segment N-1's verified head
 * (genesis seed before the very first), with globally contiguous seqs.
 */
export async function verifyOrgChain(
  env: Env,
  org: string,
): Promise<DOResult<{ seq: number; head: string | null; segments: number }>> {
  const segments = await listSegments(env, org);
  if (segments.length === 0) return { ok: true, seq: 0, head: null, segments: 0 };

  let expectedPrev = await genesisHash(org);
  let expectedBaseSeq = 0;
  let head: string | null = null;

  for (const rec of segments) {
    const result = await segmentStub(env, org, rec.period).verifyChainIntegrity();
    if (!result.ok) return err(result.code, `segment ${rec.period}: ${result.error}`);
    if (result.baseSeq !== expectedBaseSeq) {
      return err(
        "seq_discontinuity",
        `segment ${rec.period} starts after seq ${result.baseSeq}, expected ${expectedBaseSeq}`,
      );
    }
    if (result.basePrev !== null && result.basePrev !== expectedPrev) {
      return err("broken_segment_link", `segment ${rec.period} does not chain from its predecessor's head`);
    }
    expectedBaseSeq = result.seq;
    expectedPrev = result.head ?? expectedPrev;
    head = result.head ?? head;
  }
  return { ok: true, seq: expectedBaseSeq, head, segments: segments.length };
}
