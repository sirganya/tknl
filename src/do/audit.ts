import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import type { AuditEntry, AuditEntryBody, Checkpoint, DOResult } from "../types";
import { err } from "../types";
import { concatBytes, hex, utf8 } from "../lib/encoding";
import { sha256 } from "../lib/crypto";
import { jcs } from "../lib/jcs";
import { merkleProof, merkleRoot, type ProofStep } from "../lib/merkle";

/**
 * AuditChainDO — one SEGMENT of an org's append-only, hash-chained ledger.
 *
 * A single DO per org caps the org's whole transaction rate, because audit
 * appends are synchronous and in the critical path of every value operation.
 * The chain is therefore sharded by time period: one DO per (org, UTC day),
 * addressed by `idFromName(org + ":" + period)`. The pre-sharding single DO
 * (addressed by org alone) is the "legacy" segment — still readable in place,
 * never copied. Sequence numbers are GLOBAL and monotonic across segments, and
 * the hash-chain format is unchanged:
 *
 *   entry_hash(n) = sha256( utf8(JCS(entry minus entry_hash)) || utf8(prev_hash(n)) )
 *   prev_hash(n)  = entry_hash(n-1); the org's very first entry uses the
 *                   fixed org-scoped genesis seed.
 *
 * ## Boundary protocol (chain continuity across segments)
 *
 * The critical invariant is that segment N's first entry links to segment
 * N-1's head with no fork at the period boundary. The predecessor's DO is the
 * single writer for its own head, so continuity is anchored there:
 *
 *  1. A segment's first append runs `initSegment` inside blockConcurrencyWhile
 *     (so concurrent first-appends cannot interleave the protocol).
 *  2. It asks the org's AuditDirectoryDO for the latest known segment.
 *     - none, and the legacy DO has entries → the predecessor is the legacy DO
 *     - none, legacy empty                  → chain starts at the genesis seed
 *     - some earlier segment                → that segment is the predecessor
 *  3. It calls `seal()` on the predecessor. Sealing is atomic in the
 *     predecessor (single writer): it rejects every later append with code
 *     "sealed" and returns its final {seq, head} — idempotently, so a crashed
 *     init can simply re-run. Only AFTER the predecessor is sealed does the
 *     new segment learn its base (prev hash + first seq) and accept appends;
 *     nothing can extend the predecessor afterwards, so a fork is impossible.
 *  4. It persists its init record, then registers the transition in the
 *     directory (`advance`, also idempotent). A "registered" flag makes a
 *     crash between those two steps self-healing on the next append.
 *
 * A Worker whose clock still says period P after P has been sealed gets the
 * "sealed" rejection and retries against the directory's latest segment (see
 * services/audit.ts) — appends never silently drop, and audit-before-effect
 * failure semantics are preserved for the caller.
 */
const SEQ_PAD = 12;

function entryKey(seq: number): string {
  return "e:" + seq.toString().padStart(SEQ_PAD, "0");
}

function checkpointKey(seq: number): string {
  return "cp:" + seq.toString().padStart(SEQ_PAD, "0");
}

export async function genesisHash(org: string): Promise<string> {
  return "sha256:" + hex(await sha256(utf8("utap.v0.1.audit-genesis:" + org)));
}

export async function computeEntryHash(entryWithoutHash: Omit<AuditEntry, "entry_hash">): Promise<string> {
  const digest = await sha256(
    concatBytes(utf8(jcs(entryWithoutHash)), utf8(entryWithoutHash.prev_hash)),
  );
  return "sha256:" + hex(digest);
}

interface SegmentInit {
  period: string;
  /** Last global seq before this segment (0 for the org's first segment). */
  baseSeq: number;
  /** Head hash this segment chains from (genesis seed for the first). */
  basePrev: string;
}

export class AuditChainDO extends DurableObject<Env> {
  /**
   * Append an entry. `period` is set by the routing service for sharded
   * segments; calls without it hit a legacy (pre-sharding) DO and keep the
   * original genesis-anchored behaviour until the DO is sealed.
   */
  async append(
    org: string,
    body: AuditEntryBody,
    period?: string,
  ): Promise<DOResult<{ entry: AuditEntry }>> {
    if (await this.ctx.storage.get<boolean>("sealed")) {
      return err("sealed", "segment is sealed; append to the active segment");
    }
    if (period !== undefined) {
      if ((await this.ctx.storage.get<SegmentInit>("init")) === undefined) {
        await this.ctx.blockConcurrencyWhile(() => this.initSegment(org, period));
        if ((await this.ctx.storage.get<SegmentInit>("init")) === undefined) {
          // A newer segment is already active (slow clock) — do not fork.
          return err("stale_period", `period ${period} is older than the active segment`);
        }
      } else if ((await this.ctx.storage.get<boolean>("registered")) !== true) {
        // Crash between init and directory registration — self-heal.
        await this.register(org);
      }
    }

    const storedOrg = await this.ctx.storage.get<string>("org");
    if (storedOrg === undefined) await this.ctx.storage.put("org", org);
    else if (storedOrg !== org) return err("org_mismatch", "audit chain belongs to a different org");

    const seq = ((await this.ctx.storage.get<number>("seq")) ?? 0) + 1;
    const prevHash = (await this.ctx.storage.get<string>("head")) ?? (await genesisHash(org));

    const withoutHash: Omit<AuditEntry, "entry_hash"> = {
      ...body,
      seq,
      ts: new Date().toISOString(),
      org,
      prev_hash: prevHash,
    };
    const entry: AuditEntry = { ...withoutHash, entry_hash: await computeEntryHash(withoutHash) };

    await this.ctx.storage.put(entryKey(seq), entry);
    await this.ctx.storage.put("seq", seq);
    await this.ctx.storage.put("head", entry.entry_hash);

    // D1 indexing is derived data — enqueue best-effort, never fail the append.
    try {
      await this.env.AUDIT_QUEUE.send({ type: "audit.index", entry });
    } catch (e) {
      console.error("audit fan-out enqueue failed", { org, seq, error: String(e) });
    }
    return { ok: true, entry };
  }

  /**
   * Seal this segment: no append will ever succeed again, so the returned
   * {seq, head} is final and a successor may safely chain from it. Idempotent.
   */
  async seal(): Promise<{ seq: number; head: string | null }> {
    await this.ctx.storage.put("sealed", true);
    return {
      seq: (await this.ctx.storage.get<number>("seq")) ?? 0,
      head: (await this.ctx.storage.get<string>("head")) ?? null,
    };
  }

  private async initSegment(org: string, period: string): Promise<void> {
    if ((await this.ctx.storage.get<SegmentInit>("init")) !== undefined) return;

    const dir = this.env.AUDIT_DIR.get(this.env.AUDIT_DIR.idFromName(org));
    const latest = await dir.latest();

    let basePrev: string;
    let baseSeq: number;
    let sealedRec: { period: string; lastSeq: number } | undefined;

    if (latest === null) {
      // First sharded segment for this org. The pre-sharding DO (if it has
      // history) becomes the read-only "legacy" segment, in place.
      const legacy = this.env.AUDIT_DO.get(this.env.AUDIT_DO.idFromName(org));
      const sealed = await legacy.seal();
      if (sealed.seq > 0 && sealed.head !== null) {
        basePrev = sealed.head;
        baseSeq = sealed.seq;
        sealedRec = { period: "legacy", lastSeq: sealed.seq };
      } else {
        basePrev = await genesisHash(org);
        baseSeq = 0;
      }
    } else if (latest.period !== period) {
      // Never seal a NEWER segment from a stale-clocked worker: that would
      // brick the active chain. Leave init unset; append reports stale_period
      // and the routing service retries against the directory's latest.
      const latestKey = latest.period === "legacy" ? "0000-00-00" : latest.period;
      if (latestKey > period) return;
      const name = latest.period === "legacy" ? org : `${org}:${latest.period}`;
      const predecessor = this.env.AUDIT_DO.get(this.env.AUDIT_DO.idFromName(name));
      const sealed = await predecessor.seal();
      basePrev = sealed.head ?? (await genesisHash(org));
      baseSeq = sealed.seq;
      sealedRec = { period: latest.period, lastSeq: sealed.seq };
    } else {
      // Directory already lists this period (lost storage would be the only
      // path here; recover a consistent base from the registration).
      basePrev = (await this.ctx.storage.get<string>("head")) ?? (await genesisHash(org));
      baseSeq = (await this.ctx.storage.get<number>("seq")) ?? latest.firstSeq - 1;
    }

    await this.ctx.storage.put<SegmentInit>("init", { period, baseSeq, basePrev });
    await this.ctx.storage.put("org", org);
    await this.ctx.storage.put("seq", baseSeq);
    await this.ctx.storage.put("head", basePrev);
    await this.ctx.storage.put("lastCheckpointSeq", baseSeq);
    if (sealedRec) await this.ctx.storage.put("sealedPredecessor", sealedRec);
    await this.register(org);
  }

  private async register(org: string): Promise<void> {
    const init = (await this.ctx.storage.get<SegmentInit>("init"))!;
    const sealedRec = await this.ctx.storage.get<{ period: string; lastSeq: number }>("sealedPredecessor");
    const dir = this.env.AUDIT_DIR.get(this.env.AUDIT_DIR.idFromName(org));
    await dir.advance({
      sealed: sealedRec,
      next: { period: init.period, firstSeq: init.baseSeq + 1 },
    });
    await this.ctx.storage.put("registered", true);
  }

  async head(): Promise<{ seq: number; head: string | null }> {
    return {
      seq: (await this.ctx.storage.get<number>("seq")) ?? 0,
      head: (await this.ctx.storage.get<string>("head")) ?? null,
    };
  }

  async getEntries(fromSeq: number, toSeq: number, limit = 500): Promise<AuditEntry[]> {
    const map = await this.ctx.storage.list<AuditEntry>({
      start: entryKey(Math.max(1, fromSeq)),
      end: entryKey(toSeq) + "￿",
      limit: Math.min(limit, 1000),
    });
    return [...map.values()];
  }

  /**
   * Checkpoint entries appended since the last checkpoint: Merkle root,
   * segment archived to R2 (key format `audit/{org}/{from}-{to}.json` with
   * GLOBAL seq ranges, unchanged from pre-sharding), root row inserted into
   * D1. The DO's own checkpoint record is committed last, so a failed
   * external write is retried on the next cron rather than leaving a gap.
   */
  async checkpoint(): Promise<DOResult<{ checkpoint: Checkpoint | null }>> {
    const org = await this.ctx.storage.get<string>("org");
    const seq = (await this.ctx.storage.get<number>("seq")) ?? 0;
    const lastCp = (await this.ctx.storage.get<number>("lastCheckpointSeq")) ?? 0;
    if (!org || seq <= lastCp) return { ok: true, checkpoint: null };

    const entries = await this.getEntries(lastCp + 1, seq, 1000);
    const covered = entries[entries.length - 1]!.seq;
    const root = await merkleRoot(entries.map((e) => e.entry_hash));
    const cp: Checkpoint = {
      org,
      from_seq: lastCp + 1,
      seq: covered,
      merkle_root: root,
      ts: new Date().toISOString(),
    };

    const segmentKey = `audit/${org}/${String(cp.from_seq).padStart(SEQ_PAD, "0")}-${String(cp.seq).padStart(SEQ_PAD, "0")}.json`;
    try {
      await this.env.AUDIT_ARCHIVE.put(segmentKey, JSON.stringify({ checkpoint: cp, entries }), {
        customMetadata: { org, merkle_root: root },
      });
      await this.env.DB.prepare(
        "INSERT OR REPLACE INTO checkpoints (org, seq, merkle_root, ts, anchor_ref) VALUES (?, ?, ?, ?, ?)",
      )
        .bind(org, cp.seq, cp.merkle_root, cp.ts, null)
        .run();
    } catch (e) {
      return err("archive_failed", `checkpoint external write failed: ${String(e)}`);
    }

    await this.ctx.storage.put(checkpointKey(cp.seq), cp);
    await this.ctx.storage.put("lastCheckpointSeq", cp.seq);
    return { ok: true, checkpoint: cp };
  }

  async getCheckpoints(): Promise<Checkpoint[]> {
    const map = await this.ctx.storage.list<Checkpoint>({ prefix: "cp:" });
    return [...map.values()];
  }

  /** Merkle inclusion proof for one entry against its covering checkpoint. */
  async proof(seq: number): Promise<
    DOResult<{ entry: AuditEntry; proof: ProofStep[]; checkpoint: Checkpoint }>
  > {
    const entry = await this.ctx.storage.get<AuditEntry>(entryKey(seq));
    if (!entry) return err("not_found", `no entry with seq ${seq}`);

    const checkpoints = await this.getCheckpoints();
    const cp = checkpoints.find((c) => c.from_seq <= seq && seq <= c.seq);
    if (!cp) return err("not_checkpointed", `entry ${seq} is not covered by a checkpoint yet`);

    const segment = await this.getEntries(cp.from_seq, cp.seq, 1000);
    const index = segment.findIndex((e) => e.seq === seq);
    const proof = await merkleProof(
      segment.map((e) => e.entry_hash),
      index,
    );
    return { ok: true, entry, proof, checkpoint: cp };
  }

  /**
   * Recompute this segment's chain. Returns the segment's base linkage too,
   * so services/audit.ts can verify head→prev continuity ACROSS segments.
   */
  async verifyChainIntegrity(): Promise<
    DOResult<{ seq: number; head: string | null; baseSeq: number; basePrev: string | null }>
  > {
    const org = await this.ctx.storage.get<string>("org");
    if (!org) return { ok: true, seq: 0, head: null, baseSeq: 0, basePrev: null };
    const init = await this.ctx.storage.get<SegmentInit>("init");
    const baseSeq = init?.baseSeq ?? 0;
    const basePrev = init?.basePrev ?? (await genesisHash(org));
    const seq = (await this.ctx.storage.get<number>("seq")) ?? baseSeq;

    let prev = basePrev;
    for (let s = baseSeq + 1; s <= seq; s++) {
      const entry = await this.ctx.storage.get<AuditEntry>(entryKey(s));
      if (!entry) return err("gap", `missing entry at seq ${s}`);
      if (entry.prev_hash !== prev) return err("broken_link", `prev_hash mismatch at seq ${s}`);
      const { entry_hash, ...withoutHash } = entry;
      if ((await computeEntryHash(withoutHash)) !== entry_hash) {
        return err("bad_hash", `entry_hash mismatch at seq ${s}`);
      }
      prev = entry_hash;
    }
    return { ok: true, seq, head: prev, baseSeq, basePrev };
  }
}
