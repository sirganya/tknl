import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { AuditEntry, AuditEntryBody } from "../../src/types";
import { computeEntryHash } from "../../src/do/audit";
import { verifyMerkleProof } from "../../src/lib/merkle";
import {
  auditAppend,
  checkpointOrg,
  getOrgEntries,
  getOrgHead,
  verifyOrgChain,
} from "../../src/services/audit";
import { api } from "../helpers";

const body = (n: number): AuditEntryBody => ({ event: "TOKEN_ISSUED", detail: `entry ${n}` });
const entryKey = (seq: number) => "e:" + seq.toString().padStart(12, "0");

function segment(org: string, period: string) {
  return env.AUDIT_DO.get(env.AUDIT_DO.idFromName(`${org}:${period}`));
}

describe("audit chain sharding by (org, period)", () => {
  it("chains appends across a period boundary with global seqs and a sealed predecessor", async () => {
    const org = "shard-a.example";
    await auditAppend(env, org, body(1), "2026-01-01");
    await auditAppend(env, org, body(2), "2026-01-01");
    const third = await auditAppend(env, org, body(3), "2026-01-02");
    expect(third.ok).toBe(true);
    if (!third.ok) return;
    expect(third.entry.seq).toBe(3);

    // Segment 2's first entry links to segment 1's (now-final) head.
    const head1 = await segment(org, "2026-01-01").head();
    expect(head1.seq).toBe(2);
    expect(third.entry.prev_hash).toBe(head1.head);

    // The predecessor is sealed: direct appends can never fork it.
    const lateAppend = await segment(org, "2026-01-01").append(org, body(9), "2026-01-01");
    expect(lateAppend).toMatchObject({ ok: false, code: "sealed" });

    // A slow-clocked worker's append (old period) is rerouted, not dropped.
    const rerouted = await auditAppend(env, org, body(4), "2026-01-01");
    expect(rerouted.ok).toBe(true);
    if (rerouted.ok) expect(rerouted.entry.seq).toBe(4);

    const verdict = await verifyOrgChain(env, org);
    expect(verdict).toMatchObject({ ok: true, seq: 4, segments: 2 });

    const entries = await getOrgEntries(env, org, 1, 10);
    expect(entries.map((e) => e.seq)).toEqual([1, 2, 3, 4]);
    expect((await getOrgHead(env, org)).seq).toBe(4);
  });

  it("treats a pre-sharding chain as the legacy segment and serves proofs from older segments", async () => {
    const org = "shard-b.example";
    // Simulate pre-migration history: direct appends to the org-addressed DO.
    const legacy = env.AUDIT_DO.get(env.AUDIT_DO.idFromName(org));
    await legacy.append(org, body(1));
    await legacy.append(org, body(2));

    // First sharded append seals the legacy DO in place — no data copied.
    const post = await auditAppend(env, org, body(3), "2026-02-01");
    expect(post.ok).toBe(true);
    if (post.ok) expect(post.entry.seq).toBe(3);
    expect(await legacy.append(org, body(9))).toMatchObject({ ok: false, code: "sealed" });

    const verdict = await verifyOrgChain(env, org);
    expect(verdict).toMatchObject({ ok: true, seq: 3, segments: 2 });

    // Checkpoints cover both the legacy segment (1-2) and the active one (3).
    const cps = await checkpointOrg(env, org);
    expect(cps.ok).toBe(true);
    expect(cps.checkpoints.map((c) => [c.from_seq, c.seq])).toEqual([
      [1, 2],
      [3, 3],
    ]);

    // Proof retrieval for an entry in the older (legacy) segment, via the
    // public endpoint — routed by global seq.
    const proof = await api(`/v1/audit/${org}/proof/1`);
    expect(proof.status).toBe(200);
    expect(
      await verifyMerkleProof(proof.body.entry.entry_hash, proof.body.proof, proof.body.checkpoint.merkle_root),
    ).toBe(true);
  });

  it("detects tampering inside a segment and a broken link between segments", async () => {
    const org = "shard-c.example";
    await auditAppend(env, org, body(1), "2026-03-01");
    await auditAppend(env, org, body(2), "2026-03-02");
    expect(await verifyOrgChain(env, org)).toMatchObject({ ok: true, seq: 2 });

    // Tamper with an archived entry's payload → hash recomputation fails.
    await runInDurableObject(segment(org, "2026-03-01"), async (_instance, state) => {
      const entry = (await state.storage.get<AuditEntry>(entryKey(1)))!;
      await state.storage.put(entryKey(1), { ...entry, detail: "tampered" });
    });
    expect(await verifyOrgChain(env, org)).toMatchObject({ ok: false, code: "bad_hash" });
    await runInDurableObject(segment(org, "2026-03-01"), async (_instance, state) => {
      const entry = (await state.storage.get<AuditEntry>(entryKey(1)))!;
      await state.storage.put(entryKey(1), { ...entry, detail: "entry 1" });
    });
    expect(await verifyOrgChain(env, org)).toMatchObject({ ok: true });

    // Rewrite segment 2 to chain from a forged head, internally consistent —
    // only the cross-segment linkage check can catch this.
    await runInDurableObject(segment(org, "2026-03-02"), async (_instance, state) => {
      const init = (await state.storage.get<{ period: string; baseSeq: number; basePrev: string }>("init"))!;
      const forged = "sha256:" + "0".repeat(64);
      const entry = (await state.storage.get<AuditEntry>(entryKey(init.baseSeq + 1)))!;
      const { entry_hash: _oldHash, ...rest } = entry;
      const rewritten = { ...rest, prev_hash: forged };
      const rehashed: AuditEntry = { ...rewritten, entry_hash: await computeEntryHash(rewritten) };
      await state.storage.put(entryKey(init.baseSeq + 1), rehashed);
      await state.storage.put("init", { ...init, basePrev: forged });
      await state.storage.put("head", rehashed.entry_hash);
    });
    expect(await verifyOrgChain(env, org)).toMatchObject({ ok: false, code: "broken_segment_link" });
  });
});
