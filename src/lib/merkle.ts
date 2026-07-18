import { concatBytes, hex, utf8 } from "./encoding";
import { sha256 } from "./crypto";

/**
 * Merkle tree over audit entry hashes for checkpointing and inclusion proofs.
 *
 * Leaves are the utf8 bytes of the "sha256:<hex>" entry_hash strings, hashed
 * once (leaf = SHA-256(0x00 || entry_hash)); interior nodes are
 * SHA-256(0x01 || left || right). Domain-separating leaf and node hashes
 * prevents second-preimage tree-collision attacks. An unpaired node is
 * promoted to the next level unchanged (no duplication).
 */
const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

async function leafHash(entryHash: string): Promise<Uint8Array> {
  return sha256(concatBytes(LEAF_PREFIX, utf8(entryHash)));
}

async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes(NODE_PREFIX, left, right));
}

export interface ProofStep {
  side: "left" | "right";
  hash: string; // hex of sibling node
}

export async function merkleRoot(entryHashes: string[]): Promise<string> {
  if (entryHashes.length === 0) throw new Error("merkle: empty leaf set");
  let level = await Promise.all(entryHashes.map(leafHash));
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) next.push(await nodeHash(level[i]!, level[i + 1]!));
      else next.push(level[i]!);
    }
    level = next;
  }
  return "merkle-sha256:" + hex(level[0]!);
}

/** Inclusion proof for the leaf at `index` in `entryHashes`. */
export async function merkleProof(entryHashes: string[], index: number): Promise<ProofStep[]> {
  if (index < 0 || index >= entryHashes.length) throw new Error("merkle: index out of range");
  let level = await Promise.all(entryHashes.map(leafHash));
  let idx = index;
  const proof: ProofStep[] = [];
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        if (i === idx || i + 1 === idx) {
          const siblingIdx = i === idx ? i + 1 : i;
          proof.push({
            side: siblingIdx < idx ? "left" : "right",
            hash: hex(level[siblingIdx]!),
          });
        }
        next.push(await nodeHash(level[i]!, level[i + 1]!));
      } else {
        next.push(level[i]!);
      }
      if (i === idx || i + 1 === idx) idx = next.length - 1;
    }
    level = next;
  }
  return proof;
}

/** Verify an inclusion proof produced by merkleProof. */
export async function verifyMerkleProof(
  entryHash: string,
  proof: ProofStep[],
  root: string,
): Promise<boolean> {
  let node = await leafHash(entryHash);
  for (const step of proof) {
    const sibling = hexToBytes(step.hash);
    node = step.side === "left" ? await nodeHash(sibling, node) : await nodeHash(node, sibling);
  }
  return "merkle-sha256:" + hex(node) === root;
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
