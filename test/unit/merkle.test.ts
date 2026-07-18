import { describe, expect, it } from "vitest";
import { merkleProof, merkleRoot, verifyMerkleProof } from "../../src/lib/merkle";

const leaves = (n: number) => Array.from({ length: n }, (_, i) => `sha256:${"0".repeat(60)}${i.toString().padStart(4, "0")}`);

describe("merkle tree over audit entry hashes", () => {
  it("produces stable roots", async () => {
    const set = leaves(5);
    expect(await merkleRoot(set)).toBe(await merkleRoot([...set]));
    expect(await merkleRoot(set)).not.toBe(await merkleRoot(leaves(4)));
  });

  it("verifies inclusion proofs for every leaf, odd and even sizes", async () => {
    for (const n of [1, 2, 3, 7, 8, 13]) {
      const set = leaves(n);
      const root = await merkleRoot(set);
      for (let i = 0; i < n; i++) {
        const proof = await merkleProof(set, i);
        expect(await verifyMerkleProof(set[i]!, proof, root), `n=${n} i=${i}`).toBe(true);
      }
    }
  });

  it("rejects proofs for tampered leaves", async () => {
    const set = leaves(6);
    const root = await merkleRoot(set);
    const proof = await merkleProof(set, 2);
    expect(await verifyMerkleProof(set[3]!, proof, root)).toBe(false);
    expect(await verifyMerkleProof("sha256:" + "f".repeat(64), proof, root)).toBe(false);
  });
});
