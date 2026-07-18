import { beforeAll, describe, expect, it } from "vitest";
import type { DelegationCredential } from "../../src/types";
import { credentialSigningPayload, verifyChain, type PrincipalDirectory } from "../../src/lib/chain";
import { generateEd25519Jwk, SIG_CONTEXT, signJcs } from "../../src/lib/crypto";

const PERSON = "did:web:acme.example:person:gkavanagh";
const AGENT1 = "did:web:acme.example:agent:procure-01";
const AGENT2 = "did:web:acme.example:agent:procure-02";
const NOW = 1_750_000_000;

interface Actor {
  did: string;
  privateJwk: JsonWebKey;
  publicJwk: JsonWebKey;
}

const keys = new Map<string, JsonWebKey[]>();
const revoked = new Set<string>();
const dir: PrincipalDirectory = {
  getKeys: async (did) => keys.get(did) ?? [],
  isRevoked: async (_iss, jti) => revoked.has(jti),
};

let person: Actor, agent1: Actor, agent2: Actor;

async function actor(did: string): Promise<Actor> {
  const pair = await generateEd25519Jwk();
  keys.set(did, [pair.publicJwk]);
  return { did, ...pair };
}

async function credential(
  issuer: Actor,
  sub: string,
  jti: string,
  overrides: Partial<DelegationCredential["scope"]> = {},
  time: Partial<Pick<DelegationCredential, "nbf" | "exp">> = {},
): Promise<DelegationCredential> {
  const unsigned = {
    iss: issuer.did,
    sub,
    scope: {
      max_amount: "50000.00",
      ccy: "EUR",
      purposes: ["COMPUTE.*", "DATA.LICENSE"],
      budget_refs: ["bud_acme_eng_q3"],
      max_depth: 2,
      ...overrides,
    },
    nbf: time.nbf ?? NOW - 1000,
    exp: time.exp ?? NOW + 100_000,
    jti,
  };
  const sig = await signJcs(issuer.privateJwk, SIG_CONTEXT.delegation, unsigned);
  return { ...unsigned, sig };
}

const request = (over: Partial<Parameters<typeof verifyChain>[2]> = {}) => ({
  amountMinor: 4_000_000n, // 40000.00 EUR
  ccy: "EUR",
  purposeCode: "COMPUTE.INFERENCE",
  budgetRef: "bud_acme_eng_q3",
  agentDid: AGENT1,
  nowSeconds: NOW,
  ...over,
});

beforeAll(async () => {
  person = await actor(PERSON);
  agent1 = await actor(AGENT1);
  agent2 = await actor(AGENT2);
});

describe("delegation chain verification (UTAP §8)", () => {
  it("accepts a valid single-hop chain and reports the principal", async () => {
    const chain = [await credential(person, AGENT1, "dlg_ok1")];
    const verdict = await verifyChain(chain, dir, request());
    expect(verdict).toMatchObject({ ok: true, principal: PERSON, agent: AGENT1 });
  });

  it("accepts a two-hop chain and intersects scopes (most restrictive wins)", async () => {
    const chain = [
      await credential(person, AGENT1, "dlg_h1"),
      await credential(agent1, AGENT2, "dlg_h2", { max_amount: "10000.00", max_depth: 0 }),
    ];
    const ok = await verifyChain(chain, dir, request({ agentDid: AGENT2, amountMinor: 1_000_000n }));
    expect(ok.ok).toBe(true);
    if (ok.ok) expect(ok.effectiveMaxAmountMinor).toBe(1_000_000n);

    const tooMuch = await verifyChain(chain, dir, request({ agentDid: AGENT2, amountMinor: 2_000_000n }));
    expect(tooMuch).toMatchObject({ ok: false, code: "amount_exceeds_scope" });
  });

  it("rejects a chain whose root is not a human principal", async () => {
    const chain = [await credential(agent1, AGENT2, "dlg_rootagent")];
    expect(await verifyChain(chain, dir, request({ agentDid: AGENT2 }))).toMatchObject({
      ok: false,
      code: "root_not_person",
    });
  });

  it("rejects iss/sub discontinuity", async () => {
    const chain = [
      await credential(person, AGENT1, "dlg_c1"),
      await credential(agent2, AGENT1, "dlg_c2"), // iss != previous sub
    ];
    expect(await verifyChain(chain, dir, request())).toMatchObject({ ok: false, code: "chain_discontinuity" });
  });

  it("rejects tampered credentials", async () => {
    const cred = await credential(person, AGENT1, "dlg_tamper");
    const tampered = { ...cred, scope: { ...cred.scope, max_amount: "999999.00" } };
    expect(await verifyChain([tampered], dir, request())).toMatchObject({ ok: false, code: "bad_signature" });
  });

  it("checks time validity at the current time, per hop", async () => {
    const expired = [await credential(person, AGENT1, "dlg_exp", {}, { exp: NOW - 1 })];
    expect(await verifyChain(expired, dir, request())).toMatchObject({ ok: false, code: "expired" });
    const future = [await credential(person, AGENT1, "dlg_nbf", {}, { nbf: NOW + 50 })];
    expect(await verifyChain(future, dir, request())).toMatchObject({ ok: false, code: "not_yet_valid" });
  });

  it("rejects revoked credentials immediately", async () => {
    const cred = await credential(person, AGENT1, "dlg_revoked");
    revoked.add("dlg_revoked");
    expect(await verifyChain([cred], dir, request())).toMatchObject({ ok: false, code: "revoked" });
  });

  it("enforces max_depth from every hop", async () => {
    const chain = [
      await credential(person, AGENT1, "dlg_d1", { max_depth: 0 }),
      await credential(agent1, AGENT2, "dlg_d2"),
    ];
    expect(await verifyChain(chain, dir, request({ agentDid: AGENT2 }))).toMatchObject({
      ok: false,
      code: "depth_exceeded",
    });
  });

  it("enforces purpose and budget scope at every hop", async () => {
    const chain = [
      await credential(person, AGENT1, "dlg_p1"),
      await credential(agent1, AGENT2, "dlg_p2", { purposes: ["DATA.LICENSE"], max_depth: 0 }),
    ];
    expect(await verifyChain(chain, dir, request({ agentDid: AGENT2 }))).toMatchObject({
      ok: false,
      code: "purpose_not_allowed",
    });

    const budgetChain = [await credential(person, AGENT1, "dlg_b1", { budget_refs: ["bud_other"] })];
    expect(await verifyChain(budgetChain, dir, request())).toMatchObject({ ok: false, code: "budget_not_allowed" });
  });

  it("rejects a caller who is not the final delegate", async () => {
    const chain = [await credential(person, AGENT1, "dlg_who")];
    expect(await verifyChain(chain, dir, request({ agentDid: AGENT2 }))).toMatchObject({
      ok: false,
      code: "agent_mismatch",
    });
  });

  it("binds signatures to their domain-separation context", async () => {
    const cred = await credential(person, AGENT1, "dlg_ctx");
    const wrongContext = await signJcs(person.privateJwk, SIG_CONTEXT.token, credentialSigningPayload(cred));
    expect(await verifyChain([{ ...cred, sig: wrongContext }], dir, request())).toMatchObject({
      ok: false,
      code: "bad_signature",
    });
  });
});
