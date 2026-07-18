import { env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { api, authHeader, bootstrapAuth, makeActor, registerActor, signDelegation, type Actor } from "../helpers";
import { SIG_CONTEXT, verifyJcs } from "../../src/lib/crypto";
import { verifyMerkleProof } from "../../src/lib/merkle";
import type { AuditEntry, Token } from "../../src/types";

const ORG = "acme.example";
const PERSON = "did:web:acme.example:person:gkavanagh";
const AGENT = "did:web:acme.example:agent:procure-01";
const MERCHANT = "did:web:vendor.example";
const MERCHANT2 = "did:web:othervendor.example";

let person: Actor, agent: Actor, merchant: Actor, merchant2: Actor;

const now = () => Math.floor(Date.now() / 1000);

function mintBody(over: Record<string, unknown> = {}, chain?: unknown) {
  return {
    amount: { value: "40000.00", ccy: "EUR" },
    purpose: {
      code: "COMPUTE.INFERENCE",
      desc: "GPU inference, batch job 8817",
      constraints: { merchant_allow: [MERCHANT], mcc_allow: ["7372"] },
    },
    budget_ref: "bud_acme_eng_q3",
    chain,
    ttl_seconds: 3600,
    ...over,
  };
}

let rootDelegation: Awaited<ReturnType<typeof signDelegation>>;

beforeAll(async () => {
  person = await makeActor(PERSON);
  agent = await makeActor(AGENT);
  merchant = await makeActor(MERCHANT);
  merchant2 = await makeActor(MERCHANT2);
  for (const a of [person, agent, merchant, merchant2]) await registerActor(a);

  const year = new Date().getFullYear();
  const period = { start: `${year}-01-01`, end: `${year + 1}-12-31` };
  const root = await api("/v1/budgets/bud_acme", {
    method: "PUT",
    auth: bootstrapAuth(),
    body: { org: ORG, limit: "500000.00", ccy: "EUR", period },
  });
  expect(root.status).toBe(201);
  const leaf = await api("/v1/budgets/bud_acme_eng_q3", {
    method: "PUT",
    auth: bootstrapAuth(),
    body: {
      org: ORG,
      parent: "bud_acme",
      limit: "250000.00",
      ccy: "EUR",
      period,
      policy: { purposes_allow: ["COMPUTE.*"], per_txn_max: "50000.00" },
    },
  });
  expect(leaf.status).toBe(201);

  rootDelegation = await signDelegation(person, {
    iss: PERSON,
    sub: AGENT,
    scope: {
      max_amount: "50000.00",
      ccy: "EUR",
      purposes: ["COMPUTE.*", "DATA.LICENSE"],
      budget_refs: ["bud_acme_eng_q3", "bud_acme_ml"],
      max_depth: 2,
    },
    nbf: now() - 60,
    exp: now() + 86_400,
    jti: "dlg_root_1",
  });
  const issued = await api("/v1/delegations", {
    auth: person,
    body: { credential: rootDelegation },
  });
  expect(issued.status).toBe(201);
});

describe("UTAP CFP end-to-end", () => {
  it("runs the full mint → reserve → redeem lifecycle with a verifiable audit trail", async () => {
    // -- mint ---------------------------------------------------------------
    const minted = await api("/v1/tokens", { auth: agent, body: mintBody({}, [rootDelegation]) });
    expect(minted.status, JSON.stringify(minted.body)).toBe(201);
    const token: Token = minted.body.token;
    expect(token.state).toBe("issued");
    expect(token.principal).toBe(PERSON);
    expect(minted.body.uri_query).toContain(`utap_tid=${token.tid}`);

    // Token signature verifies against the CFP's published JWKS.
    const jwks = await api("/.well-known/jwks.json");
    const { sig, ...unsigned } = token;
    expect(await verifyJcs(jwks.body.keys[0], SIG_CONTEXT.token, unsigned, sig!)).toBe(true);

    // Budget shows the hierarchical reservation at leaf and root.
    const leafBudget = await api("/v1/budgets/bud_acme_eng_q3", { auth: person });
    expect(leafBudget.body.budget.reserved).toBe("40000.00");
    const rootBudget = await api("/v1/budgets/bud_acme", { auth: person });
    expect(rootBudget.body.budget.reserved).toBe("40000.00");

    // -- reserve (merchant hold, anti-replay binding) -----------------------
    const wrongMerchant = await api(`/v1/tokens/${token.tid}/reserve`, { auth: merchant2, body: {} });
    expect(wrongMerchant.status).toBe(403); // not on the purpose allow-list

    const reserved = await api(`/v1/tokens/${token.tid}/reserve`, { auth: merchant, body: {} });
    expect(reserved.status, JSON.stringify(reserved.body)).toBe(200);
    expect(reserved.body.token.state).toBe("reserved");

    const replay = await api(`/v1/tokens/${token.tid}/reserve`, { auth: merchant, body: {} });
    expect(replay.status).toBe(200); // same-merchant retry is idempotent

    // -- redeem -------------------------------------------------------------
    const badMcc = await api(`/v1/tokens/${token.tid}/redeem`, { auth: merchant, body: { mcc: "9999" } });
    expect(badMcc.status).toBe(400);

    const redeemed = await api(`/v1/tokens/${token.tid}/redeem`, { auth: merchant, body: { mcc: "7372" } });
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
    expect(redeemed.body.token.state).toBe("redeemed");
    expect(redeemed.body.budget_after).toBe("210000.00"); // 250000 - 40000

    // Double-spend: a second redeem is rejected by the state machine.
    const doubleSpend = await api(`/v1/tokens/${token.tid}/redeem`, { auth: merchant, body: { mcc: "7372" } });
    expect(doubleSpend.status).toBe(409);
    expect(doubleSpend.body.error.code).toBe("invalid_transition");

    const spent = await api("/v1/budgets/bud_acme_eng_q3", { auth: person });
    expect(spent.body.budget.spent).toBe("40000.00");
    expect(spent.body.budget.reserved).toBe("0.00");

    // -- audit chain --------------------------------------------------------
    const audit = await api(`/v1/audit/${ORG}/entries`, { auth: person });
    const events = (audit.body.entries as AuditEntry[]).map((e) => e.event);
    for (const expected of ["TOKEN_ISSUED", "TOKEN_RESERVED", "TOKEN_REDEEMED", "DELEGATION_ISSUED"]) {
      expect(events).toContain(expected);
    }
    // Hash chain recomputes end to end inside the DO.
    const integrity = await env.AUDIT_DO.get(env.AUDIT_DO.idFromName(ORG)).verifyChainIntegrity();
    expect(integrity).toMatchObject({ ok: true });

    // -- checkpoint + public inclusion proof --------------------------------
    const checkpoint = await env.AUDIT_DO.get(env.AUDIT_DO.idFromName(ORG)).checkpoint();
    expect(checkpoint.ok && checkpoint.checkpoint).toBeTruthy();

    const redeemEntry = (audit.body.entries as AuditEntry[]).find((e) => e.event === "TOKEN_REDEEMED")!;
    const proof = await api(`/v1/audit/${ORG}/proof/${redeemEntry.seq}`); // no auth: proofs are public
    expect(proof.status).toBe(200);
    expect(
      await verifyMerkleProof(proof.body.entry.entry_hash, proof.body.proof, proof.body.checkpoint.merkle_root),
    ).toBe(true);

    // The R2 archive object exists and matches the checkpoint root.
    const cp = proof.body.checkpoint;
    const key = `audit/${ORG}/${String(cp.from_seq).padStart(12, "0")}-${String(cp.seq).padStart(12, "0")}.json`;
    const archived = await env.AUDIT_ARCHIVE.get(key);
    expect(archived).not.toBeNull();
    expect(JSON.parse(await archived!.text()).checkpoint.merkle_root).toBe(cp.merkle_root);
  });

  it("serialises concurrent redeem attempts: exactly one wins", async () => {
    const minted = await api("/v1/tokens", { auth: agent, body: mintBody({}, [rootDelegation]) });
    expect(minted.status).toBe(201);
    const tid = minted.body.token.tid;
    const reserved = await api(`/v1/tokens/${tid}/reserve`, { auth: merchant, body: {} });
    expect(reserved.status).toBe(200);

    const attempts = await Promise.all(
      Array.from({ length: 5 }, () => api(`/v1/tokens/${tid}/redeem`, { auth: merchant, body: { mcc: "7372" } })),
    );
    expect(attempts.filter((a) => a.status === 200)).toHaveLength(1);
    expect(attempts.filter((a) => a.status === 409)).toHaveLength(4);
  });

  it("replays idempotent mints instead of re-executing them", async () => {
    const key = crypto.randomUUID();
    const body = mintBody({}, [rootDelegation]);
    const first = await api("/v1/tokens", { auth: agent, body, idempotencyKey: key });
    const second = await api("/v1/tokens", { auth: agent, body, idempotencyKey: key });
    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
    expect(second.body.token.tid).toBe(first.body.token.tid);

    // Same key, different payload → rejected.
    const mismatch = await api("/v1/tokens", {
      auth: agent,
      body: mintBody({ amount: { value: "1.00", ccy: "EUR" } }, [rootDelegation]),
      idempotencyKey: key,
    });
    expect(mismatch.status).toBe(422);

    // Clean up the two extra reservations for later budget assertions.
    for (const tid of [first.body.token.tid]) {
      const voided = await api(`/v1/tokens/${tid}/void`, { auth: person, body: {} });
      expect(voided.status).toBe(200);
    }
  });

  it("voids unredeemed tokens and releases the reservation walk", async () => {
    const minted = await api("/v1/tokens", { auth: agent, body: mintBody({}, [rootDelegation]) });
    expect(minted.status).toBe(201);
    const tid = minted.body.token.tid;

    const before = await api("/v1/budgets/bud_acme_eng_q3", { auth: person });
    const notAllowed = await api(`/v1/tokens/${tid}/void`, { auth: merchant, body: {} });
    expect(notAllowed.status).toBe(403); // merchants are not in the chain

    const voided = await api(`/v1/tokens/${tid}/void`, { auth: person, body: {} });
    expect(voided.status).toBe(200);
    expect(voided.body.token.state).toBe("void");

    const after = await api("/v1/budgets/bud_acme_eng_q3", { auth: person });
    const toCents = (v: string) => Math.round(Number(v) * 100);
    expect(toCents(after.body.budget.reserved)).toBe(toCents(before.body.budget.reserved) - 4_000_000);

    const reserveVoided = await api(`/v1/tokens/${tid}/reserve`, { auth: merchant, body: {} });
    expect(reserveVoided.status).toBe(409);
  });

  it("enforces delegation scope and revocation at mint", async () => {
    const overScope = await api("/v1/tokens", {
      auth: agent,
      body: mintBody({ amount: { value: "60000.00", ccy: "EUR" } }, [rootDelegation]),
    });
    expect(overScope.status).toBe(403);
    expect(overScope.body.error.code).toBe("amount_exceeds_scope");

    const wrongPurpose = await api("/v1/tokens", {
      auth: agent,
      body: mintBody(
        { purpose: { code: "TRAVEL.FLIGHTS", constraints: { merchant_allow: [MERCHANT] } } },
        [rootDelegation],
      ),
    });
    expect(wrongPurpose.status).toBe(403);

    // Sub-delegation to a second agent, then revoke it: the mint must fail.
    const agent2 = await makeActor("did:web:acme.example:agent:procure-02");
    await registerActor(agent2);
    const sub = await signDelegation(agent, {
      iss: AGENT,
      sub: agent2.did,
      scope: { max_amount: "20000.00", ccy: "EUR", purposes: ["COMPUTE.*"], budget_refs: ["bud_acme_eng_q3"], max_depth: 0 },
      nbf: now() - 60,
      exp: now() + 86_400,
      jti: "dlg_sub_1",
      parent_jti: "dlg_root_1",
    });
    const issued = await api("/v1/delegations", { auth: agent, body: { credential: sub } });
    expect(issued.status).toBe(201);

    const chainView = await api("/v1/delegations/dlg_sub_1/chain", { auth: person });
    expect(chainView.body.valid).toBe(true);
    expect(chainView.body.principal).toBe(PERSON);

    const okMint = await api("/v1/tokens", {
      auth: agent2,
      body: mintBody({ amount: { value: "1000.00", ccy: "EUR" } }, [rootDelegation, sub]),
    });
    expect(okMint.status, JSON.stringify(okMint.body)).toBe(201);
    await api(`/v1/tokens/${okMint.body.token.tid}/void`, { auth: person, body: {} });

    const revoked = await api("/v1/delegations/dlg_sub_1", { method: "DELETE", auth: person });
    expect(revoked.status).toBe(200);

    const afterRevoke = await api("/v1/tokens", {
      auth: agent2,
      body: mintBody({ amount: { value: "1000.00", ccy: "EUR" } }, [rootDelegation, sub]),
    });
    expect(afterRevoke.status).toBe(403);
    expect(afterRevoke.body.error.code).toBe("revoked");
  });

  it("gates above-threshold spends on a human approval credential", async () => {
    const year = new Date().getFullYear();
    const created = await api("/v1/budgets/bud_acme_ml", {
      method: "PUT",
      auth: bootstrapAuth(),
      body: {
        org: ORG,
        parent: "bud_acme",
        limit: "100000.00",
        ccy: "EUR",
        period: { start: `${year}-01-01`, end: `${year + 1}-12-31` },
        policy: { requires_human_approval_above: "25000.00" },
      },
    });
    expect(created.status).toBe(201);

    const pending = await api("/v1/tokens", {
      auth: agent,
      body: mintBody({ amount: { value: "30000.00", ccy: "EUR" }, budget_ref: "bud_acme_ml" }, [rootDelegation]),
    });
    expect(pending.status).toBe(202);
    const approvalId = pending.body.approval_id as string;

    // An agent-signed approval must be rejected — only the principal's key counts.
    const forged = { approval_id: approvalId, decision: "approve", nonce: crypto.randomUUID() };
    const { signJcs } = await import("../../src/lib/crypto");
    const forgedSig = await signJcs(agent.privateJwk, SIG_CONTEXT.approval, forged);
    const rejected = await api(`/v1/approvals/${approvalId}`, {
      auth: agent,
      body: { approval: forged, sig: forgedSig },
    });
    expect(rejected.status).toBe(403);

    const approval = { approval_id: approvalId, decision: "approve", nonce: crypto.randomUUID() };
    const sig = await signJcs(person.privateJwk, SIG_CONTEXT.approval, approval);
    const approved = await api(`/v1/approvals/${approvalId}`, {
      auth: agent,
      body: { approval, sig },
    });
    expect(approved.status, JSON.stringify(approved.body)).toBe(201);
    expect(approved.body.token.amt.value).toBe("30000.00");
    await api(`/v1/tokens/${approved.body.token.tid}/void`, { auth: person, body: {} });
  });

  it("refuses to mint unbound bearer tokens unless explicitly requested", async () => {
    const noAllowList = await api("/v1/tokens", {
      auth: agent,
      body: mintBody({ purpose: { code: "COMPUTE.INFERENCE" } }, [rootDelegation]),
    });
    expect(noAllowList.status).toBe(400);
    expect(noAllowList.body.error.code).toBe("unbound_token");

    const deliberate = await api("/v1/tokens", {
      auth: agent,
      body: mintBody({ purpose: { code: "COMPUTE.INFERENCE" }, allow_unbound: true }, [rootDelegation]),
    });
    expect(deliberate.status, JSON.stringify(deliberate.body)).toBe(201);
    await api(`/v1/tokens/${deliberate.body.token.tid}/void`, { auth: person, body: {} });
  });

  it("rejects replayed auth credentials (single-use nonce)", async () => {
    const header = await authHeader(person);
    const first = await api("/v1/budgets/bud_acme", { auth: header });
    expect(first.status).toBe(200);
    const replayed = await api("/v1/budgets/bud_acme", { auth: header });
    expect(replayed.status).toBe(401);
  });

  it("keeps token state private without authorisation", async () => {
    const minted = await api("/v1/tokens", { auth: agent, body: mintBody({}, [rootDelegation]) });
    const tid = minted.body.token.tid;
    expect((await api(`/v1/tokens/${tid}`)).status).toBe(401);
    expect((await api(`/v1/tokens/${tid}`, { auth: merchant2 })).status).toBe(403);
    expect((await api(`/v1/tokens/${tid}`, { auth: merchant })).status).toBe(200); // on allow-list
    expect((await api(`/v1/tokens/${tid}`, { auth: person })).status).toBe(200); // chain participant
    await api(`/v1/tokens/${tid}/void`, { auth: person, body: {} });
  });
});
