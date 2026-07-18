#!/usr/bin/env node
// Generate an Ed25519 JWK for use as CFP_SIGNING_KEY (or any actor key).
import { webcrypto } from "node:crypto";

const kid = process.argv[2] ?? "cfp-" + new Date().toISOString().slice(0, 10);
const pair = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const priv = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
const jwk = { kty: priv.kty, crv: priv.crv, d: priv.d, x: priv.x, kid };

console.log("# Private JWK (keep secret — set as CFP_SIGNING_KEY):");
console.log(JSON.stringify(jwk));
console.log("\n# Public JWK (publishable):");
console.log(JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, kid, alg: "EdDSA", use: "sig" }));
console.log("\n# .dev.vars line:");
console.log(`CFP_SIGNING_KEY=${JSON.stringify(JSON.stringify(jwk))}`);
