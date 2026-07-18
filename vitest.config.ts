import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config";

// Test-only CFP signing key. Never use outside tests.
const TEST_CFP_SIGNING_KEY = JSON.stringify({
  kty: "OKP",
  crv: "Ed25519",
  d: "jB8H1yJM348Cs8ygpoPv9PKGKkOHZ-LHO8Ff86LDC9Q",
  x: "JNhOhV-v9ZyR5qtvxp6QT1eLRJkIQwCkimxXtyTQgY0",
  kid: "cfp-test-1",
});

export default defineWorkersConfig(async () => {
  const migrations = await readD1Migrations("migrations");
  return {
    test: {
      setupFiles: ["./test/apply-migrations.ts"],
      poolOptions: {
        workers: {
          singleWorker: true,
          wrangler: { configPath: "./wrangler.jsonc" },
          miniflare: {
            bindings: {
              CFP_SIGNING_KEY: TEST_CFP_SIGNING_KEY,
              BOOTSTRAP_TOKEN: "test-bootstrap-token",
              TEST_MIGRATIONS: migrations,
            },
          },
        },
      },
    },
  };
});
