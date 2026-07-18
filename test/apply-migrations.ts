import { applyD1Migrations, env } from "cloudflare:test";

// D1 is a derived index; tests get the same schema production migrations apply.
await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
