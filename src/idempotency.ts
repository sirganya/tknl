import type { Env } from "./env";
import { errorJson } from "./http";
import { hex, utf8 } from "./lib/encoding";
import { sha256 } from "./lib/crypto";

/**
 * Idempotency wrapper for all mutating endpoints (UTAP §10: every request
 * carries an idempotency key; replays return the original response).
 *
 * Keys are scoped per caller. A replay with the same key but a different
 * payload is a 422; a concurrent duplicate is a 409. Responses ≥500 are not
 * stored, so transient failures remain retryable.
 */
export async function withIdempotency(
  env: Env,
  callerKey: string,
  request: Request,
  bodyText: string,
  fn: () => Promise<Response>,
): Promise<Response> {
  const key = request.headers.get("idempotency-key");
  if (!key || key.length > 200) {
    return errorJson(400, "idempotency_key_required", "provide an Idempotency-Key header");
  }
  const url = new URL(request.url);
  const fingerprint = hex(await sha256(utf8(`${request.method}|${url.pathname}|${bodyText}`)));

  const stub = env.IDEMPOTENCY_DO.get(env.IDEMPOTENCY_DO.idFromName(`${callerKey}|${key}`));
  const begin = await stub.begin(fingerprint);

  switch (begin.state) {
    case "replay":
      return new Response(begin.body, {
        status: begin.httpStatus,
        headers: { "content-type": "application/json; charset=utf-8", "idempotency-replay": "true" },
      });
    case "in_progress":
      return errorJson(409, "in_progress", "a request with this idempotency key is already executing");
    case "mismatch":
      return errorJson(422, "idempotency_mismatch", "idempotency key reused with a different payload");
    case "new":
      break;
  }

  let response: Response;
  try {
    response = await fn();
  } catch (e) {
    await stub.abort();
    throw e;
  }
  if (response.status < 500) {
    await stub.complete(response.status, await response.clone().text());
  } else {
    await stub.abort();
  }
  return response;
}
