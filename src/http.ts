export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

export function json(body: unknown, status = 200, headers?: Record<string, string>): Response {
  return new Response(JSON.stringify(body, null, 2) + "\n", {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  });
}

export function errorJson(status: number, code: string, message: string): Response {
  return json({ error: { code, message } }, status);
}

/** Map DO-level error codes onto HTTP statuses. */
export function statusForCode(code: string): number {
  switch (code) {
    case "not_found":
      return 404;
    case "forbidden":
    case "merchant_mismatch":
    case "merchant_not_allowed":
      return 403;
    case "invalid_transition":
    case "exists":
    case "already_decided":
    case "reservation_conflict":
    case "jti_conflict":
      return 409;
    case "insufficient_budget":
    case "per_txn_max":
    case "amount_exceeds_scope":
      return 422;
    case "audit_failed":
    case "archive_failed":
      return 503;
    default:
      return 400;
  }
}
