/**
 * Every client-visible failure collapses into one of these codes.
 *
 * Nothing derived from the request ever reaches the client: no zod messages, no
 * crypto errors, no stack traces. In particular `decrypt_failed` is returned
 * identically for a malformed token, a tampered token, a mismatched encryption
 * context and an unknown KEK version, so the endpoint is not an oracle.
 */
export type KmsErrorCode =
  | "invalid_request"
  | "unauthorized"
  | "decrypt_failed"
  | "not_found"
  | "internal_error";

export class KmsError extends Error {
  readonly code: KmsErrorCode;
  readonly status: number;

  constructor(code: KmsErrorCode, status: number) {
    // The message is the code itself: there is nothing else safe to put here.
    super(code);
    this.name = `KmsError:${code}`;
    this.code = code;
    this.status = status;
  }
}

export const isKmsError = (error: unknown): error is KmsError => error instanceof KmsError;

/** Request body failed schema validation, or was not JSON. */
export const invalidRequest = (): KmsError => new KmsError("invalid_request", 400);

/** Missing/unknown caller token, or the caller is not scoped to this context. */
export const unauthorized = (): KmsError => new KmsError("unauthorized", 401);

/** Unwrap failed. Deliberately indistinguishable across all causes. */
export const decryptFailed = (): KmsError => new KmsError("decrypt_failed", 400);

export const notFound = (): KmsError => new KmsError("not_found", 404);

export const errorResponse = (error: KmsError): Response =>
  Response.json({ error: { code: error.code } }, { status: error.status });

/**
 * Maps a thrown value onto a response.
 *
 * Anything that is not a deliberate {@link KmsError} is a bug or a
 * misconfiguration (e.g. a malformed `KEK_V*` secret). Those are reported as an
 * opaque 500 and logged. Caller input never reaches these messages — request
 * parsing failures are converted to `invalid_request` before they can escape.
 */
export const toErrorResponse = (error: unknown): Response => {
  if (isKmsError(error)) {
    return errorResponse(error);
  }

  console.error(
    JSON.stringify({
      level: "error",
      scope: "cf-kms",
      message: "unhandled error",
      name: error instanceof Error ? error.name : typeof error,
      detail: error instanceof Error ? error.message : undefined,
    }),
  );

  return errorResponse(new KmsError("internal_error", 500));
};
