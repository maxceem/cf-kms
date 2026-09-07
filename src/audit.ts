import type { EncryptionContext } from "./crypto/context";

/**
 * The audit trail: one structured line per authenticated request, shipped to
 * Workers Logs by the observability config in `wrangler.jsonc`.
 *
 * The line is built field by field on purpose. Nothing may be spread into it,
 * so plaintext DEKs, wrapped tokens and bearer tokens cannot leak here even by
 * accident. `test/audit.test.ts` scans emitted lines for secret material.
 */
export type AuditOperation = "generate-data-key" | "decrypt" | "re-wrap";

export interface AuditEntry {
  /** `null` when the request never authenticated. */
  caller: string | null;
  op: AuditOperation;
  /**
   * The KEK version the operation used: the wrap version for
   * `generate-data-key`, the unwrap version for `decrypt`, and the new
   * (current) version for `re-wrap`. `null` when the request failed first.
   */
  kekVersion: number | null;
  /** `null` when the request failed before the body was validated. */
  context: EncryptionContext | null;
  success: boolean;
}

export const writeAuditLog = (entry: AuditEntry): void => {
  console.log(
    JSON.stringify({
      audit: true,
      caller: entry.caller,
      op: entry.op,
      kekVersion: entry.kekVersion,
      context: entry.context,
      success: entry.success,
    }),
  );
};

/** Mutable slots an in-flight operation fills in before the line is written. */
export interface AuditDraft {
  kekVersion: number | null;
  context: EncryptionContext | null;
}

/**
 * Runs `operation`, emitting exactly one audit line either way. Failures are
 * logged and rethrown — the response shape is decided elsewhere.
 */
export const audited = async <T>(
  caller: string,
  op: AuditOperation,
  operation: (draft: AuditDraft) => Promise<T>,
): Promise<T> => {
  const draft: AuditDraft = { kekVersion: null, context: null };

  try {
    const result = await operation(draft);

    writeAuditLog({ caller, op, kekVersion: draft.kekVersion, context: draft.context, success: true });

    return result;
  } catch (error) {
    writeAuditLog({
      caller,
      op,
      kekVersion: draft.kekVersion,
      context: draft.context,
      success: false,
    });

    throw error;
  }
};
