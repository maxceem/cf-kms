/**
 * Fixed test material. These KEKs and tokens are throwaway values generated for
 * the test suite only — they are not, and must never become, real secrets.
 *
 * Imported by `vitest.config.ts` (which hashes the tokens into the `CALLERS`
 * binding on the host) as well as by the tests themselves.
 */
export const testKeks = {
  v1: "zgiqgC6Tb4ZYqRtgN+w3WELa7N5stGxAXo3f6x9iZRM=",
  v2: "xZ4jqGkd++qWm4WUm+ZcEsZVozu08p5IkWzOtv/uK2E=",
  v3: "SL2qn3jF8tg2jHl20EHURbRn+gbfQZSUUV3xT/pwRDM=",
} as const;

export interface TestCaller {
  name: string;
  token: string;
  requiredContext: Record<string, string>;
}

export const acmeCaller: TestCaller = {
  name: "acme",
  token: "ckms_acme_mxLM4XeNy-_sq5X_x5u_jb_5FIQkd5VL",
  requiredContext: { service: "acme" },
};

export const widgetsCaller: TestCaller = {
  name: "widgets",
  token: "ckms_widgets_3uHJv87l17Bh_a_QTdXteQ0YDL4cS7dc",
  requiredContext: {},
};

/** Well-formed, correctly named, but not configured on any deployment. */
export const unknownCallerToken = "ckms_ghost_-nPc1i0o2vPo2R86dm2at7SvuJdCCUTB";

export const testCallers: readonly TestCaller[] = [acmeCaller, widgetsCaller];

/** The context the `acme` caller is scoped to. */
export const acmeContext = {
  service: "acme",
  tenantId: "org_123",
  purpose: "provider-key",
} as const;
