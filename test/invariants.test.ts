import { describe, expect, it } from "vitest";

/**
 * Grep-level security invariants: the properties the threat model in the README
 * rests on, asserted against the sources themselves. Sources are inlined by the
 * bundler at build time (`?raw`), so this runs inside the Workers pool like
 * every other test.
 */
// `import.meta.glob` is a Vite builtin; typed locally so the project does not
// need to depend on `vite/client`.
type ImportGlob = (
  pattern: string,
  options: { query: string; import: string; eager: true },
) => Record<string, string>;

const sources = (import.meta as unknown as { glob: ImportGlob }).glob("../src/**/*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

const sourcePath = (path: string) => path.replace("../", "");

/** Block comments and whole-line `//` comments — prose, not behaviour. */
const stripComments = (source: string) =>
  source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

const codeOf = (source: string) =>
  stripComments(source)
    .split("\n")
    .filter((line) => line.trim() !== "");

describe("source invariants", () => {
  it("sees every source file", () => {
    const paths = Object.keys(sources).map(sourcePath).sort();

    expect(paths).toStrictEqual([
      "src/audit.ts",
      "src/auth.ts",
      "src/client/index.ts",
      "src/crypto/base64url.ts",
      "src/crypto/context.ts",
      "src/crypto/kek.ts",
      "src/crypto/wrap.ts",
      "src/env.ts",
      "src/errors.ts",
      "src/routes.ts",
      "src/worker.ts",
    ]);
  });

  it("touches KEK material only in crypto/kek.ts", () => {
    const offenders = Object.entries(sources)
      .filter(([path]) => sourcePath(path) !== "src/crypto/kek.ts")
      .filter(([, source]) => codeOf(source).some((line) => line.includes("KEK_")))
      .map(([path]) => sourcePath(path));

    expect(offenders).toStrictEqual([]);
  });

  it("writes to the console only from audit.ts and errors.ts", () => {
    const offenders = Object.entries(sources)
      .filter(([path]) => !["src/audit.ts", "src/errors.ts"].includes(sourcePath(path)))
      .filter(([, source]) => codeOf(source).some((line) => line.includes("console.")))
      .map(([path]) => sourcePath(path));

    expect(offenders).toStrictEqual([]);
  });

  it("keeps the runtime small enough to audit by hand", () => {
    const lines = Object.entries(sources)
      .filter(([path]) => sourcePath(path) !== "src/client/index.ts")
      .reduce((total, [, source]) => total + codeOf(source).length, 0);

    // The security argument for this Worker is its smallness — the design
    // target is well under ~500 lines of runtime code. The worker
    // sits a little above that in the house formatting style (one statement per
    // paragraph); this is a regression guard, not a licence to grow.
    expect(lines).toBeLessThan(650);
  });

  it("keeps the published client free of runtime dependencies", () => {
    const client = sources["../src/client/index.ts"] ?? "";
    const imports = [...client.matchAll(/^\s*import\s.+from\s+["'](.+)["'];?$/gm)].map(
      (match) => match[1],
    );

    expect(imports).toStrictEqual([]);
  });
});
