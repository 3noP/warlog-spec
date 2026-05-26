/**
 * @warlog/spec conformance tests.
 *
 * 1. Coverage : `PRODUCERS` MUST contain exactly the 18 productible
 *    types the spec defines. (Bundle shapes — TriageBundle,
 *    InvestigationBundle, ResponseBundle, IncidentBundle — are
 *    deliberately out of scope of the open spec ; they live in the
 *    Warlog backend as product-specific UI projections.)
 * 2. Validity : each factory output MUST validate against the
 *    corresponding JSON Schema from `warlog-spec/schemas/`. Schemas
 *    are loaded via Ajv at test time so this test exercises the same
 *    contract a third-party adopter would see.
 * 3. Determinism : `produceAll()` is byte-deterministic across calls.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { describe, expect, it } from "vitest";

import { PRODUCERS, produceAll } from "../src/conformance.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMAS_ROOT_CANDIDATES = [
  resolve(__dirname, "../../../warlog-spec/schemas"),
  resolve(__dirname, "../../../schemas"),
];
const SCHEMAS_ROOT = SCHEMAS_ROOT_CANDIDATES.find((candidate) =>
  existsSync(resolve(candidate, "action-catalog.json")),
);
if (!SCHEMAS_ROOT) {
  throw new Error(
    `Could not find warlog-spec schemas directory. Checked: ${SCHEMAS_ROOT_CANDIDATES.join(
      ", ",
    )}`,
  );
}

const EXPECTED_PRODUCTIBLE = new Set([
  "artifacts/approval-decision.json",
  "artifacts/case-return-summary.json",
  "artifacts/classification-assessment.json",
  "artifacts/closure-summary.json",
  "artifacts/enrichment-assessment.json",
  "artifacts/mitre-assessment.json",
  "artifacts/risk-arbitration.json",
  "proposals/investigation-summary-proposal.json",
  "proposals/next-step-proposal.json",
  "proposals/playbook-candidate-proposal.json",
  "proposals/triage-proposal.json",
  "provider-abi/audit-row.json",
  "provider-abi/connector-capability.json",
  "provider-abi/connector-error.json",
  "provider-abi/response-action-result.json",
  "provider-abi/response-action-spec.json",
  "provider-abi/signed-audit-row.json",
  "registry/pack-manifest.json",
]);

function loadSchema(relpath: string): Record<string, unknown> {
  const full = resolve(SCHEMAS_ROOT, relpath);
  return JSON.parse(readFileSync(full, "utf-8")) as Record<string, unknown>;
}

describe("Conformance Level 2 — producer coverage", () => {
  it("PRODUCERS covers exactly the 18 productible types", () => {
    const actual = new Set(Object.keys(PRODUCERS));
    const missing = [...EXPECTED_PRODUCTIBLE].filter((s) => !actual.has(s));
    const extras = [...actual].filter((s) => !EXPECTED_PRODUCTIBLE.has(s));
    expect(missing, `PRODUCERS missing: ${JSON.stringify(missing)}`).toEqual([]);
    expect(extras, `PRODUCERS extras: ${JSON.stringify(extras)}`).toEqual([]);
  });
});

describe("Conformance Level 2 — each factory output validates", () => {
  // Initialize Ajv once per suite. Each productible schema is registered
  // explicitly ; cross-schema $refs resolve via the shared registry.
  const ajv = new Ajv({
    strict: false,
    allErrors: true,
    validateFormats: true,
  });
  addFormats.default(ajv);

  for (const [relpath, factory] of Object.entries(PRODUCERS)) {
    it(`${relpath}`, () => {
      const schema = loadSchema(relpath);
      const validate = ajv.compile(schema);
      const example = factory();
      const ok = validate(example);
      if (!ok) {
        const errors = (validate.errors ?? []).map(
          (e) => `${e.instancePath} ${e.message}`,
        );
        throw new Error(
          `Factory output for ${relpath} does not validate:\n  ` +
            errors.join("\n  ") +
            `\n\nOutput was:\n${JSON.stringify(example, null, 2)}`,
        );
      }
      expect(ok).toBe(true);
    });
  }
});

describe("Conformance Level 2 — determinism", () => {
  it("produceAll() returns byte-identical output across calls", () => {
    const a = produceAll();
    const b = produceAll();
    expect(JSON.stringify(a)).toEqual(JSON.stringify(b));
  });
});
