/**
 * @warlog/spec — Warlog Spec, TypeScript reference implementation.
 *
 * Mirrors the Python `warlog-spec` package. Same wire format
 * (camelCase JSON, sorted-keys canonicalization for the audit chain),
 * same productible types covered by the conformance factories.
 *
 * Usage :
 *
 *     import { AuditRow, canonicalizeV1, produceAll } from "@warlog/spec";
 *
 *     const row = AuditRow.parse(rawJson);
 *     const bytes = canonicalizeV1(row);
 *     // ...
 */

export const SPEC_VERSION = "0.1.0";
export const ABI_VERSION = "1.0";

export * from "./enums.js";
export * from "./provider-abi.js";
export * from "./artifacts.js";
export * from "./proposals.js";
export * from "./pack-manifest.js";
export { AbiConnector, AbiEnricher, ConnectorAbiError } from "./abi.js";
export {
  CANONICALIZATION_FORMAT_V1,
  canonicalizeV1,
  computeGenesis,
  computeSignature,
  verifySignature,
  sha256Hex,
} from "./audit-chain.js";
export {
  AuditChainVerificationError,
  verifyAuditJsonlFile,
  verifyAuditJsonlText,
} from "./verify.js";
export type { VerificationReport } from "./verify.js";
export {
  MOCK_PROVIDER_SCENARIO_ID,
  MOCK_VENDOR_ID,
  MockResponseVendor,
  MockVendorConnector,
  mockProviderActionSpec,
  mockUnsupportedActionSpec,
  runMockProviderLevel4,
} from "./provider-conformance.js";
export type { Level4ProviderReport } from "./provider-conformance.js";
export type { ProviderConnectorClass } from "./provider-conformance.js";
export {
  canonicalizeOcsfEvent,
  hashOcsfEvent,
  mapOcsfDetectionFinding,
} from "./ocsf.js";
export type { OcsfDetectionFindingMapping } from "./ocsf.js";
