/**
 * Outbound STIX 2.1 projection — RFC-0003.
 *
 * TypeScript port of `warlog_spec.stix_projection`. Same shape,
 * same deterministic uuid5-derived ids, same field mapping. Two
 * tenants projecting the same source produce the same STIX ids,
 * so a consumer can dedup across MSSPs.
 *
 * See `warlog-spec/rfcs/0003-stix-projection.md` for the contract.
 */

import { createHash } from "node:crypto";

import type {
  ArtifactConfidence,
  CaseReturnSummary,
  ExtractedIOC,
} from "./artifacts.js";
import { IOCType } from "./enums.js";

// Standard UUID namespace OID (RFC 4122) used by Python's uuid5
// when called with NAMESPACE_OID — byte-for-byte equivalent.
const NAMESPACE_OID = "6ba7b812-9dad-11d1-80b4-00c04fd430c8";
const NS = "warlog-spec:stix:";

/**
 * Deterministic UUIDv5 per RFC 4122 §4.3.
 *
 * Equivalent to Python's `uuid.uuid5(namespace, name)`. We
 * re-implement here rather than pull a uuid library — the
 * dependency surface stays at zero.
 */
function uuid5(namespace: string, name: string): string {
  // RFC 4122 : SHA-1 hash of (namespace bytes || name bytes), then
  // set version 5 and variant RFC 4122.
  const nsBytes = uuidStringToBytes(namespace);
  const nameBytes = Buffer.from(name, "utf-8");
  const hash = createHash("sha1");
  hash.update(nsBytes);
  hash.update(nameBytes);
  const digest = hash.digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  // Version 5 = 0101 in the high nibble of byte 6.
  bytes[6] = (bytes[6]! & 0x0f) | 0x50;
  // Variant 10x in the high bits of byte 8.
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  return bytesToUuidString(bytes);
}

function uuidStringToBytes(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, ""), "hex");
}

function bytesToUuidString(b: Buffer): string {
  const hex = b.toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
}

function buildId(stixType: string, name: string): string {
  return `${stixType}--${uuid5(NAMESPACE_OID, NS + name)}`;
}

function confidenceToInt(confidence: ArtifactConfidence): number {
  if (confidence.score !== null && confidence.score !== undefined) {
    return Math.max(0, Math.min(100, Math.round(confidence.score * 100)));
  }
  switch (confidence.band) {
    case "low":
      return 25;
    case "medium":
      return 60;
    case "high":
      return 85;
    case "unknown":
    default:
      return 0;
  }
}

function abstractFor(caseReturn: CaseReturnSummary): string {
  const verdict = caseReturn.finalVerdict.toUpperCase();
  const text = `Closure of ${caseReturn.caseNumber} — verdict=${verdict}`;
  return text.length <= 200 ? text : text.slice(0, 197) + "...";
}

function contentFor(caseReturn: CaseReturnSummary): string {
  const lines: string[] = [];
  lines.push(`# Closure : ${caseReturn.caseNumber}`);
  lines.push("");
  lines.push(`**Verdict** : ${caseReturn.finalVerdict}`);
  lines.push(`**Category** : ${caseReturn.finalCategory}`);
  lines.push(`**Severity** : ${caseReturn.finalSeverity}`);
  lines.push("");
  lines.push("## Outcome summary");
  lines.push(caseReturn.outcomeSummary);
  if (caseReturn.rootCause) {
    lines.push("");
    lines.push("## Root cause");
    lines.push(caseReturn.rootCause);
  }
  if (caseReturn.lessonsLearned) {
    lines.push("");
    lines.push("## Lessons learned");
    lines.push(caseReturn.lessonsLearned);
  }
  const body = lines.join("\n");
  return body.length <= 65535 ? body : body.slice(0, 65532) + "...";
}

export interface StixNote {
  type: "note";
  spec_version: "2.1";
  id: string;
  created: string;
  modified: string;
  created_by_ref: string;
  abstract: string;
  content: string;
  authors: string[];
  object_refs: string[];
  external_references: Array<{
    source_name: string;
    external_id: string;
    url?: string;
  }>;
  labels: string[];
  confidence: number;
}

/**
 * Project a `CaseReturnSummary` to a STIX 2.1 Note SDO.
 *
 * Returns the dict-shaped Note ready for JSON serialization. The
 * shape conforms to STIX 2.1 §4.10.
 */
export function caseReturnToStixNote(
  caseReturn: CaseReturnSummary,
  opts: {
    tenantId: string;
    caseUrl?: string;
    authorDisplayName?: string;
  },
): StixNote {
  const createdByRef = buildId("identity", `tenant:${opts.tenantId}`);
  const objectRefs = caseReturn.linkedAlertIds.map((aid) =>
    buildId("incident", `alert:${aid}`),
  );

  const generatedIso = caseReturn.generatedAt.endsWith("Z")
    ? caseReturn.generatedAt
    : caseReturn.generatedAt.replace(/\+00:00$/, "Z");

  const externalRef: StixNote["external_references"][number] = {
    source_name: "warlog-spec",
    external_id: caseReturn.caseId,
  };
  if (opts.caseUrl) {
    externalRef.url = opts.caseUrl;
  }

  return {
    type: "note",
    spec_version: "2.1",
    id: buildId("note", `case-return:${caseReturn.caseId}`),
    created: generatedIso,
    modified: generatedIso,
    created_by_ref: createdByRef,
    abstract: abstractFor(caseReturn),
    content: contentFor(caseReturn),
    authors: [opts.authorDisplayName ?? "warlog-spec"],
    object_refs: objectRefs,
    external_references: [externalRef],
    labels: ["closure", caseReturn.finalCategory],
    confidence: confidenceToInt(caseReturn.confidence),
  };
}

export interface StixIndicator {
  type: "indicator";
  spec_version: "2.1";
  id: string;
  created: string;
  modified: string;
  created_by_ref: string;
  pattern_type: "stix";
  pattern: string;
  valid_from: string;
  confidence: number;
  labels: string[];
}

function iocToStixPattern(ioc: ExtractedIOC): string | null {
  const v = ioc.value.replace(/'/g, "\\'");
  switch (ioc.iocType) {
    case IOCType.IP:
      return `[ipv4-addr:value = '${v}']`;
    case IOCType.IPV6:
      return `[ipv6-addr:value = '${v}']`;
    case IOCType.DOMAIN:
      return `[domain-name:value = '${v}']`;
    case IOCType.URL:
      return `[url:value = '${v}']`;
    case IOCType.HASH_MD5:
      return `[file:hashes.MD5 = '${v}']`;
    case IOCType.HASH_SHA1:
      return `[file:hashes.'SHA-1' = '${v}']`;
    case IOCType.HASH_SHA256:
      return `[file:hashes.'SHA-256' = '${v}']`;
    case IOCType.EMAIL:
      return `[email-addr:value = '${v}']`;
    case IOCType.FILE_PATH:
      return `[file:name = '${v}']`;
    default:
      return null;
  }
}

/**
 * Project an `ExtractedIOC` to a STIX 2.1 Indicator SDO. Returns
 * `null` when the IOC type has no clean STIX pattern.
 */
export function iocToStixIndicator(
  ioc: ExtractedIOC,
  opts: { tenantId: string },
): StixIndicator | null {
  const pattern = iocToStixPattern(ioc);
  if (pattern === null) return null;
  const createdByRef = buildId("identity", `tenant:${opts.tenantId}`);
  const seen = ioc.firstSeen ?? ioc.lastSeen ?? "1970-01-01T00:00:00Z";
  const lastSeen = ioc.lastSeen ?? ioc.firstSeen ?? "1970-01-01T00:00:00Z";
  return {
    type: "indicator",
    spec_version: "2.1",
    id: buildId("indicator", `ioc:${ioc.iocType}:${ioc.value}`),
    created: seen,
    modified: lastSeen,
    created_by_ref: createdByRef,
    pattern_type: "stix",
    pattern,
    valid_from: seen,
    confidence: confidenceToInt(ioc.confidence),
    labels:
      ioc.maliciousness === "true_positive"
        ? ["malicious-activity"]
        : ["anomalous-activity"],
  };
}
