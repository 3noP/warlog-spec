import { readFileSync } from "node:fs";

import { canonicalizeV1, computeGenesis, computeSignature } from "./audit-chain.js";
import { AuditRow, SignedAuditRow } from "./provider-abi.js";

export interface VerificationReport {
  rows: number;
  tenantId: string | null;
  headSignature: string | null;
}

export class AuditChainVerificationError extends Error {
  readonly rowNumber: number | null;

  constructor(message: string, rowNumber: number | null = null) {
    super(message);
    this.name = "AuditChainVerificationError";
    this.rowNumber = rowNumber;
  }
}

interface SignedEntry {
  row: AuditRow;
  prevHash: string;
  signature: string;
  canonicalBytes: Buffer;
}

function requireRecord(value: unknown, rowNumber: number): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AuditChainVerificationError(`row ${rowNumber} must be a JSON object`, rowNumber);
  }
  return value as Record<string, unknown>;
}

function requireString(
  entry: Record<string, unknown>,
  key: string,
  rowNumber: number,
): string {
  const value = entry[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new AuditChainVerificationError(
      `row ${rowNumber} missing required string field '${key}'`,
      rowNumber,
    );
  }
  return value;
}

function decodeBase64(value: string, rowNumber: number): Buffer {
  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new AuditChainVerificationError(
      `row ${rowNumber} canonicalBytes is not valid base64`,
      rowNumber,
    );
  }
  return Buffer.from(value, "base64");
}

function decodeEntry(entry: Record<string, unknown>, rowNumber: number): SignedEntry {
  if ("row" in entry) {
    let row: AuditRow;
    try {
      row = AuditRow.parse(entry.row);
    } catch (error) {
      throw new AuditChainVerificationError(
        `row ${rowNumber} payload does not match AuditRow`,
        rowNumber,
      );
    }
    const canonicalizationFormat = entry.canonicalizationFormat ?? "v1";
    if (canonicalizationFormat !== "v1") {
      throw new AuditChainVerificationError(
        `row ${rowNumber} unsupported canonicalization format '${String(canonicalizationFormat)}'`,
        rowNumber,
      );
    }
    const canonicalValue = entry.canonicalBytes;
    return {
      row,
      prevHash: requireString(entry, "prevHash", rowNumber),
      signature: requireString(entry, "signature", rowNumber),
      canonicalBytes:
        typeof canonicalValue === "string"
          ? decodeBase64(canonicalValue, rowNumber)
          : canonicalizeV1(row),
    };
  }

  let signed: SignedAuditRow;
  try {
    signed = SignedAuditRow.parse(entry);
  } catch (error) {
    throw new AuditChainVerificationError(
      `row ${rowNumber} is neither JsonlFilePersister nor SignedAuditRow format`,
      rowNumber,
    );
  }
  if (signed.attestation.algorithm !== "HMAC-SHA256") {
    throw new AuditChainVerificationError(
      `row ${rowNumber} unsupported signature algorithm '${signed.attestation.algorithm}'`,
      rowNumber,
    );
  }
  if (signed.attestation.canonicalizationFormat !== "v1") {
    throw new AuditChainVerificationError(
      `row ${rowNumber} unsupported canonicalization format '${signed.attestation.canonicalizationFormat}'`,
      rowNumber,
    );
  }
  return {
    row: signed.payload,
    prevHash: signed.attestation.prevRowHash,
    signature: signed.attestation.signatureValue,
    canonicalBytes: canonicalizeV1(signed.payload),
  };
}

export function verifyAuditJsonlText(text: string, secret: Buffer): VerificationReport {
  if (secret.length === 0) {
    throw new AuditChainVerificationError("secret is empty");
  }

  let rows = 0;
  let tenantId: string | null = null;
  let expectedPrev: string | null = null;
  let headSignature: string | null = null;
  const lines = text.split(/\r?\n/);

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const rawLine = lines[lineIndex];
    if (rawLine === undefined) {
      continue;
    }
    const line = rawLine.trim();
    if (line.length === 0) {
      continue;
    }
    const rowNumber = rows + 1;
    let rawEntry: unknown;
    try {
      rawEntry = JSON.parse(line);
    } catch (error) {
      throw new AuditChainVerificationError(
        `row ${rowNumber} is not valid JSON (line ${lineIndex + 1})`,
        rowNumber,
      );
    }

    const entry = decodeEntry(requireRecord(rawEntry, rowNumber), rowNumber);
    if (tenantId === null) {
      tenantId = entry.row.tenantId;
      expectedPrev = computeGenesis(tenantId, secret);
    } else if (entry.row.tenantId !== tenantId) {
      throw new AuditChainVerificationError(
        `row ${rowNumber} tenantId changed from '${tenantId}' to '${entry.row.tenantId}'`,
        rowNumber,
      );
    }

    if (entry.prevHash !== expectedPrev) {
      throw new AuditChainVerificationError(`row ${rowNumber} prevHash mismatch`, rowNumber);
    }

    const recomputed = computeSignature(entry.prevHash, entry.canonicalBytes, secret);
    if (recomputed !== entry.signature) {
      throw new AuditChainVerificationError(`row ${rowNumber} signature mismatch`, rowNumber);
    }

    rows += 1;
    headSignature = entry.signature;
    expectedPrev = entry.signature;
  }

  return { rows, tenantId, headSignature };
}

export function verifyAuditJsonlFile(path: string, secret: Buffer): VerificationReport {
  return verifyAuditJsonlText(readFileSync(path, "utf-8"), secret);
}