import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { canonicalizeV1, computeGenesis, computeSignature } from "../src/audit-chain.js";
import { produceAuditRow } from "../src/conformance.js";
import { main } from "../src/verify-cli.js";
import {
  AuditChainVerificationError,
  verifyAuditJsonlFile,
  verifyAuditJsonlText,
} from "../src/verify.js";

const SECRET = Buffer.from("verify-secret-do-not-ship", "utf-8");
const tmpDirs: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  while (tmpDirs.length > 0) {
    const dir = tmpDirs.pop();
    if (dir !== undefined) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

function signedEntry(row: ReturnType<typeof produceAuditRow>, prevHash: string) {
  const canonicalBytes = canonicalizeV1(row);
  const signature = computeSignature(prevHash, canonicalBytes, SECRET);
  return {
    row,
    prevHash,
    signature,
    canonicalBytes: canonicalBytes.toString("base64"),
    canonicalizationFormat: "v1",
  };
}

function validJsonl(): string {
  const firstRow = produceAuditRow();
  const secondRow = { ...produceAuditRow(), auditId: "audit-verify-002", phase: "verify" };
  const first = signedEntry(firstRow, computeGenesis(firstRow.tenantId, SECRET));
  const second = signedEntry(secondRow, first.signature);
  return `${JSON.stringify(first)}\n${JSON.stringify(second)}\n`;
}

describe("audit-chain verifier", () => {
  it("accepts a valid JsonlFilePersister-style chain", () => {
    const report = verifyAuditJsonlText(validJsonl(), SECRET);

    expect(report.rows).toBe(2);
    expect(report.tenantId).toBe("tenant-conformance");
    expect(report.headSignature).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects a tampered signature", () => {
    const entries = validJsonl()
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    entries[1].signature = "0".repeat(64);
    const tampered = `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`;

    expect(() => verifyAuditJsonlText(tampered, SECRET)).toThrow(
      /row 2 signature mismatch/,
    );
  });

  it("accepts public SignedAuditRow JSONL", () => {
    const row = produceAuditRow();
    const prevHash = computeGenesis(row.tenantId, SECRET);
    const signature = computeSignature(prevHash, canonicalizeV1(row), SECRET);
    const signedRow = {
      payload: row,
      attestation: {
        prevRowHash: prevHash,
        signatureValue: signature,
        algorithm: "HMAC-SHA256",
        canonicalizationFormat: "v1",
        keyId: "tenant:verify:hmac:v1",
      },
    };

    const report = verifyAuditJsonlText(`${JSON.stringify(signedRow)}\n`, SECRET);

    expect(report.rows).toBe(1);
    expect(report.tenantId).toBe(row.tenantId);
  });

  it("verifies a file from the CLI entrypoint", () => {
    const tempDir = mkdtempSync(join(tmpdir(), "warlog-verify-cli-"));
    tmpDirs.push(tempDir);
    const auditLog = join(tempDir, "audit.jsonl");
    const secretFile = join(tempDir, "secret.bin");
    writeFileSync(auditLog, validJsonl(), "utf-8");
    writeFileSync(secretFile, SECRET);
    vi.spyOn(console, "log").mockImplementation(() => undefined);

    const code = main([auditLog, "--secret-file", secretFile]);

    expect(code).toBe(0);
    expect(verifyAuditJsonlFile(auditLog, readFileSync(secretFile)).rows).toBe(2);
  });

  it("returns an error code for invalid chains", () => {
    const tempDir = mkdtempSync(join(tmpdir(), "warlog-verify-cli-"));
    tmpDirs.push(tempDir);
    const auditLog = join(tempDir, "audit.jsonl");
    const secretFile = join(tempDir, "secret.bin");
    writeFileSync(auditLog, '{"not":"a signed row"}\n', "utf-8");
    writeFileSync(secretFile, SECRET);
    vi.spyOn(console, "error").mockImplementation(() => undefined);

    const code = main([auditLog, "--secret-file", secretFile]);

    expect(code).toBe(1);
  });

  it("exposes rowNumber on verification failures", () => {
    try {
      verifyAuditJsonlText("not-json\n", SECRET);
      throw new Error("expected verifier to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(AuditChainVerificationError);
      expect((error as AuditChainVerificationError).rowNumber).toBe(1);
    }
  });
});