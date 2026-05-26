#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { AuditChainVerificationError, verifyAuditJsonlFile } from "./verify.js";

function usage(): string {
  return [
    "Usage:",
    "  warlog-verify <audit.jsonl> --secret-file <secret.bin>",
    "",
    "Verifies a Warlog HMAC audit-chain JSONL file.",
  ].join("\n");
}

function readSecretFile(args: string[]): string | null {
  const secretIndex = args.indexOf("--secret-file");
  if (secretIndex === -1) {
    return null;
  }
  const secretFile = args[secretIndex + 1];
  return secretFile && secretFile.length > 0 ? secretFile : null;
}

export function main(argv = process.argv.slice(2)): number {
  const [auditLog] = argv;
  if (auditLog === "--help" || auditLog === "-h") {
    console.log(usage());
    return 0;
  }
  if (auditLog === undefined || auditLog.startsWith("-")) {
    console.error(usage());
    return 2;
  }

  const secretFile = readSecretFile(argv);
  if (secretFile === null) {
    console.error("Missing required --secret-file <secret.bin> argument.\n");
    console.error(usage());
    return 2;
  }

  try {
    const secret = readFileSync(secretFile);
    const report = verifyAuditJsonlFile(auditLog, secret);
    console.log(`OK : ${report.rows} rows, chain valid, no gaps, no tampering`);
    return 0;
  } catch (error) {
    if (error instanceof AuditChainVerificationError || error instanceof Error) {
      console.error(`FAIL : ${error.message}`);
      return 1;
    }
    console.error("FAIL : unknown verification error");
    return 1;
  }
}

function isCliEntrypoint(): boolean {
  const entrypoint = process.argv[1];
  return entrypoint !== undefined && resolve(entrypoint) === fileURLToPath(import.meta.url);
}

if (isCliEntrypoint()) {
  process.exitCode = main();
}