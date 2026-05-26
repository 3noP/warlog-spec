/**
 * Append-only JSONL persister for signed audit rows.
 *
 * Mirrors the Python ``JsonlFilePersister`` in ``warlog_spec.integrate``.
 * Each line is one signed entry ``{row, prevHash, signature, canonicalBytes,
 * canonicalizationFormat}``. On boot, the file is scanned to recover the
 * head signature so the chain survives proxy restarts without phantom
 * breaks.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

import type { AuditRow } from "@warlog/spec";

export interface SignedAuditEntry {
  row: AuditRow;
  prevHash: string;
  signature: string;
  canonicalBytes: Buffer;
  canonicalizationFormat: string;
}

export class JsonlAuditPersister {
  private path: string;
  private headSig: string | null = null;

  constructor(path: string) {
    this.path = path;
    this.headSig = this.recoverHead();
  }

  private recoverHead(): string | null {
    if (!existsSync(this.path)) return null;
    const lines = readFileSync(this.path, "utf-8").split(/\r?\n/);
    let last: string | null = null;
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const entry = JSON.parse(trimmed);
        if (typeof entry.signature === "string") last = entry.signature;
      } catch {
        // Skip malformed lines but keep scanning.
      }
    }
    return last;
  }

  headSignature(): string | null {
    return this.headSig;
  }

  append(entry: SignedAuditEntry): void {
    const dir = dirname(this.path);
    if (dir && !existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    // Build with sorted keys explicitly so the JSON line is deterministic
    // — useful for diffing chains across runs without confusing the
    // JSON.stringify(value, replacer-array) semantics that would have
    // dropped nested keys.
    const payload = {
      canonicalBytes: entry.canonicalBytes.toString("base64"),
      canonicalizationFormat: entry.canonicalizationFormat,
      prevHash: entry.prevHash,
      row: entry.row,
      signature: entry.signature,
    };
    const line = JSON.stringify(payload) + "\n";
    appendFileSync(this.path, line, "utf-8");
    this.headSig = entry.signature;
  }
}
