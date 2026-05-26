#!/usr/bin/env node

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { produceAll } from "./conformance.js";
import { runMockProviderLevel4 } from "./provider-conformance.js";

function usage(): string {
  return [
    "Usage:",
    "  warlog-spec dump --out <dir>",
    "  warlog-spec provider-check --out <report.json>",
    "",
    "Commands:",
    "  dump    Write one Level 2 conformance fixture per productible type.",
    "  provider-check    Run the Level 4 mock-provider contract.",
  ].join("\n");
}

function sortKeysDeep(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  const input = value as Record<string, unknown>;
  const output: Record<string, unknown> = {};
  for (const key of Object.keys(input).sort()) {
    output[key] = sortKeysDeep(input[key]);
  }
  return output;
}

function fixturePath(outDir: string, schemaRelpath: string): string {
  const separator = schemaRelpath.lastIndexOf("/");
  if (separator === -1) {
    throw new Error(`schema path must include a subdirectory: ${schemaRelpath}`);
  }
  const subdir = schemaRelpath.slice(0, separator);
  const schemaFile = schemaRelpath.slice(separator + 1);
  const schemaStem = schemaFile.replace(/\.json$/, "");
  return join(outDir, subdir, `${schemaStem}.warlog-spec-ts.json`);
}

function readOutDir(args: string[]): string | null {
  const outIndex = args.indexOf("--out");
  if (outIndex === -1) {
    return null;
  }
  const outDir = args[outIndex + 1];
  return outDir && outDir.length > 0 ? outDir : null;
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const [command] = argv;
  if (command === "--help" || command === "-h") {
    console.log(usage());
    return 0;
  }

  if (command !== "dump" && command !== "provider-check") {
    console.error(usage());
    return 2;
  }

  const outDir = readOutDir(argv);
  if (outDir === null) {
    console.error("Missing required --out <dir> argument.\n");
    console.error(usage());
    return 2;
  }

  if (command === "provider-check") {
    const report = await runMockProviderLevel4();
    mkdirSync(dirname(outDir), { recursive: true });
    writeFileSync(outDir, `${JSON.stringify(sortKeysDeep(report), null, 2)}\n`, "utf-8");
    console.error(`wrote ${outDir}`);
    return 0;
  }

  mkdirSync(outDir, { recursive: true });
  const fixtures = produceAll();
  for (const [schemaRelpath, example] of Object.entries(fixtures)) {
    const path = fixturePath(outDir, schemaRelpath);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(sortKeysDeep(example), null, 2)}\n`, "utf-8");
    console.error(`wrote ${path}`);
  }
  console.error(`\nDumped ${Object.keys(fixtures).length} fixtures to ${outDir}`);
  return 0;
}

function isCliEntrypoint(): boolean {
  const entrypoint = process.argv[1];
  return entrypoint !== undefined && resolve(entrypoint) === fileURLToPath(import.meta.url);
}

if (isCliEntrypoint()) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      console.error(error);
      process.exitCode = 1;
    });
}