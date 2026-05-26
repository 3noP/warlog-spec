import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { main } from "../src/cli.js";

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

describe("warlog-spec CLI", () => {
  it("dumps Level 2 fixtures in the conformance runner layout", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "warlog-spec-cli-"));
    tmpDirs.push(outDir);
    vi.spyOn(console, "error").mockImplementation(() => undefined);

    const code = await main(["dump", "--out", outDir]);

    expect(code).toBe(0);
    const fixturePath = join(
      outDir,
      "provider-abi",
      "signed-audit-row.warlog-spec-ts.json",
    );
    expect(existsSync(fixturePath)).toBe(true);

    const fixture = JSON.parse(readFileSync(fixturePath, "utf-8")) as {
      attestation?: { signatureValue?: string };
    };
    expect(fixture.attestation?.signatureValue).toMatch(/^[a-f0-9]{64}$/);
  });

  it("writes a Level 4 provider report", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "warlog-spec-cli-"));
    tmpDirs.push(outDir);
    const reportPath = join(outDir, "provider-report.json");
    vi.spyOn(console, "error").mockImplementation(() => undefined);

    const code = await main(["provider-check", "--out", reportPath]);

    expect(code).toBe(0);
    const report = JSON.parse(readFileSync(reportPath, "utf-8")) as {
      level?: number;
      verify?: { verified?: boolean };
    };
    expect(report.level).toBe(4);
    expect(report.verify?.verified).toBe(true);
  });

  it("returns a usage error when --out is missing", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);

    await expect(main(["dump"])).resolves.toBe(2);
  });
});