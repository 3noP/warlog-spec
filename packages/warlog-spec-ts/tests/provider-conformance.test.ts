import { describe, expect, it } from "vitest";

import {
  ConnectorCapability,
  ConnectorError,
  ResponseActionResult,
  ResponseActionSpec,
} from "../src/provider-abi.js";
import { runMockProviderLevel4 } from "../src/provider-conformance.js";

describe("Level 4 mock-provider conformance", () => {
  it("produces a complete provider evidence report", async () => {
    const report = await runMockProviderLevel4();

    expect(report.specVersion).toBe("1.0");
    expect(report.level).toBe(4);
    expect(report.scenario.id).toBe("mock-vendor.host-isolate.v1");

    const capability = ConnectorCapability.parse(report.capability);
    const spec = ResponseActionSpec.parse(report.spec);
    const result = ResponseActionResult.parse(report.apply.result);
    const replay = ResponseActionResult.parse(report.idempotency.result);
    const unsupported = ConnectorError.parse(report.unsupportedAction.error);

    expect(capability.egress.supportsResponseActions).toContain(spec.actionId);
    expect(report.dryRun.mutationsBefore).toBe(0);
    expect(report.dryRun.mutationsAfter).toBe(0);
    expect(result.outcome).toBe("success");
    expect(report.verify.verified).toBe(true);
    expect(replay.outcome).toBe("success");
    expect(report.idempotency.mutationsAfterReplay).toBe(report.apply.mutationsAfter);
    expect(report.idempotency.sameVendorTask).toBe(true);
    expect(unsupported.category).toBe("policy");
  });
});