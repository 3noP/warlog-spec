/**
 * AbiConnector ABC tests via the EchoEdrConnector reference impl.
 *
 * Exercises :
 *   - authenticate failure when config is missing
 *   - dryRun rejects unknown hosts (not_found)
 *   - dryRun rejects already-isolated hosts (state_conflict)
 *   - full happy lifecycle on a known host
 *   - verify reflects upstream state after apply
 */

import { describe, expect, it } from "vitest";

import { EchoEdrConnector } from "../examples/echo-connector.js";
import { ConnectorAbiError } from "../src/abi.js";
import type { ResponseActionSpec } from "../src/index.js";

function spec(
  action: "host.isolate" | "host.unisolate",
  host: string,
): ResponseActionSpec {
  return {
    specVersion: "1.0",
    actionId: action,
    subject: {
      kind: "endpoint",
      selectorType: "agent_id",
      selectorValue: host,
      selectorRepresentation: "raw",
      selectorKeyId: null,
    },
    params: {},
    approval: {
      required: false,
      level: "analyst",
      rationale: "test",
    },
    dryRun: false,
    idempotencyKey: `idem-${action}-${host}`,
    expiresAt: null,
  };
}

describe("AbiConnector — EchoEdrConnector reference", () => {
  it("authenticate fails when apiKey is missing", async () => {
    const connector = new EchoEdrConnector({});
    await expect(connector.authenticate()).rejects.toThrowError(
      ConnectorAbiError,
    );
    try {
      await connector.authenticate();
    } catch (err) {
      expect((err as ConnectorAbiError).category).toEqual("auth");
      expect((err as ConnectorAbiError).retryable).toBe(false);
    }
  });

  it("authenticate succeeds with apiKey set", async () => {
    const connector = new EchoEdrConnector({
      apiKey: "k",
      knownHosts: ["h1"],
    });
    await expect(connector.authenticate()).resolves.toBeUndefined();
  });

  it("dryRun rejects an unknown host with category=not_found", async () => {
    const connector = new EchoEdrConnector({
      apiKey: "k",
      knownHosts: ["h1"],
    });
    await connector.authenticate();
    try {
      await connector.dryRun(spec("host.isolate", "unknown-host"));
      expect.fail("expected ConnectorAbiError");
    } catch (err) {
      expect(err).toBeInstanceOf(ConnectorAbiError);
      expect((err as ConnectorAbiError).category).toEqual("not_found");
    }
  });

  it("dryRun rejects already-isolated host with category=state_conflict", async () => {
    const connector = new EchoEdrConnector({
      apiKey: "k",
      knownHosts: ["h1"],
      alreadyIsolated: ["h1"],
    });
    await connector.authenticate();
    try {
      await connector.dryRun(spec("host.isolate", "h1"));
      expect.fail("expected ConnectorAbiError");
    } catch (err) {
      expect(err).toBeInstanceOf(ConnectorAbiError);
      expect((err as ConnectorAbiError).category).toEqual("state_conflict");
    }
  });

  it("full lifecycle : authenticate → dryRun → apply → verify", async () => {
    const connector = new EchoEdrConnector({
      apiKey: "k",
      knownHosts: ["h1"],
    });
    await connector.authenticate();
    const isolateSpec = spec("host.isolate", "h1");
    await expect(connector.dryRun(isolateSpec)).resolves.toBeUndefined();
    const result = await connector.apply(isolateSpec);
    expect(result.outcome).toEqual("success");
    expect(connector.isIsolated("h1")).toBe(true);
    await expect(connector.verify(isolateSpec, result)).resolves.toBe(true);

    // Unisolate cycle inverts the state.
    const unisolateSpec = spec("host.unisolate", "h1");
    await connector.dryRun(unisolateSpec);
    const r2 = await connector.apply(unisolateSpec);
    expect(r2.outcome).toEqual("success");
    expect(connector.isIsolated("h1")).toBe(false);
    await expect(connector.verify(unisolateSpec, r2)).resolves.toBe(true);
  });

  it("ConnectorAbiError.toConnectorError() serializes to the wire shape", () => {
    const err = new ConnectorAbiError({
      category: "transient",
      message: "vendor returned 502",
      vendorCode: "BAD_GATEWAY",
      vendorMessage: "Upstream temporarily unavailable",
    });
    const wire = err.toConnectorError();
    expect(wire.category).toEqual("transient");
    expect(wire.retryable).toBe(true); // default for transient
    expect(wire.vendorCode).toEqual("BAD_GATEWAY");
    expect(wire.specVersion).toEqual("1.0");
  });
});
