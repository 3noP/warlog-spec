/**
 * Reference connector tests — exercise the ABI contract against
 * mocked vendor APIs.
 *
 * The tests don't care about the exact HTTP shape Falcon / Okta use ;
 * they validate that :
 *
 * 1. The connector's capability declares the right action set.
 * 2. `authenticate` rejects missing config with category=auth.
 * 3. `dryRun` calls the vendor (proven by mock call count).
 * 4. `apply` returns outcome=success with vendor details.
 * 5. Error responses from the vendor map to the correct
 *    ConnectorAbiError category.
 * 6. (Okta) PII pseudonymization gate : a pseudonymized selector
 *    without a resolveSubject callback raises category=policy.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CrowdstrikeFalconConnector } from "../examples/crowdstrike-falcon-connector.js";
import { OktaUserResponseConnector } from "../examples/okta-user-response-connector.js";
import {
  ConnectorAbiError,
  type ResponseActionSpec,
} from "../src/index.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function noContent(): Response {
  return new Response(null, { status: 204 });
}

function spec(
  actionId: ResponseActionSpec["actionId"],
  selectorKind: ResponseActionSpec["subject"]["kind"],
  selectorValue: string,
  options: Partial<ResponseActionSpec["subject"]> = {},
): ResponseActionSpec {
  return {
    specVersion: "1.0",
    actionId,
    subject: {
      kind: selectorKind,
      selectorType: selectorKind === "identity" ? "user_principal_name" : "agent_id",
      selectorValue,
      selectorRepresentation: "raw",
      selectorKeyId: null,
      ...options,
    },
    params: {},
    approval: {
      required: false,
      level: "analyst",
      rationale: "test",
    },
    dryRun: false,
    idempotencyKey: `idem-${actionId}-${selectorValue}`,
    expiresAt: null,
  };
}

// ============================================================================
// CrowdStrike Falcon
// ============================================================================

describe("CrowdstrikeFalconConnector — capability", () => {
  it("declares the canonical EDR action subset", () => {
    const actions = CrowdstrikeFalconConnector.capability.egress
      .supportsResponseActions;
    expect(actions).toContain("host.isolate");
    expect(actions).toContain("host.unisolate");
    expect(actions).toContain("hash.block");
    expect(actions).toHaveLength(5);
  });

  it("declares OAuth2 client credentials auth", () => {
    expect(CrowdstrikeFalconConnector.capability.auth.model).toEqual(
      "oauth2_client_credentials",
    );
  });
});

describe("CrowdstrikeFalconConnector — lifecycle", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("authenticate fails without config", async () => {
    const c = new CrowdstrikeFalconConnector({});
    await expect(c.authenticate()).rejects.toBeInstanceOf(ConnectorAbiError);
  });

  it("authenticate exchanges credentials for a bearer", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { access_token: "tok-123", expires_in: 1800 }),
    );
    const c = new CrowdstrikeFalconConnector({
      baseUrl: "https://api.us-2.crowdstrike.com",
      clientId: "id",
      clientSecret: "secret",
    });
    await c.authenticate();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]![0]).toContain("/oauth2/token");
  });

  it("authenticate maps 401 to category=auth", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(401, { errors: [{ code: 401, message: "Invalid client" }] }),
    );
    const c = new CrowdstrikeFalconConnector({
      baseUrl: "https://api.us-2.crowdstrike.com",
      clientId: "id",
      clientSecret: "bad",
    });
    try {
      await c.authenticate();
      expect.fail("expected ConnectorAbiError");
    } catch (err) {
      expect(err).toBeInstanceOf(ConnectorAbiError);
      expect((err as ConnectorAbiError).category).toEqual("auth");
      expect((err as ConnectorAbiError).vendorCode).toEqual("401");
    }
  });

  it("host.isolate full lifecycle", async () => {
    // 1. auth, 2. dryRun GET device, 3. apply POST action, 4. verify GET device
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, { access_token: "tok", expires_in: 1800 }))
      .mockResolvedValueOnce(jsonResponse(200, { resources: [{ device_id: "host-1" }] }))
      .mockResolvedValueOnce(jsonResponse(200, { resources: ["action-id-1"], meta: { writes: { resources_affected: 1 } } }))
      .mockResolvedValueOnce(
        jsonResponse(200, {
          resources: [{ device_id: "host-1", containment_status: "contained" }],
        }),
      );

    const c = new CrowdstrikeFalconConnector({
      baseUrl: "https://api.us-2.crowdstrike.com",
      clientId: "id",
      clientSecret: "secret",
    });
    const isolateSpec = spec("host.isolate", "endpoint", "host-1");
    await c.authenticate();
    await c.dryRun(isolateSpec);
    const result = await c.apply(isolateSpec);
    expect(result.outcome).toEqual("success");
    const verified = await c.verify(isolateSpec, result);
    expect(verified).toBe(true);
  });

  it("host.isolate 404 maps to category=not_found at dryRun", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, { access_token: "tok", expires_in: 1800 }))
      .mockResolvedValueOnce(
        jsonResponse(404, { errors: [{ code: 404, message: "Device not found" }] }),
      );

    const c = new CrowdstrikeFalconConnector({
      baseUrl: "https://api.us-2.crowdstrike.com",
      clientId: "id",
      clientSecret: "secret",
    });
    await c.authenticate();
    try {
      await c.dryRun(spec("host.isolate", "endpoint", "unknown"));
      expect.fail("expected ConnectorAbiError");
    } catch (err) {
      expect(err).toBeInstanceOf(ConnectorAbiError);
      expect((err as ConnectorAbiError).category).toEqual("not_found");
    }
  });
});

// ============================================================================
// Okta
// ============================================================================

describe("OktaUserResponseConnector — capability", () => {
  it("declares the canonical identity action subset", () => {
    const actions = OktaUserResponseConnector.capability.egress
      .supportsResponseActions;
    expect(actions).toContain("user.disable");
    expect(actions).toContain("user.force_logout");
    expect(actions).toContain("user.reset_mfa");
    expect(actions).toContain("user.revoke_tokens");
    expect(actions).toContain("user.reset_password");
    expect(actions).toHaveLength(5);
  });

  it("declares api_key auth", () => {
    expect(OktaUserResponseConnector.capability.auth.model).toEqual("api_key");
  });
});

describe("OktaUserResponseConnector — lifecycle", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("authenticate fails without config", async () => {
    const c = new OktaUserResponseConnector({});
    await expect(c.authenticate()).rejects.toBeInstanceOf(ConnectorAbiError);
  });

  it("authenticate health-checks via /users/me", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { id: "me", status: "ACTIVE" }));
    const c = new OktaUserResponseConnector({
      baseUrl: "https://tenant.okta.com",
      apiToken: "tok",
    });
    await c.authenticate();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]![0]).toContain("/api/v1/users/me");
    // Authorization header MUST use SSWS scheme.
    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>).authorization).toMatch(/^SSWS /);
  });

  it("user.disable full lifecycle with raw selector", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, { id: "me", status: "ACTIVE" })) // authenticate
      .mockResolvedValueOnce(jsonResponse(200, { id: "user-1", status: "ACTIVE" })) // dryRun GET
      .mockResolvedValueOnce(noContent()) // apply POST suspend
      .mockResolvedValueOnce(jsonResponse(200, { id: "user-1", status: "SUSPENDED" })); // verify GET

    const c = new OktaUserResponseConnector({
      baseUrl: "https://tenant.okta.com",
      apiToken: "tok",
    });
    const disableSpec = spec("user.disable", "identity", "user-1");
    await c.authenticate();
    await c.dryRun(disableSpec);
    const result = await c.apply(disableSpec);
    expect(result.outcome).toEqual("success");
    expect(result.details.userId).toEqual("user-1");
    const verified = await c.verify(disableSpec, result);
    expect(verified).toBe(true);
  });

  it("user.disable rejects pseudonymized selector without resolveSubject callback", async () => {
    // authenticate runs first
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { id: "me", status: "ACTIVE" }));
    const c = new OktaUserResponseConnector({
      baseUrl: "https://tenant.okta.com",
      apiToken: "tok",
    });
    await c.authenticate();
    const pseudonymized = spec("user.disable", "identity", "c".repeat(64), {
      selectorRepresentation: "sha256_salted",
      selectorKeyId: "tenant:t:salt:v1",
    });
    try {
      await c.dryRun(pseudonymized);
      expect.fail("expected ConnectorAbiError");
    } catch (err) {
      expect(err).toBeInstanceOf(ConnectorAbiError);
      expect((err as ConnectorAbiError).category).toEqual("policy");
      expect((err as ConnectorAbiError).vendorCode).toEqual(
        "warlog.okta.resolver_missing",
      );
    }
  });

  it("user.disable resolves pseudonymized selector via callback", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, { id: "me", status: "ACTIVE" }))
      .mockResolvedValueOnce(jsonResponse(200, { id: "user-1", status: "ACTIVE" }));

    const resolveSubject = vi
      .fn()
      .mockImplementation(async (h: string) => `resolved:${h.slice(0, 8)}`);

    const c = new OktaUserResponseConnector({
      baseUrl: "https://tenant.okta.com",
      apiToken: "tok",
      resolveSubject,
    });
    await c.authenticate();
    await c.dryRun(
      spec("user.disable", "identity", "c".repeat(64), {
        selectorRepresentation: "sha256_salted",
        selectorKeyId: "tenant:t:salt:v1",
      }),
    );
    expect(resolveSubject).toHaveBeenCalledTimes(1);
    expect(resolveSubject.mock.calls[0]![0]).toEqual("c".repeat(64));
  });

  it("user.disable already-suspended → category=state_conflict", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(200, { id: "me", status: "ACTIVE" })) // authenticate
      .mockResolvedValueOnce(jsonResponse(200, { id: "user-1", status: "SUSPENDED" })); // dryRun

    const c = new OktaUserResponseConnector({
      baseUrl: "https://tenant.okta.com",
      apiToken: "tok",
    });
    await c.authenticate();
    try {
      await c.dryRun(spec("user.disable", "identity", "user-1"));
      expect.fail("expected ConnectorAbiError");
    } catch (err) {
      expect(err).toBeInstanceOf(ConnectorAbiError);
      expect((err as ConnectorAbiError).category).toEqual("state_conflict");
    }
  });
});
