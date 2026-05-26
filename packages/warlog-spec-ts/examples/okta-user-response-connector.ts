/**
 * Okta identity response connector — TypeScript reference.
 *
 * Mirrors `packages/warlog-spec-py/examples/okta_user_response_connector.py`.
 * Covers the canonical identity sub-graph of the ABI :
 *
 * - user.disable          → POST /api/v1/users/{id}/lifecycle/suspend
 * - user.force_logout     → DELETE /api/v1/users/{id}/sessions
 * - user.reset_mfa        → POST /api/v1/users/{id}/lifecycle/reset_factors
 * - user.revoke_tokens    → POST /api/v1/users/{id}/lifecycle/clear_sessions + tokens
 * - user.reset_password   → POST /api/v1/users/{id}/lifecycle/reset_password
 *
 * Auth model is SSWS API token : ``Authorization: SSWS <token>``. The
 * token is long-lived ; rotation is operator-driven.
 *
 * PII pseudonymization gate :
 *
 * The runtime requires identity-family actions to carry
 * ``selectorRepresentation = sha256_salted`` (RFC-0001 §C). The
 * connector receives the hash, NOT the plaintext UPN. To call the
 * vendor API it MUST resolve the hash → upn via a tenant-side
 * secret store. This example takes a ``resolveSubject`` callback in
 * config — production connectors typically inject a Vault-backed
 * resolver.
 *
 * Configuration shape :
 *
 *     {
 *       "baseUrl": "https://your-tenant.okta.com",
 *       "apiToken": "00abc...",
 *       "resolveSubject": async (hashedValue) => "alice@warlog.demo"
 *     }
 */

import {
  AbiConnector,
  ConnectorAbiError,
  ConnectorCapability,
  type ResponseActionResult,
  type ResponseActionSpec,
} from "../src/index.js";

type SubjectResolver = (hashedValue: string) => Promise<string>;

interface OktaConfig {
  baseUrl: string;
  apiToken: string;
  resolveSubject?: SubjectResolver;
}

const CAPABILITY = ConnectorCapability.parse({
  specVersion: "1.0",
  connectorId: "okta",
  connectorVersion: "0.1.0",
  vendor: "Okta",
  kind: "iam",
  auth: {
    model: "api_key",
    scopes: ["okta.users.manage", "okta.sessions.manage"],
    discoveryUrl: null,
  },
  ingress: {
    produces: ["ocsf.account_change.v1.4"],
    delivery: "polling",
    pollingMinIntervalS: 60,
  },
  egress: {
    supportsResponseActions: [
      "user.disable",
      "user.force_logout",
      "user.reset_mfa",
      "user.revoke_tokens",
      "user.reset_password",
    ],
  },
  enrichment: {
    producesArtifactTypes: [],
    supportsEntityTypes: [],
    supportsIocTypes: [],
    freshness: "unknown",
    bulkLookup: false,
  },
  dryRun: { supported: true, scope: "egress" },
  lifecycle: {
    supportsHealthCheck: true,
    supportsCredentialRotation: false,
    supportsPausedState: false,
  },
  compat: { warlogSpecMin: "1.0.0", warlogSpecMax: "1.x", dependsOnPacks: [] },
});

function mapOktaError(status: number, body: unknown): ConnectorAbiError {
  const oktaErr = body as {
    errorCode?: string;
    errorSummary?: string;
  } | undefined;
  const vendorCode = oktaErr?.errorCode ?? null;
  const vendorMessage = oktaErr?.errorSummary ?? null;

  if (status === 401 || status === 403) {
    return new ConnectorAbiError({
      category: "auth",
      message: `Okta auth failed (${status})`,
      retryable: false,
      vendorCode,
      vendorMessage,
    });
  }
  if (status === 404) {
    return new ConnectorAbiError({
      category: "not_found",
      message: vendorMessage ?? "Okta user not found",
      retryable: false,
      vendorCode,
      vendorMessage,
    });
  }
  // Okta returns 400 with E0000016 for "Activation failed - user already active",
  // E0000031 for "already disabled", etc. Map those to state_conflict.
  if (status === 400 && vendorCode && vendorCode.startsWith("E000003")) {
    return new ConnectorAbiError({
      category: "state_conflict",
      message: vendorMessage ?? "Okta state conflict",
      retryable: false,
      vendorCode,
      vendorMessage,
    });
  }
  if (status === 429 || status >= 500) {
    return new ConnectorAbiError({
      category: "transient",
      message: vendorMessage ?? `Okta transient (${status})`,
      retryable: true,
      vendorCode,
      vendorMessage,
    });
  }
  return new ConnectorAbiError({
    category: "policy",
    message: vendorMessage ?? `Okta rejected request (${status})`,
    retryable: false,
    vendorCode,
    vendorMessage,
  });
}

export class OktaUserResponseConnector extends AbiConnector {
  static override readonly capability = CAPABILITY;

  private readonly cfg: OktaConfig;

  constructor(config: Record<string, unknown> = {}) {
    super(config);
    this.cfg = config as unknown as OktaConfig;
  }

  async authenticate(): Promise<void> {
    if (!this.cfg.baseUrl || !this.cfg.apiToken) {
      throw new ConnectorAbiError({
        category: "auth",
        message: "Okta connector requires baseUrl and apiToken",
        retryable: false,
      });
    }
    // Health-check : GET /api/v1/users/me. Authoritative auth check
    // without side effects.
    const res = await fetch(`${this.cfg.baseUrl}/api/v1/users/me`, {
      headers: { authorization: `SSWS ${this.cfg.apiToken}` },
    });
    if (!res.ok) {
      throw mapOktaError(res.status, await res.json().catch(() => ({})));
    }
  }

  /**
   * Resolve the pseudonymized selector to the upstream user id /
   * login. Production connectors MUST plug into a tenant-side secret
   * lookup (Vault, KMS-encrypted DB). This example accepts a
   * callback in config.
   */
  private async resolveUserId(spec: ResponseActionSpec): Promise<string> {
    if (spec.subject.selectorRepresentation === "raw") {
      return spec.subject.selectorValue;
    }
    if (!this.cfg.resolveSubject) {
      throw new ConnectorAbiError({
        category: "policy",
        message:
          "Okta connector received a pseudonymized selector but no " +
          "resolveSubject callback was configured. Pseudonymized subjects " +
          "require a tenant-side hash→identity lookup.",
        retryable: false,
        vendorCode: "warlog.okta.resolver_missing",
      });
    }
    return this.cfg.resolveSubject(spec.subject.selectorValue);
  }

  private async vendorRequest(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<Record<string, unknown> | null> {
    const init: RequestInit = {
      method,
      headers: {
        authorization: `SSWS ${this.cfg.apiToken}`,
        accept: "application/json",
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
      },
    };
    if (body !== undefined) init.body = JSON.stringify(body);
    const res = await fetch(`${this.cfg.baseUrl}${path}`, init);
    if (!res.ok) {
      throw mapOktaError(res.status, await res.json().catch(() => ({})));
    }
    // Some Okta lifecycle endpoints return 204 No Content.
    if (res.status === 204) return null;
    return (await res.json()) as Record<string, unknown>;
  }

  async dryRun(spec: ResponseActionSpec): Promise<void> {
    const userId = await this.resolveUserId(spec);
    // GET the user to confirm existence + current state.
    const user = await this.vendorRequest("GET", `/api/v1/users/${encodeURIComponent(userId)}`);
    const status = (user as { status?: string } | null)?.status;

    if (spec.actionId === "user.disable" && status === "SUSPENDED") {
      throw new ConnectorAbiError({
        category: "state_conflict",
        message: `Okta user ${userId} is already suspended`,
        retryable: false,
        vendorCode: "warlog.okta.already_suspended",
      });
    }
  }

  async apply(spec: ResponseActionSpec): Promise<ResponseActionResult> {
    const userId = await this.resolveUserId(spec);
    const details: Record<string, unknown> = { userId };

    switch (spec.actionId) {
      case "user.disable":
        await this.vendorRequest(
          "POST",
          `/api/v1/users/${encodeURIComponent(userId)}/lifecycle/suspend`,
        );
        break;
      case "user.force_logout":
        await this.vendorRequest(
          "DELETE",
          `/api/v1/users/${encodeURIComponent(userId)}/sessions`,
        );
        break;
      case "user.reset_mfa":
        await this.vendorRequest(
          "POST",
          `/api/v1/users/${encodeURIComponent(userId)}/lifecycle/reset_factors`,
        );
        break;
      case "user.revoke_tokens":
        // Okta combines session clearing + token revocation via
        // clear_sessions with ?oauthTokens=true.
        await this.vendorRequest(
          "POST",
          `/api/v1/users/${encodeURIComponent(userId)}/clearSessions?oauthTokens=true`,
        );
        break;
      case "user.reset_password": {
        const resp = await this.vendorRequest(
          "POST",
          `/api/v1/users/${encodeURIComponent(userId)}/lifecycle/reset_password?sendEmail=true`,
        );
        if (resp) details.reset_response = resp;
        break;
      }
      default:
        throw new ConnectorAbiError({
          category: "policy",
          message: `Okta connector does not implement ${spec.actionId}`,
          retryable: false,
        });
    }

    return {
      specVersion: "1.0",
      executionId: "",
      actionId: spec.actionId,
      outcome: "success",
      subject: spec.subject,
      details,
      error: null,
    };
  }

  async verify(
    spec: ResponseActionSpec,
    _result: ResponseActionResult,
  ): Promise<boolean> {
    const userId = await this.resolveUserId(spec);
    const user = await this.vendorRequest(
      "GET",
      `/api/v1/users/${encodeURIComponent(userId)}`,
    );
    const status = (user as { status?: string } | null)?.status;

    if (spec.actionId === "user.disable") {
      return status === "SUSPENDED";
    }
    // For session/MFA/token actions, verification on the GET shape is
    // weaker — Okta doesn't surface "last-revoked-at" cleanly. We
    // return true unconditionally and rely on the apply call's
    // success status. Production connectors may add a custom check.
    return true;
  }
}
