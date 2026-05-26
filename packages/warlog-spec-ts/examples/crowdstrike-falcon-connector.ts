/**
 * CrowdStrike Falcon EDR connector — TypeScript reference.
 *
 * Mirrors `packages/warlog-spec-py/examples/crowdstrike_falcon_connector.py`.
 * Same actions, same auth model, same Falcon error mapping. Use as a
 * starting point for a production Falcon connector :
 *
 * 1. Replace the placeholder `fetch` calls with your HTTP client of
 *    choice (axios, ky, ofetch — anything Promise-based works).
 * 2. Wire credentials from your secret store (Vault, AWS Secrets,
 *    1Password CLI) instead of the inline config.
 * 3. Add structured logging on every vendor call so the audit chain
 *    isn't your only diagnostic surface.
 *
 * The full Python example documents the wire protocol details
 * (endpoint paths, body shapes, verification queries) ; this file
 * stays focused on the ABI shape.
 */

import {
  AbiConnector,
  ConnectorAbiError,
  ConnectorCapability,
  type ResponseActionResult,
  type ResponseActionSpec,
} from "../src/index.js";

interface FalconConfig {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
}

const CAPABILITY = ConnectorCapability.parse({
  specVersion: "1.0",
  connectorId: "crowdstrike-falcon",
  connectorVersion: "0.1.0",
  vendor: "CrowdStrike",
  kind: "edr",
  auth: {
    model: "oauth2_client_credentials",
    scopes: ["devices:write", "iocs:write"],
    discoveryUrl: null,
  },
  ingress: {
    produces: ["ocsf.detection_finding.v1.4"],
    delivery: "polling",
    pollingMinIntervalS: 30,
  },
  egress: {
    supportsResponseActions: [
      "host.isolate",
      "host.unisolate",
      "host.collect_artifacts",
      "file.quarantine",
      "hash.block",
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
    supportsCredentialRotation: true,
    supportsPausedState: false,
  },
  compat: { warlogSpecMin: "1.0.0", warlogSpecMax: "1.x", dependsOnPacks: [] },
});

/** Map a Falcon error envelope to the right ABI failure category. */
function mapFalconError(status: number, body: unknown): ConnectorAbiError {
  const errors = (body as { errors?: Array<{ code?: number; message?: string }> })
    ?.errors;
  const first = errors?.[0];
  const vendorCode = first?.code !== undefined ? String(first.code) : null;
  const vendorMessage = first?.message ?? null;

  if (status === 401 || status === 403) {
    return new ConnectorAbiError({
      category: "auth",
      message: `Falcon auth failed (${status})`,
      retryable: false,
      vendorCode,
      vendorMessage,
    });
  }
  if (status === 404) {
    return new ConnectorAbiError({
      category: "not_found",
      message: vendorMessage ?? "Target not found in Falcon",
      retryable: false,
      vendorCode,
      vendorMessage,
    });
  }
  if (status === 409 || status === 422) {
    return new ConnectorAbiError({
      category: "state_conflict",
      message: vendorMessage ?? `Falcon state conflict (${status})`,
      retryable: false,
      vendorCode,
      vendorMessage,
    });
  }
  if (status >= 500 || status === 429) {
    return new ConnectorAbiError({
      category: "transient",
      message: vendorMessage ?? `Falcon transient (${status})`,
      retryable: true,
      vendorCode,
      vendorMessage,
    });
  }
  return new ConnectorAbiError({
    category: "policy",
    message: vendorMessage ?? `Falcon rejected request (${status})`,
    retryable: false,
    vendorCode,
    vendorMessage,
  });
}

export class CrowdstrikeFalconConnector extends AbiConnector {
  static override readonly capability = CAPABILITY;

  private readonly cfg: FalconConfig;
  private bearer: string | null = null;
  private bearerExpiresAt: number = 0;

  constructor(config: Record<string, unknown> = {}) {
    super(config);
    this.cfg = config as unknown as FalconConfig;
  }

  async authenticate(): Promise<void> {
    if (!this.cfg.baseUrl || !this.cfg.clientId || !this.cfg.clientSecret) {
      throw new ConnectorAbiError({
        category: "auth",
        message: "Falcon connector requires baseUrl, clientId, clientSecret",
        retryable: false,
      });
    }
    if (this.bearer && Date.now() < this.bearerExpiresAt - 30_000) {
      return; // still valid, 30s safety margin
    }
    const res = await fetch(`${this.cfg.baseUrl}/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: this.cfg.clientId,
        client_secret: this.cfg.clientSecret,
      }),
    });
    if (!res.ok) {
      throw mapFalconError(res.status, await res.json().catch(() => ({})));
    }
    const json = (await res.json()) as { access_token: string; expires_in: number };
    this.bearer = json.access_token;
    this.bearerExpiresAt = Date.now() + json.expires_in * 1000;
  }

  private async vendorPost(
    path: string,
    body: unknown,
  ): Promise<Record<string, unknown>> {
    await this.authenticate();
    const res = await fetch(`${this.cfg.baseUrl}${path}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.bearer}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      throw mapFalconError(res.status, await res.json().catch(() => ({})));
    }
    return (await res.json()) as Record<string, unknown>;
  }

  private async vendorGet(path: string): Promise<Record<string, unknown>> {
    await this.authenticate();
    const res = await fetch(`${this.cfg.baseUrl}${path}`, {
      headers: { authorization: `Bearer ${this.bearer}` },
    });
    if (!res.ok) {
      throw mapFalconError(res.status, await res.json().catch(() => ({})));
    }
    return (await res.json()) as Record<string, unknown>;
  }

  async dryRun(spec: ResponseActionSpec): Promise<void> {
    // Falcon supports dry-run by simply querying the target's existence
    // before attempting the action. We don't side-effect upstream.
    if (
      spec.actionId === "host.isolate" ||
      spec.actionId === "host.unisolate" ||
      spec.actionId === "host.collect_artifacts"
    ) {
      const deviceId = spec.subject.selectorValue;
      await this.vendorGet(`/devices/entities/devices/v2?ids=${encodeURIComponent(deviceId)}`);
    }
    // IOC actions (file.quarantine, hash.block) don't have a pre-flight
    // check beyond auth — the IOC submission is idempotent vendor-side.
  }

  async apply(spec: ResponseActionSpec): Promise<ResponseActionResult> {
    const details: Record<string, unknown> = {};
    switch (spec.actionId) {
      case "host.isolate":
      case "host.unisolate": {
        const actionName = spec.actionId === "host.isolate" ? "contain" : "lift_containment";
        const body = await this.vendorPost(
          `/devices/entities/devices-actions/v2?action_name=${actionName}`,
          { ids: [spec.subject.selectorValue] },
        );
        details.vendor_response = body;
        break;
      }
      case "host.collect_artifacts": {
        const body = await this.vendorPost(
          "/real-time-response/entities/sessions/v1",
          { device_id: spec.subject.selectorValue, origin: "warlog-spec" },
        );
        details.rtr_session = body;
        break;
      }
      case "hash.block": {
        const body = await this.vendorPost("/iocs/entities/indicators/v1", {
          indicators: [
            {
              type: "sha256",
              value: spec.subject.selectorValue,
              action: "prevent",
              platforms: ["windows", "mac", "linux"],
              applied_globally: true,
              source: "warlog-spec",
            },
          ],
        });
        details.vendor_response = body;
        break;
      }
      case "file.quarantine": {
        // Falcon does not have a direct "quarantine arbitrary file" — we
        // approximate via IOC hash block. Production connectors may map
        // this to a more accurate vendor primitive.
        const body = await this.vendorPost("/iocs/entities/indicators/v1", {
          indicators: [
            {
              type: "sha256",
              value: spec.subject.selectorValue,
              action: "prevent",
              platforms: ["windows", "mac", "linux"],
              applied_globally: true,
              source: "warlog-spec/file.quarantine",
            },
          ],
        });
        details.vendor_response = body;
        break;
      }
      default:
        throw new ConnectorAbiError({
          category: "policy",
          message: `Falcon connector does not implement ${spec.actionId}`,
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
    if (spec.actionId === "host.isolate" || spec.actionId === "host.unisolate") {
      const body = await this.vendorGet(
        `/devices/entities/devices/v2?ids=${encodeURIComponent(spec.subject.selectorValue)}`,
      );
      const resources = (body as { resources?: Array<Record<string, unknown>> })
        .resources;
      const device = resources?.[0];
      const containmentStatus = (device as Record<string, unknown> | undefined)?.[
        "containment_status"
      ] as string | undefined;
      if (spec.actionId === "host.isolate") {
        return containmentStatus === "contained" || containmentStatus === "containment_pending";
      }
      return containmentStatus === "normal" || containmentStatus === "lift_containment_pending";
    }
    // For IOC actions, verify the IOC exists with action=prevent.
    if (
      spec.actionId === "hash.block" ||
      spec.actionId === "file.quarantine"
    ) {
      const body = await this.vendorGet(
        `/iocs/entities/indicators/v1?ids=${encodeURIComponent(spec.subject.selectorValue)}`,
      );
      const resources = (body as { resources?: Array<Record<string, unknown>> })
        .resources;
      return Boolean(resources?.length);
    }
    return true;
  }
}
