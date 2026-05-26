/**
 * Echo connector — minimal reference implementation that exercises
 * the ABI lifecycle without talking to any real vendor. Mirrors
 * `packages/warlog-spec-py/examples/echo_connector.py`.
 *
 * Use it as a starting point for your own connector :
 *
 * 1. Replace the in-memory state with calls to your vendor SDK.
 * 2. Tighten the capability manifest (action_ids, auth model,
 *    dry_run scope).
 * 3. Implement real authenticate / dryRun / apply / verify logic.
 * 4. Map upstream failures to ``ConnectorAbiError`` with the right
 *    category so the runner records them faithfully in the audit
 *    chain.
 *
 * Run :
 *
 *     tsx examples/echo-connector.ts
 */

import {
  AbiConnector,
  ConnectorAbiError,
  ConnectorCapability,
  type ResponseActionResult,
  type ResponseActionSpec,
} from "../src/index.js";

const CAPABILITY = ConnectorCapability.parse({
  specVersion: "1.0",
  connectorId: "echo-edr",
  connectorVersion: "0.1.0",
  vendor: "Echo Reference",
  kind: "edr",
  auth: {
    model: "api_key",
    scopes: ["host.read", "host.respond"],
    discoveryUrl: null,
  },
  ingress: {
    produces: [],
    delivery: "polling",
    pollingMinIntervalS: null,
  },
  egress: {
    supportsResponseActions: ["host.isolate", "host.unisolate"],
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
    supportsHealthCheck: false,
    supportsCredentialRotation: false,
    supportsPausedState: false,
  },
  compat: { warlogSpecMin: "1.0.0", warlogSpecMax: "1.x", dependsOnPacks: [] },
});

interface EchoConfig {
  apiKey?: string;
  knownHosts?: string[];
  alreadyIsolated?: string[];
}

/**
 * Echoes back what was asked. Production connectors call the vendor
 * SDK instead ; the lifecycle shape and the failure mapping stay
 * identical.
 */
export class EchoEdrConnector extends AbiConnector {
  static override readonly capability = CAPABILITY;

  private readonly cfg: EchoConfig;
  private readonly isolated: Set<string>;

  constructor(config: Record<string, unknown> = {}) {
    super(config);
    this.cfg = config as EchoConfig;
    this.isolated = new Set(this.cfg.alreadyIsolated ?? []);
  }

  async authenticate(): Promise<void> {
    if (!this.cfg.apiKey) {
      throw new ConnectorAbiError({
        category: "auth",
        message: "Echo connector requires an apiKey in config",
        retryable: false,
      });
    }
  }

  async dryRun(spec: ResponseActionSpec): Promise<void> {
    const host = spec.subject.selectorValue;
    if (
      this.cfg.knownHosts &&
      !this.cfg.knownHosts.includes(host)
    ) {
      throw new ConnectorAbiError({
        category: "not_found",
        message: `Host ${host} is not known to this Echo connector`,
        retryable: false,
      });
    }
    if (
      spec.actionId === "host.isolate" &&
      this.isolated.has(host)
    ) {
      throw new ConnectorAbiError({
        category: "state_conflict",
        message: `Host ${host} is already isolated`,
        retryable: false,
      });
    }
  }

  async apply(spec: ResponseActionSpec): Promise<ResponseActionResult> {
    const host = spec.subject.selectorValue;
    if (spec.actionId === "host.isolate") {
      this.isolated.add(host);
    } else if (spec.actionId === "host.unisolate") {
      this.isolated.delete(host);
    }
    return {
      specVersion: "1.0",
      executionId: "",
      actionId: spec.actionId,
      outcome: "success",
      subject: spec.subject,
      details: { echoed: true, host },
      error: null,
    };
  }

  async verify(
    spec: ResponseActionSpec,
    _result: ResponseActionResult,
  ): Promise<boolean> {
    const host = spec.subject.selectorValue;
    if (spec.actionId === "host.isolate") return this.isolated.has(host);
    if (spec.actionId === "host.unisolate") return !this.isolated.has(host);
    return true;
  }

  isIsolated(host: string): boolean {
    return this.isolated.has(host);
  }
}

// ----------------------------------------------------------------------------
// CLI demo — exercises the lifecycle end-to-end without a runner
// ----------------------------------------------------------------------------

async function demo(): Promise<void> {
  const connector = new EchoEdrConnector({
    apiKey: "demo-key",
    knownHosts: ["agent-007"],
  });

  await connector.authenticate();
  console.log("authenticate OK");

  const spec: ResponseActionSpec = {
    specVersion: "1.0",
    actionId: "host.isolate",
    subject: {
      kind: "endpoint",
      selectorType: "agent_id",
      selectorValue: "agent-007",
      selectorRepresentation: "raw",
      selectorKeyId: null,
    },
    params: { reason: "Echo demo" },
    approval: {
      required: false,
      level: "analyst",
      rationale: "demo",
    },
    dryRun: false,
    idempotencyKey: "demo-idem-001",
    expiresAt: null,
  };

  await connector.dryRun(spec);
  console.log("dryRun OK");

  const result = await connector.apply(spec);
  console.log(`apply : outcome=${result.outcome}, host=${result.details.host}`);

  const verified = await connector.verify(spec, result);
  console.log(`verify : isolated=${verified}`);
}

// Only run when executed directly (not when imported).
if (import.meta.url === `file://${process.argv[1]}`) {
  demo().catch((err) => {
    console.error(err);
    process.exitCode = 1;
  });
}
