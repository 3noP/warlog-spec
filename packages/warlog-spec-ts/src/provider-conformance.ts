import { createHash } from "node:crypto";

import { AbiConnector, ConnectorAbiError } from "./abi.js";
import {
  ConnectorCapability,
  ResponseActionResult,
  ResponseActionSpec,
  type ConnectorCapability as ConnectorCapabilityModel,
  type ConnectorError,
  type ResponseActionResult as ResponseActionResultModel,
  type ResponseActionSpec as ResponseActionSpecModel,
} from "./provider-abi.js";

export const MOCK_VENDOR_ID = "warlog.mock-response-vendor.v1";
export const MOCK_PROVIDER_SCENARIO_ID = "mock-vendor.host-isolate.v1";
export const MOCK_HOST_ID = "host-001";
export const MOCK_IDEMPOTENCY_KEY = "mock-provider-host-isolate-001";

type MockHost = { isolated: boolean };

export type ProviderConnectorClass = {
  new (config?: Record<string, unknown>): AbiConnector;
  readonly capability: ConnectorCapabilityModel;
};

export interface Level4ProviderReport {
  specVersion: "1.0";
  level: 4;
  implementation: {
    name: string;
    version: string;
    language: string;
  };
  scenario: {
    id: string;
    mockVendor: string;
    actionId: string;
  };
  capability: ConnectorCapabilityModel;
  spec: ResponseActionSpecModel;
  dryRun: {
    called: boolean;
    mutationsBefore: number;
    mutationsAfter: number;
  };
  apply: {
    called: boolean;
    result: ResponseActionResultModel;
    mutationsAfter: number;
  };
  verify: {
    called: boolean;
    verified: boolean;
  };
  idempotency: {
    replayed: boolean;
    result: ResponseActionResultModel;
    mutationsAfterReplay: number;
    sameVendorTask: boolean;
  };
  unsupportedAction: {
    rejected: boolean;
    error: ConnectorError | null;
  };
}

export class MockResponseVendor {
  readonly apiKey: string;
  readonly hosts = new Map<string, MockHost>([
    [MOCK_HOST_ID, { isolated: false }],
  ]);
  readonly idempotency = new Map<string, string>();
  mutationCount = 0;

  constructor(args: { apiKey?: string } = {}) {
    this.apiKey = args.apiKey ?? "test-key";
  }

  authenticate(apiKey: unknown): void {
    if (apiKey !== this.apiKey) {
      throw new ConnectorAbiError({
        category: "auth",
        message: "mock vendor rejected api key",
        vendorCode: "mock.auth.invalid",
      });
    }
  }

  getHost(hostId: string): MockHost {
    const host = this.hosts.get(hostId);
    if (host === undefined) {
      throw new ConnectorAbiError({
        category: "not_found",
        message: `mock host ${JSON.stringify(hostId)} not found`,
        vendorCode: "mock.host.not_found",
      });
    }
    return host;
  }

  isolateHost(hostId: string, idempotencyKey: string): {
    taskId: string;
    dedup: boolean;
  } {
    const cachedTaskId = this.idempotency.get(idempotencyKey);
    if (cachedTaskId !== undefined) {
      return { taskId: cachedTaskId, dedup: true };
    }

    const host = this.getHost(hostId);
    if (host.isolated) {
      throw new ConnectorAbiError({
        category: "state_conflict",
        message: `mock host ${JSON.stringify(hostId)} already isolated`,
        vendorCode: "mock.host.already_isolated",
      });
    }

    const taskId = `mock-task-${createHash("sha256")
      .update(idempotencyKey, "utf-8")
      .digest("hex")
      .slice(0, 16)}`;
    host.isolated = true;
    this.idempotency.set(idempotencyKey, taskId);
    this.mutationCount += 1;
    return { taskId, dedup: false };
  }

  hostIsolated(hostId: string): boolean {
    return this.getHost(hostId).isolated;
  }
}

export class MockVendorConnector extends AbiConnector {
  static override readonly capability: ConnectorCapabilityModel = ConnectorCapability.parse({
    specVersion: "1.0",
    connectorId: "mock-response-vendor",
    connectorVersion: "0.1.0",
    vendor: "Warlog Mock Response Vendor",
    kind: "edr",
    auth: { model: "api_key", scopes: ["mock.respond"] },
    ingress: { produces: [], delivery: "polling", pollingMinIntervalS: null },
    egress: { supportsResponseActions: ["host.isolate"] },
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
    compat: { warlogSpecMin: "1.0", warlogSpecMax: "1.0" },
  });

  get vendor(): MockResponseVendor {
    const vendor = this.config.vendor;
    if (vendor instanceof MockResponseVendor) {
      return vendor;
    }
    throw new ConnectorAbiError({
      category: "policy",
      message: "mock vendor instance missing from connector config",
      vendorCode: "mock.vendor.missing",
    });
  }

  override async authenticate(): Promise<void> {
    this.vendor.authenticate(this.config.apiKey);
  }

  override async dryRun(spec: ResponseActionSpecModel): Promise<void> {
    this.ensureSupported(spec);
    const host = this.vendor.getHost(spec.subject.selectorValue);
    if (host.isolated) {
      throw new ConnectorAbiError({
        category: "state_conflict",
        message: "mock host is already isolated",
        vendorCode: "mock.host.already_isolated",
      });
    }
  }

  override async apply(
    spec: ResponseActionSpecModel,
  ): Promise<ResponseActionResultModel> {
    this.ensureSupported(spec);
    const mutation = this.vendor.isolateHost(
      spec.subject.selectorValue,
      spec.idempotencyKey,
    );
    return ResponseActionResult.parse({
      specVersion: "1.0",
      executionId: "",
      actionId: spec.actionId,
      outcome: "success",
      subject: spec.subject,
      details: {
        vendorTaskId: mutation.taskId,
        vendorDedup: mutation.dedup,
        mutationCount: this.vendor.mutationCount,
      },
      error: null,
    });
  }

  override async verify(
    spec: ResponseActionSpecModel,
    result: ResponseActionResultModel,
  ): Promise<boolean> {
    this.ensureSupported(spec);
    return result.outcome === "success" && this.vendor.hostIsolated(spec.subject.selectorValue);
  }

  private ensureSupported(spec: ResponseActionSpecModel): void {
    if (spec.actionId !== "host.isolate") {
      throw new ConnectorAbiError({
        category: "policy",
        message: `mock connector does not implement ${JSON.stringify(spec.actionId)}`,
        vendorCode: "mock.action.unsupported",
      });
    }
  }
}

export function mockProviderActionSpec(): ResponseActionSpecModel {
  return ResponseActionSpec.parse({
    specVersion: "1.0",
    actionId: "host.isolate",
    subject: {
      kind: "endpoint",
      selectorType: "agent_id",
      selectorValue: MOCK_HOST_ID,
      selectorRepresentation: "raw",
      selectorKeyId: null,
    },
    params: {},
    approval: {
      required: false,
      level: "none",
      rationale: "Level 4 mock-provider conformance scenario",
    },
    dryRun: false,
    idempotencyKey: MOCK_IDEMPOTENCY_KEY,
    expiresAt: null,
  });
}

export function mockUnsupportedActionSpec(): ResponseActionSpecModel {
  return ResponseActionSpec.parse({
    specVersion: "1.0",
    actionId: "process.kill",
    subject: {
      kind: "endpoint",
      selectorType: "pid",
      selectorValue: "4242",
      selectorRepresentation: "raw",
      selectorKeyId: null,
    },
    params: {},
    approval: {
      required: false,
      level: "none",
      rationale: "Unsupported-action negative control",
    },
    dryRun: false,
    idempotencyKey: "mock-provider-unsupported-001",
    expiresAt: null,
  });
}

export async function runMockProviderLevel4(args: {
  connectorClass?: ProviderConnectorClass;
  implementationName?: string;
  implementationVersion?: string;
  implementationLanguage?: string;
  config?: Record<string, unknown>;
} = {}): Promise<Level4ProviderReport> {
  const vendor = new MockResponseVendor();
  const connectorClass = args.connectorClass ?? MockVendorConnector;
  const connector = new connectorClass({
    apiKey: "test-key",
    vendor,
    ...args.config,
  });
  const capability = ConnectorCapability.parse(connectorClass.capability);
  const spec = mockProviderActionSpec();

  await connector.authenticate();

  const mutationsBeforeDryRun = vendor.mutationCount;
  await connector.dryRun(spec);
  const mutationsAfterDryRun = vendor.mutationCount;

  const result = await connector.apply(spec);
  const verified = await connector.verify(spec, result);
  const mutationsAfterApply = vendor.mutationCount;

  const replayResult = await connector.apply(spec);
  const mutationsAfterReplay = vendor.mutationCount;

  let unsupportedError: ConnectorError | null = null;
  try {
    await connector.dryRun(mockUnsupportedActionSpec());
  } catch (error) {
    if (error instanceof ConnectorAbiError) {
      unsupportedError = error.toConnectorError();
    } else {
      throw error;
    }
  }

  return {
    specVersion: "1.0",
    level: 4,
    implementation: {
      name: args.implementationName ?? "warlog-spec-ts",
      version: args.implementationVersion ?? "0.1.0",
      language: args.implementationLanguage ?? "typescript",
    },
    scenario: {
      id: MOCK_PROVIDER_SCENARIO_ID,
      mockVendor: MOCK_VENDOR_ID,
      actionId: spec.actionId,
    },
    capability,
    spec,
    dryRun: {
      called: true,
      mutationsBefore: mutationsBeforeDryRun,
      mutationsAfter: mutationsAfterDryRun,
    },
    apply: {
      called: true,
      result,
      mutationsAfter: mutationsAfterApply,
    },
    verify: { called: true, verified },
    idempotency: {
      replayed: true,
      result: replayResult,
      mutationsAfterReplay,
      sameVendorTask: result.details.vendorTaskId === replayResult.details.vendorTaskId,
    },
    unsupportedAction: {
      rejected: unsupportedError !== null,
      error: unsupportedError,
    },
  };
}