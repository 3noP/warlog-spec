/**
 * AbiConnector — abstract base class for a response-action connector
 * in TypeScript. Mirrors `warlog_spec.abi.AbiConnector` in the Python
 * package.
 *
 * A connector wraps a vendor API (CrowdStrike Falcon, SentinelOne,
 * Okta, Defender, Proofpoint, …) behind the canonical ABI lifecycle :
 *
 *     authenticate  →  dryRun  →  apply  →  verify
 *
 * The runner enforces this lifecycle. The connector implements each
 * step ; the canonical params are validated by the runner BEFORE
 * ``dryRun`` is invoked, so the connector can assume well-formed
 * input.
 *
 * Failure model : any error the connector throws is wrapped by the
 * runner into a :class:`ConnectorError`. Use :class:`ConnectorAbiError`
 * when you have an explicit failure category to surface (auth,
 * not_found, state_conflict, transient, policy) — the runner
 * preserves it verbatim. Anything else is mapped to ``TRANSIENT``
 * (retryable) by default.
 */

import type {
  ConnectorCapability,
  ConnectorError,
  FailureCategoryValue,
  ResponseActionResult,
  ResponseActionSpec,
} from "./provider-abi.js";

// ============================================================================
// Connector error class
// ============================================================================

/**
 * Throw from any of the lifecycle methods when the connector knows
 * exactly which failure category to surface. The runner maps this
 * to a :class:`ConnectorError` 1:1 (no loss of vendor metadata via
 * the optional ``vendorCode`` / ``vendorMessage`` fields).
 *
 * Common categories :
 *
 * - ``auth`` : credentials rejected / expired / missing
 * - ``not_found`` : target host / user / id doesn't exist upstream
 * - ``state_conflict`` : target is already in the desired state
 *   (e.g. host already isolated, user already disabled)
 * - ``transient`` : network blip, rate limit, upstream 5xx
 * - ``policy`` : the operation is forbidden by upstream policy
 *   (e.g. cannot disable the last admin, host has a maintenance hold)
 */
export class ConnectorAbiError extends Error {
  readonly category: FailureCategoryValue;
  readonly retryable: boolean;
  readonly vendorCode: string | null;
  readonly vendorMessage: string | null;

  constructor(args: {
    category: FailureCategoryValue;
    message: string;
    retryable?: boolean;
    vendorCode?: string | null;
    vendorMessage?: string | null;
  }) {
    super(args.message);
    this.name = "ConnectorAbiError";
    this.category = args.category;
    // Default : transient is retryable, everything else isn't.
    this.retryable = args.retryable ?? args.category === "transient";
    this.vendorCode = args.vendorCode ?? null;
    this.vendorMessage = args.vendorMessage ?? null;
  }

  /**
   * Convert to the wire-format :class:`ConnectorError` the runner
   * embeds in the audit chain. The runner usually calls this
   * implicitly ; expose it for connectors that want to surface
   * the error in a custom response body.
   */
  toConnectorError(): ConnectorError {
    return {
      specVersion: "1.0",
      category: this.category,
      message: this.message,
      retryable: this.retryable,
      vendorCode: this.vendorCode,
      vendorMessage: this.vendorMessage,
    };
  }
}

// ============================================================================
// AbiConnector base class
// ============================================================================

/**
 * Subclass this and implement the four lifecycle methods. The
 * subclass also exposes a static :attr:`capability` (an instance of
 * :class:`ConnectorCapability`) declaring which actions it supports
 * and how it authenticates ; the runner reads the capability to
 * route requests and decide whether dry-run is exercised.
 *
 * The constructor receives a free-form ``config`` dict (typically the
 * tenant's connector binding row). Subclasses should validate the
 * keys they care about in their constructor — fail fast on missing
 * required config.
 *
 * Example :
 *
 * ```ts
 * import {
 *   AbiConnector,
 *   ConnectorAbiError,
 *   type ConnectorCapability,
 *   type ResponseActionResult,
 *   type ResponseActionSpec,
 * } from "@warlog/spec";
 *
 * export class FalconConnector extends AbiConnector {
 *   static readonly capability: ConnectorCapability = ConnectorCapability.parse({ ... });
 *
 *   async authenticate(): Promise<void> {
 *     if (!this.config.apiKey) {
 *       throw new ConnectorAbiError({
 *         category: "auth", message: "Missing apiKey", retryable: false,
 *       });
 *     }
 *   }
 *
 *   async dryRun(spec: ResponseActionSpec): Promise<void> { ... }
 *
 *   async apply(spec: ResponseActionSpec): Promise<ResponseActionResult> { ... }
 *
 *   async verify(spec: ResponseActionSpec, result: ResponseActionResult): Promise<boolean> { ... }
 * }
 * ```
 */
export abstract class AbiConnector {
  /**
   * Static capability the runner reads to route + gate actions.
   * Subclasses MUST override with a concrete :class:`ConnectorCapability`.
   * Declared as ``unknown`` here so TypeScript doesn't require every
   * subclass to repeat the type ; the runner narrows at use time.
   */
  static readonly capability: ConnectorCapability;

  readonly config: Record<string, unknown>;

  constructor(config: Record<string, unknown> = {}) {
    this.config = config;
  }

  /**
   * Establish a session with the upstream vendor.
   *
   * The runner calls this exactly once at the start of every
   * action lifecycle, BEFORE dry-run. Failure here short-circuits
   * the whole lifecycle to FAILURE / category=auth — the audit
   * chain records a row at the APPLY phase with the auth error.
   *
   * Implementations SHOULD be idempotent : a second call within
   * the same lifecycle should be a no-op (or cached).
   */
  abstract authenticate(): Promise<void>;

  /**
   * Pre-flight check WITHOUT side effects upstream.
   *
   * Validates the target exists, the action is permitted under
   * current upstream state, and the connector can authenticate.
   * Throws :class:`ConnectorAbiError` with the appropriate
   * category when any precondition fails.
   *
   * The runner ALWAYS calls dryRun before apply (even when
   * ``spec.dryRun`` is false — dry-run is a precondition, not a
   * mode). Connectors that genuinely cannot validate without a
   * side effect SHOULD document the limitation in their
   * :attr:`capability.dryRun.scope`.
   */
  abstract dryRun(spec: ResponseActionSpec): Promise<void>;

  /**
   * Execute the action on the upstream vendor.
   *
   * MUST be idempotent w.r.t. ``spec.idempotencyKey`` : a re-invoke
   * with the same key MUST observe the prior state (no double-isolate,
   * no double-revoke). Vendor APIs that expose their own idempotency
   * token (CrowdStrike Falcon, SentinelOne) should forward
   * ``spec.idempotencyKey`` ; vendors without one need a tenant-side
   * dedup store.
   *
   * Returns a :class:`ResponseActionResult` with the outcome
  * (success / failure / expired) and optional vendor details.
  * ``pending_approval`` and ``denied`` are runner / approval-gate
  * outcomes used when execution stops before vendor mutation.
  * Throwing :class:`ConnectorAbiError` is equivalent to returning
  * a result with outcome=failure + the error's category.
   */
  abstract apply(
    spec: ResponseActionSpec,
  ): Promise<ResponseActionResult>;

  /**
   * Confirm the apply landed and the upstream state matches.
   *
   * Called by the runner AFTER apply, with the spec + apply result.
   * Returns ``true`` when verification succeeds, ``false`` when
   * the target state was not reached within the connector's
   * attempt budget. The runner records the verification outcome
   * as a separate audit row at the VERIFY phase.
   *
   * Connectors with no meaningful verify step (e.g. fire-and-
   * forget notifications) MAY return ``true`` unconditionally.
   */
  abstract verify(
    spec: ResponseActionSpec,
    result: ResponseActionResult,
  ): Promise<boolean>;
}

// ============================================================================
// AbiEnricher base class (read-side dual of AbiConnector)
// ============================================================================

/**
 * Optional base class for read-side connectors (VirusTotal,
 * AbuseIPDB, Shodan, GreyNoise, internal ML). Mirrors
 * :class:`warlog_spec.abi.AbiEnricher`. Implementations advertise
 * which artifact types they produce via
 * :attr:`ConnectorCapability.enrichment`.
 *
 * Distinct from :class:`AbiConnector` : no dry_run / approval /
 * verify lifecycle, no idempotency key. The enricher is read-only ;
 * the assessment IS the result.
 */
export abstract class AbiEnricher {
  static readonly capability: ConnectorCapability;
  readonly config: Record<string, unknown>;

  constructor(config: Record<string, unknown> = {}) {
    this.config = config;
  }

  abstract authenticate(): Promise<void>;

  /**
   * Produce a canonical artifact for the given subject + target.
   *
   * Returns ``null`` when the enricher had no information for the
   * subject. Returning a partial artifact is also acceptable when
   * the upstream had degraded data — the producer's confidence
   * band MUST reflect the degradation.
   *
   * The return type is intentionally ``unknown`` here ; concrete
   * subclasses narrow it to one of the canonical artifact types
   * (:class:`EnrichmentAssessment`, :class:`MitreAssessment`, …).
   * Untyped union avoids forcing every enricher to import every
   * artifact ; the runner re-validates via Zod at the call site.
   */
  abstract enrich(request: {
    subjectType: "alert" | "case";
    subjectId: string;
    target: unknown;
  }): Promise<unknown | null>;
}
