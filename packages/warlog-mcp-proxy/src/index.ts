/**
 * @warlog/mcp-proxy — programmatic API.
 *
 * Most users invoke the CLI (``warlog-mcp-proxy wrap ...``) ; this index
 * exposes the building blocks for tests and for integrators who want to
 * embed the proxy in a larger Node application.
 */

export {
	Auditor,
	type ApprovalDecisionResult,
	type ApprovalGate,
	type ApprovalRequest,
	type AuditDecision,
	type AuditorConfig,
	type AuditorContext,
} from "./auditor.js";
export { loadMappingFile, type ApprovalPolicy, type MappingFile, type ToolMapping } from "./mapping.js";
export { JsonlAuditPersister, type SignedAuditEntry } from "./persister.js";
export { runProxy, type ProxyOptions } from "./proxy.js";
