import { createHash } from "node:crypto";

import {
  ArtifactCitation,
  ArtifactConfidence,
  ArtifactEnvelope,
  ArtifactProducer,
  ClassificationAssessment,
  ClassificationDecision,
  EnrichmentAssessment,
  EnrichmentAssessmentPayload,
  ExtractedIOC,
  MitreAssessment,
  MitreMapping,
  NormalizedEntity,
  type ArtifactConfidence as ArtifactConfidenceModel,
  type ClassificationAssessment as ClassificationAssessmentModel,
  type EnrichmentAssessment as EnrichmentAssessmentModel,
  type ExtractedIOC as ExtractedIOCModel,
  type MitreAssessment as MitreAssessmentModel,
  type NormalizedEntity as NormalizedEntityModel,
} from "./artifacts.js";
import { TriggerSignalRef, type TriggerSignalRef as TriggerSignalRefModel } from "./provider-abi.js";

type JsonObject = Record<string, unknown>;
type SubjectType = "alert" | "case";

const HEX64_RE = /^[0-9a-fA-F]{64}$/;
const HEX40_RE = /^[0-9a-fA-F]{40}$/;
const HEX32_RE = /^[0-9a-fA-F]{32}$/;

export interface OcsfDetectionFindingMapping {
  sourceEventId: string;
  sourceContentHash: string;
  triggerSignal: TriggerSignalRefModel;
  classification: ClassificationAssessmentModel;
  enrichment: EnrichmentAssessmentModel;
  mitre: MitreAssessmentModel | null;
}

export function canonicalizeOcsfEvent(event: JsonObject): Buffer {
  return Buffer.from(JSON.stringify(sortKeysDeep(event)), "utf-8");
}

export function hashOcsfEvent(event: JsonObject): string {
  return createHash("sha256").update(canonicalizeOcsfEvent(event)).digest("hex");
}

export function mapOcsfDetectionFinding(
  event: JsonObject,
  args: { subjectType?: SubjectType; producerName?: string } = {},
): OcsfDetectionFindingMapping {
  const subjectType = args.subjectType ?? "alert";
  const producerName = args.producerName ?? "ocsf.detection_finding.mapper";
  const eventId = eventIdFrom(event);
  const contentHash = hashOcsfEvent(event);
  const generatedAt = eventTime(event);
  const confidence = confidenceFrom(event);
  const citation = ArtifactCitation.parse({
    sourceId: eventId,
    sourceKind: "ocsf_detection_finding",
    section: "$",
    score: confidence.score,
  });
  const producer = ArtifactProducer.parse({ kind: "system", name: producerName, model: null });

  const category = categoryFrom(event);
  const severity = severityFrom(event);
  const verdict = verdictFrom(event);
  const classification = ClassificationAssessment.parse({
    envelope: ArtifactEnvelope.parse({
      artifactType: "classification_assessment",
      subjectType,
      subjectId: eventId,
      producer,
      generatedAt,
      confidence,
      citations: [citation],
    }),
    classification: ClassificationDecision.parse({
      category,
      severity,
      verdict,
      shouldEscalate: severity === "critical" || severity === "high" || verdict === "true_positive",
      escalationRisk: bandForSeverity(severity),
    }),
    reasoning: reasoning(event, category, severity, verdict),
    evidenceSummary: evidenceSummary(event),
    missingEvidence: attacks(event).length > 0 ? [] : ["No OCSF attacks[] mapping present"],
  });

  const enrichment = EnrichmentAssessment.parse({
    envelope: ArtifactEnvelope.parse({
      artifactType: "enrichment.ocsf_context",
      subjectType,
      subjectId: eventId,
      producer,
      generatedAt,
      confidence,
      citations: [citation],
    }),
    payload: EnrichmentAssessmentPayload.parse({
      relatedEntities: entities(event, confidence),
      matchedIocs: iocs(event, verdict, confidence),
      prevalenceSummary: stringFromPaths(event, ["finding", "desc"], ["finding", "description"], ["message"]),
    }),
  });

  return {
    sourceEventId: eventId,
    sourceContentHash: contentHash,
    triggerSignal: TriggerSignalRef.parse({
      kind: "ocsf_event",
      sourceId: eventId,
      contentHash,
    }),
    classification,
    enrichment,
    mitre: mitre(event, eventId, generatedAt, producer, confidence, citation, subjectType),
  };
}

function eventIdFrom(event: JsonObject): string {
  const value = stringFromPaths(
    event,
    ["uid"],
    ["finding", "uid"],
    ["finding", "id"],
    ["metadata", "uid"],
    ["metadata", "event_id"],
    ["metadata", "correlation_uid"],
  );
  return value ?? `ocsf:${hashOcsfEvent(event).slice(0, 16)}`;
}

function eventTime(event: JsonObject): string {
  const text = stringFromPaths(event, ["time_dt"], ["metadata", "logged_time_dt"]);
  if (text !== null) {
    const parsed = isoTimestamp(text);
    if (parsed !== null) {
      return parsed;
    }
  }
  const raw = path(event, ["time"]);
  if (typeof raw === "number" && Number.isFinite(raw)) {
    const parsed = isoTimestamp(raw > 10_000_000_000 ? raw : raw * 1000);
    if (parsed !== null) {
      return parsed;
    }
  }
  return "1970-01-01T00:00:00.000Z";
}

function isoTimestamp(value: string | number): string | null {
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

function confidenceFrom(event: JsonObject): ArtifactConfidenceModel {
  const rawScore = path(event, ["confidence_score"]);
  if (typeof rawScore === "number" && Number.isFinite(rawScore)) {
    const score = Math.max(0, Math.min(1, rawScore > 1 ? rawScore / 100 : rawScore));
    return ArtifactConfidence.parse({ score, band: bandForScore(score) });
  }
  const raw = stringFromPaths(event, ["confidence"], ["confidence_name"]);
  return ArtifactConfidence.parse({ score: null, band: bandForText(raw ?? "") });
}

function severityFrom(event: JsonObject): string {
  const raw = stringFromPaths(event, ["severity"], ["severity_name"]);
  const normalized = raw?.toLowerCase().replace(/\s+/g, "_");
  if (["critical", "high", "medium", "low", "info", "unknown"].includes(normalized ?? "")) {
    return normalized!;
  }
  const rawId = path(event, ["severity_id"]);
  if (typeof rawId === "number") {
    return ({ 1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "critical" } as Record<number, string>)[rawId] ?? "unknown";
  }
  return "unknown";
}

function categoryFrom(event: JsonObject): string {
  const text = searchText(event);
  const mappings: Array<[string[], string]> = [
    [["phish"], "phishing"],
    [["credential", "password", "token", "mfa"], "credential_access"],
    [["unauthorized", "login", "authentication"], "unauthorized_access"],
    [["lateral"], "lateral_movement"],
    [["powershell", "script", "execution", "process"], "execution"],
    [["persist"], "persistence"],
    [["exfil"], "exfiltration"],
    [["malware", "ransom", "trojan", "beacon"], "malware"],
    [["recon", "scan"], "reconnaissance"],
    [["impact", "destruct", "wipe"], "impact"],
    [["policy"], "policy_violation"],
    [["denial", "dos", "ddos"], "denial_of_service"],
  ];
  return mappings.find(([keywords]) => keywords.some((keyword) => text.includes(keyword)))?.[1] ?? "unknown";
}

function verdictFrom(event: JsonObject): string {
  const text = searchText(event);
  if (text.includes("false positive") || text.includes("false_positive")) {
    return "false_positive";
  }
  if (text.includes("benign")) {
    return "benign";
  }
  if (text.includes("true positive") || text.includes("true_positive") || text.includes("confirmed")) {
    return "true_positive";
  }
  if (text.includes("suspicious") || text.includes("malicious") || text.includes("threat")) {
    return "suspicious";
  }
  return "undetermined";
}

function mitre(
  event: JsonObject,
  eventId: string,
  generatedAt: string,
  producer: unknown,
  confidence: ArtifactConfidenceModel,
  citation: unknown,
  subjectType: SubjectType,
): MitreAssessmentModel | null {
  const tacticIds: string[] = [];
  const techniqueIds: string[] = [];
  for (const attack of attacks(event)) {
    const tactic = stringFromPaths(attack, ["tactic_id"], ["tactic", "uid"], ["tactic", "id"]);
    const technique = stringFromPaths(attack, ["technique_id"], ["technique", "uid"], ["technique", "id"], ["technique_uid"]);
    if (tactic !== null && !tacticIds.includes(tactic)) {
      tacticIds.push(tactic);
    }
    if (technique !== null && !techniqueIds.includes(technique)) {
      techniqueIds.push(technique);
    }
  }
  if (tacticIds.length === 0 && techniqueIds.length === 0) {
    return null;
  }
  return MitreAssessment.parse({
    envelope: ArtifactEnvelope.parse({
      artifactType: "mitre_assessment",
      subjectType,
      subjectId: eventId,
      producer,
      generatedAt,
      confidence,
      citations: [citation],
    }),
    mitre: MitreMapping.parse({ tactics: tacticIds, techniques: techniqueIds }),
    reasoning: "Mapped from OCSF attacks[] references.",
  });
}

function entities(event: JsonObject, confidence: ArtifactConfidenceModel): NormalizedEntityModel[] {
  const output: NormalizedEntityModel[] = [];
  addEntity(output, "host", stringFromPaths(event, ["device", "hostname"], ["device", "name"], ["device", "uid"]), "target", confidence, ["device"]);
  addEntity(output, "host", stringFromPaths(event, ["endpoint", "hostname"], ["endpoint", "name"], ["endpoint", "uid"]), "target", confidence, ["endpoint"]);
  addEntity(output, "user", stringFromPaths(event, ["actor", "user", "name"], ["actor", "user", "uid"], ["user", "name"], ["user", "uid"]), "related", confidence, ["actor.user", "user"]);
  addEntity(output, "process", stringFromPaths(event, ["process", "name"], ["process", "cmd_line"]), "related", confidence, ["process"]);
  addEntity(output, "file", stringFromPaths(event, ["file", "path"], ["file", "name"]), "related", confidence, ["file"]);
  addEntity(output, "ip", stringFromPaths(event, ["src_endpoint", "ip"], ["src_ip"]), "related", confidence, ["src_endpoint.ip", "src_ip"]);
  addEntity(output, "ip", stringFromPaths(event, ["dst_endpoint", "ip"], ["dst_ip"]), "target", confidence, ["dst_endpoint.ip", "dst_ip"]);
  for (const observable of observables(event)) {
    const value = observableValue(observable);
    const kindText = observableKindText(observable);
    if (value === null) {
      continue;
    }
    if (kindText.includes("domain")) {
      addEntity(output, "domain", value, "related", confidence, ["observables"]);
    } else if (kindText.includes("url") || kindText.includes("uri")) {
      addEntity(output, "url", value, "related", confidence, ["observables"]);
    } else if (kindText.includes("email")) {
      addEntity(output, "email", value, "related", confidence, ["observables"]);
    }
  }
  return output;
}

function addEntity(
  output: NormalizedEntityModel[],
  entityType: string,
  value: string | null,
  role: string,
  confidence: ArtifactConfidenceModel,
  sourceFields: string[],
): void {
  if (value === null) {
    return;
  }
  if (output.some((entity) => entity.entityType === entityType && entity.value === value && entity.role === role)) {
    return;
  }
  output.push(NormalizedEntity.parse({ entityType, value, role, confidence, sourceFields }));
}

function iocs(event: JsonObject, verdict: string, confidence: ArtifactConfidenceModel): ExtractedIOCModel[] {
  const output: ExtractedIOCModel[] = [];
  for (const [value, sourceField] of [
    [stringFromPaths(event, ["src_endpoint", "ip"], ["src_ip"]), "src_endpoint.ip"],
    [stringFromPaths(event, ["dst_endpoint", "ip"], ["dst_ip"]), "dst_endpoint.ip"],
    [stringFromPaths(event, ["url", "url_string"], ["url", "full"], ["url"]), "url"],
  ] as Array<[string | null, string]>) {
    addIoc(output, value, guessIocType(value ?? ""), verdict, confidence, [sourceField]);
  }
  for (const observable of observables(event)) {
    const value = observableValue(observable);
    if (value === null) {
      continue;
    }
    addIoc(output, value, guessIocType(value, observableKindText(observable)), verdict, confidence, ["observables"]);
  }
  return output;
}

function addIoc(
  output: ExtractedIOCModel[],
  value: string | null,
  iocType: string,
  verdict: string,
  confidence: ArtifactConfidenceModel,
  sourceFields: string[],
): void {
  if (value === null) {
    return;
  }
  if (output.some((ioc) => ioc.iocType === iocType && ioc.value === value)) {
    return;
  }
  output.push(ExtractedIOC.parse({ iocType, value, maliciousness: verdict, confidence, sourceFields }));
}

function guessIocType(value: string, hint = ""): string {
  const text = `${hint} ${value}`.toLowerCase();
  if (text.includes("sha256") || HEX64_RE.test(value)) {
    return "hash_sha256";
  }
  if (text.includes("sha1") || HEX40_RE.test(value)) {
    return "hash_sha1";
  }
  if (text.includes("md5") || HEX32_RE.test(value)) {
    return "hash_md5";
  }
  if (text.includes("url") || value.startsWith("http://") || value.startsWith("https://")) {
    return "url";
  }
  if (text.includes("email") || value.includes("@")) {
    return "email";
  }
  if (text.includes("domain")) {
    return "domain";
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    return "ip";
  }
  return "other";
}

function attacks(event: JsonObject): JsonObject[] {
  const raw = path(event, ["attacks"]);
  return Array.isArray(raw) ? raw.filter(isJsonObject) : [];
}

function observables(event: JsonObject): JsonObject[] {
  const raw = path(event, ["observables"]);
  return Array.isArray(raw) ? raw.filter(isJsonObject) : [];
}

function observableValue(observable: JsonObject): string | null {
  return stringFromPaths(observable, ["value"], ["name"], ["data"]);
}

function observableKindText(observable: JsonObject): string {
  return [
    stringFromPaths(observable, ["type"]),
    stringFromPaths(observable, ["type_name"]),
    stringFromPaths(observable, ["name"]),
  ].filter((item): item is string => item !== null).join(" ").toLowerCase();
}

function reasoning(event: JsonObject, category: string, severity: string, verdict: string): string {
  const title = stringFromPaths(event, ["finding", "title"], ["type_name"], ["activity_name"], ["message"]);
  if (title !== null) {
    return `OCSF Detection Finding mapped from ${JSON.stringify(title)}: category=${category}, severity=${severity}, verdict=${verdict}.`;
  }
  return `OCSF Detection Finding mapped to category=${category}, severity=${severity}, verdict=${verdict}.`;
}

function evidenceSummary(event: JsonObject): string[] {
  const output: string[] = [];
  for (const value of [
    stringFromPaths(event, ["finding", "title"]),
    stringFromPaths(event, ["message"]),
    stringFromPaths(event, ["type_name"]),
    stringFromPaths(event, ["activity_name"]),
    stringFromPaths(event, ["class_name"]),
  ]) {
    if (value !== null && !output.includes(value)) {
      output.push(value);
    }
  }
  return output;
}

function searchText(event: JsonObject): string {
  return [
    stringFromPaths(event, ["category_name"]),
    stringFromPaths(event, ["class_name"]),
    stringFromPaths(event, ["type_name"]),
    stringFromPaths(event, ["activity_name"]),
    stringFromPaths(event, ["message"]),
    stringFromPaths(event, ["finding", "title"]),
    stringFromPaths(event, ["finding", "desc"], ["finding", "description"]),
    stringFromPaths(event, ["disposition"]),
    stringFromPaths(event, ["status"]),
  ].filter((item): item is string => item !== null).join(" ").toLowerCase();
}

function bandForText(text: string): string {
  const lowered = text.toLowerCase();
  if (lowered.includes("high")) {
    return "high";
  }
  if (lowered.includes("medium") || lowered.includes("moderate")) {
    return "medium";
  }
  if (lowered.includes("low")) {
    return "low";
  }
  return "unknown";
}

function bandForScore(score: number): string {
  if (score >= 0.75) {
    return "high";
  }
  if (score >= 0.4) {
    return "medium";
  }
  return "low";
}

function bandForSeverity(severity: string): string {
  if (severity === "critical" || severity === "high") {
    return "high";
  }
  if (severity === "medium") {
    return "medium";
  }
  if (severity === "low" || severity === "info") {
    return "low";
  }
  return "unknown";
}

function stringFromPaths(event: JsonObject, ...paths: string[][]): string | null {
  for (const itemPath of paths) {
    const value = path(event, itemPath);
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
    if (typeof value === "number" && Number.isFinite(value)) {
      return String(value);
    }
  }
  return null;
}

function path(event: JsonObject, itemPath: string[]): unknown {
  let current: unknown = event;
  for (const segment of itemPath) {
    if (!isJsonObject(current)) {
      return null;
    }
    current = current[segment];
  }
  return current;
}

function sortKeysDeep(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  const output: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    output[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
  }
  return output;
}

function isJsonObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}