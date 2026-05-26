/**
 * PackManifest — the spec contract for distributing playbooks,
 * detection rules, and connector configs as signed registry packs.
 * Mirrors `warlog_spec.pack_manifest`.
 */

import { z } from "zod";

export const PACK_MANIFEST_VERSION = "1.0";

export const PackKind = z.enum([
  "playbook",
  "detection_rules",
  "kb_articles",
  "connector_spec",
  "action_mappings",
]);
export type PackKindValue = z.infer<typeof PackKind>;

export const TrustLevel = z.enum(["community", "verified", "certified"]);
export type TrustLevelValue = z.infer<typeof TrustLevel>;

export const PackPublisher = z.object({
  id: z.string().min(1).max(128),
  trustLevel: TrustLevel,
  signature: z.string(),
});
export type PackPublisher = z.infer<typeof PackPublisher>;

export const PackDependency = z.object({
  id: z.string(),
  version: z.string(),
});
export type PackDependency = z.infer<typeof PackDependency>;

export const PackCompat = z.object({
  warlogSpecMin: z.string(),
  warlogSpecMax: z.string(),
  dependsOnPacks: z.array(PackDependency).default([]),
});
export type PackCompat = z.infer<typeof PackCompat>;

export const PackContents = z.object({
  detectionRules: z.array(z.string()).default([]),
  playbooks: z.array(z.string()).default([]),
  kbArticles: z.array(z.string()).default([]),
  connectorSpecs: z.array(z.string()).default([]),
  actionMappings: z.array(z.string()).default([]),
  examples: z.array(z.string()).default([]),
  tests: z.array(z.string()).default([]),
});
export type PackContents = z.infer<typeof PackContents>;

export const PackProvenance = z.object({
  sourceRepo: z.string(),
  sourceCommit: z.string(),
  buildAt: z.string().datetime({ offset: true }),
  sbom: z.string().nullable().default(null),
  builderIdentity: z.string().nullable().default(null),
});
export type PackProvenance = z.infer<typeof PackProvenance>;

export const PackManifest = z.object({
  specVersion: z.literal("1.0").default("1.0"),
  packId: z.string().min(1).max(128),
  packVersion: z.string(),
  kind: PackKind,
  publisher: PackPublisher,
  title: z.string().min(1).max(200),
  description: z.string().min(1),
  compat: PackCompat,
  license: z.string(),
  contents: PackContents.default({
    detectionRules: [],
    playbooks: [],
    kbArticles: [],
    connectorSpecs: [],
    actionMappings: [],
    examples: [],
    tests: [],
  }),
  provenance: PackProvenance,
});
export type PackManifest = z.infer<typeof PackManifest>;
