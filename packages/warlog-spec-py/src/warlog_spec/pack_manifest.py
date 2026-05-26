"""Pack manifest — distribution layer for the registry.

A pack is the unit of distribution in the Warlog registry: a versioned,
signed bundle of detection rules, playbooks, KB articles, connectors,
or response action mappings.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field

from warlog_spec._base import SpecModel

PACK_MANIFEST_VERSION = "1.0"


class PackKind(StrEnum):
    """Five canonical pack categories."""

    DETECTION = "detection"
    PLAYBOOK = "playbook"
    KB = "kb"
    CONNECTOR = "connector"
    ACTION = "action"


class TrustLevel(StrEnum):
    """Publisher trust gradient — informs default install posture per
    tenant policy."""

    CERTIFIED = "certified"
    COMMUNITY = "community"
    PRIVATE = "private"


class PackPublisher(SpecModel):
    """Publisher identity and signature material."""

    id: str = Field(min_length=1, max_length=128)
    trust_level: TrustLevel
    signature: str


class PackDependency(SpecModel):
    """Reference to another pack this one needs."""

    id: str
    version: str


class PackCompat(SpecModel):
    """Spec + dependency compat declaration."""

    warlog_spec_min: str
    warlog_spec_max: str
    depends_on_packs: list[PackDependency] = Field(default_factory=list)


class PackContents(SpecModel):
    """Manifest of files inside the pack archive."""

    detection_rules: list[str] = Field(default_factory=list)
    playbooks: list[str] = Field(default_factory=list)
    kb_articles: list[str] = Field(default_factory=list)
    connector_specs: list[str] = Field(default_factory=list)
    action_mappings: list[str] = Field(default_factory=list)
    examples: list[str] = Field(default_factory=list)
    tests: list[str] = Field(default_factory=list)


class PackProvenance(SpecModel):
    """Supply-chain attestation for the pack."""

    source_repo: str
    source_commit: str
    build_at: datetime
    sbom: str | None = None
    builder_identity: str | None = None


class PackManifest(SpecModel):
    """Top-level manifest declared at the root of every pack archive."""

    spec_version: Literal["1.0"] = PACK_MANIFEST_VERSION
    pack_id: str = Field(min_length=1, max_length=128)
    pack_version: str
    kind: PackKind
    publisher: PackPublisher
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)
    compat: PackCompat
    license: str
    contents: PackContents = Field(default_factory=PackContents)
    provenance: PackProvenance


__all__ = [
    "PACK_MANIFEST_VERSION",
    "PackCompat",
    "PackContents",
    "PackDependency",
    "PackKind",
    "PackManifest",
    "PackProvenance",
    "PackPublisher",
    "TrustLevel",
]
