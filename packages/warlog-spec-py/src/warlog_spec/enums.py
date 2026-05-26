"""Canonical workflow enums — the single source of truth for spec values.

These match the Postgres ENUM types persisted by Warlog reference
implementation (and any conformant runtime). Adding a new value is a
MINOR spec bump; removing one is MAJOR. See ``warlog-spec/VERSIONING.md``.
"""

from __future__ import annotations

import enum


class AlertSeverity(enum.StrEnum):
    """Alert severity levels following CVSS-style categorization.

    ``UNKNOWN`` is a first-class persisted value: the system says
    "unknown" rather than guessing ``MEDIUM`` when a source does not
    provide a mapped severity.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class AlertStatus(enum.StrEnum):
    """Alert lifecycle status."""

    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    PENDING = "pending"
    RESOLVED = "resolved"
    CLOSED = "closed"
    SUPPRESSED = "suppressed"


class AlertVerdict(enum.StrEnum):
    """Final determination on alert validity."""

    UNDETERMINED = "undetermined"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MIXED = "mixed"
    NEEDS_REVIEW = "needs_review"


class AlertSource(enum.StrEnum):
    """Alert source systems."""

    SIEM = "siem"
    SPLUNK = "splunk"
    ELASTICSEARCH = "elasticsearch"
    SENTINEL = "sentinel"
    CROWDSTRIKE = "crowdstrike"
    PALO_ALTO = "palo_alto"
    FORTINET = "fortinet"
    MANUAL = "manual"
    API = "api"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class AlertCategory(enum.StrEnum):
    """Canonical alert category."""

    MALWARE = "malware"
    PHISHING = "phishing"
    CREDENTIAL_ACCESS = "credential_access"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    LATERAL_MOVEMENT = "lateral_movement"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    POLICY_VIOLATION = "policy_violation"
    DENIAL_OF_SERVICE = "denial_of_service"
    RECONNAISSANCE = "reconnaissance"
    IMPACT = "impact"
    OTHER = "other"
    UNKNOWN = "unknown"
    NEEDS_REVIEW = "needs_review"


class CaseSeverity(enum.StrEnum):
    """Case severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class CaseStatus(enum.StrEnum):
    """Case lifecycle status (SOC standard)."""

    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    CLOSED = "closed"
    PENDING_L1_INFO = "pending_l1_info"


class CasePriority(enum.StrEnum):
    """Case priority for SLA."""

    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"
    UNKNOWN = "unknown"


class CaseCategory(enum.StrEnum):
    """Incident category."""

    MALWARE = "malware"
    PHISHING = "phishing"
    CREDENTIAL_ACCESS = "credential_access"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    DENIAL_OF_SERVICE = "denial_of_service"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    LATERAL_MOVEMENT = "lateral_movement"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    POLICY_VIOLATION = "policy_violation"
    RECONNAISSANCE = "reconnaissance"
    IMPACT = "impact"
    OTHER = "other"
    UNKNOWN = "unknown"
    NEEDS_REVIEW = "needs_review"


class EntityType(enum.StrEnum):
    """Normalized entity type — 12-value canonical taxonomy."""

    HOST = "host"
    USER = "user"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE = "file"
    PROCESS = "process"
    EMAIL = "email"
    REGISTRY = "registry"
    VULNERABILITY = "vulnerability"
    CERTIFICATE = "certificate"
    OTHER = "other"


class EntityRole(enum.StrEnum):
    """Role of an entity in an alert/case context."""

    PRINCIPAL = "principal"
    TARGET = "target"
    SOURCE = "source"
    INTERMEDIARY = "intermediary"
    OBSERVER = "observer"
    RELATED = "related"
    UNKNOWN = "unknown"


class IOCType(enum.StrEnum):
    """Indicator of Compromise types."""

    IP = "ip"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    USER = "user"
    PROCESS = "process"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    CERTIFICATE = "certificate"
    CVE = "cve"
    OTHER = "other"


__all__ = [
    "AlertCategory",
    "AlertSeverity",
    "AlertSource",
    "AlertStatus",
    "AlertVerdict",
    "CaseCategory",
    "CasePriority",
    "CaseSeverity",
    "CaseStatus",
    "EntityRole",
    "EntityType",
    "IOCType",
]
