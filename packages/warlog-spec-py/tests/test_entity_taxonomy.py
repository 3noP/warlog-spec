"""The canonical entity taxonomy, pinned in both packages.

An entity one package emits is one the other, and the platform's database,
accept: ``packages/warlog-spec-ts/tests/smoke.test.ts`` pins the same list.
The TypeScript package had drifted (``hash``, ``asset_group``,
``organization`` where this one has ``registry``, ``vulnerability``,
``certificate``), so an artifact built with it failed validation here.
"""

from __future__ import annotations

from warlog_spec.enums import EntityType


def test_the_entity_taxonomy_is_pinned() -> None:
    assert [e.value for e in EntityType] == [
        "host",
        "user",
        "ip",
        "domain",
        "url",
        "file",
        "process",
        "email",
        "registry",
        "vulnerability",
        "certificate",
        "cloud_resource",
        "other",
    ]
