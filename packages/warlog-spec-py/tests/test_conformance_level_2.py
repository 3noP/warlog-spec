"""Level 2 (Write) conformance — produced examples validate against schemas.

This test is what makes ``warlog-spec-py`` a Level 2 reference implementation :
:func:`warlog_spec.conformance.produce_all` outputs one canonical example
for each of the 18 productible artifact types, and every output validates
against the matching JSON Schema bundled in ``warlog-spec/schemas/``.

The test does NOT depend on the canonical examples in
``warlog-spec/examples/`` — those exercise Level 1 (read). Here we
exercise Level 2 (write) : we produce, then validate.

If this test fails after a schema or model change, either :
- the producer in ``warlog_spec.conformance`` drifted from the schema
  (fix the factory), or
- the schema itself drifted from the model (regenerate the schemas).
"""

from __future__ import annotations

from pathlib import Path

import pytest

# jsonschema is in ``warlog-spec[verify]`` — gate the import so the
# core package install (without [verify]) doesn't break test collection.
jsonschema = pytest.importorskip("jsonschema")
referencing = pytest.importorskip("referencing")
from referencing.jsonschema import DRAFT202012

from warlog_spec.conformance import PRODUCERS, produce_all


_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent.parent
_SCHEMAS_DIR_CANDIDATES = (
    _REPO_ROOT / "warlog-spec" / "schemas",
    _REPO_ROOT / "schemas",
)
_SCHEMAS_DIR = next(
    (
        candidate
        for candidate in _SCHEMAS_DIR_CANDIDATES
        if (candidate / "action-catalog.json").is_file()
    ),
    _SCHEMAS_DIR_CANDIDATES[0],
)


def _build_registry() -> tuple[dict[str, dict], referencing.Registry]:
    """Load every schema under ``_SCHEMAS_DIR`` keyed by relpath AND by $id.

    Mirrors the runner's registry build so cross-schema $refs resolve.
    """
    import json

    schemas: dict[str, dict] = {}
    resources: list[tuple[str, referencing.Resource]] = []
    for path in _SCHEMAS_DIR.rglob("*.json"):
        if path.name == "manifest.json":
            continue
        if path.relative_to(_SCHEMAS_DIR).parts[0] == "draft":
            continue
        rel = str(path.relative_to(_SCHEMAS_DIR)).replace("\\", "/")
        schema = json.loads(path.read_text(encoding="utf-8"))
        resource = referencing.Resource.from_contents(
            schema, default_specification=DRAFT202012
        )
        schemas[rel] = schema
        resources.append((rel, resource))
        if "$id" in schema:
            schemas[schema["$id"]] = schema
            resources.append((schema["$id"], resource))
    return schemas, referencing.Registry().with_resources(resources)


@pytest.fixture(scope="module")
def registry() -> tuple[dict[str, dict], referencing.Registry]:
    if not _SCHEMAS_DIR.is_dir():
        checked = ", ".join(str(candidate) for candidate in _SCHEMAS_DIR_CANDIDATES)
        pytest.skip(f"Schemas directory not found. Checked: {checked}")
    return _build_registry()


def test_producers_cover_all_productible_types() -> None:
    """The producer registry MUST cover every productible type the spec defines.

    Bundle shapes (``TriageBundle``, ``InvestigationBundle``, ``ResponseBundle``,
    ``IncidentBundle``) are deliberately NOT in this list — they live in the
    Warlog backend as product-specific UI projections, not in the open spec.
    """
    expected = {
        "artifacts/approval-decision.json",
        "artifacts/case-return-summary.json",
        "artifacts/classification-assessment.json",
        "artifacts/closure-summary.json",
        "artifacts/enrichment-assessment.json",
        "artifacts/mitre-assessment.json",
        "artifacts/risk-arbitration.json",
        "proposals/investigation-summary-proposal.json",
        "proposals/next-step-proposal.json",
        "proposals/playbook-candidate-proposal.json",
        "proposals/triage-proposal.json",
        "provider-abi/audit-row.json",
        "provider-abi/connector-capability.json",
        "provider-abi/connector-error.json",
        "provider-abi/response-action-result.json",
        "provider-abi/response-action-spec.json",
        "provider-abi/signed-audit-row.json",
        "registry/pack-manifest.json",
    }
    actual = set(PRODUCERS.keys())
    missing = expected - actual
    extras = actual - expected
    assert not missing, f"PRODUCERS missing types: {sorted(missing)}"
    assert not extras, f"PRODUCERS has unexpected types: {sorted(extras)}"


def test_decision_artifact_type_mapping_is_complete_and_consistent() -> None:
    """Every DecisionArtifactType value MUST appear in the mapping file,
    and every mapping entry MUST point to a real schema."""
    import json
    from warlog_spec.provider_abi import DecisionArtifactType

    mapping_path = _SCHEMAS_DIR / "provider-abi" / "decision-artifact-type-mapping.json"
    if not mapping_path.is_file():
        pytest.skip(f"Mapping file not found at {mapping_path}")

    doc = json.loads(mapping_path.read_text(encoding="utf-8"))
    mapping: dict[str, str] = doc["mapping"]

    enum_values = {member.value for member in DecisionArtifactType}
    mapped_keys = set(mapping.keys())

    assert enum_values == mapped_keys, (
        f"DecisionArtifactType / mapping mismatch.\n"
        f"  enum values missing from mapping : {sorted(enum_values - mapped_keys)}\n"
        f"  mapping keys missing from enum   : {sorted(mapped_keys - enum_values)}"
    )

    for enum_value, schema_relpath in mapping.items():
        schema_path = _SCHEMAS_DIR / schema_relpath
        assert schema_path.is_file(), (
            f"Mapping value {schema_relpath!r} for enum {enum_value!r} "
            f"does not resolve to a schema file"
        )


@pytest.mark.parametrize("schema_relpath,factory", sorted(PRODUCERS.items()))
def test_each_factory_output_validates(
    registry: tuple[dict[str, dict], referencing.Registry],
    schema_relpath: str,
    factory,
) -> None:
    """Each factory output validates against its target schema."""
    example = factory()
    schemas, schema_registry = registry
    schema = schemas.get(schema_relpath)
    assert schema is not None, f"Schema not found in registry: {schema_relpath}"

    validator = jsonschema.validators.Draft202012Validator(
        schema, registry=schema_registry
    )
    errors = list(validator.iter_errors(example))
    formatted = "\n".join(
        f"  - {list(e.absolute_path)} : {e.message}" for e in errors
    )
    assert not errors, (
        f"Factory output for {schema_relpath} does not validate:\n{formatted}\n"
        f"Output was:\n{example}"
    )


def test_produce_all_is_deterministic() -> None:
    """Calling produce_all() twice yields identical output (no timestamps leaking)."""
    first = produce_all()
    second = produce_all()
    assert first == second
