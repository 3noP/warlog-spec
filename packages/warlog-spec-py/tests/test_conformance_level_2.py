"""Level 2 (Write) conformance — produced examples validate against schemas.

This test is what makes ``warlog-spec-py`` a Level 2 reference implementation :
:func:`warlog_spec.conformance.produce_all` outputs one canonical example
for each of the 20 productible artifact types, and every output validates
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

import importlib.util
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
        "artifacts/playbook-gate-evaluation.json",
        "artifacts/risk-arbitration.json",
        "proposals/investigation-summary-proposal.json",
        "proposals/next-step-proposal.json",
        "proposals/playbook-candidate-proposal.json",
        "proposals/triage-proposal.json",
        "provider-abi/a2a-attestation.json",
        "provider-abi/audit-row.json",
        "provider-abi/connector-capability.json",
        "provider-abi/connector-error.json",
        "provider-abi/response-action-result.json",
        "provider-abi/response-action-spec.json",
        "provider-abi/scan-verdict.json",
        "provider-abi/signed-audit-row.json",
        "registry/pack-manifest.json",
    }
    actual = set(PRODUCERS.keys())
    missing = expected - actual
    extras = actual - expected
    assert not missing, f"PRODUCERS missing types: {sorted(missing)}"
    assert not extras, f"PRODUCERS has unexpected types: {sorted(extras)}"


def test_the_level_2_gate_requires_everything_this_package_can_produce() -> None:
    """``runner.py``'s Level 2 set MUST equal ``PRODUCERS``, not merely resemble it.

    The two lists claimed to be "kept in lockstep" in a comment, and were not:
    the runner required 18 types while PRODUCERS held 20, so
    ``playbook-gate-evaluation`` and ``a2a-attestation`` were productible by the
    reference implementations and required of nobody. A third-party gateway
    could have been certified Level 2 without ever emitting an agent
    attestation, which is the one artifact the whole A2A story rests on.

    A comment cannot hold two lists together. This test can.
    """
    runner_path = _SCHEMAS_DIR.parent / "tests" / "conformance" / "runner.py"
    if not runner_path.is_file():
        pytest.skip(f"Conformance runner not found at {runner_path}")

    spec = importlib.util.spec_from_file_location("_warlog_conformance_runner", runner_path)
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)

    required: frozenset[str] = runner.LEVEL_2_PRODUCTIBLE_SCHEMAS
    producible = set(PRODUCERS.keys())

    assert producible - required == set(), (
        "these types are productible here but NOT required for Level 2, so an "
        f"implementation could skip them and still certify: {sorted(producible - required)}"
    )
    assert required - producible == set(), (
        "the Level 2 gate demands types this reference package cannot produce: "
        f"{sorted(required - producible)}"
    )


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


def test_every_decision_artifact_is_productible_by_this_package() -> None:
    """A referenced decision artifact MUST be producible, not merely described.

    ``AuditRow.decisionRef`` is what makes an action's justification checkable,
    so an implementer has to be able to build one of each referenced artifact
    and validate it WITHOUT the Warlog backend — the whole point of the spec
    shipping as a standalone package.

    The gap this closes is a real one: ``playbook_gate_evaluation`` was added to
    the enum, the mapping and the schemas while remaining absent from
    ``PRODUCERS``, and every existing test stayed green. A schema plus a mapping
    entry describes a shape; only a producer proves the shape can be built.
    """
    import json

    mapping_path = _SCHEMAS_DIR / "provider-abi" / "decision-artifact-type-mapping.json"
    if not mapping_path.is_file():
        pytest.skip(f"Mapping file not found at {mapping_path}")

    mapping: dict[str, str] = json.loads(
        mapping_path.read_text(encoding="utf-8")
    )["mapping"]

    unproducible = sorted(
        f"{enum_value} -> {relpath}"
        for enum_value, relpath in mapping.items()
        if relpath not in PRODUCERS
    )
    assert unproducible == [], (
        "these decision artifacts are referenced by AuditRow.decisionRef but "
        f"this package cannot produce one: {unproducible}"
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
