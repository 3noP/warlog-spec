"""Conformance test runner for Warlog Spec implementations.

An implementation claims conformance to spec version X.Y by running this
runner against the bundled fixtures and submitting the results to
``COMPAT.md`` via PR.

Levels (see ``COMPAT.md``):
    Level 1 — Read    : implementation accepts valid artifacts and rejects invalid ones
    Level 2 — Write   : implementation can produce conformant artifacts
    Level 3 — Full    : both, across declared scope
    Level 4 — Provider: implements provider ABI against a mock vendor

This runner executes Level 1 (validation of canonical examples plus the
negative corpus) and Level 2 (validation of an implementation's produced fixtures, with a
coverage requirement on the 18 productible types). It also validates
Level 4 provider evidence reports emitted by reference packages or
third-party provider test suites.

Usage:
    # Level 1 — validate canonical examples in warlog-spec/examples/
    python runner.py --level 1

    # Level 2 — validate implementation-produced fixtures
    python runner.py --level 2 --fixtures-dir ./my-impl-fixtures/

    # Level 4 — validate mock-provider ABI lifecycle evidence
    python runner.py --level 4 --provider-report ./provider-report.json

    # Validate a single file against a chosen schema
    python runner.py --json some-artifact.json --schema bundles/triage-bundle.json

Dependencies:
    pip install jsonschema
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012
except ImportError:
    sys.stderr.write(
        "Missing dependency: jsonschema. Install with `pip install jsonschema`.\n"
    )
    sys.exit(2)


HERE = Path(__file__).resolve().parent
SPEC_ROOT = HERE.parent.parent  # warlog-spec/
DEFAULT_SCHEMAS_DIR = SPEC_ROOT / "schemas"
DEFAULT_EXAMPLES_DIR = SPEC_ROOT / "examples"
DEFAULT_INVALID_FIXTURES_DIR = HERE / "fixtures" / "invalid"


def _schema_paths(schemas_dir: Path) -> Iterable[Path]:
    """Yield canonical source schemas, excluding publication aliases."""
    for path in sorted(schemas_dir.rglob("*.json")):
        rel = path.relative_to(schemas_dir)
        if path.name == "manifest.json" or rel.parts[0] == "draft":
            continue
        yield path


# Productible artifact types — the 18 shapes that an implementation
# MUST produce one example of to claim Level 2. Kept in lockstep with
# ``warlog_spec.conformance.PRODUCERS`` (the Python reference producer).
#
# Enums (common/*.json), envelopes (envelopes/*.json), the
# decision-artifact-type-mapping, and the action-catalog are NOT
# productible on their own — they appear embedded inside the productible
# artifacts.
#
# Bundle shapes (triage / investigation / response / incident) are
# deliberately NOT in this set : they are product-specific UI projections
# the spec does not standardize. See ``warlog_spec.conformance`` module
# docstring for the doctrine.
LEVEL_2_PRODUCTIBLE_SCHEMAS: frozenset[str] = frozenset(
    {
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
)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _strip_comments(obj: object) -> object:
    """Recursively drop keys starting with '_' (e.g. '_comment') from examples."""
    if isinstance(obj, dict):
        return {
            k: _strip_comments(v) for k, v in obj.items() if not k.startswith("_")
        }
    if isinstance(obj, list):
        return [_strip_comments(item) for item in obj]
    return obj


def _build_registry(schemas_dir: Path) -> tuple[dict[str, dict], Registry]:
    """Load every JSON Schema under ``schemas_dir``, key by $id and by relpath."""
    schemas: dict[str, dict] = {}
    resources: list[tuple[str, Resource]] = []
    for path in _schema_paths(schemas_dir):
        schema = _load_json(path)
        rel = str(path.relative_to(schemas_dir)).replace("\\", "/")
        resource = Resource.from_contents(schema, default_specification=DRAFT202012)
        schemas[rel] = schema
        resources.append((rel, resource))
        if "$id" in schema:
            schemas[schema["$id"]] = schema
            resources.append((schema["$id"], resource))
    return schemas, Registry().with_resources(resources)


def _examples_for(schema_path: Path, examples_dir: Path, schemas_dir: Path) -> Iterable[Path]:
    """Find canonical examples for a given schema.

    Convention: ``<examples_dir>/<subdir>/<schema-stem>.<variant>.json``.
    """
    rel = schema_path.relative_to(schemas_dir)
    subdir = rel.parent.as_posix()  # e.g. "bundles"
    stem = rel.stem  # e.g. "triage-bundle"
    pattern = f"{stem}.*.json"
    candidate_dir = examples_dir / subdir
    if not candidate_dir.exists():
        return []
    return sorted(candidate_dir.glob(pattern))


def validate_one(json_obj: object, schema: dict, registry: Registry) -> list[str]:
    """Validate a JSON object against a schema. Returns list of error paths."""
    validator = Draft202012Validator(schema, registry=registry)
    return [
        f"{list(err.absolute_path)} : {err.message}"
        for err in validator.iter_errors(json_obj)
    ]


def _run_validation_pass(schemas_dir: Path, examples_dir: Path) -> tuple[int, int, set[str]]:
    """Validate every example against its schema. Shared by Level 1 and 2.

    Returns ``(total, failed, schemas_with_examples)`` — the third value
    is the set of schema relpaths that have at least one example.
    """
    schemas, schema_registry = _build_registry(schemas_dir)
    covered: set[str] = set()
    failed = 0
    total = 0
    for schema_path in _schema_paths(schemas_dir):
        examples = list(_examples_for(schema_path, examples_dir, schemas_dir))
        if not examples:
            continue
        schema = _load_json(schema_path)
        rel = str(schema_path.relative_to(schemas_dir)).replace("\\", "/")
        for example_path in examples:
            total += 1
            example = _strip_comments(_load_json(example_path))
            errors = validate_one(example, schema, schema_registry)
            label = f"{example_path.relative_to(SPEC_ROOT) if example_path.is_relative_to(SPEC_ROOT) else example_path} vs schemas/{rel}"
            if errors:
                failed += 1
                print(f"FAIL {label}")
                for err in errors:
                    print(f"  - {err}")
            else:
                print(f"OK   {label}")
                covered.add(rel)
    return total, failed, covered


def _run_negative_validation_pass(schemas_dir: Path, invalid_dir: Path) -> tuple[int, int, set[str]]:
    """Validate that every invalid fixture is rejected by its target schema.

    Returns ``(total, unexpectedly_valid, covered)`` where ``covered`` is
    the set of schema relpaths that have at least one negative fixture.
    """
    schemas, schema_registry = _build_registry(schemas_dir)
    covered: set[str] = set()
    unexpectedly_valid = 0
    total = 0
    if not invalid_dir.exists():
        print(f"WARN negative corpus not found: {invalid_dir}")
        return total, unexpectedly_valid, covered

    for schema_path in _schema_paths(schemas_dir):
        invalid_examples = list(_examples_for(schema_path, invalid_dir, schemas_dir))
        if not invalid_examples:
            continue
        schema = _load_json(schema_path)
        rel = str(schema_path.relative_to(schemas_dir)).replace("\\", "/")
        for example_path in invalid_examples:
            total += 1
            example = _strip_comments(_load_json(example_path))
            errors = validate_one(example, schema, schema_registry)
            label = f"{example_path.relative_to(SPEC_ROOT) if example_path.is_relative_to(SPEC_ROOT) else example_path} vs schemas/{rel}"
            if errors:
                print(f"OK   rejected {label}")
                covered.add(rel)
            else:
                unexpectedly_valid += 1
                print(f"FAIL invalid fixture unexpectedly validated: {label}")
    return total, unexpectedly_valid, covered


def run_level_1(schemas_dir: Path, examples_dir: Path, invalid_dir: Path) -> int:
    """Level 1 — Read. Valid examples pass and invalid corpus fails."""
    total, failed, _ = _run_validation_pass(schemas_dir, examples_dir)
    print(f"\n{total - failed}/{total} examples validate against their schemas")
    invalid_total, unexpectedly_valid, invalid_covered = _run_negative_validation_pass(schemas_dir, invalid_dir)
    print(f"{invalid_total - unexpectedly_valid}/{invalid_total} invalid fixtures rejected by their schemas")
    print(f"Negative coverage : {len(invalid_covered)} schema surfaces represented")
    return 0 if failed == 0 and unexpectedly_valid == 0 else 1


def run_level_2(schemas_dir: Path, fixtures_dir: Path) -> int:
    """Level 2 — Write. Implementation-produced fixtures must :

    1. Validate against their schema (same check as Level 1).
    2. Cover every productible artifact type (at least one fixture
       per entry in :data:`LEVEL_2_PRODUCTIBLE_SCHEMAS`).

    Coverage gap fails the claim even if every individual fixture
    passes — a Level 2 implementation must demonstrate it can produce
    every canonical shape, not a subset.
    """
    total, failed, covered = _run_validation_pass(schemas_dir, fixtures_dir)
    missing = LEVEL_2_PRODUCTIBLE_SCHEMAS - covered
    extras = covered - LEVEL_2_PRODUCTIBLE_SCHEMAS

    print(
        f"\n{total - failed}/{total} fixtures validate against their schemas"
    )
    print(
        f"Coverage : {len(covered & LEVEL_2_PRODUCTIBLE_SCHEMAS)}/{len(LEVEL_2_PRODUCTIBLE_SCHEMAS)} "
        f"productible types represented"
    )
    if missing:
        print("\nMISSING productible types (no fixture covers these):")
        for rel in sorted(missing):
            print(f"  - {rel}")
    if extras:
        print("\nExtra fixtures outside the Level 2 productible set (informational):")
        for rel in sorted(extras):
            print(f"  - {rel}")

    if failed:
        return 1
    if missing:
        return 1
    return 0


def _nested(obj: object, *keys: str) -> object | None:
    current = obj
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _append_schema_errors(
    *,
    label: str,
    obj: object,
    schema_relpath: str,
    schemas: dict[str, dict],
    schema_registry: Registry,
    failures: list[str],
) -> None:
    schema = schemas.get(schema_relpath)
    if schema is None:
        failures.append(f"runner error: schema not found: {schema_relpath}")
        return
    errors = validate_one(obj, schema, schema_registry)
    for err in errors:
        failures.append(f"{label} schema violation: {err}")


def run_level_4(schemas_dir: Path, provider_report: Path) -> int:
    """Level 4 — Provider.

    A provider evidence report proves an implementation exercised the public
    Provider ABI lifecycle against a deterministic mock vendor. The runner
    validates the embedded ABI objects against their public schemas and checks
    the semantic invariants that matter for runtime trust boundaries.
    """

    schemas, schema_registry = _build_registry(schemas_dir)
    report = _strip_comments(_load_json(provider_report))
    failures: list[str] = []

    if not isinstance(report, dict):
        failures.append("provider report must be a JSON object")
        report = {}

    if report.get("specVersion") != "1.0":
        failures.append("specVersion must be '1.0'")
    if report.get("level") != 4:
        failures.append("level must be 4")

    implementation = report.get("implementation")
    if not isinstance(implementation, dict):
        failures.append("implementation must be an object")
    else:
        for key in ("name", "version", "language"):
            if not implementation.get(key):
                failures.append(f"implementation.{key} is required")

    scenario = report.get("scenario")
    if not isinstance(scenario, dict):
        failures.append("scenario must be an object")
    else:
        if not scenario.get("id"):
            failures.append("scenario.id is required")
        if not scenario.get("mockVendor"):
            failures.append("scenario.mockVendor is required")
        if not scenario.get("actionId"):
            failures.append("scenario.actionId is required")

    capability = report.get("capability")
    spec = report.get("spec")
    apply_result = _nested(report, "apply", "result")
    replay_result = _nested(report, "idempotency", "result")
    unsupported_error = _nested(report, "unsupportedAction", "error")

    if capability is None:
        failures.append("capability is required")
    else:
        _append_schema_errors(
            label="capability",
            obj=capability,
            schema_relpath="provider-abi/connector-capability.json",
            schemas=schemas,
            schema_registry=schema_registry,
            failures=failures,
        )
    if spec is None:
        failures.append("spec is required")
    else:
        _append_schema_errors(
            label="spec",
            obj=spec,
            schema_relpath="provider-abi/response-action-spec.json",
            schemas=schemas,
            schema_registry=schema_registry,
            failures=failures,
        )
    if apply_result is None:
        failures.append("apply.result is required")
    else:
        _append_schema_errors(
            label="apply.result",
            obj=apply_result,
            schema_relpath="provider-abi/response-action-result.json",
            schemas=schemas,
            schema_registry=schema_registry,
            failures=failures,
        )
    if replay_result is None:
        failures.append("idempotency.result is required")
    else:
        _append_schema_errors(
            label="idempotency.result",
            obj=replay_result,
            schema_relpath="provider-abi/response-action-result.json",
            schemas=schemas,
            schema_registry=schema_registry,
            failures=failures,
        )
    if unsupported_error is None:
        failures.append("unsupportedAction.error is required")
    else:
        _append_schema_errors(
            label="unsupportedAction.error",
            obj=unsupported_error,
            schema_relpath="provider-abi/connector-error.json",
            schemas=schemas,
            schema_registry=schema_registry,
            failures=failures,
        )

    action_id = spec.get("actionId") if isinstance(spec, dict) else None
    declared_actions = _nested(capability, "egress", "supportsResponseActions")
    if isinstance(declared_actions, list) and action_id not in declared_actions:
        failures.append("spec.actionId must be declared by capability.egress.supportsResponseActions")

    if _nested(report, "dryRun", "called") is not True:
        failures.append("dryRun.called must be true")
    if _nested(report, "dryRun", "mutationsBefore") != _nested(
        report, "dryRun", "mutationsAfter"
    ):
        failures.append("dry_run must not mutate mock vendor state")

    if _nested(report, "apply", "called") is not True:
        failures.append("apply.called must be true")
    if isinstance(apply_result, dict) and apply_result.get("outcome") != "success":
        failures.append("apply.result.outcome must be 'success'")
    if isinstance(apply_result, dict) and action_id and apply_result.get("actionId") != action_id:
        failures.append("apply.result.actionId must match spec.actionId")

    if _nested(report, "verify", "called") is not True:
        failures.append("verify.called must be true")
    if _nested(report, "verify", "verified") is not True:
        failures.append("verify.verified must be true")

    if _nested(report, "idempotency", "replayed") is not True:
        failures.append("idempotency.replayed must be true")
    if _nested(report, "idempotency", "sameVendorTask") is not True:
        failures.append("idempotency.sameVendorTask must be true")
    if _nested(report, "idempotency", "mutationsAfterReplay") != _nested(
        report, "apply", "mutationsAfter"
    ):
        failures.append("idempotency replay must not add a vendor mutation")
    if isinstance(replay_result, dict) and replay_result.get("outcome") != "success":
        failures.append("idempotency.result.outcome must be 'success'")

    if _nested(report, "unsupportedAction", "rejected") is not True:
        failures.append("unsupportedAction.rejected must be true")
    if isinstance(unsupported_error, dict) and unsupported_error.get("category") != "policy":
        failures.append("unsupportedAction.error.category must be 'policy'")

    impl_label = "unknown implementation"
    if isinstance(implementation, dict):
        impl_label = (
            f"{implementation.get('name', 'unknown')} "
            f"{implementation.get('version', 'unknown')} "
            f"({implementation.get('language', 'unknown')})"
        )
    if failures:
        print(f"FAIL Level 4 provider report: {provider_report} [{impl_label}]")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"OK   Level 4 provider report: {provider_report} [{impl_label}]")
    print("OK   capability/spec/results validate against provider ABI schemas")
    print("OK   dry_run had no vendor mutation")
    print("OK   apply succeeded and verify confirmed vendor state")
    print("OK   idempotency replay produced no duplicate vendor mutation")
    print("OK   unsupported action rejected with category=policy")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Warlog Spec conformance runner")
    parser.add_argument("--level", type=int, choices=[1, 2, 4], default=1)
    parser.add_argument(
        "--schemas-dir",
        type=Path,
        default=DEFAULT_SCHEMAS_DIR,
        help="Directory containing JSON Schemas (default: ../../schemas)",
    )
    parser.add_argument(
        "--examples-dir",
        type=Path,
        default=DEFAULT_EXAMPLES_DIR,
        help="Directory containing canonical examples for Level 1 (default: ../../examples)",
    )
    parser.add_argument(
        "--invalid-fixtures-dir",
        type=Path,
        default=DEFAULT_INVALID_FIXTURES_DIR,
        help="Directory containing invalid fixtures that MUST fail validation for Level 1.",
    )
    parser.add_argument(
        "--fixtures-dir",
        type=Path,
        default=None,
        help=(
            "Directory containing implementation-produced fixtures for Level 2. "
            "Layout follows the convention <subdir>/<schema-stem>.<variant>.json "
            "matching the schemas/ tree."
        ),
    )
    parser.add_argument(
        "--provider-report",
        type=Path,
        default=None,
        help="Level 4 provider evidence report emitted by a mock-vendor contract run.",
    )
    parser.add_argument("--json", type=Path, default=None, help="Single JSON file to validate")
    parser.add_argument("--schema", type=str, default=None, help="Schema relpath under schemas-dir")
    args = parser.parse_args()

    schemas_dir = args.schemas_dir.resolve()

    if args.json and args.schema:
        schemas, schema_registry = _build_registry(schemas_dir)
        schema = schemas.get(args.schema) or _load_json(schemas_dir / args.schema)
        obj = _strip_comments(_load_json(args.json))
        errors = validate_one(obj, schema, schema_registry)
        if errors:
            print(f"FAIL {args.json}")
            for err in errors:
                print(f"  - {err}")
            return 1
        print(f"OK   {args.json}")
        return 0

    if args.level == 1:
        return run_level_1(
            schemas_dir,
            args.examples_dir.resolve(),
            args.invalid_fixtures_dir.resolve(),
        )

    if args.level == 4:
        if args.provider_report is None:
            sys.stderr.write(
                "Level 4 requires --provider-report FILE (mock-vendor evidence report).\n"
            )
            return 2
        return run_level_4(schemas_dir, args.provider_report.resolve())

    # Level 2 — fixtures-dir is required.
    if args.fixtures_dir is None:
        sys.stderr.write(
            "Level 2 requires --fixtures-dir DIR (an implementation's produced fixtures).\n"
        )
        return 2
    return run_level_2(schemas_dir, args.fixtures_dir.resolve())


if __name__ == "__main__":
    sys.exit(main())
