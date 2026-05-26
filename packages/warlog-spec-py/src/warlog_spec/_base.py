"""Pydantic base configuration for spec types.

Spec models serialize to camelCase JSON (the wire format used in the
JSON Schemas) but accept both camelCase and snake_case at the constructor.
This single base class enforces that contract.
"""

from __future__ import annotations

from typing import cast

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class SpecModel(BaseModel):
    """Base for all warlog-spec Pydantic models.

    Serializes snake_case fields under camelCase aliases ; accepts both
    in input. Mirrors the ``CamelCaseSchema`` used internally by the
    Warlog backend so models round-trip identically through the spec
    or the runtime.

    **Security : ``extra="forbid"``.** Spec types are interop contracts
    — passing an unknown field is either a typo or an attack. A common
    attack against discriminated unions is to pass a payload that
    looks like one variant but carries extra fields from another (e.g.
    ``{kind: "human", id: "alice", agent: {...automation details...}}``
    against ``AuditActor``). With ``extra="ignore"`` Pydantic would
    silently drop the offending fields and instantiate the wrong
    actor, masking the true executor. With ``extra="forbid"`` Pydantic
    rejects the input and the attack surfaces as a validation error.
    """

    # ``validate_by_name`` / ``serialize_by_alias`` are forward-looking
    # Pydantic 2.11+ keys ; on 2.10 they're silently ignored at runtime,
    # but ConfigDict's TypedDict signature in 2.10 doesn't include them
    # yet. We declare via dict + cast so type checkers treat them as
    # no-ops rather than TypedDict errors. Direct kwargs once the floor
    # moves to 2.11.
    model_config = cast(
        "ConfigDict",
        {
            "alias_generator": to_camel,
            "populate_by_name": True,
            "validate_by_name": True,
            "serialize_by_alias": True,
            "from_attributes": True,
            "str_strip_whitespace": True,
            "validate_assignment": True,
            "extra": "forbid",
        },
    )


__all__ = ["SpecModel"]
