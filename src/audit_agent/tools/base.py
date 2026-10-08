"""Tool spec, per-call context, and rationale injection.

Every tool declares a JSON input schema *without* ``rationale``. ``Tool.anthropic_schema``
injects a required ``rationale`` string, so the model must state why it is calling
each tool. The rationale is stripped from the arguments before the tool runs.

Tools never open files directly. They ask their ``ToolContext`` to resolve paths
(sandbox-checked by ``PermissionGuard``) and record every read or write as a
``data_access`` audit event.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from audit_agent.audit.events import DataOperation
from audit_agent.audit.logger import AuditLogger
from audit_agent.tools.permissions import PermissionGuard

RATIONALE_PROPERTY: dict[str, Any] = {
    "type": "string",
    "minLength": 1,
    "description": (
        "One or two sentences explaining why you are calling this tool now and what you "
        "expect to learn or produce. This is recorded in the audit log."
    ),
}

_JSON_TYPES: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
}


class ToolInputError(ValueError):
    """The model supplied arguments that do not match the tool's schema."""


@dataclass
class ToolContext:
    """What a running tool may use: sandboxed paths and the audit logger."""

    run_id: str
    tool_name: str
    logger: AuditLogger
    guard: PermissionGuard

    def resolve_read(self, path: str | Path) -> Path:
        return self.guard.resolve_read(path)

    def resolve_write(self, path: str | Path) -> Path:
        return self.guard.resolve_write(path)

    def record_access(
        self,
        path: Path,
        operation: DataOperation,
        *,
        records: int | None = None,
        fields: Sequence[str] | None = None,
    ) -> None:
        """Log a ``data_access`` event. Field names only, never values."""
        self.logger.data_access(
            self.run_id,
            self.tool_name,
            self.guard.display_path(path),
            operation,
            records_touched=records,
            fields_accessed=list(fields) if fields is not None else None,
        )


ToolFunc = Callable[[ToolContext, dict[str, Any]], str]


@dataclass(frozen=True)
class Tool:
    """A tool the model can call. ``func`` returns the text sent back to the model."""

    name: str
    description: str
    input_schema: dict[str, Any]
    func: ToolFunc = field(repr=False)

    def anthropic_schema(self) -> dict[str, Any]:
        """Schema for the Anthropic ``tools`` parameter, with ``rationale`` required."""
        schema = dict(self.input_schema)
        properties = dict(schema.get("properties", {}))
        properties["rationale"] = RATIONALE_PROPERTY
        required = [r for r in schema.get("required", []) if r != "rationale"]
        schema |= {"type": "object", "properties": properties, "required": [*required, "rationale"]}
        return {"name": self.name, "description": self.description, "input_schema": schema}

    def prepare_args(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        """Drop ``rationale``, apply defaults, and validate against ``input_schema``."""
        args = {k: v for k, v in raw.items() if k != "rationale"}
        return validate_args(self.input_schema, args)


def validate_args(schema: Mapping[str, Any], args: Mapping[str, Any]) -> dict[str, Any]:
    """Minimal JSON-schema check for flat tool inputs (types, enum, bounds, required)."""
    properties: Mapping[str, Any] = schema.get("properties", {})
    out = dict(args)
    if schema.get("additionalProperties") is False:
        unknown = sorted(set(out) - set(properties))
        if unknown:
            raise ToolInputError(f"Unknown argument(s): {', '.join(unknown)}")
    for name, spec in properties.items():
        if name not in out and "default" in spec:
            out[name] = spec["default"]
    missing = [name for name in schema.get("required", []) if name not in out]
    if missing:
        raise ToolInputError(f"Missing required argument(s): {', '.join(missing)}")
    for name, value in out.items():
        if name in properties:
            _check_value(name, properties[name], value)
    return out


def _check_value(name: str, spec: Mapping[str, Any], value: Any) -> None:
    expected = spec.get("type")
    if expected is not None:
        py_type = _JSON_TYPES[expected]
        if isinstance(value, bool) and expected != "boolean" or not isinstance(value, py_type):
            raise ToolInputError(f"Argument {name!r} must be of type {expected}")
    if "enum" in spec and value not in spec["enum"]:
        raise ToolInputError(f"Argument {name!r} must be one of {spec['enum']}")
    if "minimum" in spec and value < spec["minimum"]:
        raise ToolInputError(f"Argument {name!r} must be >= {spec['minimum']}")
    if "maximum" in spec and value > spec["maximum"]:
        raise ToolInputError(f"Argument {name!r} must be <= {spec['maximum']}")
    if "minLength" in spec and len(value) < spec["minLength"]:
        raise ToolInputError(f"Argument {name!r} must have length >= {spec['minLength']}")
    if "maxLength" in spec and len(value) > spec["maxLength"]:
        raise ToolInputError(f"Argument {name!r} must have length <= {spec['maxLength']}")
