"""Portable, versioned reporting data. No workflow imports or rendering IO.

Legacy ReportSpec remains supported; new producers use these structured blocks.
JSON serialization is deliberately strict: never stringify arbitrary objects.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
from typing import Any

SCHEMA_VERSION = 1
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_FINDINGS = 10_000
STATES = frozenset({"pending", "running", "completed", "partial", "skipped", "failed", "cancelled", "unknown"})
BLOCK_KINDS = frozenset({"paragraph", "table", "list", "code", "section", "diagram", "legacy_markdown"})


def _strings(value: Any, field_name: str) -> None:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{field_name}: expected an array of strings")


def _objects(value: Any, field_name: str) -> None:
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise ValueError(f"{field_name}: expected an array of objects")


def _scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, bool, int)) or (isinstance(value, float) and math.isfinite(value))


def json_value(value: Any, path: str = "$", depth: int = 0) -> Any:
    """Validate and copy JSON values; errors identify the offending field."""
    if depth > 40:
        raise ValueError(f"{path}: reporting nesting limit exceeded")
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    if isinstance(value, (list, tuple)):
        return [json_value(v, f"{path}[{i}]", depth + 1) for i, v in enumerate(value)]
    if isinstance(value, dict) and all(isinstance(k, str) for k in value):
        return {k: json_value(v, f"{path}.{k}", depth + 1) for k, v in value.items()}
    raise ValueError(f"{path}: unsupported reporting value {type(value).__name__}")


def encode(value: Any) -> bytes:
    data = json.dumps(json_value(value), sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
    if len(data) > MAX_JSON_BYTES:
        raise ValueError("Reporting JSON exceeds 32 MiB; capture a declared bounded projection")
    return data


def digest(value: Any) -> str:
    return hashlib.sha256(encode(value)).hexdigest()


@dataclass
class Inline:
    kind: str
    text: str
    url: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> Inline:
        if (not isinstance(data, dict) or not isinstance(data.get("kind"), str)
                or data["kind"] not in {"text", "strong", "emphasis", "code", "link"}
                or not isinstance(data.get("text"), str) or not isinstance(data.get("url", ""), str)
                or set(data) - {"kind", "text", "url"}):
            raise ValueError("Invalid report inline content")
        return cls(**data)


@dataclass
class Block:
    kind: str
    title: str = ""
    text: str = ""
    columns: list[str] = field(default_factory=list)
    rows: list[list[Any]] = field(default_factory=list)
    items: list[str] = field(default_factory=list)
    language: str = ""
    children: list[Block] = field(default_factory=list)
    source_refs: list[str] = field(default_factory=list)
    extensions: dict[str, Any] = field(default_factory=dict)
    inline: list[Inline] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict, depth: int = 0) -> Block:
        if depth > 16 or not isinstance(data, dict) or not isinstance(data.get("kind"), str) or data["kind"] not in BLOCK_KINDS:
            raise ValueError("Invalid or excessively nested report block")
        allowed = set(cls.__dataclass_fields__)
        if set(data) - allowed:
            raise ValueError("Unsupported report block fields")
        result = cls(**{k: v for k, v in data.items() if k not in {"children", "inline"}})
        for name in ("title", "text", "language"):
            if not isinstance(getattr(result, name), str):
                raise ValueError(f"Invalid block {name}")
        for name in ("columns", "items", "source_refs"):
            value = getattr(result, name)
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ValueError(f"Invalid block {name}")
        if not isinstance(result.rows, list) or not all(isinstance(r, list) for r in result.rows):
            raise ValueError("Invalid table rows")
        if result.kind == "table" and any(len(row) != len(result.columns) or not all(_scalar(v) for v in row) for row in result.rows):
            raise ValueError("Table rows must match columns and contain scalar values")
        if not isinstance(result.extensions, dict) or not isinstance(data.get("children", []), list):
            raise ValueError("Invalid block extensions or children")
        result.children = [cls.from_dict(c, depth + 1) for c in data.get("children", [])]
        if not isinstance(data.get("inline", []), list):
            raise ValueError("Invalid block inline content")
        result.inline = [Inline.from_dict(c) for c in data.get("inline", [])]
        return result


@dataclass
class StageEnvelope:
    stage_id: str
    state: str = "unknown"
    producer: str = "raptor"
    pass_id: str = ""
    attempt_id: str = ""
    original_state: str = ""
    reason: str = ""
    duration_seconds: float | None = None
    scope: dict[str, Any] = field(default_factory=dict)
    coverage: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    extensions: dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION
    producer_version: str = "unknown"
    run_id: str = ""

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != SCHEMA_VERSION:
            raise ValueError("Unsupported stage envelope schema version")
        self.validate()
        if self.state not in STATES:
            self.original_state = self.state
            self.state = "unknown"
            self.diagnostics = [*self.diagnostics, "Unrecognized stage state"]

    def validate(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != SCHEMA_VERSION:
            raise ValueError("Unsupported stage envelope schema version")
        for name in ("stage_id", "state", "producer", "pass_id", "attempt_id", "original_state", "reason", "producer_version", "run_id"):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"Invalid stage {name}")
        if self.duration_seconds is not None and (isinstance(self.duration_seconds, bool) or not isinstance(self.duration_seconds, (int, float))
                                                  or not math.isfinite(self.duration_seconds) or self.duration_seconds < 0):
            raise ValueError("Invalid stage duration_seconds")
        _strings(self.diagnostics, "stage.diagnostics")
        _objects(self.coverage, "stage.coverage")
        _objects(self.artifacts, "stage.artifacts")
        if not isinstance(self.scope, dict) or not isinstance(self.extensions, dict):
            raise ValueError("Invalid stage scope or extensions")


@dataclass
class ReportContext:
    kind: str
    run_id: str
    target: str = ""
    state: str = "unknown"
    findings: list[dict[str, Any]] = field(default_factory=list)
    stages: list[StageEnvelope] = field(default_factory=list)
    expected_stages: list[str] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    parents: list[str] = field(default_factory=list)
    pass_id: str = ""
    attempt_id: str = ""
    generated_at: str = ""
    extensions: dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict:
        if type(self.schema_version) is not int or self.schema_version != SCHEMA_VERSION or not isinstance(self.state, str) or self.state not in STATES:
            raise ValueError("Unsupported context version or execution state")
        for name in ("kind", "run_id", "target", "pass_id", "attempt_id", "generated_at"):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"Invalid context {name}")
        for name in ("diagnostics", "expected_stages", "parents"):
            _strings(getattr(self, name), f"context.{name}")
        _objects(self.findings, "context.findings")
        _objects(self.artifacts, "context.artifacts")
        for artifact in self.artifacts:
            for name in ("path", "uri", "digest", "canonical_digest"):
                if artifact.get(name) is not None and not isinstance(artifact[name], str):
                    raise ValueError(f"Invalid artifact {name}")
        if not isinstance(self.extensions, dict) or not isinstance(self.stages, list) or not all(isinstance(s, StageEnvelope) for s in self.stages):
            raise ValueError("Invalid context extensions or stages")
        for stage in self.stages:
            stage.validate()
        refs = [f.get("occurrence_ref") for f in self.findings]
        if not all(isinstance(r, str) and r for r in refs) or len(set(refs)) != len(refs):
            raise ValueError("Missing or duplicate finding occurrence references")
        for finding in self.findings:
            source_id = finding.get("source_id")
            if source_id is not None and (isinstance(source_id, bool) or not isinstance(source_id, (str, int))):
                raise ValueError("Invalid normalized finding source_id")
            if finding.get("source_occurrence_ref") is not None and not isinstance(finding["source_occurrence_ref"], str):
                raise ValueError("Invalid normalized finding source_occurrence_ref")
            for name in ("tool", "rule_id", "message", "file", "status", "verdict_origin", "scanner_level", "severity"):
                if finding.get(name) is not None and not isinstance(finding[name], str):
                    raise ValueError(f"Invalid normalized finding {name}")
            line = finding.get("line")
            if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
                raise ValueError("Invalid normalized finding line")
        if len(self.findings) > MAX_FINDINGS:
            raise ValueError("Reporting finding limit exceeded")
        return json_value(asdict(self))

    @property
    def snapshot_id(self) -> str:
        return digest(self.to_dict())

    @property
    def completion_state(self) -> str:
        known = {s.stage_id for s in self.stages}
        if (self.state == "completed" and
                (any(s not in known for s in self.expected_stages)
                 or any(s.state not in {"completed", "skipped"} for s in self.stages))):
            return "partial"
        return self.state

    @classmethod
    def from_dict(cls, data: dict) -> ReportContext:
        if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("Unsupported report context schema version")
        data = json_value(data)
        identity = data.pop("snapshot_id", None)
        if set(data) - set(cls.__dataclass_fields__):
            raise ValueError("Unsupported context fields")
        if not isinstance(data.get("stages", []), list) or not all(isinstance(s, dict) for s in data.get("stages", [])):
            raise ValueError("Invalid stage envelopes")
        try:
            result = cls(**{**data, "stages": [StageEnvelope(**s) for s in data.get("stages", [])]})
        except TypeError as exc:
            raise ValueError("Invalid reporting context or stage fields") from exc
        for name in ("kind", "run_id", "target", "pass_id", "attempt_id", "generated_at"):
            if not isinstance(getattr(result, name), str):
                raise ValueError(f"Invalid context {name}")
        if not isinstance(result.findings, list) or not all(isinstance(f, dict) and isinstance(f.get("occurrence_ref"), str) for f in result.findings):
            raise ValueError("Invalid normalized findings")
        for name in ("diagnostics", "expected_stages", "parents"):
            value = getattr(result, name)
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ValueError(f"Invalid context {name}")
        result.to_dict()
        if identity is not None and identity != result.snapshot_id:
            raise ValueError("Context snapshot digest mismatch")
        return result


@dataclass
class ReportDocument:
    title: str
    kind: str
    snapshot_id: str
    metadata: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    blocks: list[Block] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    extensions: dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION
    builder_version: str = "1"

    def to_dict(self) -> dict:
        return json_value(asdict(self))

    @classmethod
    def from_dict(cls, data: dict) -> ReportDocument:
        if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("Unsupported report document schema version")
        json_value(data)
        if set(data) - set(cls.__dataclass_fields__):
            raise ValueError("Unsupported document fields; use namespaced extensions")
        for key in ("title", "kind", "snapshot_id", "builder_version"):
            if not isinstance(data.get(key), str):
                raise ValueError(f"Invalid document {key}")
        for key in ("metadata", "summary", "extensions"):
            if not isinstance(data.get(key, {}), dict):
                raise ValueError(f"Invalid document {key}")
        if any(not _scalar(v) for key in ("metadata", "summary") for v in data.get(key, {}).values()):
            raise ValueError("Report metadata and summary values must be scalar")
        if not isinstance(data.get("diagnostics", []), list) or not all(isinstance(x, str) for x in data.get("diagnostics", [])):
            raise ValueError("Invalid document diagnostics")
        if not isinstance(data.get("blocks", []), list):
            raise ValueError("Invalid document blocks")
        return cls(**{**data, "blocks": [Block.from_dict(b) for b in data.get("blocks", [])]})
