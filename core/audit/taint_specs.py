"""Project-specific taint specification synthesis.

The LLM reads codebase functions and generates taint specifications
that teach mechanical tools (Joern, CodeQL, Semgrep) the project's
vocabulary — which functions are sources, sinks, sanitisers,
and propagators.

This runs once during the summary phase and the synthesised specs
power all subsequent mechanical tool queries for the rest of the
audit.  One LLM pass generates specs; mechanical tools consume
them at near-zero marginal cost.

Spec types:
  - Source: produces attacker-controlled data
  - Sink: consumes data in a security-sensitive way
  - Sanitiser: kills taint for specific threat classes
  - Propagator: transforms data while preserving/changing taint

Each spec carries a trust_level and the threat classes it applies to,
so mechanical tools can make precise taint decisions instead of
guessing "propagate everything" or "propagate nothing".
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

logger = logging.getLogger(__name__)


class TaintRole(str, Enum):
    SOURCE = "source"
    SINK = "sink"
    SANITISER = "sanitiser"
    PROPAGATOR = "propagator"


class TrustLevel(str, Enum):
    UNTRUSTED = "untrusted"
    PARTIALLY_TRUSTED = "partially_trusted"
    TRUSTED = "trusted"


_THREAT_CLASSES = frozenset({
    "xss",
    "sql_injection",
    "command_injection",
    "path_traversal",
    "html_injection",
    "ldap_injection",
    "xml_injection",
    "ssrf",
    "open_redirect",
    "deserialization",
    "buffer_overflow",
    "format_string",
})


@dataclass
class TaintSpec:
    """A project-specific taint specification for one function."""

    function: str
    file: str
    role: TaintRole
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    threat_classes: list[str] = field(default_factory=list)
    params_affected: list[str] = field(default_factory=list)
    return_affected: bool = False
    taint_class: str = ""
    taint_class_change: str = ""
    confidence: str = "medium"
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "function": self.function,
            "file": self.file,
            "role": self.role.value,
            "trust_level": self.trust_level.value,
            "confidence": self.confidence,
        }
        if self.threat_classes:
            d["threat_classes"] = self.threat_classes
        if self.params_affected:
            d["params_affected"] = self.params_affected
        if self.return_affected:
            d["return_affected"] = True
        if self.taint_class:
            d["taint_class"] = self.taint_class
        if self.taint_class_change:
            d["taint_class_change"] = self.taint_class_change
        if self.reasoning:
            d["reasoning"] = self.reasoning
        return d


@dataclass
class TaintSpecSet:
    """Collection of taint specs for a project."""

    specs: list[TaintSpec] = field(default_factory=list)

    def add(self, spec: TaintSpec) -> None:
        self.specs.append(spec)

    def sources(self) -> list[TaintSpec]:
        return [s for s in self.specs if s.role == TaintRole.SOURCE]

    def sinks(self) -> list[TaintSpec]:
        return [s for s in self.specs if s.role == TaintRole.SINK]

    def sanitisers(self) -> list[TaintSpec]:
        return [s for s in self.specs if s.role == TaintRole.SANITISER]

    def propagators(self) -> list[TaintSpec]:
        return [s for s in self.specs if s.role == TaintRole.PROPAGATOR]

    def by_file(self, file_path: str) -> list[TaintSpec]:
        return [s for s in self.specs if s.file == file_path]

    def by_function(self, function_name: str) -> list[TaintSpec]:
        return [s for s in self.specs if s.function == function_name]

    def to_dict(self) -> dict[str, Any]:
        return {
            "specs": [s.to_dict() for s in self.specs],
            "summary": {
                "sources": len(self.sources()),
                "sinks": len(self.sinks()),
                "sanitisers": len(self.sanitisers()),
                "propagators": len(self.propagators()),
                "total": len(self.specs),
            },
        }

    def merge(self, other: TaintSpecSet) -> None:
        existing = {(s.function, s.file, s.role) for s in self.specs}
        for spec in other.specs:
            key = (spec.function, spec.file, spec.role)
            if key not in existing:
                self.specs.append(spec)
                existing.add(key)


def load_taint_specs(path: Path) -> TaintSpecSet:
    spec_set = TaintSpecSet()
    if not path.is_file():
        return spec_set

    try:
        data = json.loads(path.read_text())
    except Exception:
        logger.debug("failed to load taint specs from %s", path, exc_info=True)
        return spec_set

    for item in data.get("specs", []):
        try:
            spec = TaintSpec(
                function=item["function"],
                file=item["file"],
                role=TaintRole(item["role"]),
                trust_level=TrustLevel(item.get("trust_level", "untrusted")),
                threat_classes=item.get("threat_classes", []),
                params_affected=item.get("params_affected", []),
                return_affected=item.get("return_affected", False),
                taint_class=item.get("taint_class", ""),
                taint_class_change=item.get("taint_class_change", ""),
                confidence=item.get("confidence", "medium"),
                reasoning=item.get("reasoning", ""),
            )
            spec_set.add(spec)
        except (KeyError, ValueError):
            continue

    return spec_set


def save_taint_specs(spec_set: TaintSpecSet, path: Path) -> None:
    """Atomic write — the spec set is a cross-run artifact; a torn
    write left load_taint_specs silently starting from empty."""
    from core.atomic_fs import write_text_atomically
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomically(path, json.dumps(spec_set.to_dict(), indent=2))


_SOURCE_PATTERNS = frozenset({
    "read", "recv", "recvfrom", "recvmsg", "fread", "fgets",
    "getenv", "getline", "scanf", "gets",
    "load", "fetch", "consume", "poll", "dequeue",
    "get_param", "get_query", "get_header", "get_cookie",
    "request", "input",
})

_SINK_PATTERNS = frozenset({
    "exec", "system", "popen", "eval", "query", "execute",
    "write", "send", "sendto", "sendmsg", "fwrite",
    "memcpy", "memmove", "strcpy", "strcat", "sprintf",
    "render", "render_template", "innerHTML",
    "open", "fopen", "unlink", "remove", "rename",
})

_SANITISER_PATTERNS = frozenset({
    "sanitize", "sanitise", "escape", "encode", "filter",
    "validate", "check", "verify", "clean", "strip",
    "parameterize", "parameterise", "quote", "htmlspecialchars",
})


def classify_role_heuristic(function_name: str) -> TaintRole | None:
    """Heuristic role classification based on function name."""
    name_lower = function_name.lower()

    for pattern in _SANITISER_PATTERNS:
        if pattern in name_lower:
            return TaintRole.SANITISER

    for pattern in _SOURCE_PATTERNS:
        if pattern in name_lower:
            return TaintRole.SOURCE

    for pattern in _SINK_PATTERNS:
        if pattern in name_lower:
            return TaintRole.SINK

    return None


def spec_from_summary(
    function: str,
    file: str,
    summary: dict[str, Any],
) -> TaintSpec | None:
    """Extract a taint spec from a function summary if the function
    is a plausible source, sink, or sanitiser.

    Returns None if the function doesn't match any of those roles.
    Propagator specs are never produced here — the name heuristic
    cannot identify propagation; they enter the spec set via other
    paths.
    """
    role = classify_role_heuristic(function)
    if role is None:
        return None

    threat_classes = []
    trust = TrustLevel.UNTRUSTED

    callers = summary.get("callers", [])

    if role == TaintRole.SOURCE:
        if any("config" in c.lower() for c in callers):
            trust = TrustLevel.PARTIALLY_TRUSTED
            taint_class = "config_controlled"
        else:
            taint_class = "user_controlled"
        return TaintSpec(
            function=function,
            file=file,
            role=role,
            trust_level=trust,
            taint_class=taint_class,
            return_affected=True,
            confidence="medium",
        )

    if role == TaintRole.SINK:
        if any(s in function.lower() for s in ("exec", "system", "popen", "eval")):
            threat_classes = ["command_injection"]
        elif any(s in function.lower() for s in ("query", "execute")):
            threat_classes = ["sql_injection"]
        elif any(s in function.lower() for s in ("memcpy", "strcpy", "sprintf")):
            threat_classes = ["buffer_overflow"]
        elif any(s in function.lower() for s in ("render", "innerhtml")):
            threat_classes = ["xss"]

        return TaintSpec(
            function=function,
            file=file,
            role=role,
            threat_classes=threat_classes,
            params_affected=["param[0]"],
            confidence="medium",
        )

    if role == TaintRole.SANITISER:
        if any(s in function.lower() for s in ("html", "xss")):
            threat_classes = ["xss", "html_injection"]
        elif any(s in function.lower() for s in ("sql", "query", "param")):
            threat_classes = ["sql_injection"]
        elif any(s in function.lower() for s in ("path", "file")):
            threat_classes = ["path_traversal"]
        elif any(s in function.lower() for s in ("cmd", "shell", "exec")):
            threat_classes = ["command_injection"]

        return TaintSpec(
            function=function,
            file=file,
            role=role,
            threat_classes=threat_classes,
            params_affected=["param[0]"],
            return_affected=True,
            confidence="medium",
        )

    return None


def format_specs_for_joern(spec_set: TaintSpecSet) -> str:
    """Format taint specs as Joern-compatible source/sink definitions."""
    lines = []

    sources = spec_set.sources()
    if sources:
        lines.append("// Project-specific sources")
        lines.extend(f'def source = cpg.method.fullNameExact("{s.function}")'
                f'.parameter  // {s.taint_class or "user_controlled"}' for s in sources)

    sinks = spec_set.sinks()
    if sinks:
        lines.append("")
        lines.append("// Project-specific sinks")
        for s in sinks:
            classes = ", ".join(s.threat_classes) if s.threat_classes else "generic"
            lines.append(
                f'def sink = cpg.method.fullNameExact("{s.function}")'
                f'.parameter  // {classes}'
            )

    sanitisers = spec_set.sanitisers()
    if sanitisers:
        lines.append("")
        lines.append("// Project-specific sanitisers")
        for s in sanitisers:
            classes = ", ".join(s.threat_classes) if s.threat_classes else "generic"
            lines.append(
                f'def sanitizer = cpg.method.fullNameExact("{s.function}")'
                f'  // kills taint for: {classes}'
            )

    return "\n".join(lines)


def format_specs_for_prompt(spec_set: TaintSpecSet) -> str:
    """Format taint specs as context for LLM prompts."""
    if not spec_set.specs:
        return ""

    sections = []

    sources = spec_set.sources()
    if sources:
        parts = ["Project-specific taint sources:"]
        for s in sources:
            trust = s.trust_level.value.replace("_", " ")
            parts.append(
                f"  - {s.function} ({s.file}): "
                f"{s.taint_class or 'user_controlled'}, {trust}"
            )
        sections.append("\n".join(parts))

    sinks = spec_set.sinks()
    if sinks:
        parts = ["Project-specific sinks:"]
        for s in sinks:
            classes = ", ".join(s.threat_classes) if s.threat_classes else "generic"
            parts.append(f"  - {s.function} ({s.file}): {classes}")
        sections.append("\n".join(parts))

    sanitisers = spec_set.sanitisers()
    if sanitisers:
        parts = ["Project-specific sanitisers:"]
        for s in sanitisers:
            classes = ", ".join(s.threat_classes) if s.threat_classes else "generic"
            parts.append(
                f"  - {s.function} ({s.file}): kills taint for {classes}"
            )
        sections.append("\n".join(parts))

    propagators = spec_set.propagators()
    if propagators:
        parts = ["Project-specific propagators:"]
        for s in propagators:
            change = f" ({s.taint_class_change})" if s.taint_class_change else ""
            parts.append(f"  - {s.function} ({s.file}){change}")
        sections.append("\n".join(parts))

    return "\n\n".join(sections)


def format_specs_summary(spec_set: TaintSpecSet) -> str:
    if not spec_set.specs:
        return "Taint specs: none synthesised"

    parts = []
    for role, items in [
        ("sources", spec_set.sources()),
        ("sinks", spec_set.sinks()),
        ("sanitisers", spec_set.sanitisers()),
        ("propagators", spec_set.propagators()),
    ]:
        if items:
            parts.append(f"{len(items)} {role}")

    return f"Taint specs: {', '.join(parts)} ({len(spec_set.specs)} total)"


# ── Post-loop taint checks ──────────────────────────────────────────


@dataclass
class TaintFinding:
    """A finding from persistence-layer or config-as-taint analysis."""

    check: str
    title: str
    description: str
    file: str = ""
    function: str = ""
    cwe: str = ""
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "check": self.check,
            "title": self.title,
            "description": self.description,
            "confidence": self.confidence,
        }
        if self.file:
            d["file"] = self.file
        if self.function:
            d["function"] = self.function
        if self.cwe:
            d["cwe"] = self.cwe
        return d


def _read_gap_source(
    gap: dict[str, Any],
    target_path: Path | None,
) -> str:
    """Read source text for a gap from disk using its line span."""
    if not target_path:
        return ""
    from .gaps import read_gap_source
    return read_gap_source(gap, target_path)


_DB_WRITE_PATTERNS = [
    re.compile(r"\b(?:INSERT|UPDATE|REPLACE)\b", re.IGNORECASE),
    re.compile(r"\.(?:save|create|update|put|set|write|insert)\s*\(", re.IGNORECASE),
    re.compile(r"\.(?:execute|query)\s*\(\s*[\"'](?:INSERT|UPDATE)", re.IGNORECASE),
]

_DB_READ_PATTERNS = [
    re.compile(r"\bSELECT\b", re.IGNORECASE),
    re.compile(r"\.(?:get|find|filter|all|first|fetch|read|query|select)\s*\(", re.IGNORECASE),
    re.compile(r"\.(?:execute|query)\s*\(\s*[\"']SELECT", re.IGNORECASE),
]


_TABLE_NAME_RE = re.compile(
    r"(?:INTO|FROM|UPDATE|JOIN|TABLE)\s+[`\"']?(\w+)[`\"']?",
    re.IGNORECASE,
)
_MODEL_NAME_RE = re.compile(
    r"(\w+)\.(?:objects|query|filter|get|find|save|create|update|delete|all)\s*\(",
    re.IGNORECASE,
)
_CACHE_KEY_RE = re.compile(
    r"(?:cache|redis|memcache)\w*\.(?:get|set|delete|hget|hset)\s*\(\s*[\"']([^\"']+)",
    re.IGNORECASE,
)


def _extract_storage_names(source: str) -> set[str]:
    """Extract table, model, and cache key names from source."""
    names: set[str] = set()
    for m in _TABLE_NAME_RE.finditer(source):
        names.add(m.group(1).lower())
    for m in _MODEL_NAME_RE.finditer(source):
        name = m.group(1).lower()
        if name not in ("self", "cls", "os", "sys", "re", "json", "log", "logger"):
            names.add(name)
    for m in _CACHE_KEY_RE.finditer(source):
        names.add(m.group(1).lower().split(":")[0])
    return names


def check_stored_taint(
    gaps: Sequence[dict[str, Any]],
    *,
    target_path: Path | None = None,
) -> list[TaintFinding]:
    """Detect persistence-layer taint gaps across function boundaries.

    Links writer functions to reader functions via shared table/model/cache
    names, then flags readers that render stored data without sanitization.
    """
    writers: list[dict[str, Any]] = []
    readers: list[dict[str, Any]] = []
    writer_names: dict[str, set[str]] = {}
    reader_names: dict[str, set[str]] = {}
    resolved_source: dict[str, str] = {}

    for gap in gaps:
        source = gap.get("source", "") or _read_gap_source(gap, target_path)
        if not source:
            continue

        is_writer = any(p.search(source) for p in _DB_WRITE_PATTERNS)
        is_reader = any(p.search(source) for p in _DB_READ_PATTERNS)
        key = f"{gap.get('file', '')}:{gap.get('name', '')}"

        if is_writer:
            writers.append(gap)
            writer_names[key] = _extract_storage_names(source)
        if is_reader:
            readers.append(gap)
            reader_names[key] = _extract_storage_names(source)
        if is_writer or is_reader:
            resolved_source[key] = source

    if not writers or not readers:
        return []

    all_written_names: set[str] = set()
    for names in writer_names.values():
        all_written_names |= names

    findings: list[TaintFinding] = []
    for reader in readers:
        rkey = f"{reader.get('file', '')}:{reader.get('name', '')}"
        source = resolved_source.get(rkey, "")
        has_sanitizer = bool(re.search(
            r"\b(?:escape|sanitiz|sanitise|html_escape|quote|param)\b",
            source, re.IGNORECASE,
        ))
        if has_sanitizer:
            continue

        has_render = bool(re.search(
            r"\b(?:render|template|format_html|format_template|render_template"
            r"|innerHTML|response_write|write_html|f[\"']|\.html\b|response\.write)\b",
            source, re.IGNORECASE,
        ))
        if not has_render:
            continue

        reader_key = f"{reader.get('file', '')}:{reader.get('name', '')}"
        r_names = reader_names.get(reader_key, set())
        shared = r_names & all_written_names

        linked_writers = []
        if shared:
            for w_key, w_names in writer_names.items():
                if w_names & shared:
                    linked_writers.append(w_key)

        if linked_writers:
            writer_desc = ", ".join(linked_writers[:3])
            shared_desc = ", ".join(sorted(shared)[:3])
            description = (
                f"{reader.get('name', '?')} reads from persistence "
                f"({shared_desc}) and renders output without sanitization. "
                f"Data written by {writer_desc} flows through storage to "
                f"this reader — cross-function stored taint"
            )
            confidence = "high"
        else:
            description = (
                f"{reader.get('name', '?')} reads from persistence and "
                f"renders output without visible sanitization — potential "
                f"stored XSS or injection if the stored data is user-controlled"
            )
            confidence = "medium"

        findings.append(TaintFinding(
            check="stored_taint",
            title="Persistence read rendered without sanitization",
            description=description,
            file=reader.get("file", ""),
            function=reader.get("name", ""),
            cwe="CWE-79",
            confidence=confidence,
        ))

    return findings


_CONFIG_READ_PATTERNS = [
    re.compile(r"os\.environ\b|getenv\b|process\.env\b", re.IGNORECASE),
    re.compile(r"ConfigParser|yaml\.(?:safe_)?load|json\.load|toml\.load", re.IGNORECASE),
    re.compile(r"settings\.\w+|app\.config\[", re.IGNORECASE),
]

_SECURITY_DECISION_PATTERNS = [
    re.compile(r"(?:auth|authenticat|permission|role|admin|sudo|privilege)", re.IGNORECASE),
    re.compile(r"(?:tls|ssl|https|cert|cipher|encrypt|decrypt)", re.IGNORECASE),
    re.compile(r"(?:cors|origin|allow|deny|firewall|whitelist|allowlist)", re.IGNORECASE),
    re.compile(r"(?:debug|verbose|trace|log.?level)", re.IGNORECASE),
]


def check_config_dependent(
    gaps: Sequence[dict[str, Any]],
    *,
    target_path: Path | None = None,
) -> list[TaintFinding]:
    """Detect security decisions controlled by external configuration."""
    findings: list[TaintFinding] = []

    for gap in gaps:
        source = gap.get("source", "") or _read_gap_source(gap, target_path)
        if not source:
            continue

        has_config = any(p.search(source) for p in _CONFIG_READ_PATTERNS)
        if not has_config:
            continue

        has_security_decision = any(
            p.search(source) for p in _SECURITY_DECISION_PATTERNS
        )
        if not has_security_decision:
            continue

        findings.append(TaintFinding(
            check="config_dependent",
            title="Security decision depends on external configuration",
            description=(
                f"{gap.get('name', '?')} reads configuration from an "
                f"external source and uses it in a security-relevant "
                f"decision. Verify the security property holds under "
                f"ALL plausible configuration values."
            ),
            file=gap.get("file", ""),
            function=gap.get("name", ""),
            cwe="CWE-15",
            confidence="low",
        ))

    return findings
