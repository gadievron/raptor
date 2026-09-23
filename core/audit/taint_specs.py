"""Persistence-layer and config-as-taint lexical checks.

Two regex-tier checks the orchestrator runs over gap source:
``check_stored_taint`` (second-order injection — tainted data written
to a store in one function, read and used unsafely in another) and
``check_config_dependent`` (security decisions driven by mutable
configuration).

The taint-spec synthesis pipeline itself (TaintSpec, role heuristics,
Joern/prompt formatters) lives in ``core.iris.specs`` — an earlier
duplicate that lived here was never wired to production and has been
removed.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

logger = logging.getLogger(__name__)


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
# \b pins each attempt to a word start: unanchored, a hostile word
# run retries every suffix — quadratic. Mid-word starts were never
# real model or cache receiver names.
_MODEL_NAME_RE = re.compile(
    r"\b(\w+)\.(?:objects|query|filter|get|find|save|create|update|delete|all)\s*\(",
    re.IGNORECASE,
)
_CACHE_KEY_RE = re.compile(
    r"\b(?:cache|redis|memcache)\w*\.(?:get|set|delete|hget|hset)\s*\(\s*[\"']([^\"']+)",
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
