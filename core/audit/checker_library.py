"""Persistent checker library for cross-audit learning.

When checker synthesis (Cap 4) produces a Semgrep rule or Coccinelle
script that finds a true positive, it is saved here.  Subsequent audits
run the library first — cheaply, mechanically — before the LLM pass.
The library grows with use and prunes low-precision rules automatically.

Each checker carries:
- rule_id: unique identifier
- language: target language(s)
- tool: semgrep | coccinelle | codeql
- cwe: CWE category (optional)
- pattern: the rule content (YAML for Semgrep, .cocci for Coccinelle)
- source_audit: which run synthesised it
- source_finding: the original finding that triggered synthesis
- precision: true positives / total matches across runs
- match_count: total times it has fired
- tp_count: confirmed true positives
- created: ISO timestamp
- last_fired: ISO timestamp
- retired: whether the rule is below precision threshold

Storage: one JSON file per checker in the library directory.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_LIBRARY_DIR = "core/audit/checkers"
_PRECISION_THRESHOLD = 0.3
_MIN_MATCHES_FOR_RETIRE = 5


@dataclass
class CheckerEntry:
    """A persistent checker rule in the library."""

    rule_id: str
    language: str
    tool: str
    pattern: str
    cwe: str = ""
    source_audit: str = ""
    source_finding: str = ""
    precision: float = 1.0
    match_count: int = 0
    tp_count: int = 0
    created: str = ""
    last_fired: str = ""
    retired: bool = False
    description: str = ""

    @property
    def is_precise(self) -> bool:
        if self.match_count < _MIN_MATCHES_FOR_RETIRE:
            return True
        return self.precision >= _PRECISION_THRESHOLD

    def record_match(self, is_tp: bool) -> None:
        self.match_count += 1
        if is_tp:
            self.tp_count += 1
        self.precision = self.tp_count / self.match_count if self.match_count else 1.0
        self.last_fired = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CheckerLibrary:
    """The persistent checker store."""

    entries: dict[str, CheckerEntry] = field(default_factory=dict)
    library_dir: Path | None = None

    def add(self, entry: CheckerEntry) -> None:
        self.entries[entry.rule_id] = entry
        if self.library_dir:
            self._write_entry(entry)

    def get(self, rule_id: str) -> CheckerEntry | None:
        return self.entries.get(rule_id)

    def active_checkers(self, *, language: str | None = None) -> list[CheckerEntry]:
        result = [e for e in self.entries.values() if not e.retired]
        if language:
            result = [e for e in result if e.language in (language, "*")]
        return result

    def retire_low_precision(self) -> list[str]:
        retired = []
        for entry in self.entries.values():
            if entry.retired:
                continue
            if not entry.is_precise:
                entry.retired = True
                retired.append(entry.rule_id)
                if self.library_dir:
                    self._write_entry(entry)
        return retired

    def record_match(self, rule_id: str, is_tp: bool) -> None:
        entry = self.entries.get(rule_id)
        if entry is None:
            return
        entry.record_match(is_tp)
        if self.library_dir:
            self._write_entry(entry)

    def summary(self) -> str:
        total = len(self.entries)
        active = sum(1 for e in self.entries.values() if not e.retired)
        retired = total - active
        if total == 0:
            return "Checker library: empty"
        avg_prec = 0.0
        prec_entries = [e for e in self.entries.values() if e.match_count > 0]
        if prec_entries:
            avg_prec = sum(e.precision for e in prec_entries) / len(prec_entries)
        return (
            f"Checker library: {active} active, {retired} retired, "
            f"avg precision {avg_prec:.0%}"
        )

    def _write_entry(self, entry: CheckerEntry) -> None:
        if not self.library_dir:
            return
        self.library_dir.mkdir(parents=True, exist_ok=True)
        path = self.library_dir / f"{entry.rule_id}.json"
        fd, tmp = tempfile.mkstemp(
            dir=str(self.library_dir), suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(entry.to_dict(), f, indent=2)
            os.replace(tmp, str(path))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def load_library(library_dir: Path) -> CheckerLibrary:
    """Load all checkers from the library directory."""
    lib = CheckerLibrary(library_dir=library_dir)
    if not library_dir.is_dir():
        return lib

    for path in sorted(library_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
            entry = CheckerEntry(**{
                k: v for k, v in data.items()
                if k in CheckerEntry.__dataclass_fields__
            })
            lib.entries[entry.rule_id] = entry
        except Exception:
            logger.debug("failed to load checker %s", path, exc_info=True)

    return lib


def checker_from_synthesis(
    rule_id: str,
    tool: str,
    pattern: str,
    language: str,
    *,
    cwe: str = "",
    source_audit: str = "",
    source_finding: str = "",
    description: str = "",
) -> CheckerEntry:
    """Create a new checker entry from synthesis output."""
    return CheckerEntry(
        rule_id=rule_id,
        language=language,
        tool=tool,
        pattern=pattern,
        cwe=cwe,
        source_audit=source_audit,
        source_finding=source_finding,
        description=description,
        created=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )


_GRADUATION_MIN_TPS = 2
_GRADUATION_MIN_PRECISION = 0.8
_GRADUATION_MIN_MATCHES = 3


def graduate_checkers(
    library: CheckerLibrary,
    engine_rules_dir: Path,
) -> list[str]:
    """Promote high-confidence checkers to the shared engine rules directory.

    A rule graduates when it has confirmed true positives across multiple
    runs (min 2 TPs, min 3 matches, precision >= 80%). Graduated rules
    run as first-class engine rules in /scan and /agentic, not just /audit.

    Returns list of graduated rule_ids.
    """
    graduated = []
    engine_rules_dir = Path(engine_rules_dir)

    for entry in library.entries.values():
        if entry.retired:
            continue
        if entry.tp_count < _GRADUATION_MIN_TPS:
            continue
        if entry.match_count < _GRADUATION_MIN_MATCHES:
            continue
        if entry.precision < _GRADUATION_MIN_PRECISION:
            continue

        dest = _graduation_path(engine_rules_dir, entry)
        if dest.exists():
            continue

        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(entry.pattern)
            graduated.append(entry.rule_id)
            logger.info(
                "graduated checker %s → %s (precision %.0f%%, %d TPs)",
                entry.rule_id, dest, entry.precision * 100, entry.tp_count,
            )
        except OSError:
            logger.warning("failed to graduate %s", entry.rule_id, exc_info=True)

    return graduated


def _graduation_path(engine_dir: Path, entry: CheckerEntry) -> Path:
    """Compute the target path for a graduated rule."""
    if entry.tool == "semgrep":
        return engine_dir / "semgrep" / "rules" / f"{entry.rule_id}.yaml"
    if entry.tool == "coccinelle":
        return engine_dir / "coccinelle" / f"{entry.rule_id}.cocci"
    if entry.tool == "codeql":
        return engine_dir / "codeql" / f"{entry.rule_id}.ql"
    return engine_dir / entry.tool / f"{entry.rule_id}.rule"
