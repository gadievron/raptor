"""Regex preflight for LLM input — non-blocking, signals confidence haircut.

Background: a pure classifier-based detector is unsuitable for RAPTOR
because the corpus the framework analyses *is* vulnerable code with
attacker-shaped strings — a classifier would fire on legitimate inputs.
Preflight here is different: it's regex-based, opt-in per call, and
**non-blocking**. A hit returns `confidence_haircut=0.5` and the names of
the patterns that fired; the *consumer* decides what to do (lower its own
confidence numeric, log the indicators, treat outputs more conservatively).

Patterns live in `injection_patterns/*.txt`. Each non-comment line is one
regex. The corpus is loaded at import time. Adding a new attack pattern is
a single-file edit; the public API does not change.

Suitable consumers: stages that produce *confidence verdicts* over short,
structured inputs (SCA install-script review, /understand verdicts, /validate
exploitability). Unsuitable for: bulk source-code analysis where every
finding has injection-shaped strings inside the code under review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


_PATTERNS_DIR = Path(__file__).parent / "injection_patterns"

_HAIRCUT_ON_HIT = 0.5

_NO_HIT_HAIRCUT = 1.0


@dataclass(frozen=True)
class PreflightResult:
    """Result of running preflight against a piece of untrusted content.

    `indicators` lists the corpus *file stems* (e.g. "english",
    "role_injection") whose patterns fired — not the individual regexes,
    so the consumer logs a stable signal even as the corpus grows. The
    consumer is expected to multiply its LLM-returned confidence numeric
    by `confidence_haircut`.
    """

    has_injection_indicators: bool
    indicators: tuple[str, ...] = field(default_factory=tuple)
    confidence_haircut: float = _NO_HIT_HAIRCUT


def _load_patterns() -> dict[str, tuple[re.Pattern[str], ...]]:
    by_file: dict[str, tuple[re.Pattern[str], ...]] = {}
    if not _PATTERNS_DIR.exists():
        return by_file
    for path in sorted(_PATTERNS_DIR.glob("*.txt")):
        compiled: list[re.Pattern[str]] = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                compiled.append(re.compile(stripped, re.IGNORECASE))
            except re.error:
                continue
        if compiled:
            by_file[path.stem] = tuple(compiled)
    return by_file


_PATTERNS = _load_patterns()


def preflight(content: str) -> PreflightResult:
    """Scan content for known injection-pattern indicators.

    Non-blocking: a hit produces a confidence haircut, never an exception.
    The consumer decides whether to lower its own confidence verdict, log
    the indicators, refuse to render, or any combination. An empty or
    missing corpus returns `confidence_haircut=1.0` (fail-open) so a
    misconfigured deployment cannot silently disable the rest of the
    pipeline by returning haircut-zero results.
    """
    indicators: list[str] = []
    for name, patterns in _PATTERNS.items():
        if any(p.search(content) for p in patterns):
            indicators.append(name)
    if indicators:
        return PreflightResult(
            has_injection_indicators=True,
            indicators=tuple(indicators),
            confidence_haircut=_HAIRCUT_ON_HIT,
        )
    return PreflightResult(
        has_injection_indicators=False,
        indicators=(),
        confidence_haircut=_NO_HIT_HAIRCUT,
    )


def loaded_corpora() -> tuple[str, ...]:
    """File stems of corpora that loaded successfully — for diagnostics."""
    return tuple(sorted(_PATTERNS.keys()))
