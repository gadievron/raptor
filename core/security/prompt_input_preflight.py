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

Corpora whose filename contains ``_multiline`` are compiled with
``re.MULTILINE | re.DOTALL`` so they can catch phrases split across line
boundaries. All other corpora use ``re.IGNORECASE`` only (single-line
matching) to keep false-positive rates low on large inputs.

``preflight()`` accepts an optional ``corpora`` parameter to restrict which
pattern files are checked. Pass ``corpora=("english_multiline",)`` for
short, structured inputs where multiline detection is worthwhile.

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


# Catastrophic-backtracking shapes — nested unbounded quantifiers
# like `(a+)+`, `(.*)*`, `(\w+)+`. Any of these against pathological
# input causes wallclock to grow super-linearly. Reject at corpus
# load time so a future maintainer adding a pattern doesn't
# accidentally introduce a ReDoS vector through the framework's own
# preflight scanner.
_REDOS_SHAPES = (
    re.compile(r'[+*]\)[+*]'),       # (...+)+ , (...*)* , (...+)* , (...*)+
    re.compile(r'\)\?\)\?\)'),        # deeply nested optional groups
    re.compile(r'\([^()]*\|[^()]*\)\+'),  # (a|aa)+ alternation overlap
)


def _looks_redos(pattern: str) -> bool:
    return any(s.search(pattern) for s in _REDOS_SHAPES)


def _load_patterns() -> dict[str, tuple[re.Pattern[str], ...]]:
    by_file: dict[str, tuple[re.Pattern[str], ...]] = {}
    if not _PATTERNS_DIR.exists():
        return by_file
    for path in sorted(_PATTERNS_DIR.glob("*.txt")):
        flags = re.IGNORECASE
        if "_multiline" in path.stem:
            flags |= re.MULTILINE | re.DOTALL
        compiled: list[re.Pattern[str]] = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # ReDoS lint at corpus-load time. The patterns are
            # framework-shipped today (not attacker-controlled), but
            # the corpus file format is "easy to add a new pattern,
            # no review", so a future maintainer drafting a pattern
            # like `(\w+)*[!]` could inadvertently introduce a
            # super-linear matcher into a hot path. Drop the
            # offender with a clear log line so the pattern author
            # sees it on first run.
            if _looks_redos(stripped):
                # No `logger` import in this module — use stdlib
                # logging at module scope to avoid the import.
                import logging
                logging.getLogger(__name__).warning(
                    "preflight: dropping pattern with catastrophic-"
                    "backtracking shape (file=%s pattern=%r)",
                    path.name, stripped[:80],
                )
                continue
            try:
                compiled.append(re.compile(stripped, flags))
            except re.error:
                continue
        if compiled:
            by_file[path.stem] = tuple(compiled)
    return by_file


_PATTERNS = _load_patterns()


def preflight(
    content: str,
    *,
    corpora: tuple[str, ...] | None = None,
    strict: bool = False,
) -> PreflightResult:
    """Scan content for known injection-pattern indicators.

    Non-blocking: a hit produces a confidence haircut, never an exception.
    The consumer decides whether to lower its own confidence verdict, log
    the indicators, refuse to render, or any combination. An empty or
    missing corpus returns `confidence_haircut=1.0` (fail-open) so a
    misconfigured deployment cannot silently disable the rest of the
    pipeline by returning haircut-zero results.

    *corpora* restricts which pattern files to check. ``None`` (default)
    checks all loaded corpora. Pass a tuple of file stems to limit — e.g.
    ``corpora=("english", "english_multiline")`` for short structured inputs.

    Raises ``ValueError`` if any name in *corpora* doesn't match a loaded
    pattern file. Pre-fix a typo (``corpora=("englsih",)``) silently
    iterated over zero patterns and returned the no-hit haircut — a
    fail-open misconfiguration the operator wouldn't see in normal logs.
    Failing fast surfaces the typo at the call site instead.

    When ``strict=True``, raises ``RuntimeError`` if ``_PATTERNS`` is empty
    (corpus directory missing or all files rejected at load time). Default
    ``strict=False`` preserves the documented fail-open policy — an empty
    corpus returns ``confidence_haircut=1.0`` rather than zeroing all
    downstream confidence scores.

    The ``strict`` check evaluates ``_PATTERNS`` *at call time*, not at
    module import time — so a corpus that loads asynchronously after
    import (rare, but possible for callers that hot-reload pattern
    files) still satisfies ``strict=True`` once populated. The check
    fails only when ``_PATTERNS`` is still empty when this function is
    invoked, which is the actual fail-open exposure window the kwarg
    is designed to surface.
    """
    if strict and not _PATTERNS:
        raise RuntimeError(
            f"preflight: strict=True but no corpora loaded from "
            f"{_PATTERNS_DIR!r}; a missing or empty corpus directory "
            f"would silently return confidence_haircut=1.0 (fail-open). "
            f"Fix the corpus path or pass strict=False to allow fail-open."
        )
    if corpora is not None:
        loaded = set(_PATTERNS)
        unknown = [c for c in corpora if c not in loaded]
        if unknown:
            raise ValueError(
                f"preflight: unknown corpora {unknown!r}. "
                f"Loaded corpora: {sorted(loaded)!r}"
            )
    indicators: list[str] = []
    for name, patterns in _PATTERNS.items():
        if corpora is not None and name not in corpora:
            continue
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
