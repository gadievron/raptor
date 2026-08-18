"""Guard analysis for install-hook payload scripts.

When an install hook (npm postinstall, setup.py, build.rs, Cargo
build script, etc.) references an in-tree script or IS a parseable
source file, this module runs the condition extraction + sink
discovery stack on the payload to classify whether dangerous calls
are conditional (guarded) or unconditional.

A guarded dangerous call (e.g. ``if os.environ.get("CI"): eval(…)``)
is still suspicious, but a lower priority than an unconditional one.
Conversely, an unconditional sink call in an install hook is the
strongest mechanical signal for the Iron Worm / credential-stealer
archetype.

Tree-sitter only — no Joern dependency. The analysis runs on raw
source text without needing a full project checkout.

Consumers: ``install_hooks.py``, ``python_lifecycle_hooks.py``,
``cargo_build_scripts.py`` via the ``analyze_hook_payload`` entry
point.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .sink_vocab import HOOK_PAYLOAD_EXTRA_SINKS, SHARED_SUPPLY_CHAIN_SINKS

logger = logging.getLogger(__name__)

# Composed from the shared supply-chain authority plus the
# hook-payload-specific extras (see sink_vocab.py for the rationale).
_HOOK_SINKS: frozenset[str] = (
    SHARED_SUPPLY_CHAIN_SINKS | HOOK_PAYLOAD_EXTRA_SINKS
)


@dataclass
class HookSinkInfo:
    """One dangerous sink found in a hook payload."""

    sink_api: str
    line: int
    unconditional: bool
    guard_count: int
    guard_categories: list[str] = field(default_factory=list)
    adequacy_verdict: str = "unknown"


@dataclass
class HookGuardAnalysis:
    """Guard analysis result for one hook payload file."""

    file_path: str
    language: str
    total_sinks: int
    unconditional_sinks: int
    guarded_sinks: int
    sinks: list[HookSinkInfo] = field(default_factory=list)

    @property
    def has_unconditional_dangerous_call(self) -> bool:
        return self.unconditional_sinks > 0

    @property
    def all_sinks_guarded(self) -> bool:
        return self.total_sinks > 0 and self.unconditional_sinks == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "language": self.language,
            "total_sinks": self.total_sinks,
            "unconditional_sinks": self.unconditional_sinks,
            "guarded_sinks": self.guarded_sinks,
            "has_unconditional_dangerous_call": (
                self.has_unconditional_dangerous_call
            ),
            "sinks": [
                {
                    "sink_api": s.sink_api,
                    "line": s.line,
                    "unconditional": s.unconditional,
                    "guard_count": s.guard_count,
                    "guard_categories": s.guard_categories,
                    "adequacy": s.adequacy_verdict,
                }
                for s in self.sinks
            ],
        }


def analyze_hook_payload(
    source: str,
    filepath: str,
    *,
    sink_names: frozenset[str] | None = None,
) -> HookGuardAnalysis | None:
    """Analyze a hook payload script for dangerous sinks and guards.

    Args:
        source: raw source text of the payload file
        filepath: path string (used for language detection via extension)
        sink_names: override the default sink set if needed

    Returns:
        HookGuardAnalysis, or None if the file's language isn't
        supported or condition extraction is unavailable.
    """
    try:
        from core.audit.condition_adequacy import assess_guard_adequacy
        from core.audit.condition_extraction import (
            extract_sink_guards,
            language_for_file,
        )
    except ImportError:
        logger.debug(
            "hook_guard_analysis: condition stack not importable"
        )
        return None

    lang = language_for_file(filepath)
    if lang is None:
        return None

    sinks = sink_names if sink_names is not None else _HOOK_SINKS

    guards = extract_sink_guards(source, filepath, sink_names=sinks)
    if not guards:
        return HookGuardAnalysis(
            file_path=filepath,
            language=lang,
            total_sinks=0,
            unconditional_sinks=0,
            guarded_sinks=0,
        )

    sink_infos: list[HookSinkInfo] = []
    for sg in guards:
        adequacy = assess_guard_adequacy(sg.sink_api, sg.guards)
        categories = sorted({g.category for g in sg.guards})

        sink_infos.append(HookSinkInfo(
            sink_api=sg.sink_api,
            line=sg.sink_line,
            unconditional=sg.unconditional,
            guard_count=sg.guard_count,
            guard_categories=categories,
            adequacy_verdict=adequacy.verdict.value,
        ))

    unconditional = sum(1 for s in sink_infos if s.unconditional)
    return HookGuardAnalysis(
        file_path=filepath,
        language=lang,
        total_sinks=len(sink_infos),
        unconditional_sinks=unconditional,
        guarded_sinks=len(sink_infos) - unconditional,
        sinks=sink_infos,
    )


def analyze_intree_targets(
    intree_targets: list,
    project_root: Path,
) -> list[HookGuardAnalysis]:
    """Analyze in-tree files referenced by an install hook.

    Args:
        intree_targets: list of IntreeTarget objects from _intree_resolve
        project_root: root of the package being scanned

    Returns:
        List of HookGuardAnalysis, one per parseable in-tree target.
    """
    results: list[HookGuardAnalysis] = []
    for t in intree_targets:
        target_path = project_root / t.path
        try:
            source = target_path.read_text(
                encoding="utf-8", errors="replace",
            )
        except OSError:
            continue

        analysis = analyze_hook_payload(source, str(t.path))
        if analysis is not None and analysis.total_sinks > 0:
            results.append(analysis)

    return results


__all__ = [
    "HookGuardAnalysis",
    "HookSinkInfo",
    "analyze_hook_payload",
    "analyze_intree_targets",
]
