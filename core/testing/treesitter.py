"""Tree-sitter availability probes for test suites.

The tree-sitter grammar wheels are OPTIONAL dependencies (commented
out in requirements.txt): bare CI installs none of them, developer
hosts usually install all of them. Tests that exercise parser-backed
detection therefore need one of two treatments, per the audit-suite
degradation contracts:

* capability genuinely required (no honest fallback — the consistency
  dimension detectors, the Go/Java fail-open analyzers): skip with a
  reason via :func:`requires_ts`, plus a hermetic parser-absent
  contract test pinning the graceful degradation (empty result /
  ``language-unsupported`` inconclusive — never a crash);

* a documented fallback exists (the return census's regex tier): pin
  BOTH behaviours by parametrising over the tier and forcing the
  fallback with :func:`force_census_regex_fallback` on the second leg.

Probing goes through the production parser plumbing
(``core.audit.condition_extraction._get_parser``) rather than bare
``import tree_sitter`` so a broken / partially installed grammar set
is classified exactly the way the detectors themselves would see it.
"""

from __future__ import annotations

import pytest


def ts_parser_available(lang: str) -> bool:
    """True when the production plumbing can hand out a tree-sitter
    parser for *lang* (core library + grammar wheel installed)."""
    try:
        from core.audit.condition_extraction import _get_parser
    except ImportError:
        return False
    try:
        return _get_parser(lang) is not None
    except Exception:  # noqa: BLE001 — a broken grammar counts as absent
        return False


def requires_ts(*langs: str) -> pytest.MarkDecorator:
    """``skipif`` mark for tests that need real grammars for *langs*.

    The reason names the missing grammars so a bare-CI skip report
    reads as an inventory of what was not installed, not as noise.
    """
    missing = sorted(lang for lang in langs if not ts_parser_available(lang))
    return pytest.mark.skipif(
        bool(missing),
        reason=(
            "requires tree-sitter grammar(s) not installed: "
            + ", ".join(missing)
            if missing
            else "tree-sitter grammars present"
        ),
    )


def force_census_regex_fallback(monkeypatch) -> None:
    """Force the return census onto its regex tier for one test.

    Flips ``core.audit.callsite_consistency._TS_AVAILABLE`` (the same
    flag a host without tree-sitter computes at import time) and swaps
    in a fresh parse cache for the duration, so no tree cached by a
    previous test leaks into the fallback leg and none of the
    ``(None, None)`` entries the fallback caches survive into later
    tree-sitter-tier tests. Both changes ride the ``monkeypatch``
    undo stack.
    """
    import core.audit.callsite_consistency as cc

    monkeypatch.setattr(cc, "_TS_AVAILABLE", False)
    monkeypatch.setattr(cc, "_parse_cache", type(cc._parse_cache)())
