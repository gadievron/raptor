"""Tests for the function_intel_status() invariant.

Per design strict invariant: never fabricate; explicitly report
``name_not_in_tree`` when PR-4 prereqs ran but didn't see the
function name.
"""

from __future__ import annotations

import pytest

from packages.coccinelle.runner import meets_min_version as _spatch_meets_min

from packages.source_intel.analyze import SourceIntelResult, analyze


def test_status_unknown_when_no_target():
    r = SourceIntelResult()  # no target set
    assert r.function_intel_status("anything") == "unknown"


@pytest.mark.skipif(
    not _spatch_meets_min(),
    reason="spatch >= 1.3 required for prereqs E2E",
)
@pytest.mark.slow  # genuine cost: full analyze()/spatch E2E through the sandbox exceeds the 10s default-tier budget; logic-level coverage stays default-tier
def test_status_in_tree_for_defined_function(tmp_path):
    src = tmp_path / "x.c"
    src.write_text(
        "int defined_fn(int x) {\n"
        "    return x + 1;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert r.function_intel_status("defined_fn") == "in_tree"


@pytest.mark.skipif(
    not _spatch_meets_min(),
    reason="spatch >= 1.3 required for prereqs E2E",
)
@pytest.mark.slow  # genuine cost: full analyze()/spatch E2E through the sandbox exceeds the 10s default-tier budget; logic-level coverage stays default-tier
def test_status_name_not_in_tree_for_undefined(tmp_path):
    src = tmp_path / "x.c"
    src.write_text(
        "int real_fn(int x) {\n"
        "    return x + 1;\n"
        "}\n"
    )
    r = analyze(tmp_path)
    assert r.function_intel_status("not_in_this_file") == "name_not_in_tree"


def test_status_mapping_unit(tmp_path, monkeypatch):
    """Default-tier twin of the spatch E2Es above: the
    facts→status mapping (in_tree / name_not_in_tree /
    prereqs_skipped) with gather_prereqs stubbed, so a mapping
    regression fails in every run tier, not just nightly."""
    import packages.coccinelle.prereqs as prereqs_mod

    class _Facts:
        def __init__(self, skipped: bool, exists: bool,
                     complete: bool = True):
            self.is_skipped = skipped
            self._exists = exists
            self.complete = complete

        def function_exists(self, name: str) -> bool:
            return self._exists

    result = SourceIntelResult()

    monkeypatch.setattr(
        prereqs_mod, "gather_prereqs", lambda t: _Facts(False, True),
    )
    assert result.function_intel_status("f", target=tmp_path) == "in_tree"

    monkeypatch.setattr(
        prereqs_mod, "gather_prereqs", lambda t: _Facts(False, False),
    )
    assert result.function_intel_status(
        "f", target=tmp_path,
    ) == "name_not_in_tree"

    monkeypatch.setattr(
        prereqs_mod, "gather_prereqs", lambda t: _Facts(True, True),
    )
    assert result.function_intel_status(
        "f", target=tmp_path,
    ) == "prereqs_skipped"

    # Partial sweep: "I scanned and the name isn't here" is only
    # claimable from a complete sweep — absence degrades to skipped,
    # positive hits still count.
    monkeypatch.setattr(
        prereqs_mod, "gather_prereqs",
        lambda t: _Facts(False, False, complete=False),
    )
    assert result.function_intel_status(
        "f", target=tmp_path,
    ) == "prereqs_skipped"

    monkeypatch.setattr(
        prereqs_mod, "gather_prereqs",
        lambda t: _Facts(False, True, complete=False),
    )
    assert result.function_intel_status(
        "f", target=tmp_path,
    ) == "in_tree"
