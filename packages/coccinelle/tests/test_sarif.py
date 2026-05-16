"""Tests for the SpatchResult → SARIF converter.

Pure conversion; no I/O. Tests cover shape pinning (driver name,
ruleId match, location coordinates), edge cases (no matches, errors
without matches, absolute vs relative paths), and SARIF schema
versioning.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_RAPTOR_DIR = os.environ["RAPTOR_DIR"]
if _RAPTOR_DIR not in sys.path:
    sys.path.insert(0, _RAPTOR_DIR)

from packages.coccinelle.models import SpatchMatch, SpatchResult
from packages.coccinelle.sarif import results_to_sarif


def _run0(doc):
    return doc["runs"][0]


def test_empty_results_emits_minimal_sarif(tmp_path):
    """No SpatchResults at all → still a valid SARIF doc with the
    cocci tool driver and an empty results list. Operators get an
    empty-but-well-formed file rather than nothing."""
    doc = results_to_sarif([], tmp_path)
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    run = _run0(doc)
    assert run["tool"]["driver"]["name"] == "coccinelle"
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_single_match_round_trip(tmp_path):
    """One rule, one match → one rule definition + one result, with
    file/line/column preserved and ruleId matching the rule's stem."""
    src = tmp_path / "vuln.c"
    src.write_text("// stub\n")
    result = SpatchResult(
        rule="missing_null_check",
        rule_path="engine/coccinelle/rules/missing_null_check.cocci",
        matches=[SpatchMatch(
            file=str(src), line=42,
            column=8, line_end=42, column_end=20,
            rule="missing_null_check",
            message="Allocation result p used without NULL check",
        )],
    )
    doc = results_to_sarif([result], tmp_path)
    run = _run0(doc)
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "missing_null_check"

    assert len(run["results"]) == 1
    sr = run["results"][0]
    assert sr["ruleId"] == "missing_null_check"
    assert sr["level"] == "warning"
    assert "Allocation result p used" in sr["message"]["text"]
    loc = sr["locations"][0]["physicalLocation"]
    # Path normalised to repo-relative.
    assert loc["artifactLocation"]["uri"] == "vuln.c"
    region = loc["region"]
    assert region["startLine"] == 42
    assert region["endLine"] == 42
    assert region["startColumn"] == 8
    assert region["endColumn"] == 20


def test_relative_path_preserved(tmp_path):
    """SpatchMatch.file already-relative passes through unchanged
    (no surprising repo-resolve attempts)."""
    result = SpatchResult(rule="r", matches=[
        SpatchMatch(file="src/parser.c", line=1, message="x"),
    ])
    doc = results_to_sarif([result], tmp_path)
    sr = _run0(doc)["results"][0]
    assert sr["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"] == "src/parser.c"


def test_cross_fs_path_preserved():
    """A match in a system header (outside the repo) doesn't crash
    the conversion — leaves the absolute path as-is."""
    result = SpatchResult(rule="r", matches=[
        SpatchMatch(file="/usr/include/string.h", line=1, message="x"),
    ])
    doc = results_to_sarif([result], Path("/tmp/some-other-repo"))
    sr = _run0(doc)["results"][0]
    assert sr["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"] == "/usr/include/string.h"


def test_multiple_rules_dedup_in_driver(tmp_path):
    """Three SpatchResults for two distinct rules → two rule
    definitions in tool.driver.rules (not three). Pin so a future
    "include duplicates" change gets caught."""
    results = [
        SpatchResult(rule="rule_a", matches=[
            SpatchMatch(file="a.c", line=1, message="m1")]),
        SpatchResult(rule="rule_b", matches=[
            SpatchMatch(file="b.c", line=2, message="m2")]),
        SpatchResult(rule="rule_a", matches=[
            SpatchMatch(file="c.c", line=3, message="m3")]),
    ]
    doc = results_to_sarif(results, tmp_path)
    rule_ids = [r["id"] for r in _run0(doc)["tool"]["driver"]["rules"]]
    assert rule_ids == ["rule_a", "rule_b"]
    assert len(_run0(doc)["results"]) == 3


def test_errors_without_matches_surface_as_invocations(tmp_path):
    """A rule that errored AND produced no matches → SARIF
    ``invocations[].toolExecutionNotifications`` carries the error.
    Operators see the rule had a problem, not silently lost."""
    result = SpatchResult(
        rule="broken_rule",
        matches=[],
        errors=["semantic error: unbound metavariable foo"],
        returncode=1,
    )
    doc = results_to_sarif([result], tmp_path)
    run = _run0(doc)
    assert "invocations" in run
    notifications = run["invocations"][0]["toolExecutionNotifications"]
    assert len(notifications) == 1
    assert "unbound metavariable" in notifications[0]["message"]["text"]
    assert notifications[0]["associatedRule"]["id"] == "broken_rule"
    # No false-positive results.
    assert run["results"] == []


def test_rule_with_matches_and_errors_has_both(tmp_path):
    """Some rules emit partial results (some matches, some errors).
    SARIF carries both — results aren't dropped because of an error."""
    result = SpatchResult(
        rule="partial",
        matches=[SpatchMatch(file="a.c", line=1, message="m1")],
        errors=["warning: ambiguous metavariable"],
        returncode=0,
    )
    doc = results_to_sarif([result], tmp_path)
    run = _run0(doc)
    assert len(run["results"]) == 1
    assert "invocations" in run


def test_no_errors_omits_invocations_block(tmp_path):
    """Clean run (no errors anywhere) → no ``invocations`` key in
    the run. SARIF spec allows it; keeping it absent reduces noise
    in the merged output."""
    result = SpatchResult(rule="r", matches=[
        SpatchMatch(file="a.c", line=1, message="m")])
    doc = results_to_sarif([result], tmp_path)
    run = _run0(doc)
    assert "invocations" not in run


def test_match_without_message_synthesizes_one(tmp_path):
    """SpatchMatch with empty message → SARIF result still has a
    non-empty message text (operator-readable), synthesised from
    the ruleId."""
    result = SpatchResult(rule="my_rule", matches=[
        SpatchMatch(file="a.c", line=1, message=""),
    ])
    doc = results_to_sarif([result], tmp_path)
    text = _run0(doc)["results"][0]["message"]["text"]
    assert "my_rule" in text


def test_optional_region_fields_omitted_when_zero(tmp_path):
    """SpatchMatch with line_end=0 / column=0 → the SARIF region
    omits those fields rather than emitting zeros (which break some
    SARIF viewers that expect 1-indexed positions)."""
    result = SpatchResult(rule="r", matches=[
        SpatchMatch(file="a.c", line=5,
                    column=0, line_end=0, column_end=0,
                    message="m"),
    ])
    region = _run0(doc := results_to_sarif([result], tmp_path))[
        "results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 5
    assert "endLine" not in region
    assert "startColumn" not in region
    assert "endColumn" not in region
