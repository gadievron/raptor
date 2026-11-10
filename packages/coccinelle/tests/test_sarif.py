"""Tests for the SpatchResult → SARIF converter.

Pure conversion; no I/O. Tests cover shape pinning (driver name,
ruleId match, location coordinates), edge cases (no matches, errors
without matches, absolute vs relative paths), and SARIF schema
versioning.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


# parents[3] climbs:
#   [0] packages/coccinelle/tests/  (this file's directory)
#   [1] packages/coccinelle/
#   [2] packages/
#   [3] <repo root>
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if __name__ == "__main__":
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)

from packages.coccinelle.models import SpatchMatch, SpatchResult  # noqa: E402
from packages.coccinelle.sarif import results_to_sarif  # noqa: E402


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
    doc = results_to_sarif([result], Path("./some-other-repo"))
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
    region = _run0(results_to_sarif([result], tmp_path))[
        "results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 5
    assert "endLine" not in region
    assert "startColumn" not in region
    assert "endColumn" not in region


@pytest.mark.parametrize('line', [0, -3, True], ids=['unknown', 'negative', 'boolean'])
def test_unlocated_match_remains_a_finding_without_line_one(tmp_path, line):
    result = SpatchResult(rule='r', matches=[SpatchMatch(file='a.c', line=line, column=5)])
    run = _run0(results_to_sarif([result], tmp_path))
    assert len(run['results']) == 1
    assert run['results'][0]['locations'][0]['physicalLocation']['region'] == {}


def test_converter_resolves_only_target_root_and_keeps_source_spelling(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    link = root / 'link.c'
    link.symlink_to(root.parent / 'outside.c')
    outside = str(root.parent / 'header.h')
    original = Path.resolve
    resolved = []
    def resolve(path, *args, **kwargs):
        assert path == root, 'formatting must not resolve source files'
        resolved.append(path)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'resolve', resolve)
    paths = [str(root / 'missing.c')] * 100 + ['src/../missing.c', str(link), outside]
    result = SpatchResult(rule='r', matches=[SpatchMatch(file=path, line=5) for path in paths])
    rows = _run0(results_to_sarif([result], root))['results']
    assert resolved == [root]
    uris = [row['locations'][0]['physicalLocation']['artifactLocation']['uri'] for row in rows]
    assert uris[:101] == ['missing.c'] * 101
    assert uris[-2:] == ['link.c', outside]


def test_cocci_export_drops_backwards_end_without_dropping_match(tmp_path):
    result = SpatchResult(rule='r', matches=[
        SpatchMatch(file='a.c', line=8, line_end=7, column=9, column_end=12),
    ])
    rows = _run0(results_to_sarif([result], tmp_path))['results']
    assert len(rows) == 1
    assert rows[0]['locations'][0]['physicalLocation']['region'] == {'startLine': 8, 'startColumn': 9}


@pytest.mark.parametrize('failure', [OSError, RuntimeError], ids=['root-unavailable', 'root-cycle'])
def test_root_resolution_failure_preserves_findings_with_original_paths(tmp_path, monkeypatch, failure):
    def unavailable(*args, **kwargs):
        raise failure('root cannot be resolved')
    monkeypatch.setattr(Path, 'resolve', unavailable)
    result = SpatchResult(rule='r', matches=[SpatchMatch(file='src/a.c', line=8)])
    rows = _run0(results_to_sarif([result], tmp_path))['results']
    assert len(rows) == 1
    physical = rows[0]['locations'][0]['physicalLocation']
    assert physical['artifactLocation']['uri'] == 'src/a.c'
    assert physical['region'] == {'startLine': 8}


def test_uri_looking_source_path_does_not_rebind_to_a_local_basename(tmp_path):
    result = SpatchResult(rule='r', matches=[SpatchMatch(file='file://literal.c', line=8)])
    rows = _run0(results_to_sarif([result], tmp_path))['results']
    assert rows[0]['locations'][0]['physicalLocation']['artifactLocation']['uri'] == 'file://literal.c'


@pytest.mark.parametrize('profile', ['repeated', 'unique'])
def test_report_normalizes_each_plain_path_once_across_rules(tmp_path, monkeypatch, profile):
    import json

    from packages.coccinelle import sarif
    from packages.coccinelle.runner import _parse_results

    root = tmp_path.resolve()
    spellings = [str(root / 'src/a.c'), 'src/../b.c',
                 str(root.parent / 'external.h'), 'file://literal.c']
    expected_paths = ['src/a.c', 'b.c', spellings[2], spellings[3]]
    if profile == 'unique':
        spellings = [f'src/file-{index}.c' for index in range(512)]
        expected_paths = list(spellings)
    results = []
    for rule_index, rule in enumerate(['first', 'second']):
        output = '\n'.join('COCCIRESULT-owned:' + json.dumps({
            'file': spellings[(index + rule_index * 256) % len(spellings)], 'line': index + 1,
            'col': 3, 'rule': rule, 'message': f'match-{index}',
        }) for index in range(256))
        diagnostics = []
        matches = _parse_results(output, rule, nonce='owned', diagnostics=diagnostics)
        assert len(matches) == 256 and not diagnostics
        results.append(SpatchResult(rule=rule, matches=matches))
    original = sarif._rel_to_repo
    calls = []

    def observed(path, resolved_root):
        calls.append((path, resolved_root))
        return original(path, resolved_root)

    monkeypatch.setattr(sarif, '_rel_to_repo', observed)
    report = sarif.results_to_sarif(iter(results), root)
    used = spellings
    assert [path for path, _ in calls] == used
    rows = _run0(report)['results']
    assert len(rows) == 512
    expected = expected_paths if profile == 'unique' else expected_paths * 128
    assert [row['locations'][0]['physicalLocation']['artifactLocation']['uri']
            for row in rows] == expected
    assert [row['ruleId'] for row in rows] == ['first'] * 256 + ['second'] * 256
    assert [row['message']['text'] for row in rows] == [f'match-{i}' for i in range(256)] * 2
    assert [row['locations'][0]['physicalLocation']['region'] for row in rows] == [
        {'startLine': i + 1, 'startColumn': 3} for i in range(256)
    ] * 2
    # Reusing the URI must not alias the surrounding result/location objects.
    rows[0]['locations'][0]['physicalLocation']['artifactLocation']['uri'] = 'changed'
    assert rows[256]['locations'][0]['physicalLocation']['artifactLocation']['uri'] == expected[256]
    other = root.parent / 'different-root'
    second = sarif.results_to_sarif(results, other)
    assert len(calls) == len(used) * 2
    expected_first = spellings[0] if profile == 'repeated' else expected_paths[0]
    assert _run0(second)['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'] == expected_first


def test_path_string_adapter_is_not_hashed_or_memoized(tmp_path, monkeypatch):
    from packages.coccinelle import sarif

    class PathAdapter(str):
        def __hash__(self) -> int:
            pytest.fail('path adapters must retain the uncached path')

    spelling = PathAdapter('src/a.c')
    original = sarif._rel_to_repo
    calls = []

    def observed(path, root):
        calls.append(path)
        return original(path, root)

    monkeypatch.setattr(sarif, '_rel_to_repo', observed)
    result = SpatchResult(rule='r', matches=[SpatchMatch(file=spelling, line=1)] * 2)
    rows = _run0(sarif.results_to_sarif([result], tmp_path))['results']
    assert calls == [spelling, spelling]
    assert [row['locations'][0]['physicalLocation']['artifactLocation']['uri']
            for row in rows] == ['src/a.c', 'src/a.c']
