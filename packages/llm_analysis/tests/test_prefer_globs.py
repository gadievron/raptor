"""Tests for ``apply_prefer_globs`` — the operator-controlled
attack-surface ordering primitive used by /agentic's ``--prefer`` flag.

The function re-buckets findings: those whose file_path matches any of
the supplied globs sort to the front; everything else keeps its
relative order. Stable within each bucket so existing dataflow-then-
SARIF order survives for non-matching findings.
"""

from __future__ import annotations

import sys
from pathlib import Path

# packages/llm_analysis/tests/test_prefer_globs.py -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis.agent import (  # noqa: E402
    _file_matches_globs,
    apply_exclude_dir_globs,
    apply_prefer_globs,
)


class TestFileMatchesGlobs:
    """fnmatch-OR semantics across the supplied globs."""

    def test_single_glob_match(self):
        assert _file_matches_globs("src/http/server.c", ["src/http/*"]) is True

    def test_single_glob_no_match(self):
        assert _file_matches_globs("src/util.c", ["src/http/*"]) is False

    def test_multiple_globs_or_semantics(self):
        # First glob misses, second glob matches → True.
        assert _file_matches_globs(
            "src/protocols/mysql.c",
            ["src/http/*", "src/protocols/*"],
        ) is True

    def test_empty_globs_list(self):
        # No globs supplied → no match.
        assert _file_matches_globs("anywhere.c", []) is False

    def test_empty_path(self):
        # Defensive: missing file_path treated as no-match.
        assert _file_matches_globs("", ["src/*"]) is False

    def test_none_path_treated_as_empty(self):
        # apply_prefer_globs passes "" via f.get("file_path", "") — verify
        # the helper handles empty gracefully (no AttributeError on None
        # propagating from a caller that forgot the default).
        assert _file_matches_globs(None, ["src/*"]) is False  # type: ignore[arg-type]


class TestApplyPreferGlobs:
    """Re-bucket findings: matches first, others second, stable within."""

    @staticmethod
    def _f(path: str, **kw):
        return {"file_path": path, **kw}

    def test_none_globs_is_noop(self):
        findings = [self._f("a.c"), self._f("b.c")]
        assert apply_prefer_globs(findings, None) == findings

    def test_empty_globs_is_noop(self):
        findings = [self._f("a.c"), self._f("b.c")]
        assert apply_prefer_globs(findings, []) == findings

    def test_match_sorts_to_front(self):
        findings = [
            self._f("src/util.c"),         # non-match
            self._f("src/http/server.c"),  # match
        ]
        result = apply_prefer_globs(findings, ["src/http/*"])
        assert [f["file_path"] for f in result] == [
            "src/http/server.c",
            "src/util.c",
        ]

    def test_stable_within_buckets(self):
        # Within "matches" bucket, original order preserved.
        # Within "others" bucket, original order preserved.
        # Re-runs produce stable diffs.
        findings = [
            self._f("src/util.c"),               # other 1
            self._f("src/http/server.c"),        # match 1
            self._f("src/cli.c"),                # other 2
            self._f("src/http/processor.c"),     # match 2
            self._f("src/log.c"),                # other 3
        ]
        result = apply_prefer_globs(findings, ["src/http/*"])
        assert [f["file_path"] for f in result] == [
            "src/http/server.c",      # match 1 first
            "src/http/processor.c",   # match 2 second
            "src/util.c",             # other 1 (original order)
            "src/cli.c",              # other 2
            "src/log.c",              # other 3
        ]

    def test_multiple_globs_or_semantics(self):
        findings = [
            self._f("src/util.c"),
            self._f("src/http/server.c"),
            self._f("src/protocols/mysql.c"),
            self._f("src/log.c"),
        ]
        result = apply_prefer_globs(
            findings, ["src/http/*", "src/protocols/*"],
        )
        # Both matchers sort to front in original order.
        assert [f["file_path"] for f in result] == [
            "src/http/server.c",
            "src/protocols/mysql.c",
            "src/util.c",
            "src/log.c",
        ]

    def test_all_match(self):
        findings = [self._f("src/http/a.c"), self._f("src/http/b.c")]
        # All match → ordering unchanged (everything's in the front bucket).
        assert apply_prefer_globs(findings, ["src/http/*"]) == findings

    def test_none_match(self):
        findings = [self._f("src/util.c"), self._f("src/log.c")]
        # No matches → ordering unchanged (everything's in the others bucket).
        assert apply_prefer_globs(findings, ["src/http/*"]) == findings

    def test_finding_without_file_path_treated_as_other(self):
        # Defensive: a malformed finding without file_path doesn't
        # crash; it stays in the others bucket regardless of glob.
        findings = [
            {"id": "no-path"},                      # malformed
            self._f("src/http/server.c"),           # match
        ]
        result = apply_prefer_globs(findings, ["src/http/*"])
        assert result[0]["file_path"] == "src/http/server.c"
        assert result[1] == {"id": "no-path"}

    def test_pre_cap_ordering_for_low_max_findings(self):
        # The headline use case: with --max-findings=2 and 4 findings
        # (3 noise, 1 attack-surface), pre-fix the cap took 2 of 3
        # noise findings and dropped the attack-surface one. Post-fix,
        # --prefer guarantees the attack-surface finding is in the
        # captured set.
        findings = [
            self._f("src/device/sysdep_LINUX.c"),
            self._f("src/device/sysdep_AIX.c"),
            self._f("src/http/server.c"),  # attack-surface
            self._f("src/util.c"),
        ]
        prioritised = apply_prefer_globs(findings, ["src/http/*"])
        capped = prioritised[:2]  # simulate --max-findings 2
        assert any(
            f["file_path"] == "src/http/server.c" for f in capped
        ), "attack-surface finding must survive the cap when --prefer matched it"


class TestApplyExcludeDirGlobs:
    """Drop findings whose file_path matches any exclude glob;
    order-preserving for the rest. Operator escape hatch for vendored
    / test / generated paths."""

    @staticmethod
    def _f(path: str, **kw):
        return {"file_path": path, **kw}

    def test_none_globs_is_noop(self):
        findings = [self._f("a.c"), self._f("b.c")]
        assert apply_exclude_dir_globs(findings, None) == findings

    def test_empty_globs_is_noop(self):
        findings = [self._f("a.c"), self._f("b.c")]
        assert apply_exclude_dir_globs(findings, []) == findings

    def test_single_glob_drops_matches(self):
        findings = [
            self._f("vendor/lib.c"),         # drop
            self._f("src/http/server.c"),    # keep
            self._f("vendor/util.c"),        # drop
        ]
        result = apply_exclude_dir_globs(findings, ["vendor/*"])
        assert [f["file_path"] for f in result] == ["src/http/server.c"]

    def test_multiple_globs_or_semantics(self):
        findings = [
            self._f("src/util.c"),           # keep
            self._f("vendor/lib.c"),         # drop (first glob)
            self._f("tests/test_x.c"),       # drop (second glob)
            self._f("src/http/server.c"),    # keep
        ]
        result = apply_exclude_dir_globs(
            findings, ["vendor/*", "tests/*"],
        )
        assert [f["file_path"] for f in result] == [
            "src/util.c", "src/http/server.c",
        ]

    def test_order_preserved_among_kept(self):
        findings = [
            self._f("a.c"),
            self._f("vendor/x.c"),
            self._f("b.c"),
            self._f("vendor/y.c"),
            self._f("c.c"),
        ]
        result = apply_exclude_dir_globs(findings, ["vendor/*"])
        assert [f["file_path"] for f in result] == ["a.c", "b.c", "c.c"]

    def test_missing_file_path_kept_defensively(self):
        # Malformed finding without file_path: operator-excludes
        # shouldn't silently drop these — if metadata is broken the
        # operator wants to see them, not have them filtered.
        findings = [
            {"id": "no-path"},
            self._f("vendor/lib.c"),
            self._f("src/util.c"),
        ]
        result = apply_exclude_dir_globs(findings, ["vendor/*"])
        assert {"id": "no-path"} in result
        assert self._f("src/util.c") in result
        assert self._f("vendor/lib.c") not in result

    def test_no_matches_returns_unchanged(self):
        findings = [self._f("src/a.c"), self._f("src/b.c")]
        result = apply_exclude_dir_globs(findings, ["vendor/*"])
        assert result == findings

    def test_all_matches_returns_empty(self):
        findings = [self._f("vendor/a.c"), self._f("vendor/b.c")]
        result = apply_exclude_dir_globs(findings, ["vendor/*"])
        assert result == []
