"""Tests for the shared glibc version helpers.

Pins the loose-parse semantics operators actually see:

  * ``parse_major_minor`` accepts ``"2.35"`` / ``"2.35.1"`` /
    whitespace forms; returns ``None`` on garbage.
  * ``search_major_minor`` scans for the first ``\\d+\\.\\d+``
    occurrence in a wrapping string (``ldd`` / ``apt list`` output).
  * ``resolve_greatest_leq`` picks the greatest candidate ≤ target,
    or ``None`` when target predates every candidate — the "cover"
    semantics so a target on 2.40 falls to the 2.35 entry rather
    than being silently dropped for lack of an exact match.
  * ``compare_versions`` handles unequal-depth tuples via zero-pad
    so ``(2, 35) == (2, 35, 0)``.
"""

from __future__ import annotations

import pytest

from core.binary.glibc_versions import (
    compare_versions,
    parse_major_minor,
    parse_version,
    resolve_greatest_leq,
    search_major_minor,
)


class TestParseMajorMinor:
    @pytest.mark.parametrize("raw,expected", [
        ("2.35", (2, 35)),
        ("2.31", (2, 31)),
        ("2.35.1", (2, 35)),
        ("  2.43  ", (2, 43)),
        ("3", (3, 0)),
    ])
    def test_valid(self, raw, expected):
        assert parse_major_minor(raw) == expected

    @pytest.mark.parametrize("raw", [None, "", "abc", "2.x", "  "])
    def test_invalid(self, raw):
        assert parse_major_minor(raw) is None


class TestSearchMajorMinor:
    @pytest.mark.parametrize("raw,expected", [
        # Clean inputs — substring semantics still match.
        ("2.35", (2, 35)),
        ("2.35.1", (2, 35)),
        # Wrapped ``ldd --version`` first-line output — the shape
        # exploit_feasibility receives.
        ("ldd (Ubuntu GLIBC 2.38-0ubuntu3) 2.38", (2, 38)),
        ("ldd (GNU libc) 2.31", (2, 31)),
        # apt-list style.
        ("libc6/jammy 2.35-0ubuntu3.4 amd64", (2, 35)),
        # First match wins when multiple version-like tokens present.
        ("older 2.28 newer 2.35", (2, 28)),
    ])
    def test_valid(self, raw, expected):
        # Regression pin: pre-fix ``create_dependency_graph`` on the
        # /exploit branch routed through ``parse_major_minor`` (anchored)
        # and silently dropped the ldd-wrapped input, leaving
        # ``glibc_hooks_removed`` off the active_mitigations set.
        assert search_major_minor(raw) == expected

    @pytest.mark.parametrize("raw", [
        None, "", "no version here", "abc",
        # No digit-dot-digit — bare integer isn't enough.
        "3",
    ])
    def test_invalid(self, raw):
        assert search_major_minor(raw) is None


class TestParseVersion:
    def test_variable_depth(self):
        assert parse_version("2.35.1") == (2, 35, 1)
        assert parse_version("2.35") == (2, 35)

    def test_empty(self):
        assert parse_version("") == ()

    def test_non_numeric_collapses_to_zero(self):
        # Consumers (predicate evaluator) don't need to reject —
        # they compare with sensible zero fill.
        assert parse_version("2.x") == (2, 0)

    @pytest.mark.parametrize("raw,expected", [
        # Distro suffixes on the minor component — the shape real
        # /etc/ld.so.conf.d and glibc-common package strings take.
        # Semantic: each dotted component keeps its LEADING digit
        # run (so a Fedora ``fc35`` component with no leading digits
        # collapses to 0 — that's fine because 2.32 vs 2.32.0 comparisons
        # zero-pad anyway).
        ("2.35-0ubuntu3.4", (2, 35, 4)),
        ("2.32-9.fc35",     (2, 32, 0)),
        ("2.32-ubu1",       (2, 32)),
        ("2.35+revA",       (2, 35)),
        # Suffix on the major component — implausible but let's not
        # fail closed on a well-shaped leading digit.
        ("2rc.35",          (2, 35)),
    ])
    def test_distro_suffix_stripped_per_component(self, raw, expected):
        # BLOCKER regression pin: parse_version used to str.split('.')
        # + int() and collapse "35-0ubuntu3" to 0, classifying a real
        # glibc-2.35 target as pre-2.32 and feeding it the wrong
        # tcache-safe-linking branch.
        assert parse_version(raw) == expected

    def test_distro_suffix_still_passes_ge_predicate(self):
        # The property that actually matters at the hardening branch:
        # a distro-suffixed 2.35 must compare >= (2, 32). Pin the
        # end-to-end semantics rather than trust the tuple shape alone.
        from core.binary.glibc_versions import compare_versions
        assert compare_versions(
            parse_version("2.35-0ubuntu3.4"), parse_version("2.32"),
        ) >= 0
        assert compare_versions(
            parse_version("2.32-9.fc35"), parse_version("2.32"),
        ) >= 0
        assert compare_versions(
            parse_version("2.31-0ubuntu9.9"), parse_version("2.32"),
        ) < 0


class TestCompareVersions:
    def test_equal_len(self):
        assert compare_versions((2, 35), (2, 35)) == 0
        assert compare_versions((2, 31), (2, 35)) == -1
        assert compare_versions((2, 43), (2, 35)) == 1

    def test_unequal_len_pads(self):
        assert compare_versions((2, 35), (2, 35, 0)) == 0
        assert compare_versions((2, 35), (2, 35, 1)) == -1


class TestResolveGreatestLeq:
    def test_exact_match_wins(self):
        candidates = [(2, 31), (2, 35), (2, 43)]
        assert resolve_greatest_leq((2, 35), candidates) == (2, 35)

    def test_greatest_below_target(self):
        # Target 2.40, candidates 2.31/2.35 → pick 2.35.
        candidates = [(2, 31), (2, 35)]
        assert resolve_greatest_leq((2, 40), candidates) == (2, 35)

    def test_target_below_all(self):
        # Target 2.28, candidates 2.31/2.35 → nothing covers it.
        candidates = [(2, 31), (2, 35)]
        assert resolve_greatest_leq((2, 28), candidates) is None

    def test_target_none_returns_none(self):
        assert resolve_greatest_leq(None, [(2, 31)]) is None

    def test_empty_candidates_returns_none(self):
        assert resolve_greatest_leq((2, 35), []) is None
