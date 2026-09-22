"""Substrate-validity seam: predicates, scopes, license, normalizer.

Unit layer — pure logic over language facts and fixture results; no
live tools, no LLM calls.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from core.audit.substrate import (
    Coverage,
    SubstrateScopeError,
    UNKNOWN_FAIL_OPEN,
    UNKNOWN_INCONCLUSIVE,
    _reset_substrate_caches,
    canonical_file_language,
    classify_sweep_outcome,
    file_substrate_coverage,
    license_refutation,
    registered_scope,
    substrate_covers,
    tree_language_set,
)
from core.audit.sweep import SweepResult


@pytest.fixture(autouse=True)
def _fresh_caches():
    _reset_substrate_caches()
    yield
    _reset_substrate_caches()


def _result(outcome: str, **kw) -> SweepResult:
    return SweepResult(
        tool="coccinelle", file_path="a.c", function_name="f",
        outcome=outcome, **kw,
    )


class TestClassifySweepOutcome:
    @pytest.mark.parametrize("outcome", [
        "confirmed", "refuted", "error", "inconclusive", "skipped",
    ])
    def test_known_outcomes_pass_through(self, outcome):
        assert classify_sweep_outcome(_result(outcome)) == outcome

    def test_novel_outcome_lands_in_error(self):
        # A novel outcome must land in error accounting, never be
        # miscounted as a refutation via a bare-else fall-through.
        assert classify_sweep_outcome(_result("banana")) == "error"

    def test_missing_outcome_attr_lands_in_error(self):
        assert classify_sweep_outcome(object()) == "error"

    def test_none_outcome_lands_in_error(self):
        assert classify_sweep_outcome(SimpleNamespace(outcome=None)) == "error"


class TestFilePredicate:
    def test_php_file_not_covered(self):
        cov = substrate_covers(
            "coccinelle", language="php", file_path="a.php",
        )
        assert cov.covered is False
        assert "php" in cov.reason
        assert cov.evidence == {"language": "php"}

    @pytest.mark.parametrize("lang", ["c", "cpp"])
    def test_c_family_covered(self, lang):
        cov = substrate_covers(
            "coccinelle", language=lang, file_path="a.x",
        )
        assert cov.covered is True

    def test_unknown_language_fails_open(self):
        cov = substrate_covers(
            "coccinelle", language=None, file_path="a.unknownext",
        )
        assert cov.covered is None
        assert cov.unknown_policy == UNKNOWN_FAIL_OPEN

    def test_flow_variant_shares_predicate(self):
        cov = substrate_covers(
            "coccinelle_flow", language="python", file_path="a.py",
        )
        assert cov.covered is False


class TestTreePredicate:
    def test_no_c_substrate_in_tree(self):
        cov = substrate_covers(
            "coccinelle_consistency",
            tree_languages=frozenset({"php", "javascript"}),
        )
        assert cov.covered is False
        assert "no C substrate in tree" in cov.reason

    def test_stray_c_file_covers_tree(self):
        cov = substrate_covers(
            "coccinelle_consistency",
            tree_languages=frozenset({"php", "c"}),
        )
        assert cov.covered is True
        assert cov.evidence == {"c_family_languages": ["c"]}

    def test_no_inventory_fails_open(self):
        cov = substrate_covers("coccinelle_consistency", tree_languages=None)
        assert cov.covered is None
        assert cov.unknown_policy == UNKNOWN_FAIL_OPEN


class TestScopeContract:
    @pytest.mark.parametrize("sentinel", ["<codebase>", "(path-check)"])
    @pytest.mark.parametrize("tool", ["coccinelle", "coccinelle_flow"])
    def test_sentinel_on_file_scope_raises(self, tool, sentinel):
        # Silently answering False would abolish the tier; True would
        # license vacuity — the mismatch is a programming error.
        with pytest.raises(SubstrateScopeError):
            substrate_covers(tool, language="c", file_path=sentinel)

    def test_registered_scopes(self):
        assert registered_scope("coccinelle") == "file"
        assert registered_scope("coccinelle_flow") == "file"
        assert registered_scope("coccinelle_consistency") == "tree"
        assert registered_scope("semgrep") is None

    def test_unregistered_tier_never_adjudicated(self):
        cov = substrate_covers("semgrep", language="php", file_path="a.php")
        assert cov.covered is None
        assert cov.tier == "unregistered"
        assert cov.unknown_policy == UNKNOWN_FAIL_OPEN


class TestSentinelNamedSubjectFiles:
    """Sentinel NAMES are legal filenames: a real file named after a
    result sentinel is a subject, never a scope error — raising on it
    would let a hostile tree suppress that file's findings by naming
    alone."""

    @pytest.mark.parametrize("name", ["<codebase>", "(path-check)"])
    def test_hostile_php_file_is_adjudicated_normally(self, tmp_path, name):
        (tmp_path / name).write_text("<?php system($_GET['c']);\n")
        cov = file_substrate_coverage(
            "coccinelle", target_path=tmp_path, file_path=name,
        )
        assert cov is not None
        assert cov.covered is False  # php: normal substrate skip

    def test_stamped_language_still_wins_on_sentinel_name(self, tmp_path):
        (tmp_path / "(path-check)").write_text("int f(void){return 0;}\n")
        cov = file_substrate_coverage(
            "coccinelle", target_path=tmp_path,
            file_path="(path-check)", language="c",
        )
        assert cov is not None
        assert cov.covered is True

    @pytest.mark.parametrize("name", ["<codebase>", "(path-check)"])
    def test_missing_sentinel_still_raises(self, tmp_path, name):
        # Genuine programming error: the sentinel names no subject.
        with pytest.raises(SubstrateScopeError):
            file_substrate_coverage(
                "coccinelle", target_path=tmp_path, file_path=name,
            )

    def test_symlink_named_sentinel_raises(self, tmp_path):
        # No-follow policy, mirroring the inventory probe: a symlink
        # is not a reviewable subject file.
        (tmp_path / "real.php").write_text("<?php\n")
        (tmp_path / "<codebase>").symlink_to(tmp_path / "real.php")
        with pytest.raises(SubstrateScopeError):
            file_substrate_coverage(
                "coccinelle", target_path=tmp_path,
                file_path="<codebase>",
            )


class TestLicenseRefutation:
    def _cov(self, covered, policy=UNKNOWN_FAIL_OPEN) -> Coverage:
        return Coverage(
            covered=covered, tier="language", reason="r",
            unknown_policy=policy,
        )

    def test_covered_refuted_stands_with_receipt(self):
        out = license_refutation(_result("refuted"), self._cov(True))
        assert out.outcome == "refuted"
        assert out.details["substrate"]["covered"] is True

    def test_uncovered_refuted_demotes_to_skipped(self):
        out = license_refutation(_result("refuted"), self._cov(False))
        assert out.outcome == "skipped"
        assert out.details["reason"] == "r"
        assert out.details["substrate"]["covered"] is False

    def test_unknown_fail_open_keeps_refuted(self):
        out = license_refutation(_result("refuted"), self._cov(None))
        assert out.outcome == "refuted"
        assert out.details["substrate"]["covered"] == "unknown"

    def test_unknown_inconclusive_demotes(self):
        out = license_refutation(
            _result("refuted"), self._cov(None, UNKNOWN_INCONCLUSIVE),
        )
        assert out.outcome == "inconclusive"

    @pytest.mark.parametrize("outcome", [
        "confirmed", "error", "inconclusive", "skipped",
    ])
    def test_non_refuted_pass_through_untouched(self, outcome):
        res = _result(outcome)
        assert license_refutation(res, self._cov(False)) is res


class TestCanonicalFileLanguage:
    def test_extension_detection(self, tmp_path):
        (tmp_path / "a.php").write_text("<?php f();\n")
        assert canonical_file_language(tmp_path, "a.php") == "php"

    def test_c_header_refines_to_cpp(self, tmp_path):
        (tmp_path / "a.h").write_text("template <typename T> class X {};\n")
        assert canonical_file_language(tmp_path, "a.h") == "cpp"

    def test_extensionless_php_content_probe(self, tmp_path):
        (tmp_path / "handler").write_text("<?php echo 1;\n")
        assert canonical_file_language(tmp_path, "handler") == "php"

    def test_undetectable_returns_none(self, tmp_path):
        (tmp_path / "notes.unknownext").write_text("hello\n")
        assert canonical_file_language(tmp_path, "notes.unknownext") is None

    def test_missing_file_keeps_extension_verdict(self, tmp_path):
        assert canonical_file_language(tmp_path, "gone.c") == "c"

    @pytest.mark.skipif(
        not hasattr(os, "mkfifo"), reason="platform lacks mkfifo",
    )
    def test_fifo_named_header_answers_unknown_promptly(self, tmp_path):
        # A plain open() of a reader-less FIFO blocks forever; the
        # probe must refuse non-regular files and the language must
        # come back unknown (fail-open), never a refutation-licensing
        # verdict for an object that is not source at all.
        os.mkfifo(tmp_path / "evil.h")
        assert canonical_file_language(tmp_path, "evil.h") is None

    def test_symlink_header_answers_unknown(self, tmp_path):
        # No-follow, matching the inventory probe's policy.
        (tmp_path / "real.h").write_text("template <class T> struct X;\n")
        (tmp_path / "alias.h").symlink_to(tmp_path / "real.h")
        assert canonical_file_language(tmp_path, "alias.h") is None


class TestTreeLanguageSet:
    def test_language_mix(self):
        inv = {"files": [
            {"path": "a.php", "language": "php"},
            {"path": "b.c", "language": "c"},
            {"path": "c.bin"},
        ]}
        assert tree_language_set(inv) == frozenset({"php", "c"})

    @pytest.mark.parametrize("inv", [None, {}, {"files": []}, {"files": "x"}])
    def test_unanswerable_shapes_yield_none(self, inv):
        assert tree_language_set(inv) is None


class TestFileSubstrateCoverage:
    def test_unregistered_tool_noop(self, tmp_path):
        assert file_substrate_coverage(
            "semgrep", target_path=tmp_path, file_path="a.php",
        ) is None

    def test_stamped_language_preferred_over_detection(self, tmp_path):
        # The inventory-stamped value wins even when the extension
        # disagrees (content-probed foreign-extension PHP).
        (tmp_path / "mod.c").write_text("<?php echo 1;\n")
        cov = file_substrate_coverage(
            "coccinelle", target_path=tmp_path, file_path="mod.c",
            language="php",
        )
        assert cov is not None
        assert cov.covered is False

    def test_detects_when_unstamped(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        cov = file_substrate_coverage(
            "coccinelle", target_path=tmp_path, file_path="a.py",
        )
        assert cov is not None
        assert cov.covered is False
