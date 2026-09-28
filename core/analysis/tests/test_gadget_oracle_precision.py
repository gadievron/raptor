"""Offline tests for the gadget-oracle precision harness.

Library mode is operator-run (network clones) and is deliberately
NOT exercised here — only its roster's well-formedness is checked.
Grammar-dependent tests skip with a named reason when tree-sitter-php
is not installed.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("RAPTOR_DIR", str(_REPO_ROOT))

import core.analysis.gadget_oracle as go  # noqa: E402
from core.analysis.gadget_oracle import (  # noqa: E402
    POP_SURFACE_METHODS,
    TIER_NO_CHAINS_FOUND,
    TIER_NO_GADGET_SURFACE,
    TIER_NONE,
    php_grammar_available,
)
from core.analysis.gadget_oracle_precision import (  # noqa: E402
    LIBRARY_ROSTER,
    REGEX_ALIAS_TARGETS,
    REGEX_POP_METHODS,
    CorpusReport,
    RowMeasurement,
    SyntheticCorpusDriver,
    _CANONICAL_POP,
    aggregate,
    cross_tab_rows,
    regex_surface_census,
    run_corpus,
    write_report,
)

if TYPE_CHECKING:
    pass

_GRAMMAR = pytest.mark.skipif(
    not php_grammar_available(),
    reason="tree-sitter-php not installed",
)


@pytest.fixture(autouse=True)
def _fresh_memo() -> None:
    go.reset_scan_memo()


# ---------------------------------------------------------------------------
# Regex ground-truth arm (hermetic — no grammar, no oracle)
# ---------------------------------------------------------------------------


class TestRegexSurfaceCensus:
    def test_counts_case_insensitively(self, tmp_path: Path) -> None:
        (tmp_path / "a.php").write_text(
            "<?php class A { function __DESTRUCT() {} }\n")
        (tmp_path / "b.php").write_text(
            "<?php class B { function __Wakeup() {} }\n")
        census = regex_surface_census(tmp_path)
        assert census["method_defs"] == 2
        assert census["total"] == 2

    def test_counts_files_regardless_of_extension(
            self, tmp_path: Path) -> None:
        (tmp_path / "module.inc").write_text(
            "<?php class M { function __destruct() {} }\n")
        (tmp_path / "tpl.phtml").write_text(
            "<?php class T { function __toString() { return ''; } }\n")
        (tmp_path / "noext").write_text(
            "<?php class N { function __invoke() {} }\n")
        census = regex_surface_census(tmp_path)
        assert census["method_defs"] == 3

    def test_counts_serializable_implements(
            self, tmp_path: Path) -> None:
        (tmp_path / "l.php").write_text(
            "<?php class L implements \\Serializable {\n"
            "  public function serialize() { return ''; }\n"
            "  public function unserialize($d) {}\n}\n")
        census = regex_surface_census(tmp_path)
        # The declared pair counts as pair_defs too — the arm
        # over-counts by design; what matters is total > 0.
        assert census["serializable_impls"] == 1
        assert census["pair_defs"] == 2
        assert census["total"] >= 1

    def test_counts_declared_pair_without_implements(
            self, tmp_path: Path) -> None:
        # The pair is surface however the Serializable binding is
        # spelled (alias / interface indirection / out-of-tree
        # interface) — the pair arm needs no implements clause.
        (tmp_path / "c.php").write_text(
            "<?php class C implements \\Vendor\\Store {\n"
            "  public function serialize() { return ''; }\n"
            "  public function UNSERIALIZE($d) {}\n}\n")
        census = regex_surface_census(tmp_path)
        assert census["serializable_impls"] == 0
        assert census["pair_defs"] == 2
        assert census["total"] == 2

    def test_pair_arm_ignores_near_names(self, tmp_path: Path) -> None:
        (tmp_path / "n.php").write_text(
            "<?php class N {\n"
            "  public function deserialize($d) {}\n"
            "  public function serializeAll($d) {}\n"
            "  public function myunserialize($d) {}\n}\n")
        census = regex_surface_census(tmp_path)
        assert census["pair_defs"] == 0
        assert census["total"] == 0

    def test_ignores_construct(self, tmp_path: Path) -> None:
        (tmp_path / "p.php").write_text(
            "<?php class P { function __construct($x) {} }\n")
        census = regex_surface_census(tmp_path)
        assert census["total"] == 0

    def test_skips_vcs_dirs(self, tmp_path: Path) -> None:
        gitdir = tmp_path / ".git"
        gitdir.mkdir()
        (gitdir / "blob.php").write_text(
            "<?php class G { function __destruct() {} }\n")
        (tmp_path / "clean.php").write_text(
            "<?php function ok() { return 1; }\n")
        census = regex_surface_census(tmp_path)
        assert census["total"] == 0

    def test_reference_return_and_whitespace(
            self, tmp_path: Path) -> None:
        (tmp_path / "r.php").write_text(
            "<?php class R { function &  __get($k) { return $x; } }\n")
        census = regex_surface_census(tmp_path)
        assert census["method_defs"] == 1

    def test_counts_trait_alias_adaptations(
            self, tmp_path: Path) -> None:
        (tmp_path / "t.php").write_text(
            "<?php trait H { function cleanup() {} }\n"
            "class E { use H { cleanup as __destruct; } }\n")
        (tmp_path / "v.php").write_text(
            "<?php trait H { function go() {} }\n"
            "class F { use H { go as protected __WAKEUP; } }\n")
        census = regex_surface_census(tmp_path)
        assert census["alias_defs"] == 2
        assert census["total"] >= 2

    def test_benign_alias_not_counted(self, tmp_path: Path) -> None:
        (tmp_path / "t.php").write_text(
            "<?php trait H { function a() {} }\n"
            "class E { use H { a as b; } }\n")
        census = regex_surface_census(tmp_path)
        assert census["alias_defs"] == 0
        assert census["total"] == 0

    def test_counts_autoload_registrations(
            self, tmp_path: Path) -> None:
        (tmp_path / "a.php").write_text(
            "<?php spl_autoload_register(function ($c) {\n"
            "    require $c . '.php';\n});\n")
        (tmp_path / "b.php").write_text(
            "<?php function __autoload($c) { include $c; }\n")
        (tmp_path / "c.php").write_text(
            "<?php ini_set('unserialize_callback_func', 'ldr');\n")
        census = regex_surface_census(tmp_path)
        assert census["autoload_regs"] == 3
        assert census["total"] == 3

    def test_autoload_arm_case_insensitive(
            self, tmp_path: Path) -> None:
        (tmp_path / "a.php").write_text(
            "<?php SPL_AUTOLOAD_REGISTER('ldr');\n")
        (tmp_path / "b.php").write_text(
            "<?php FUNCTION __AUTOLOAD($c) {}\n")
        census = regex_surface_census(tmp_path)
        assert census["autoload_regs"] == 2

    def test_autoload_arm_sees_the_bare_ini_option_name(
            self, tmp_path: Path) -> None:
        # Deliberate over-match: the option-name substring counts
        # wherever it appears (variable assignments included), so a
        # dynamic-key ini_set stays inside the arm's ground truth.
        (tmp_path / "d.php").write_text(
            "<?php\n$key = 'unserialize_callback_func';\n"
            "ini_set($key, 'ldr');\n")
        census = regex_surface_census(tmp_path)
        assert census["autoload_regs"] >= 1

    def test_autoload_arm_ignores_near_names(
            self, tmp_path: Path) -> None:
        (tmp_path / "n.php").write_text(
            "<?php\nfunction my__autoload($c) {}\n"
            "function autoload($c) {}\n"
            "my_spl_autoload_helper();\n"
            "unserialize($x);\n"
            "ini_set('memory_limit', '1G');\n")
        census = regex_surface_census(tmp_path)
        assert census["autoload_regs"] == 0
        assert census["total"] == 0

    def test_bare_autoload_token_counts_without_call_parens(
            self, tmp_path: Path) -> None:
        # The registration can ride a string literal, an import, or
        # an assignment — the bare token anywhere is surface.
        (tmp_path / "a.php").write_text(
            "<?php\n$r = 'spl_autoload_register';\n")
        (tmp_path / "b.php").write_text(
            "<?php\nuse function spl_autoload_register as reg;\n")
        census = regex_surface_census(tmp_path)
        assert census["autoload_regs"] == 2

    def test_bare_autoload_token_respects_word_boundaries(
            self, tmp_path: Path) -> None:
        (tmp_path / "n.php").write_text(
            "<?php\nmy_spl_autoload_register_helper();\n"
            "spl_autoload_register_wrapper();\n")
        census = regex_surface_census(tmp_path)
        assert census["autoload_regs"] == 0

    def test_callable_builtin_tokens_count(
            self, tmp_path: Path) -> None:
        (tmp_path / "c.php").write_text(
            "<?php\ncall_user_func('trim', ' x ');\n"
            "call_user_func_array('trim', [' x ']);\n"
            "CALL_USER_FUNC($cb);\n")
        census = regex_surface_census(tmp_path)
        assert census["callable_builtins"] == 3

    def test_callable_builtin_near_names_ignored(
            self, tmp_path: Path) -> None:
        (tmp_path / "n.php").write_text(
            "<?php\ncall_user_func_custom('trim');\n"
            "my_call_user_func('trim');\n")
        census = regex_surface_census(tmp_path)
        assert census["callable_builtins"] == 0
        assert census["total"] == 0

    def test_variable_invocation_counts(
            self, tmp_path: Path) -> None:
        (tmp_path / "v.php").write_text(
            "<?php\n$f = 'strlen';\n$f('abc');\n$g ('x');\n")
        census = regex_surface_census(tmp_path)
        assert census["var_invokes"] == 2

    def test_method_calls_are_not_variable_invocations(
            self, tmp_path: Path) -> None:
        (tmp_path / "m.php").write_text(
            "<?php\n$this->handle($x);\n$obj->fire($y);\n"
            "$arr['k']($z);\n")
        census = regex_surface_census(tmp_path)
        # The subscript-call shape $arr['k'](...) is a DECLARED
        # non-match: the paren does not adjoin the variable. The
        # oracle's own dynamic-callee demotion covers it (the callee
        # node is not a static name); this arm only claims the plain
        # $var(...) shape.
        assert census["var_invokes"] == 0
        assert census["total"] == 0

    def test_variable_without_adjacent_call_not_counted(
            self, tmp_path: Path) -> None:
        (tmp_path / "p.php").write_text(
            "<?php\n$x = 1;\nfoo($x);\nbar($x, $y);\n"
            "unserialize($_GET['x']);\n")
        census = regex_surface_census(tmp_path)
        assert census["var_invokes"] == 0
        assert census["total"] == 0


class TestRegexMethodListDrift:
    def test_regex_list_matches_oracle_census_set(self) -> None:
        # The lists are deliberately duplicated (independence of the
        # ground-truth arm); this pin turns silent drift into a
        # failing test.
        assert set(REGEX_POP_METHODS) == {
            m.lower() for m in POP_SURFACE_METHODS}
        assert len(REGEX_POP_METHODS) == len(POP_SURFACE_METHODS)

    def test_alias_target_list_matches_oracle_census_set(self) -> None:
        assert set(REGEX_ALIAS_TARGETS) == {
            m.lower() for m in go._SURFACE_CENSUS_NAMES}
        assert len(REGEX_ALIAS_TARGETS) == len(go._SURFACE_CENSUS_NAMES)

    def test_canonical_pop_list_matches_oracle_census_set(self) -> None:
        # The corpus generator emits canonical-case spellings; this pin
        # keeps their casefolded membership equal to the oracle census
        # set so the generated surface never drifts from the classifier.
        assert {m.lower() for m in _CANONICAL_POP} == POP_SURFACE_METHODS
        assert len(_CANONICAL_POP) == len(POP_SURFACE_METHODS)


# ---------------------------------------------------------------------------
# Aggregation / rule-of-three math (hermetic)
# ---------------------------------------------------------------------------


def _mk_measurement(**overrides: object) -> RowMeasurement:
    base: dict[str, object] = {
        "row": "r",
        "emitted_tier": TIER_NONE,
        "chains_found": 0,
        "chain_classes": (),
        "census_complete": True,
        "incomplete_reasons": (),
        "oracle_surface_total": 1,
        "regex_surface_total": 1,
        "ground_truth_surface": True,
        "flagged_miss": False,
        "false_absence": False,
        "expected_tier": None,
        "tier_match": None,
        "expect_chain": False,
        "chain_found_as_expected": None,
        "true_negative": False,
        "documented_chains": (),
        "entry_classes_found": (),
        "notes": "",
    }
    base.update(overrides)
    return RowMeasurement(**base)  # type: ignore[arg-type]


class TestAggregation:
    def test_rule_of_three_present_at_zero_misses(self) -> None:
        ms = [_mk_measurement(row=f"r{i}") for i in range(30)]
        rep = cross_tab_rows("t", "synthetic", ms)
        agg = aggregate([rep])
        assert agg["false_absence_count_total"] == 0
        assert agg["false_absence_denominator_total"] == 30
        assert agg["rule_of_three_95_upper_bound"] == pytest.approx(
            3.0 / 30)

    def test_rule_of_three_none_with_misses(self) -> None:
        ms = [_mk_measurement(row=f"r{i}") for i in range(9)]
        ms.append(_mk_measurement(
            row="miss",
            emitted_tier=TIER_NO_GADGET_SURFACE,
            false_absence=True,
        ))
        rep = cross_tab_rows("t", "synthetic", ms)
        agg = aggregate([rep])
        assert agg["false_absence_count_total"] == 1
        assert agg["rule_of_three_95_upper_bound"] is None
        assert agg["false_absence_rate"] == pytest.approx(0.1)

    def test_rule_of_three_none_with_empty_denominator(self) -> None:
        rep = cross_tab_rows("t", "synthetic", [])
        agg = aggregate([rep])
        assert agg["rule_of_three_95_upper_bound"] is None
        assert agg["false_absence_rate"] is None

    def test_tier_fire_rate_on_negatives(self) -> None:
        ms = [
            _mk_measurement(
                row="tn1", ground_truth_surface=False,
                oracle_surface_total=0, regex_surface_total=0,
                true_negative=True,
                emitted_tier=TIER_NO_GADGET_SURFACE),
            _mk_measurement(
                row="tn2", ground_truth_surface=False,
                oracle_surface_total=0, regex_surface_total=0,
                true_negative=True, emitted_tier=TIER_NONE),
        ]
        rep = cross_tab_rows("t", "synthetic", ms)
        assert rep.true_negative_rows == 2
        assert rep.tier_fired_on_negatives == 1
        assert rep.tier_fire_rate == pytest.approx(0.5)

    def test_chain_recall_counts_documented_rows(self) -> None:
        ms = [
            _mk_measurement(
                row="found", chains_found=1,
                documented_chains=("X/RCE1",)),
            _mk_measurement(
                row="missed", chains_found=0,
                documented_chains=("Y/RCE1",)),
        ]
        rep = cross_tab_rows("t", "library", ms)
        assert rep.documented_chain_rows == 2
        assert rep.chains_found_on_documented == 1
        assert rep.chain_recall == pytest.approx(0.5)

    def test_cross_tab_shape(self) -> None:
        ms = [
            _mk_measurement(row="s", emitted_tier=TIER_NO_CHAINS_FOUND),
            _mk_measurement(
                row="n", ground_truth_surface=False,
                oracle_surface_total=0, regex_surface_total=0,
                emitted_tier=TIER_NO_GADGET_SURFACE),
        ]
        rep = cross_tab_rows("t", "synthetic", ms)
        assert rep.cross_tab[TIER_NO_CHAINS_FOUND]["surface"] == 1
        assert rep.cross_tab[TIER_NO_GADGET_SURFACE]["no_surface"] == 1


class TestWriteReport:
    def test_writes_json_and_markdown(self, tmp_path: Path) -> None:
        ms = [_mk_measurement(row="only")]
        rep = cross_tab_rows("t", "synthetic", ms)
        json_path = write_report([rep], tmp_path / "run")
        assert json_path.is_file()
        md_path = json_path.parent / "report.md"
        assert md_path.is_file()
        payload = json.loads(json_path.read_text())
        assert payload["corpora"][0]["corpus"] == "t"
        assert "aggregate" in payload
        assert "false-absence rate" in md_path.read_text()


# ---------------------------------------------------------------------------
# Library roster well-formedness (hermetic; no network)
# ---------------------------------------------------------------------------


class TestLibraryRoster:
    def test_roster_meets_brief_minimums(self) -> None:
        chain_libs = [s for s in LIBRARY_ROSTER if s.chains]
        documented = [c for s in LIBRARY_ROSTER for c in s.chains]
        negatives = [s for s in LIBRARY_ROSTER if s.true_negative]
        assert len(chain_libs) >= 6
        assert len(documented) >= 8
        assert len(negatives) >= 2

    def test_pins_are_full_shas(self) -> None:
        for spec in LIBRARY_ROSTER:
            assert len(spec.commit) == 40, spec.row
            assert all(c in "0123456789abcdef"
                       for c in spec.commit), spec.row
            assert spec.tag, spec.row
            assert spec.repo.startswith("https://"), spec.row

    def test_row_names_unique(self) -> None:
        names = [s.row for s in LIBRARY_ROSTER]
        assert len(names) == len(set(names))

    def test_negatives_carry_no_chains(self) -> None:
        for spec in LIBRARY_ROSTER:
            if spec.true_negative:
                assert not spec.chains, spec.row


# ---------------------------------------------------------------------------
# Synthetic corpus end-to-end (grammar-gated)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def synthetic_report(
        tmp_path_factory: pytest.TempPathFactory) -> CorpusReport:
    go.reset_scan_memo()
    work = tmp_path_factory.mktemp("gadget-precision")
    return run_corpus(SyntheticCorpusDriver(), work)


@_GRAMMAR
class TestSyntheticCorpus:
    def test_exact_match_is_perfect(
            self, synthetic_report: CorpusReport) -> None:
        assert synthetic_report.mismatches == []
        assert synthetic_report.exact_match == 1.0

    def test_zero_false_absences_with_nonempty_denominator(
            self, synthetic_report: CorpusReport) -> None:
        assert synthetic_report.false_absence_denominator > 0
        assert synthetic_report.false_absence_count == 0
        assert synthetic_report.false_absence_rows == []

    def test_expected_findable_chains_all_found(
            self, synthetic_report: CorpusReport) -> None:
        assert synthetic_report.expected_findable_rows > 0
        assert (synthetic_report.expected_findable_found
                == synthetic_report.expected_findable_rows)

    def test_tier_fires_on_every_true_negative(
            self, synthetic_report: CorpusReport) -> None:
        assert synthetic_report.true_negative_rows >= 9
        assert (synthetic_report.tier_fired_on_negatives
                == synthetic_report.true_negative_rows)
        assert synthetic_report.tier_fire_rate == 1.0

    def test_regex_arm_flags_no_synthetic_misses_as_absent(
            self, synthetic_report: CorpusReport) -> None:
        # Flagged misses on synthetic rows are EXPECTED for census
        # degradations (.inc, symlink, oversized are invisible to the
        # oracle census too); what matters is none of them earned the
        # promotable tier.
        for m in synthetic_report.rows:
            if m.flagged_miss:
                assert m.emitted_tier != TIER_NO_GADGET_SURFACE, m.row

    def test_covers_every_pop_method(
            self, synthetic_report: CorpusReport) -> None:
        surface_rows = {m.row for m in synthetic_report.rows
                        if m.row.startswith("surface_")}
        assert len(surface_rows) == len(POP_SURFACE_METHODS)

    def test_adversarial_false_absence_rows_present(
            self, synthetic_report: CorpusReport) -> None:
        # Every live-fired false-absence repro is a MANDATORY corpus
        # row — the promotable tier's 0-false-absence claim is only
        # as strong as the shapes the corpus contains.
        names = {m.row for m in synthetic_report.rows}
        assert names >= {
            "trait_alias_destruct", "trait_alias_call",
            "uppercase_open_tag_inc", "short_open_tag_inc",
            "xml_decl_not_php", "xml_open_tag_smuggle",
            "unresolved_extends", "namespace_relative_extends",
            "use_alias_extends",
            "serializable_alias_implements",
            "serializable_interface_indirection",
            "serializable_out_of_tree_interface",
            "alias_cross_namespace_unbraced",
            "alias_cross_namespace_braced",
            "alias_cross_namespace_trait",
            "alias_before_declaration",
            "kelvin_casefold_extends",
            "dead_branch_class_decoy",
            "dead_branch_function_class_decoy",
            "dead_branch_trait_decoy",
            "extends_exception_only", "resolved_parent_in_tree",
            "node_modules_hidden", "git_hidden",
            "skipped_dir_without_php", "create_function_class",
            "preg_replace_eval_modifier",
            "autoload_spl_require", "autoload_legacy_function",
            "autoload_callback_ini", "autoload_callback_ini_alter",
            "autoload_ini_dynamic_key", "autoload_spl_benign",
            "unserialize_without_autoload", "ini_set_other_key",
            "varfunc_autoload_register",
            "call_user_func_autoload_register",
            "call_user_func_array_autoload_register",
            "parens_literal_autoload_register",
            "use_function_alias_autoload_register",
            "varfunc_iniset_callback",
            "concat_varfunc_autoload_register",
            "iniset_spread_args", "static_call_spellings",
            "arraymap_autoload_register",
            "cuf_arraymap_autoload_register",
            "arraywalk_autoload_register",
            "arrayfilter_autoload_register",
            "shutdown_autoload_register",
            "cuf_nested_arraymap_autoload_register",
            "iterator_apply_autoload_register",
            "arraymap_iniset_callback",
            "arraymap_literal_payload_autoload",
            "arrayfilter_literal_payload_autoload",
            "defparam_forward_autoload_register",
            "assigned_literal_forward_autoload_register",
            "returned_literal_forward_autoload_register",
            "defparam_array_static_forward_autoload_register",
            "splitconcat_forward_autoload_register",
            "anonclass_ctor_autoload_register",
            "attribute_literal_autoload_register",
            "heredoc_indented_whole_autoload_register",
            "heredoc_indented_splitconcat_autoload_register",
            "nowdoc_indented_splitconcat_autoload_register",
            "heredoc_cr_only_autoload_register",
            "binary_prefix_heredoc_autoload_register",
        }

    def test_adversarial_rows_never_earn_promotable_tier(
            self, synthetic_report: CorpusReport) -> None:
        by_name = {m.row: m for m in synthetic_report.rows}
        for name in ("trait_alias_destruct", "trait_alias_call",
                     "uppercase_open_tag_inc", "short_open_tag_inc",
                     "xml_open_tag_smuggle", "unresolved_extends",
                     "namespace_relative_extends", "use_alias_extends",
                     "serializable_alias_implements",
                     "serializable_interface_indirection",
                     "serializable_out_of_tree_interface",
                     "alias_cross_namespace_unbraced",
                     "alias_cross_namespace_braced",
                     "alias_cross_namespace_trait",
                     "alias_before_declaration",
                     "kelvin_casefold_extends",
                     "dead_branch_class_decoy",
                     "dead_branch_function_class_decoy",
                     "dead_branch_trait_decoy",
                     "node_modules_hidden",
                     "git_hidden", "create_function_class",
                     "preg_replace_eval_modifier",
                     "autoload_spl_require", "autoload_legacy_function",
                     "autoload_callback_ini",
                     "autoload_callback_ini_alter",
                     "autoload_ini_dynamic_key", "autoload_spl_benign",
                     "varfunc_autoload_register",
                     "call_user_func_autoload_register",
                     "call_user_func_array_autoload_register",
                     "parens_literal_autoload_register",
                     "use_function_alias_autoload_register",
                     "varfunc_iniset_callback",
                     "concat_varfunc_autoload_register",
                     "iniset_spread_args",
                     "arraymap_autoload_register",
                     "cuf_arraymap_autoload_register",
                     "arraywalk_autoload_register",
                     "arrayfilter_autoload_register",
                     "shutdown_autoload_register",
                     "cuf_nested_arraymap_autoload_register",
                     "iterator_apply_autoload_register",
                     "arraymap_iniset_callback",
                     "arraymap_literal_payload_autoload",
                     "arrayfilter_literal_payload_autoload",
                     "defparam_forward_autoload_register",
                     "assigned_literal_forward_autoload_register",
                     "returned_literal_forward_autoload_register",
                     "defparam_array_static_forward_autoload_register",
                     "splitconcat_forward_autoload_register",
                     "anonclass_ctor_autoload_register",
                     "attribute_literal_autoload_register",
                     "heredoc_indented_whole_autoload_register",
                     "heredoc_indented_splitconcat_autoload_register",
                     "nowdoc_indented_splitconcat_autoload_register",
                     "heredoc_cr_only_autoload_register",
                     "binary_prefix_heredoc_autoload_register"):
            assert (by_name[name].emitted_tier
                    != TIER_NO_GADGET_SURFACE), name
            assert by_name[name].false_absence is False, name

    def test_autoload_rows_visible_to_both_arms(
            self, synthetic_report: CorpusReport) -> None:
        # Like-with-like: registration counts as ground-truth surface
        # on BOTH arms, so an autoload row that regressed to the
        # promotable tier would surface as a false absence — not
        # slip out of the denominator.
        by_name = {m.row: m for m in synthetic_report.rows}
        for name in ("autoload_spl_require", "autoload_legacy_function",
                     "autoload_callback_ini",
                     "autoload_callback_ini_alter",
                     "autoload_ini_dynamic_key", "autoload_spl_benign",
                     "varfunc_autoload_register",
                     "call_user_func_autoload_register",
                     "call_user_func_array_autoload_register",
                     "parens_literal_autoload_register",
                     "use_function_alias_autoload_register",
                     "varfunc_iniset_callback",
                     "concat_varfunc_autoload_register",
                     "iniset_spread_args",
                     "arraymap_autoload_register",
                     "cuf_arraymap_autoload_register",
                     "arraywalk_autoload_register",
                     "arrayfilter_autoload_register",
                     "shutdown_autoload_register",
                     "cuf_nested_arraymap_autoload_register",
                     "iterator_apply_autoload_register",
                     "arraymap_iniset_callback",
                     "arraymap_literal_payload_autoload",
                     "arrayfilter_literal_payload_autoload",
                     "defparam_forward_autoload_register",
                     "assigned_literal_forward_autoload_register",
                     "returned_literal_forward_autoload_register",
                     "defparam_array_static_forward_autoload_register",
                     "anonclass_ctor_autoload_register",
                     "attribute_literal_autoload_register",
                     "heredoc_indented_whole_autoload_register",
                     "heredoc_cr_only_autoload_register"):
            m = by_name[name]
            assert m.oracle_surface_total > 0, name
            assert m.regex_surface_total > 0, name
            assert m.ground_truth_surface is True, name

    def test_splitconcat_row_is_regex_blind_but_marked(
            self, synthetic_report: CorpusReport) -> None:
        # The split-spelling rows are the forwarded-literal shapes the
        # regex arm CANNOT corroborate: its intact-token pattern never
        # matches 'spl_autoload' . '_register', nor the concat where
        # the right operand is an indented heredoc/nowdoc fragment.
        # Ground truth for these rows rides the explicit row marking.
        # Pin all the facts so a future regex change that starts (or
        # stops) seeing a split spelling shows up here, and so no row
        # can migrate into the both-arms list without a deliberate
        # edit.
        by_name = {m.row: m for m in synthetic_report.rows}
        for name in ("splitconcat_forward_autoload_register",
                     "heredoc_indented_splitconcat_autoload_register",
                     "nowdoc_indented_splitconcat_autoload_register"):
            m = by_name[name]
            assert m.regex_surface_total == 0, name
            assert m.ground_truth_surface is True, name
            assert m.oracle_surface_total > 0, name
            assert m.emitted_tier == TIER_NO_CHAINS_FOUND, name
            assert m.false_absence is False, name

    def test_autoload_negative_controls_still_earn(
            self, synthetic_report: CorpusReport) -> None:
        by_name = {m.row: m for m in synthetic_report.rows}
        for name in ("unserialize_without_autoload",
                     "ini_set_other_key", "static_call_spellings"):
            m = by_name[name]
            assert m.emitted_tier == TIER_NO_GADGET_SURFACE, name
            assert m.true_negative is True, name
            # The regex arm must also see nothing: an earning control
            # the arm flags would read as a false absence and poison
            # the denominator.
            assert m.regex_surface_total == 0, name
