"""Tests for the mechanical rule-verification runner.

The join/scoring core is exercised hermetically with stub engine
outcomes — no engine binary, no network, no LLM.  Engine-backed
integration tests are gated on the tool being installed and skip
cleanly otherwise.
"""

from __future__ import annotations

import shutil
from types import SimpleNamespace

import pytest

from core.audit.corpus.rule_eval import (
    BUG_CLASS_CWES,
    EngineOutcome,
    RuleHit,
    RuleInfo,
    _normalise_cwe,
    discover_cocci_rules,
    discover_codeql_rules,
    discover_semgrep_rules,
    evaluate,
    format_summary,
    hit_joins_label,
    rule_targets_label,
    run_cocci_engine,
    run_semgrep_engine,
)

HAVE_SEMGREP = shutil.which("semgrep") is not None
HAVE_SPATCH = shutil.which("spatch") is not None

needs_semgrep = pytest.mark.skipif(
    not HAVE_SEMGREP, reason="semgrep not installed",
)
needs_spatch = pytest.mark.skipif(
    not HAVE_SPATCH, reason="spatch not installed",
)


def _label(
    fid="net/a.c:f",
    file="net/a.c",
    bug_class="lifecycle",
    expected="finding",
    cwe="CWE-416",
    repo="test-repo",
    line_start=100,
    line_end=150,
):
    return SimpleNamespace(
        function_id=fid,
        bug_class=bug_class,
        expected_status=expected,
        cwe=cwe,
        expected_mechanism="",
        source=SimpleNamespace(
            repo=repo, sha="abc", file=file,
            line_start=line_start, line_end=line_end,
        ),
    )


def _rule(engine="coccinelle", rule_id="use_after_free",
          cwes=("CWE-416",), languages=("c", "cpp")):
    return RuleInfo(
        engine=engine, rule_id=rule_id, path=f"{rule_id}.x",
        cwes=frozenset(cwes), languages=frozenset(languages),
    )


def _hit(engine="coccinelle", rule_id="use_after_free",
         file="net/a.c", line=120, line_end=0):
    return RuleHit(engine=engine, rule_id=rule_id, file=file,
                   line=line, line_end=line_end)


def _outcomes(hits, engine="coccinelle", repo="test-repo"):
    return {repo: {engine: EngineOutcome(engine=engine, hits=list(hits))}}


class TestBugClassCweSeeds:
    def test_assembled_corpus_classes_covered(self):
        assert BUG_CLASS_CWES["fail_open"] == frozenset(
            {"CWE-636", "CWE-703"},
        )
        assert {"CWE-125", "CWE-787"} <= BUG_CLASS_CWES["variant"]
        assert {"CWE-362", "CWE-366", "CWE-367"} <= (
            BUG_CLASS_CWES["concurrency"]
        )

    def test_every_finding_label_is_targetable(self):
        """Tripwire over the committed labels: every ``finding`` label
        must be reachable by CWE targeting — an explicit ``cwe``, an
        ``expected_rule_hits`` pin, or a class entry in the seed map.
        A finding label failing all three can never score anything
        but a coverage gap, silently."""
        from core.audit.corpus.label import load_all_labels

        untargetable = [
            lb.function_id
            for lb in load_all_labels()
            if lb.expected_status == "finding"
            and not getattr(lb, "cwe", "")
            and not getattr(lb, "expected_rule_hits", None)
            and lb.bug_class not in BUG_CLASS_CWES
        ]
        assert untargetable == []


class TestNormaliseCwe:
    def test_plain(self):
        assert _normalise_cwe("CWE-89") == "CWE-89"

    def test_lower_and_padded(self):
        assert _normalise_cwe("cwe-089") == "CWE-89"

    def test_embedded(self):
        assert _normalise_cwe("external/cwe/cwe-457") == "CWE-457"

    def test_absent(self):
        assert _normalise_cwe("no cwe here") == ""


class TestHitJoinsLabel:
    def test_inside_range(self):
        assert hit_joins_label(_hit(line=120), _label())

    def test_wrong_file(self):
        assert not hit_joins_label(_hit(file="net/b.c"), _label())

    def test_slop_boundary(self):
        # range 100-150, slop 2: 98 joins, 97 does not
        assert hit_joins_label(_hit(line=98), _label(), slop=2)
        assert not hit_joins_label(_hit(line=97), _label(), slop=2)
        assert hit_joins_label(_hit(line=152), _label(), slop=2)
        assert not hit_joins_label(_hit(line=153), _label(), slop=2)

    def test_span_overlap(self):
        # hit span 90-105 overlaps range start
        assert hit_joins_label(
            _hit(line=90, line_end=105), _label(), slop=0,
        )


class TestRuleTargetsLabel:
    def test_cwe_match(self):
        assert rule_targets_label(_rule(), _label())

    def test_cwe_mismatch(self):
        assert not rule_targets_label(
            _rule(cwes=("CWE-89",)), _label(),
        )

    def test_language_incompatible(self):
        go_rule = _rule(engine="semgrep", rule_id="r",
                        languages=("go",))
        assert not rule_targets_label(go_rule, _label())

    def test_wildcard_language(self):
        generic = _rule(engine="semgrep", rule_id="r",
                        languages=("generic",))
        assert rule_targets_label(generic, _label())

    def test_class_family_fallback_when_no_label_cwe(self):
        label = _label(cwe="", bug_class="lifecycle")
        assert "CWE-416" in BUG_CLASS_CWES["lifecycle"]
        assert rule_targets_label(_rule(), label)

    def test_no_rule_cwes_never_targets(self):
        assert not rule_targets_label(_rule(cwes=()), _label())

    def test_expected_rule_hits_pin_wins(self):
        label = _label(cwe="")
        label.expected_rule_hits = {"coccinelle": ["use_after_free"]}
        assert rule_targets_label(_rule(), label)
        # A pinned engine restricts to the listed rules only.
        other = _rule(rule_id="double_free", cwes=("CWE-416",))
        assert not rule_targets_label(other, label)

    def test_expected_rule_hits_other_engine_falls_back(self):
        label = _label()  # cwe CWE-416
        label.expected_rule_hits = {"semgrep": ["some.rule"]}
        # coccinelle not pinned -> CWE fallback still applies
        assert rule_targets_label(_rule(), label)


class TestEvaluate:
    def test_true_positive(self):
        labels = [_label()]
        report = evaluate(
            labels, _outcomes([_hit()]), [_rule()],
        )
        (row,) = report["per_rule"]
        assert row["tp"] == ["net/a.c:f"]
        assert not row["fp"] and not row["misses"]
        assert report["labels"][0]["detected_by"] == [
            "coccinelle:use_after_free",
        ]
        assert report["coverage_gaps"] == []
        cls = report["per_class"]["lifecycle"]
        assert cls["finding_detected"] == 1

    def test_false_positive_on_clean(self):
        labels = [_label(expected="clean")]
        report = evaluate(
            labels, _outcomes([_hit()]), [_rule()],
        )
        (row,) = report["per_rule"]
        assert row["fp"] == ["net/a.c:f"]
        assert report["per_class"]["lifecycle"]["clean_false_alarmed"] == 1

    def test_fp_regardless_of_targeting(self):
        # A false alarm is a false alarm even from a non-targeting rule.
        labels = [_label(expected="clean", cwe="CWE-287")]
        report = evaluate(
            labels, _outcomes([_hit()]), [_rule()],
        )
        (row,) = report["per_rule"]
        assert row["fp"] == ["net/a.c:f"]

    def test_miss(self):
        labels = [_label()]
        report = evaluate(
            labels, _outcomes([]), [_rule()],
        )
        (row,) = report["per_rule"]
        assert row["misses"] == ["net/a.c:f"]

    def test_untargeted_hit(self):
        labels = [_label(cwe="CWE-457", bug_class="uninitialised")]
        report = evaluate(
            labels, _outcomes([_hit()]), [_rule()],
        )
        (row,) = report["per_rule"]
        assert row["untargeted_hits"] == ["net/a.c:f"]
        assert not row["tp"]
        cls = report["per_class"]["uninitialised"]
        assert cls["finding_untargeted_hit"] == 1
        assert cls["finding_detected"] == 0

    def test_dormant_hit_is_not_fp(self):
        labels = [_label(expected="dormant")]
        report = evaluate(
            labels, _outcomes([_hit()]), [_rule()],
        )
        (row,) = report["per_rule"]
        assert row["dormant_hits"] == ["net/a.c:f"]
        assert not row["fp"]

    def test_unexposed_label_is_not_a_miss(self):
        # Engine skipped for this repo -> no miss recorded.
        labels = [_label()]
        outcomes = {"test-repo": {"coccinelle": EngineOutcome(
            engine="coccinelle", skipped_reason="spatch not installed",
        )}}
        report = evaluate(labels, outcomes, [_rule()])
        assert report["per_rule"] == []
        assert report["labels"][0]["engines_exposed"] == []

    def test_coverage_gap(self):
        labels = [_label(cwe="CWE-457", bug_class="uninitialised")]
        report = evaluate(labels, _outcomes([]), [_rule()])
        (gap,) = report["coverage_gaps"]
        assert gap["function_id"] == "net/a.c:f"
        assert gap["cwe"] == "CWE-457"
        cls = report["per_class"]["uninitialised"]
        assert cls["finding_uncovered"] == 1

    def test_slop_respected(self):
        labels = [_label()]
        report = evaluate(
            labels, _outcomes([_hit(line=95)]), [_rule()], slop=0,
        )
        (row,) = report["per_rule"]
        assert row["misses"] == ["net/a.c:f"]
        report = evaluate(
            labels, _outcomes([_hit(line=95)]), [_rule()], slop=5,
        )
        (row,) = report["per_rule"]
        assert row["tp"] == ["net/a.c:f"]

    def test_inactive_rules_omitted_from_per_rule(self):
        clean_go = _rule(engine="semgrep", rule_id="go.only",
                         cwes=("CWE-89",), languages=("go",))
        report = evaluate([_label()], _outcomes([]), [_rule(), clean_go])
        assert [r["rule_id"] for r in report["per_rule"]] == [
            "use_after_free",
        ]

    def test_summary_formats(self):
        labels = [
            _label(),
            _label(fid="net/b.c:g", file="net/b.c", expected="clean"),
        ]
        report = evaluate(labels, _outcomes([_hit()]), [_rule()])
        report["meta"] = {
            "engines": ["coccinelle"],
            "rules_discovered": 1,
            "labels_evaluated": 2,
            "labels_skipped": 1,
            "engine_notes": ["test-repo/coccinelle: 1 hit(s) in 0s"],
            "engine_errors": [],
        }
        report["skipped"] = [
            {"function_id": "x.c:h", "reason": "source dir missing"},
        ]
        text = format_summary(report)
        assert "coccinelle:use_after_free" in text
        assert "Skipped labels (1 — not failures)" in text
        assert "No rule-coverage gaps" in text


class TestStripSemgrepPrefix:
    def test_strips_dotted_config_path(self, tmp_path):
        from core.audit.corpus.rule_eval import _strip_semgrep_prefix

        prefixed = (
            str(tmp_path.resolve()).lstrip("/").replace("/", ".")
            + ".raptor.test.rule"
        )
        assert _strip_semgrep_prefix(prefixed, tmp_path) == (
            "raptor.test.rule"
        )

    def test_bare_id_untouched(self, tmp_path):
        from core.audit.corpus.rule_eval import _strip_semgrep_prefix

        assert _strip_semgrep_prefix(
            "raptor.test.rule", tmp_path,
        ) == "raptor.test.rule"


class TestDiscovery:
    def test_semgrep_rules_parse_metadata(self, tmp_path):
        rules_dir = tmp_path / "cat"
        rules_dir.mkdir()
        (rules_dir / "r.yaml").write_text(
            "rules:\n"
            "  - id: raptor.test.rule\n"
            "    languages: [go, py]\n"
            "    message: m\n"
            "    severity: ERROR\n"
            "    pattern: foo(...)\n"
            "    metadata:\n"
            "      cwe: [\"CWE-089\"]\n"
        )
        rules, errors = discover_semgrep_rules([rules_dir])
        assert errors == []
        (rule,) = rules
        assert rule.rule_id == "raptor.test.rule"
        assert rule.cwes == frozenset({"CWE-89"})
        assert rule.languages == frozenset({"go", "python"})

    def test_semgrep_malformed_yaml_is_error_not_crash(self, tmp_path):
        rules_dir = tmp_path / "cat"
        rules_dir.mkdir()
        (rules_dir / "bad.yaml").write_text("rules: [::not yaml")
        rules, errors = discover_semgrep_rules([rules_dir])
        assert rules == []
        assert len(errors) == 1

    def test_cocci_rules_header_cwe(self, tmp_path):
        (tmp_path / "my_rule.cocci").write_text(
            "// my_rule.cocci — classic CWE-415: double-free\n"
            "// @role: verification\n"
            "@r@\nexpression E;\n@@\n* kfree(E)\n"
        )
        (rule,) = discover_cocci_rules(tmp_path)
        assert rule.rule_id == "my_rule"
        assert rule.cwes == frozenset({"CWE-415"})
        assert rule.languages == frozenset({"c", "cpp"})

    def test_cocci_body_cwe_mentions_ignored(self, tmp_path):
        (tmp_path / "r.cocci").write_text(
            "// header without a cwe\n"
            "@r@\nexpression E;\n@@\n"
            "// CWE-999 buried after SmPL starts\n* kfree(E)\n"
        )
        (rule,) = discover_cocci_rules(tmp_path)
        assert rule.cwes == frozenset()

    def test_shipped_semgrep_inventory_nonempty(self):
        from core.config import RaptorConfig

        if not RaptorConfig.SEMGREP_RULES_DIR.is_dir():
            pytest.skip("shipped semgrep rules dir absent")
        rules, _errors = discover_semgrep_rules()
        assert rules
        assert all(r.engine == "semgrep" for r in rules)

    def test_shipped_cocci_inventory_nonempty(self):
        rules = discover_cocci_rules()
        if not rules:
            pytest.skip("shipped coccinelle rules dir absent")
        assert all(r.engine == "coccinelle" for r in rules)

    def test_shipped_codeql_inventory(self):
        rules = discover_codeql_rules()
        if not rules:
            pytest.skip("shipped codeql queries dir absent")
        assert all(r.engine == "codeql" for r in rules)
        assert any(r.cwes for r in rules)


class TestEngineAbsentSkips:
    def test_semgrep_absent(self, tmp_path, monkeypatch):
        from packages.semgrep import runner as semgrep_runner

        monkeypatch.setattr(semgrep_runner, "is_available", lambda: False)
        outcome = run_semgrep_engine(tmp_path)
        assert not outcome.available
        assert "not installed" in outcome.skipped_reason
        assert not outcome.ran

    def test_spatch_absent(self, tmp_path, monkeypatch):
        from packages.coccinelle import runner as cocci_runner

        monkeypatch.setattr(cocci_runner, "is_available", lambda: False)
        outcome = run_cocci_engine(tmp_path)
        assert not outcome.available
        assert "not installed" in outcome.skipped_reason

    def test_cocci_skips_non_c_tree(self, tmp_path, monkeypatch):
        from packages.coccinelle import runner as cocci_runner

        monkeypatch.setattr(cocci_runner, "is_available", lambda: True)
        (tmp_path / "a.py").write_text("x = 1\n")
        outcome = run_cocci_engine(tmp_path, rules_dir=tmp_path)
        # rules_dir has no .cocci but the C gate fires first
        assert outcome.skipped_reason == (
            "no C/C++ sources among pinned files"
        )

    def test_codeql_absent(self, tmp_path, monkeypatch):
        import core.audit.corpus.rule_eval as rule_eval

        monkeypatch.setattr(
            rule_eval.shutil, "which", lambda name: None,
        )
        outcome = rule_eval.run_codeql_engine(
            tmp_path, [_label()], tmp_path / "out",
        )
        assert not outcome.available
        assert "codeql CLI not on PATH" in outcome.skipped_reason


def _engine_rules_base(tmp_path, *, semgrep=True, cocci=True,
                       rule_id="raptor-synth-uaf"):
    """Build a graduated engine-rules base the way graduate() lays
    it out: <base>/semgrep/rules/*.yaml + <base>/coccinelle/*.cocci."""
    base = tmp_path / "engine-rules"
    if semgrep:
        sg = base / "semgrep" / "rules"
        sg.mkdir(parents=True)
        (sg / f"{rule_id}.yaml").write_text(
            "rules:\n"
            f"  - id: {rule_id}\n"
            "    languages: [c]\n"
            "    message: m\n"
            "    severity: ERROR\n"
            "    pattern: kfree(...)\n"
            "    metadata:\n"
            "      cwe: [\"CWE-416\"]\n"
        )
    if cocci:
        cc = base / "coccinelle"
        cc.mkdir(parents=True, exist_ok=True)
        (cc / "synth_double_put.cocci").write_text(
            "// synth_double_put.cocci — CWE-416\n"
            "@r@\nexpression E;\n@@\n* put(E)\n"
        )
    return base


class TestGraduatedDiscovery:
    def test_retags_provenance_both_engines(self, tmp_path):
        from core.audit.corpus.rule_eval import discover_graduated_rules

        base = _engine_rules_base(tmp_path)
        rules, errors = discover_graduated_rules(
            ["semgrep", "coccinelle"], base,
        )
        assert errors == []
        assert {(r.engine, r.rule_id, r.provenance) for r in rules} == {
            ("semgrep", "raptor-synth-uaf", "graduated"),
            ("coccinelle", "synth_double_put", "graduated"),
        }
        # Same parsers as the shipped inventories: metadata survives.
        assert all(r.cwes == frozenset({"CWE-416"}) for r in rules)

    def test_none_base_is_empty(self):
        from core.audit.corpus.rule_eval import discover_graduated_rules

        assert discover_graduated_rules(["semgrep"], None) == ([], [])

    def test_engine_filter_respected(self, tmp_path):
        from core.audit.corpus.rule_eval import discover_graduated_rules

        base = _engine_rules_base(tmp_path)
        rules, _ = discover_graduated_rules(["coccinelle"], base)
        assert [r.engine for r in rules] == ["coccinelle"]

    def test_merge_drops_key_collisions_loudly(self):
        from core.audit.corpus.rule_eval import merge_inventories

        shipped = [_rule(rule_id="use_after_free")]
        graduated = [
            RuleInfo(engine="coccinelle", rule_id="use_after_free",
                     path="x", provenance="graduated"),
            RuleInfo(engine="coccinelle", rule_id="synth_new",
                     path="y", provenance="graduated"),
        ]
        merged, errors = merge_inventories(shipped, graduated)
        assert [r.rule_id for r in merged] == [
            "use_after_free", "synth_new",
        ]
        assert merged[0].provenance == "shipped"
        (err,) = errors
        assert "collides" in err and "use_after_free" in err


class TestFindEngineRulesBase:
    def test_out_dir_sibling_found(self, tmp_path):
        from core.audit.corpus.rule_eval import find_engine_rules_base

        _engine_rules_base(tmp_path)
        out_dir = tmp_path / "rule-eval-1"
        assert find_engine_rules_base(out_dir) == (
            tmp_path / "engine-rules"
        )

    def test_inside_fixture_tree_rejected(self, tmp_path):
        from core.audit.corpus.rule_eval import find_engine_rules_base

        _engine_rules_base(tmp_path)
        # The whole tmp tree is a fixture root: the candidate resolves
        # inside it and must not load.
        assert find_engine_rules_base(
            tmp_path / "rule-eval-1", fixture_roots=[tmp_path],
        ) is None

    def test_no_candidates(self, tmp_path):
        from core.audit.corpus.rule_eval import find_engine_rules_base

        assert find_engine_rules_base(tmp_path / "out") is None


class TestProvenanceScoring:
    def test_per_rule_rows_carry_provenance(self):
        graduated = RuleInfo(
            engine="coccinelle", rule_id="synth_uaf", path="x",
            cwes=frozenset({"CWE-416"}),
            languages=frozenset({"c", "cpp"}),
            provenance="graduated",
        )
        report = evaluate(
            [_label()],
            _outcomes([_hit(), _hit(rule_id="synth_uaf")]),
            [_rule(), graduated],
        )
        by_id = {r["rule_id"]: r["provenance"] for r in report["per_rule"]}
        assert by_id == {
            "use_after_free": "shipped", "synth_uaf": "graduated",
        }

    def test_summary_separates_populations(self):
        graduated = RuleInfo(
            engine="coccinelle", rule_id="synth_uaf", path="x",
            cwes=frozenset({"CWE-416"}),
            languages=frozenset({"c", "cpp"}),
            provenance="graduated",
        )
        report = evaluate(
            [_label()],
            _outcomes([_hit(), _hit(rule_id="synth_uaf")]),
            [_rule(), graduated],
        )
        report["meta"] = {
            "engines": ["coccinelle"], "rules_discovered": 2,
            "rules_shipped": 1, "rules_graduated": 1,
            "labels_evaluated": 1, "labels_skipped": 0,
            "engine_notes": [], "engine_errors": [],
        }
        report["skipped"] = []
        text = format_summary(report)
        assert "Rules discovered: 2 (1 shipped + 1 graduated)" in text
        shipped_at = text.find("Shipped rules with corpus interaction:")
        grad_at = text.find("Graduated rules with corpus interaction:")
        assert -1 < shipped_at < grad_at
        assert "coccinelle:synth_uaf" in text[grad_at:]

    def test_merge_engine_outcomes(self):
        from core.audit.corpus.rule_eval import merge_engine_outcomes

        a = EngineOutcome(engine="coccinelle", hits=[_hit()],
                          invocations=2, elapsed_s=1.0,
                          rule_timings={"a": 1.0})
        b = EngineOutcome(engine="coccinelle",
                          hits=[_hit(rule_id="synth_uaf")],
                          invocations=1, elapsed_s=0.5,
                          rule_timings={"b": 0.5},
                          errors=["synth_x: rc=255"])
        merged = merge_engine_outcomes(a, b)
        assert len(merged.hits) == 2
        assert merged.invocations == 3
        assert merged.rule_timings == {"a": 1.0, "b": 0.5}
        assert merged.errors == ["synth_x: rc=255"]

    def test_merge_skipped_half_contributes_nothing(self):
        from core.audit.corpus.rule_eval import merge_engine_outcomes

        ran = EngineOutcome(engine="coccinelle", hits=[_hit()])
        skipped = EngineOutcome(
            engine="coccinelle", skipped_reason="no C/C++ sources",
        )
        assert merge_engine_outcomes(ran, skipped) is ran
        assert merge_engine_outcomes(skipped, ran) is ran
        neither = merge_engine_outcomes(
            EngineOutcome(engine="coccinelle", skipped_reason="x"),
            EngineOutcome(engine="coccinelle", skipped_reason="y"),
        )
        assert neither.skipped_reason == "x"


class TestProvenanceCli:
    def _run_main(self, tmp_path, monkeypatch, argv):
        import core.audit.corpus.label as label_mod
        import core.audit.corpus.rule_eval as rule_eval
        import core.audit.corpus.run_corpus as run_corpus

        label = _label()
        src = tmp_path / "repo"
        src.mkdir(exist_ok=True)
        monkeypatch.setattr(
            label_mod, "load_all_labels",
            lambda bug_class=None: [label],
        )
        monkeypatch.setattr(
            run_corpus, "_resolve_source_dirs",
            lambda labels, do_fetch=False: {"test-repo": src},
        )
        monkeypatch.setattr(
            run_corpus, "_label_source_status",
            lambda lb, dirs: ("ok", ""),
        )
        monkeypatch.setattr(
            run_corpus, "_build_excerpt_tree",
            lambda labels, dirs: {"test-repo": src},
        )
        calls = []

        def fake_cocci(excerpt, **kw):
            calls.append(kw)
            return EngineOutcome(
                engine="coccinelle", skipped_reason="stub",
            )

        monkeypatch.setattr(rule_eval, "run_cocci_engine", fake_cocci)
        rc = rule_eval.main(argv)
        return rc, calls

    def test_graduated_only_runs_graduated_dir(
        self, tmp_path, monkeypatch,
    ):
        import json

        base = _engine_rules_base(tmp_path, semgrep=False)
        out = tmp_path / "out"
        rc, calls = self._run_main(tmp_path, monkeypatch, [
            "--engine", "coccinelle", "--provenance", "graduated",
            "--engine-rules-dir", str(base), "--out", str(out),
        ])
        assert rc == 0
        (call,) = calls
        assert call["rules_dir"] == base / "coccinelle"
        data = json.loads((out / "rule-eval-results.json").read_text())
        assert data["meta"]["provenance"] == "graduated"
        assert data["meta"]["rules_shipped"] == 0
        assert data["meta"]["rules_graduated"] == 1
        assert data["meta"]["engine_rules_dir"] == str(base)

    def test_all_runs_both_dirs(self, tmp_path, monkeypatch):
        base = _engine_rules_base(tmp_path, semgrep=False)
        rc, calls = self._run_main(tmp_path, monkeypatch, [
            "--engine", "coccinelle",
            "--engine-rules-dir", str(base),
            "--out", str(tmp_path / "out"),
        ])
        assert rc == 0
        assert len(calls) == 2
        assert calls[0].get("rules_dir") is None  # shipped pass
        assert calls[1]["rules_dir"] == base / "coccinelle"

    def test_shipped_skips_graduated_discovery(
        self, tmp_path, monkeypatch,
    ):
        import json

        base = _engine_rules_base(tmp_path, semgrep=False)
        out = tmp_path / "out"
        rc, calls = self._run_main(tmp_path, monkeypatch, [
            "--engine", "coccinelle", "--provenance", "shipped",
            "--engine-rules-dir", str(base), "--out", str(out),
        ])
        assert rc == 0
        (call,) = calls
        assert call.get("rules_dir") is None
        data = json.loads((out / "rule-eval-results.json").read_text())
        assert data["meta"]["rules_graduated"] == 0
        assert "engine_rules_dir" not in data["meta"]

    def test_graduated_without_dir_fails_loudly(
        self, tmp_path, monkeypatch, capsys,
    ):
        import core.audit.corpus.rule_eval as rule_eval

        # Hermetic: the candidate walk may find a real active
        # project's engine-rules on a dev machine.
        monkeypatch.setattr(
            rule_eval, "find_engine_rules_base",
            lambda out_dir, fixture_roots=(): None,
        )
        rc, _calls = self._run_main(tmp_path, monkeypatch, [
            "--engine", "coccinelle", "--provenance", "graduated",
            "--out", str(tmp_path / "out"),
        ])
        assert rc == 1
        assert "No graduated engine-rules dir" in capsys.readouterr().err


class TestRuleTimings:
    """Per-rule wall time lands in EngineOutcome.rule_timings and the
    spatch timeout is boundable per rule (--spatch-timeout) — two
    kernel rules hit the fixed 300s bound on a live run with no way
    to tighten it and no per-rule visibility of the spend."""

    def _cocci_run(self, tmp_path, monkeypatch, results, **engine_kw):
        from packages.coccinelle import runner as cocci_runner

        seen = {}

        def fake_run_rules(target, rules_dir, **kw):
            seen.update(kw)
            return results

        monkeypatch.setattr(cocci_runner, "is_available", lambda: True)
        monkeypatch.setattr(cocci_runner, "run_rules", fake_run_rules)
        (tmp_path / "a.c").write_text("int f(void) { return 0; }\n")
        outcome = run_cocci_engine(
            tmp_path, rules_dir=tmp_path, **engine_kw,
        )
        return outcome, seen

    def test_cocci_per_rule_timings_recorded(self, tmp_path, monkeypatch):
        from packages.coccinelle.models import SpatchResult

        outcome, _ = self._cocci_run(tmp_path, monkeypatch, [
            SpatchResult(rule="use_after_free", elapsed_ms=1500),
            SpatchResult(rule="double_free", elapsed_ms=250),
        ])
        assert outcome.rule_timings == {
            "use_after_free": 1.5, "double_free": 0.25,
        }

    def test_cocci_timeout_threaded(self, tmp_path, monkeypatch):
        _, seen = self._cocci_run(
            tmp_path, monkeypatch, [], timeout_per_rule=42,
        )
        assert seen["timeout_per_rule"] == 42

    def test_cocci_timeout_default_matches_production(
        self, tmp_path, monkeypatch,
    ):
        import inspect

        from core.audit.corpus.rule_eval import DEFAULT_SPATCH_TIMEOUT
        from packages.coccinelle import runner as cocci_runner

        # Read the production default before _cocci_run patches
        # run_rules away.
        prod_default = inspect.signature(
            cocci_runner.run_rules,
        ).parameters["timeout_per_rule"].default
        assert DEFAULT_SPATCH_TIMEOUT == prod_default
        _, seen = self._cocci_run(tmp_path, monkeypatch, [])
        assert seen["timeout_per_rule"] == DEFAULT_SPATCH_TIMEOUT

    def test_semgrep_per_category_timings_recorded(
        self, tmp_path, monkeypatch,
    ):
        from packages.semgrep import runner as semgrep_runner

        stub = SimpleNamespace(
            ok=True, errors=[], findings=[], returncode=0,
            elapsed_ms=2000,
        )
        monkeypatch.setattr(semgrep_runner, "is_available", lambda: True)
        monkeypatch.setattr(
            semgrep_runner, "run_rule", lambda *a, **kw: stub,
        )
        cat = tmp_path / "memory"
        cat.mkdir()
        outcome = run_semgrep_engine(tmp_path, config_dirs=[cat])
        assert outcome.rule_timings == {"category_memory": 2.0}

    def test_cli_threads_spatch_timeout(self, tmp_path, monkeypatch):
        import core.audit.corpus.label as label_mod
        import core.audit.corpus.rule_eval as rule_eval
        import core.audit.corpus.run_corpus as run_corpus

        # Hermetic: keep a dev machine's active project out of the
        # graduated-rules candidate walk.
        monkeypatch.setattr(
            rule_eval, "find_engine_rules_base",
            lambda out_dir, fixture_roots=(): None,
        )
        label = _label()
        src = tmp_path / "repo"
        src.mkdir()
        monkeypatch.setattr(
            label_mod, "load_all_labels",
            lambda bug_class=None: [label],
        )
        monkeypatch.setattr(
            run_corpus, "_resolve_source_dirs",
            lambda labels, do_fetch=False: {"test-repo": src},
        )
        monkeypatch.setattr(
            run_corpus, "_label_source_status",
            lambda lb, dirs: ("ok", ""),
        )
        monkeypatch.setattr(
            run_corpus, "_build_excerpt_tree",
            lambda labels, dirs: {"test-repo": src},
        )
        seen = {}

        def fake_cocci(excerpt, **kw):
            seen.update(kw)
            return EngineOutcome(
                engine="coccinelle", skipped_reason="stub",
            )

        monkeypatch.setattr(rule_eval, "run_cocci_engine", fake_cocci)
        rc = rule_eval.main([
            "--engine", "coccinelle", "--spatch-timeout", "77",
            "--out", str(tmp_path / "out"),
        ])
        assert rc == 0
        assert seen["timeout_per_rule"] == 77

    def test_timings_and_meta_in_results_json(self, tmp_path):
        import json

        from core.audit.corpus.rule_eval import _write_report

        report = {
            "labels": [], "per_rule": [], "per_class": {},
            "coverage_gaps": [], "skipped": [],
            "rule_timings": {
                "test-repo": {"coccinelle": {"use_after_free": 301.2}},
            },
            "meta": {"engines": ["coccinelle"], "spatch_timeout": 120,
                     "rules_discovered": 1, "labels_evaluated": 1,
                     "labels_skipped": 0, "engine_notes": [],
                     "engine_errors": []},
        }
        path = _write_report(report, tmp_path)
        data = json.loads(path.read_text())
        assert data["rule_timings"]["test-repo"]["coccinelle"] == {
            "use_after_free": 301.2,
        }
        assert data["meta"]["spatch_timeout"] == 120

    def test_summary_surfaces_slow_rules_only(self):
        report = {
            "labels": [], "per_rule": [], "per_class": {},
            "coverage_gaps": [], "skipped": [],
            "rule_timings": {"test-repo": {"coccinelle": {
                "slow_rule": 300.0, "fast_rule": 0.3,
            }}},
            "meta": {"engines": ["coccinelle"], "rules_discovered": 2,
                     "labels_evaluated": 1, "labels_skipped": 0,
                     "engine_notes": [], "engine_errors": []},
        }
        text = format_summary(report)
        assert "Slowest rule invocations:" in text
        assert "slow_rule" in text
        assert "fast_rule" not in text


class TestCodeqlFeasibility:
    def _which_codeql(self, monkeypatch):
        import core.audit.corpus.rule_eval as rule_eval

        monkeypatch.setattr(
            rule_eval.shutil, "which",
            lambda name: "/usr/bin/codeql" if name == "codeql" else None,
        )
        return rule_eval

    def test_python_repo_skipped(self, monkeypatch):
        rule_eval = self._which_codeql(monkeypatch)
        label = _label(file="pkg/mod.py", cwe="CWE-287")
        lang, reason = rule_eval.codeql_feasibility([label])
        assert lang == ""
        assert "no shipped custom CodeQL queries" in reason

    def test_c_repo_feasible_when_queries_shipped(self, monkeypatch):
        rule_eval = self._which_codeql(monkeypatch)
        if rule_eval.codeql_query_dir("cpp") is None:
            pytest.skip("shipped cpp queries absent")
        lang, reason = rule_eval.codeql_feasibility([_label()])
        assert lang == "cpp"
        assert reason == ""

    def test_java_repo_needs_build(self, monkeypatch):
        rule_eval = self._which_codeql(monkeypatch)
        if rule_eval.codeql_query_dir("java") is None:
            pytest.skip("shipped java queries absent")
        label = _label(file="src/Main.java")
        lang, reason = rule_eval.codeql_feasibility([label])
        assert lang == ""
        assert "traced build" in reason


@needs_semgrep
@pytest.mark.integration
class TestSemgrepIntegration:
    def test_hit_lands_in_label_space(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "app.go").write_text(
            "package main\n\nfunc main() {\n\tfoo()\n}\n"
        )
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "t.yaml").write_text(
            "rules:\n"
            "  - id: raptor.test.foo-call\n"
            "    languages: [go]\n"
            "    message: test\n"
            "    severity: ERROR\n"
            "    pattern: foo()\n"
        )
        outcome = run_semgrep_engine(target, config_dirs=[rules_dir])
        assert outcome.ran
        assert [
            (h.rule_id, h.file, h.line) for h in outcome.hits
        ] == [("raptor.test.foo-call", "app.go", 4)]


@needs_spatch
@pytest.mark.integration
class TestCocciIntegration:
    def test_hit_lands_in_label_space(self, tmp_path):
        target = tmp_path / "target"
        (target / "sub").mkdir(parents=True)
        (target / "sub" / "a.c").write_text(
            "void f(char *p)\n{\n\tkfree(p);\n\tkfree(p);\n}\n"
        )
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "test_double_free.cocci").write_text(
            "@r@\nexpression E;\nposition p;\n@@\n\n"
            "kfree(E);\n... when != E = ...\nkfree@p(E);\n"
        )
        outcome = run_cocci_engine(target, rules_dir=rules_dir)
        assert outcome.ran, outcome.errors
        assert outcome.hits, outcome.errors
        hit = outcome.hits[0]
        assert hit.rule_id == "test_double_free"
        assert hit.file == "sub/a.c"
        assert hit.line == 4


def test_cli_dry_run_smoke(capsys):
    """Full CLI dry-run over the committed labels — no engine executed."""
    from core.audit.corpus.label import load_all_labels
    from core.audit.corpus.rule_eval import main

    if not load_all_labels():
        pytest.skip("no local labels")
    rc = main(["--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Rule verification run complete" in out
    assert "dry run — no engine executed" in out
