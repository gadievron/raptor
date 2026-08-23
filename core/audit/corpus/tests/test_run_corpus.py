"""Tests for run_corpus helpers: label verification, splice, summary."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import json

import pytest

import core.audit.corpus.run_corpus as run_corpus
from core.audit.corpus.run_corpus import (
    _emit_summary,
    _label_source_status,
    _splice_results,
    _verify_labels,
)


def _label(repo="test", file="a.c", fid="a.c:f"):
    return SimpleNamespace(
        function_id=fid,
        bug_class="auth",
        expected_status="clean",
        source=SimpleNamespace(
            repo=repo, sha="abc", file=file, line_start=1, line_end=5,
        ),
    )


class TestLabelSourceStatus:
    def test_ok(self, tmp_path):
        (tmp_path / "a.c").write_text("int f;\n")
        status, detail = _label_source_status(
            _label(), {"test": tmp_path},
        )
        assert status == "ok"
        assert detail == ""

    def test_missing_dir(self, tmp_path):
        status, detail = _label_source_status(
            _label(), {"test": tmp_path / "nope"},
        )
        assert status == "missing_dir"
        assert "test" in detail

    def test_missing_file(self, tmp_path):
        status, detail = _label_source_status(
            _label(file="b.c"), {"test": tmp_path},
        )
        assert status == "missing_file"
        assert "b.c" in detail

    def test_src_prefix_probed_and_suggested(self, tmp_path):
        # src/-rooted repo: label says lex/lexer.go, the clone
        # has it at src/lex/lexer.go
        target = tmp_path / "src" / "lex"
        target.mkdir(parents=True)
        (target / "lexer.go").write_text("package lex\n")
        status, detail = _label_source_status(
            _label(file="lex/lexer.go"), {"test": tmp_path},
        )
        assert status == "prefix"
        assert detail == "src/lex/lexer.go"


class TestVerifyLabels:
    def test_clean_pass(self, tmp_path):
        (tmp_path / "a.c").write_text("int f;\n")
        errors = _verify_labels([_label()], {"test": tmp_path})
        assert errors == []

    def test_prefix_error_carries_suggestion(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int f;\n")
        errors = _verify_labels([_label()], {"test": tmp_path})
        assert len(errors) == 1
        assert "exists at src/a.c" in errors[0]
        assert "sources.json" in errors[0]

    def test_missing_reported(self, tmp_path):
        errors = _verify_labels(
            [_label(file="gone.c")], {"test": tmp_path},
        )
        assert len(errors) == 1
        assert "file not found" in errors[0]


def _result_row(fid="a.c:f", expected="clean", actual="clean"):
    return {
        "function_id": fid,
        "bug_class": "auth",
        "expected": expected,
        "actual": actual,
        "match": expected == actual,
        "hypothesis": "",
        "evidence_tool": "",
        "model": "test",
        "cost_usd": 0.0,
        "duration_s": 0.0,
    }


class TestVerifyLabelFunctions:
    """Label drift preflight: a label whose function name never appears
    in the pinned source file can only ever score error — warn before
    the run burns budget on it."""

    def _label(self, fid="a.c:f", file="a.c"):
        return SimpleNamespace(
            function_id=fid,
            bug_class="auth",
            expected_status="clean",
            source=SimpleNamespace(
                repo="test", sha="x", file=file, line_start=1, line_end=5,
            ),
        )

    def test_present_name_passes(self, tmp_path):
        (tmp_path / "a.c").write_text("int f(void) { return 0; }\n")
        warnings = run_corpus._verify_label_functions(
            [self._label()], {"test": tmp_path},
        )
        assert warnings == []

    def test_absent_name_warns(self, tmp_path):
        (tmp_path / "a.c").write_text("int other(void) { return 0; }\n")
        warnings = run_corpus._verify_label_functions(
            [self._label()], {"test": tmp_path},
        )
        assert len(warnings) == 1
        assert "label drift" in warnings[0]
        assert "a.c:f" in warnings[0]

    def test_class_qualified_name_uses_bare_method(self, tmp_path):
        (tmp_path / "a.go").write_text("func (p Parser) Decode() {}\n")
        warnings = run_corpus._verify_label_functions(
            [self._label(fid="a.go:Parser.Decode", file="a.go")],
            {"test": tmp_path},
        )
        assert warnings == []

    def test_missing_file_is_not_double_reported(self, tmp_path):
        # _verify_labels already errors on a missing file; the drift
        # probe stays silent for it.
        warnings = run_corpus._verify_label_functions(
            [self._label(file="gone.c")], {"test": tmp_path},
        )
        assert warnings == []

    def test_dry_run_prints_drift_warnings(self, tmp_path, monkeypatch, capsys):
        import core.audit.corpus.label as label_mod

        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text("int other(void) { return 0; }\n")
        monkeypatch.setattr(
            label_mod, "load_all_labels",
            lambda bug_class=None: [self._label()],
        )
        monkeypatch.setattr(
            run_corpus, "_resolve_source_dirs",
            lambda labels, do_fetch=False: {"test": src},
        )
        rc = run_corpus.main(["--dry-run"])
        assert rc == 0
        err = capsys.readouterr().err
        assert "label drift warning(s)" in err
        assert "a.c:f" in err


class TestSpliceResults:
    def _base_file(self, tmp_path, rows, wrapped=True):
        p = tmp_path / "results.json"
        data = {"meta": {"count": len(rows)}, "results": rows} if wrapped else rows
        p.write_text(json.dumps(data))
        return p

    def test_rerun_replaces_errored_row_keeps_rest(self, tmp_path):
        base = [
            _result_row("a.c:f", "clean", "error"),
            dict(_result_row("b.c:g", "finding", "finding"),
                 attribution="attributed",
                 observed_mechanisms=["smt"]),
        ]
        p = self._base_file(tmp_path, base)
        rerun = [_result_row("a.c:f", "clean", "clean")]
        merged, replaced = _splice_results(rerun, p)
        assert replaced == {"a.c:f"}
        by_id = {r["function_id"]: r for r in merged}
        assert len(merged) == 2
        assert by_id["a.c:f"]["actual"] == "clean"
        # untouched row keeps its attribution annotations
        assert by_id["b.c:g"]["attribution"] == "attributed"

    def test_sorted_output(self, tmp_path):
        base = [
            _result_row("z.c:z", "clean", "clean"),
            _result_row("a.c:a", "clean", "clean"),
        ]
        p = self._base_file(tmp_path, base, wrapped=False)
        merged, _ = _splice_results(
            [_result_row("m.c:m", "clean", "clean")], p,
        )
        assert [r["function_id"] for r in merged] == [
            "a.c:a", "m.c:m", "z.c:z",
        ]

    def test_missing_base_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="splice"):
            _splice_results([], tmp_path / "gone.json")

    def test_missing_splice_fails_fast_before_run(self, tmp_path, capsys):
        rc = run_corpus.main([
            "--dry-run", "--splice", str(tmp_path / "gone.json"),
        ])
        # 1, not 2: exit 2 is reserved for calibration gate failures
        assert rc == 1
        assert "file not found" in capsys.readouterr().err


class TestLabelPinning:
    """Labeled functions must be guaranteed review slots in EVERY pass.

    Regression: a label-filtered ensemble rerun threaded the labels
    into the bug_first pass but the security pass triage-skipped all
    of them (0 reviewed), so the merge scored the labels ``error`` for
    the missing mode.  Pins bypass triage skips and the budget cut.
    """

    def _label_for(self, fid, file, line=1):
        return SimpleNamespace(
            function_id=fid,
            bug_class="auth",
            expected_status="clean",
            expected_mechanism="",
            expected_mode_results={},
            source=SimpleNamespace(
                repo="test", sha="x", file=file,
                line_start=line, line_end=line + 5,
            ),
        )

    def test_single_pass_threads_pins(self, tmp_path, monkeypatch):
        import core.audit.pipeline as pipeline

        captured = []
        monkeypatch.setattr(
            pipeline, "run_audit_pipeline", captured.append,
        )
        monkeypatch.setattr(
            run_corpus, "_build_checklist", lambda t, o: True,
        )
        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text("int f(void) { return 0; }\n")

        labels = [
            self._label_for("a.c:f", "a.c"),
            self._label_for("a.c:Parser.Decode", "a.c", line=10),
        ]
        run_corpus._run_audit_on_target(
            src, labels, out_dir=tmp_path / "out", mode="security",
        )
        assert len(captured) == 1
        opts = captured[0]
        # every labeled function pinned: hoisted past the budget cut,
        # triage skip bypassed
        assert opts.pins == ["a.c:Parser.Decode", "a.c:f"]
        assert opts.functions == ["a.c:f:1", "a.c:Parser.Decode:10"]
        # corpus pins always force re-review: prior-run journal or
        # coverage state must not turn a labeled function into a
        # non-gap
        assert opts.force is True

    def test_every_ensemble_pass_gets_pins(self, tmp_path, monkeypatch):
        import core.audit.pipeline as pipeline

        captured = []
        monkeypatch.setattr(
            pipeline, "run_audit_pipeline", captured.append,
        )
        monkeypatch.setattr(
            run_corpus, "_build_checklist", lambda t, o: True,
        )
        monkeypatch.setattr(
            run_corpus, "_start_shared_joern", lambda dirs: None,
        )
        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text("int f(void) { return 0; }\n")

        labels = [self._label_for("a.c:f", "a.c")]
        run_corpus._run_ensemble_audit(
            labels, {"test": src}, out_dir=tmp_path / "out",
        )
        # security pass + bug_first pass, both pinned
        assert len(captured) == 2
        modes = {str(opts.mode) for opts in captured}
        assert len(modes) == 2, f"expected two distinct modes, got {modes}"
        for opts in captured:
            assert opts.pins == ["a.c:f"], (
                f"pass {opts.mode} lost the labeled-function pin"
            )
            assert opts.force is True, (
                f"pass {opts.mode} lost the pin force semantics"
            )


class TestScopeAndExcerptPrep:
    """Repo-root labels must not scope the audit to nothing, and a
    perlasm generator excerpt must carry its xlate driver.

    Regression: a label on a repo-root file (a top-level index.js /
    main.c) produced scope_dirs == ["."], the gap scope matcher
    matched nothing, and the whole group reviewed 0 functions; the
    openssl excerpt held only the labeled generator, so its driver
    lookup failed and the kernel never entered the checklist.
    """

    def _label_for(self, fid, file, line=1):
        return SimpleNamespace(
            function_id=fid,
            bug_class="auth",
            expected_status="clean",
            expected_mechanism="",
            expected_mode_results={},
            source=SimpleNamespace(
                repo="test", sha="x", file=file,
                line_start=line, line_end=line + 5,
            ),
        )

    def _opts_for(self, tmp_path, monkeypatch, labels):
        import core.audit.pipeline as pipeline

        captured = []
        monkeypatch.setattr(
            pipeline, "run_audit_pipeline", captured.append,
        )
        monkeypatch.setattr(
            run_corpus, "_build_checklist", lambda t, o: True,
        )
        src = tmp_path / "repo"
        src.mkdir(exist_ok=True)
        (src / "a.c").write_text("int f(void) { return 0; }\n")
        run_corpus._run_audit_on_target(
            src, labels, out_dir=tmp_path / "out", mode="security",
        )
        assert len(captured) == 1
        return captured[0]

    def test_root_label_means_no_scope(self, tmp_path, monkeypatch):
        opts = self._opts_for(
            tmp_path, monkeypatch, [self._label_for("a.c:f", "a.c")],
        )
        assert opts.scope is None

    def test_mixed_root_and_subdir_label_means_no_scope(
        self, tmp_path, monkeypatch,
    ):
        opts = self._opts_for(tmp_path, monkeypatch, [
            self._label_for("a.c:f", "a.c"),
            self._label_for("sub/b.c:g", "sub/b.c"),
        ])
        assert opts.scope is None

    def test_subdir_labels_keep_scope(self, tmp_path, monkeypatch):
        opts = self._opts_for(tmp_path, monkeypatch, [
            self._label_for("sub/b.c:g", "sub/b.c"),
        ])
        assert opts.scope == ["sub"]

    def test_excerpt_copies_xlate_driver(self, tmp_path):
        src_dir = tmp_path / "srcrepo"
        gen = src_dir / "crypto" / "aes" / "asm" / "gen-armv8.pl"
        gen.parent.mkdir(parents=True)
        gen.write_text(
            '$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\\.\\w+$| '
            '? pop : undef;\n'
            '$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\\.| ? shift : undef;\n'
            '( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or\n'
            '( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate);\n'
        )
        driver = src_dir / "crypto" / "perlasm" / "arm-xlate.pl"
        driver.parent.mkdir(parents=True)
        driver.write_text("# translator\n")

        excerpt = tmp_path / "excerpt"
        dst_gen = excerpt / "crypto" / "aes" / "asm" / "gen-armv8.pl"
        dst_gen.parent.mkdir(parents=True)
        dst_gen.write_text(gen.read_text())

        copied = run_corpus._copy_perlasm_drivers(excerpt, src_dir)
        assert copied == 1
        assert (excerpt / "crypto" / "perlasm" / "arm-xlate.pl").is_file()
        # Idempotent: second call copies nothing.
        assert run_corpus._copy_perlasm_drivers(excerpt, src_dir) == 0

    def test_excerpt_without_generators_copies_nothing(self, tmp_path):
        src_dir = tmp_path / "s"
        src_dir.mkdir()
        excerpt = tmp_path / "e"
        excerpt.mkdir()
        (excerpt / "plain.pl").write_text("sub f { return 1; }\n")
        assert run_corpus._copy_perlasm_drivers(excerpt, src_dir) == 0


def _write_checklist(audit_dir: Path, entries):
    """Write a minimal checklist.json with (file, name) entries."""
    files: dict = {}
    for file, name in entries:
        files.setdefault(file, []).append({"name": name, "line_start": 1})
    audit_dir.mkdir(parents=True, exist_ok=True)
    (audit_dir / "checklist.json").write_text(json.dumps({
        "files": [
            {"path": p, "items": items} for p, items in files.items()
        ],
    }))


class TestErrorReason:
    """Error cells must say WHY the label never got a verdict —
    an empty error row is indistinguishable from an LLM failure."""

    def _label_for(self, fid, file, line=1):
        return SimpleNamespace(
            function_id=fid,
            bug_class="auth",
            expected_status="clean",
            expected_mechanism="",
            expected_mode_results={},
            source=SimpleNamespace(
                repo="test", sha="x", file=file,
                line_start=line, line_end=line + 5,
            ),
        )

    def _run(self, tmp_path, monkeypatch, *, outcomes=None,
             checklist_entries=(), **kwargs):
        src = tmp_path / "repo"
        src.mkdir(exist_ok=True)
        (src / "a.c").write_text("int f(void) { return 0; }\n")
        audit_dir = tmp_path / "audit"
        _write_checklist(audit_dir, checklist_entries)
        monkeypatch.setattr(
            run_corpus, "_run_audit_on_target",
            lambda *a, **kw: (outcomes or {}, {}, audit_dir),
        )
        monkeypatch.setattr(
            run_corpus, "_start_shared_joern", lambda dirs: None,
        )
        labels = [self._label_for("a.c:f", "a.c")]
        results, _ = run_corpus._run_audit(
            labels, {"test": src}, **kwargs,
        )
        return results

    def test_source_dir_missing_reason(self):
        labels = [self._label_for("a.c:f", "a.c")]
        results, _ = run_corpus._run_audit(labels, {"test": Path("/nonexistent")})
        assert results[0]["actual"] == "error"
        assert results[0]["error_reason"] == (
            "not_reviewed:source_dir_missing:test"
        )

    def test_function_not_in_checklist_reason(self, tmp_path, monkeypatch):
        # Pin matched no gap: the labeled function is absent from the
        # inventory (label drift) — the error cell must say so.
        results = self._run(
            tmp_path, monkeypatch,
            checklist_entries=[("a.c", "other")],
        )
        assert results[0]["actual"] == "error"
        assert results[0]["error_reason"] == (
            "not_reviewed:function_not_in_checklist"
        )

    def test_outcome_error_carries_llm_reason(self, tmp_path, monkeypatch):
        results = self._run(
            tmp_path, monkeypatch,
            outcomes={"a.c:f": {
                "status": "error", "error": "429 throttled",
            }},
            checklist_entries=[("a.c", "f")],
        )
        assert results[0]["actual"] == "error"
        assert results[0]["error_reason"] == "llm_error:429 throttled"

    def test_reviewed_row_has_empty_reason(self, tmp_path, monkeypatch):
        results = self._run(
            tmp_path, monkeypatch,
            outcomes={"a.c:f": {"status": "clean"}},
            checklist_entries=[("a.c", "f")],
        )
        assert results[0]["actual"] == "clean"
        assert results[0]["error_reason"] == ""

    def test_reason_shown_in_detail_table_and_mismatches(self):
        row = dict(
            _result_row("a.c:f", "clean", "error"),
            error_reason="not_reviewed:function_not_in_checklist",
        )
        table = run_corpus._format_detail_table([row])
        assert "not_reviewed:function_not_in_checklist" in table
        summary, _ = run_corpus._format_summary([row], 1.0, "test")
        assert "reason: not_reviewed:function_not_in_checklist" in summary


class TestTriageKnob:
    """--triage off (corpus default) must stop the triage classifier
    from resolving labeled functions: the pipeline SKIP shortcut is
    disabled and the runner's inventoried-but-unreviewed fallback
    scores an explicit error instead of fabricating a triage clean.
    (Observed: 10/16 labels got clean via triage:classifier without
    ever being reviewed, gate-failing mechanism attribution 11/16.)"""

    def _label_for(self, fid="a.c:f", file="a.c"):
        return SimpleNamespace(
            function_id=fid,
            bug_class="auth",
            expected_status="clean",
            expected_mechanism="",
            expected_mode_results={},
            source=SimpleNamespace(
                repo="test", sha="x", file=file, line_start=1, line_end=6,
            ),
        )

    def _run_with(self, tmp_path, monkeypatch, *, triage):
        src = tmp_path / "repo"
        src.mkdir(exist_ok=True)
        (src / "a.c").write_text("int f(void) { return 0; }\n")
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "checklist.json").write_text(json.dumps({
            "files": [{"path": "a.c", "items": [{"name": "f"}]}],
        }))
        seen = {}

        def fake_target(*a, **kw):
            seen.update(kw)
            return {}, {}, audit_dir

        monkeypatch.setattr(run_corpus, "_run_audit_on_target", fake_target)
        monkeypatch.setattr(
            run_corpus, "_start_shared_joern", lambda dirs: None,
        )
        results, _ = run_corpus._run_audit(
            [self._label_for()], {"test": src}, triage=triage,
        )
        return results, seen

    def test_off_scores_unreviewed_label_as_error(
        self, tmp_path, monkeypatch,
    ):
        results, seen = self._run_with(tmp_path, monkeypatch, triage=False)
        assert seen["triage"] is False
        assert results[0]["actual"] == "error"
        assert results[0]["evidence_tool"] == ""
        assert results[0]["error_reason"] == (
            "not_reviewed:pin_matched_no_gap"
        )

    def test_on_keeps_legacy_triage_fallback(self, tmp_path, monkeypatch):
        results, seen = self._run_with(tmp_path, monkeypatch, triage=True)
        assert seen["triage"] is True
        assert results[0]["actual"] == "clean"
        assert results[0]["evidence_tool"] == "triage:classifier"

    def test_pipeline_opts_thread_triage(self, tmp_path, monkeypatch):
        import core.audit.pipeline as pipeline

        captured = []
        monkeypatch.setattr(
            pipeline, "run_audit_pipeline", captured.append,
        )
        monkeypatch.setattr(
            run_corpus, "_build_checklist", lambda t, o: True,
        )
        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text("int f(void) { return 0; }\n")
        run_corpus._run_audit_on_target(
            src, [self._label_for()], out_dir=tmp_path / "out",
            mode="security", triage=False,
        )
        assert captured[0].triage is False

    def test_ensemble_threads_triage_to_both_passes(
        self, tmp_path, monkeypatch,
    ):
        calls = []

        def fake_run_audit(labels, dirs, **kw):
            calls.append(kw)
            return ([{
                "function_id": lb.function_id,
                "bug_class": lb.bug_class,
                "expected": lb.expected_status,
                "actual": "suspicious",
                "match": False,
                "hypothesis": "",
                "evidence_tool": "",
                "cost_usd": 0.0,
                "duration_s": 0.0,
            } for lb in labels], [])

        monkeypatch.setattr(run_corpus, "_run_audit", fake_run_audit)
        monkeypatch.setattr(
            run_corpus, "_start_shared_joern", lambda dirs: None,
        )
        monkeypatch.setattr(
            run_corpus, "_run_phase2_classify", lambda *a, **kw: 0.0,
        )
        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text("int f(void) { return 0; }\n")
        run_corpus._run_ensemble_audit(
            [self._label_for()], {"test": src},
            out_dir=tmp_path / "out", triage=False,
        )
        assert len(calls) == 2
        assert all(kw["triage"] is False for kw in calls)

    def test_meta_records_triage_setting(self, tmp_path, monkeypatch):
        from contextlib import contextmanager

        import core.audit.corpus.label as label_mod

        @contextmanager
        def fake_project(run_tag):
            yield f"corpus-{run_tag}"

        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text("int f(void) { return 0; }\n")

        monkeypatch.setattr(
            label_mod, "load_all_labels",
            lambda bug_class=None: [self._label_for()],
        )
        monkeypatch.setattr(
            run_corpus, "_resolve_source_dirs",
            lambda labels, do_fetch=False: {"test": src},
        )
        monkeypatch.setattr(
            run_corpus, "_corpus_project_context", fake_project,
        )
        captured = {}

        def fake_ensemble(labels, dirs, **kw):
            captured.update(kw)
            # model="" matches the default-model run so the
            # conservation census stays clean.
            return (
                [dict(_result_row("a.c:f", "clean", "clean"), model="")],
                [],
            )

        monkeypatch.setattr(
            run_corpus, "_run_ensemble_audit", fake_ensemble,
        )
        out = tmp_path / "results.json"
        run_corpus.main(["--output", str(out)])
        meta = json.loads(out.read_text())["meta"]
        assert meta["triage"] == "off"
        assert captured["triage"] is False


class TestProfileKnob:
    """--profile cold (corpus default) must turn off every
    accumulated-knowledge channel in the pipeline opts — the corpus
    measures raw first-time-user capability; --profile deployed
    restores today's all-channels-on behaviour for accumulation
    comparisons. The setting must reach results.json meta and the
    history hook."""

    GATES = (
        "iris", "sage_recall", "library_replay", "cross_run_import",
        "verdict_reuse", "domain_model_import", "annotations_read",
    )

    def _label_for(self, fid="a.c:f", file="a.c"):
        return SimpleNamespace(
            function_id=fid,
            bug_class="auth",
            expected_status="clean",
            expected_mechanism="",
            expected_mode_results={},
            source=SimpleNamespace(
                repo="test", sha="x", file=file, line_start=1, line_end=6,
            ),
        )

    def _run_with(self, tmp_path, monkeypatch, *, profile):
        src = tmp_path / "repo"
        src.mkdir(exist_ok=True)
        (src / "a.c").write_text("int f(void) { return 0; }\n")
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir(exist_ok=True)
        seen = {}

        def fake_target(*a, **kw):
            seen.update(kw)
            return {}, {}, audit_dir

        monkeypatch.setattr(run_corpus, "_run_audit_on_target", fake_target)
        monkeypatch.setattr(
            run_corpus, "_start_shared_joern", lambda dirs: None,
        )
        run_corpus._run_audit(
            [self._label_for()], {"test": src}, profile=profile,
        )
        return seen

    def test_profile_threads_to_target(self, tmp_path, monkeypatch):
        seen = self._run_with(tmp_path, monkeypatch, profile="cold")
        assert seen["profile"] == "cold"
        seen = self._run_with(tmp_path, monkeypatch, profile="deployed")
        assert seen["profile"] == "deployed"

    def _target_opts(self, tmp_path, monkeypatch, *, profile):
        import core.audit.pipeline as pipeline

        captured = []
        monkeypatch.setattr(
            pipeline, "run_audit_pipeline", captured.append,
        )
        monkeypatch.setattr(
            run_corpus, "_build_checklist", lambda t, o: True,
        )
        src = tmp_path / "repo"
        src.mkdir(exist_ok=True)
        (src / "a.c").write_text("int f(void) { return 0; }\n")
        run_corpus._run_audit_on_target(
            src, [self._label_for()], out_dir=tmp_path / "out",
            mode="security", profile=profile,
        )
        return captured[0]

    def test_cold_turns_every_gate_off(self, tmp_path, monkeypatch):
        opts = self._target_opts(tmp_path, monkeypatch, profile="cold")
        assert opts.profile == "cold"
        for gate in self.GATES:
            assert getattr(opts, gate) is False, gate

    def test_deployed_leaves_every_gate_on(self, tmp_path, monkeypatch):
        opts = self._target_opts(tmp_path, monkeypatch, profile="deployed")
        assert opts.profile == "deployed"
        for gate in self.GATES:
            assert getattr(opts, gate) is True, gate

    def test_gate_dict_matches_opts_surface(self):
        """Every cold gate must be a real AuditPipelineOpts field —
        a renamed field would silently stop gating."""
        from dataclasses import fields

        from core.audit.pipeline import AuditPipelineOpts

        opt_fields = {f.name for f in fields(AuditPipelineOpts)}
        assert set(run_corpus.COLD_PROFILE_GATES) <= opt_fields

    def test_ensemble_threads_profile_to_both_passes(
        self, tmp_path, monkeypatch,
    ):
        calls = []

        def fake_run_audit(labels, dirs, **kw):
            calls.append(kw)
            return ([{
                "function_id": lb.function_id,
                "bug_class": lb.bug_class,
                "expected": lb.expected_status,
                "actual": "suspicious",
                "match": False,
                "hypothesis": "",
                "evidence_tool": "",
                "cost_usd": 0.0,
                "duration_s": 0.0,
            } for lb in labels], [])

        monkeypatch.setattr(run_corpus, "_run_audit", fake_run_audit)
        monkeypatch.setattr(
            run_corpus, "_start_shared_joern", lambda dirs: None,
        )
        monkeypatch.setattr(
            run_corpus, "_run_phase2_classify", lambda *a, **kw: 0.0,
        )
        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text("int f(void) { return 0; }\n")
        run_corpus._run_ensemble_audit(
            [self._label_for()], {"test": src},
            out_dir=tmp_path / "out", profile="cold",
        )
        assert len(calls) == 2
        assert all(kw["profile"] == "cold" for kw in calls)

    def test_meta_and_history_record_profile(self, tmp_path, monkeypatch):
        from contextlib import contextmanager

        import core.audit.corpus.label as label_mod

        @contextmanager
        def fake_project(run_tag):
            yield f"corpus-{run_tag}"

        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text("int f(void) { return 0; }\n")

        monkeypatch.setattr(
            label_mod, "load_all_labels",
            lambda bug_class=None: [self._label_for()],
        )
        monkeypatch.setattr(
            run_corpus, "_resolve_source_dirs",
            lambda labels, do_fetch=False: {"test": src},
        )
        monkeypatch.setattr(
            run_corpus, "_corpus_project_context", fake_project,
        )
        monkeypatch.setattr(
            run_corpus, "_run_ensemble_audit",
            lambda labels, dirs, **kw: (
                [dict(_result_row("a.c:f", "clean", "clean"), model="")],
                [],
            ),
        )
        recorded = {}

        import core.audit.corpus.history as history_mod

        monkeypatch.setattr(
            history_mod, "record_run",
            lambda *a, **kw: recorded.update(kw) or True,
        )
        out = tmp_path / "results.json"
        run_corpus.main(["--output", str(out)])
        meta = json.loads(out.read_text())["meta"]
        assert meta["profile"] == "cold"
        assert recorded["profile"] == "cold"

        run_corpus.main(["--output", str(out), "--profile", "deployed"])
        meta = json.loads(out.read_text())["meta"]
        assert meta["profile"] == "deployed"
        assert recorded["profile"] == "deployed"


class TestPrefilterKnob:
    """--prefilter off (corpus default) must stop the mechanical
    prefilter's skip_llm shortcut from resolving labeled functions:
    a second skip layer beneath triage that stamped labels
    clean/prefilter:skip without a deep review even with --triage off
    (observed in a full corpus run — right verdict,
    wrong mechanism, misattribution gate failure)."""

    def _label_for(self, fid="a.c:f", file="a.c"):
        return SimpleNamespace(
            function_id=fid,
            bug_class="auth",
            expected_status="clean",
            expected_mechanism="",
            expected_mode_results={},
            source=SimpleNamespace(
                repo="test", sha="x", file=file, line_start=1, line_end=6,
            ),
        )

    def _run_with(self, tmp_path, monkeypatch, *, prefilter):
        src = tmp_path / "repo"
        src.mkdir(exist_ok=True)
        (src / "a.c").write_text("int f(void) { return 0; }\n")
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "checklist.json").write_text(json.dumps({
            "files": [{"path": "a.c", "items": [{"name": "f"}]}],
        }))
        seen = {}

        def fake_target(*a, **kw):
            seen.update(kw)
            return {}, {}, audit_dir

        monkeypatch.setattr(run_corpus, "_run_audit_on_target", fake_target)
        monkeypatch.setattr(
            run_corpus, "_start_shared_joern", lambda dirs: None,
        )
        run_corpus._run_audit(
            [self._label_for()], {"test": src}, prefilter=prefilter,
        )
        return seen

    def test_off_threads_to_target(self, tmp_path, monkeypatch):
        seen = self._run_with(tmp_path, monkeypatch, prefilter=False)
        assert seen["prefilter"] is False

    def test_on_threads_to_target(self, tmp_path, monkeypatch):
        seen = self._run_with(tmp_path, monkeypatch, prefilter=True)
        assert seen["prefilter"] is True

    def test_pipeline_opts_thread_prefilter_skip(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.pipeline as pipeline

        captured = []
        monkeypatch.setattr(
            pipeline, "run_audit_pipeline", captured.append,
        )
        monkeypatch.setattr(
            run_corpus, "_build_checklist", lambda t, o: True,
        )
        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text("int f(void) { return 0; }\n")
        run_corpus._run_audit_on_target(
            src, [self._label_for()], out_dir=tmp_path / "out",
            mode="security", prefilter=False,
        )
        assert captured[0].prefilter_skip is False

    def test_ensemble_threads_prefilter_to_both_passes(
        self, tmp_path, monkeypatch,
    ):
        calls = []

        def fake_run_audit(labels, dirs, **kw):
            calls.append(kw)
            return ([{
                "function_id": lb.function_id,
                "bug_class": lb.bug_class,
                "expected": lb.expected_status,
                "actual": "suspicious",
                "match": False,
                "hypothesis": "",
                "evidence_tool": "",
                "cost_usd": 0.0,
                "duration_s": 0.0,
            } for lb in labels], [])

        monkeypatch.setattr(run_corpus, "_run_audit", fake_run_audit)
        monkeypatch.setattr(
            run_corpus, "_start_shared_joern", lambda dirs: None,
        )
        monkeypatch.setattr(
            run_corpus, "_run_phase2_classify", lambda *a, **kw: 0.0,
        )
        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text("int f(void) { return 0; }\n")
        run_corpus._run_ensemble_audit(
            [self._label_for()], {"test": src},
            out_dir=tmp_path / "out", prefilter=False,
        )
        assert len(calls) == 2
        assert all(kw["prefilter"] is False for kw in calls)

    def test_meta_records_prefilter_setting(self, tmp_path, monkeypatch):
        from contextlib import contextmanager

        import core.audit.corpus.label as label_mod

        @contextmanager
        def fake_project(run_tag):
            yield f"corpus-{run_tag}"

        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text("int f(void) { return 0; }\n")

        monkeypatch.setattr(
            label_mod, "load_all_labels",
            lambda bug_class=None: [self._label_for()],
        )
        monkeypatch.setattr(
            run_corpus, "_resolve_source_dirs",
            lambda labels, do_fetch=False: {"test": src},
        )
        monkeypatch.setattr(
            run_corpus, "_corpus_project_context", fake_project,
        )
        captured = {}

        def fake_ensemble(labels, dirs, **kw):
            captured.update(kw)
            # model="" matches the default-model run so the
            # conservation census stays clean.
            return (
                [dict(_result_row("a.c:f", "clean", "clean"), model="")],
                [],
            )

        monkeypatch.setattr(
            run_corpus, "_run_ensemble_audit", fake_ensemble,
        )
        out = tmp_path / "results.json"
        run_corpus.main(["--output", str(out)])
        meta = json.loads(out.read_text())["meta"]
        assert meta["prefilter"] == "off"
        assert captured["prefilter"] is False


class TestMetricsContract:
    """Revision-skew tripwire between run_corpus and corpus_metrics.

    The end-of-run summary once crashed because the two modules were
    recovered at different revisions (compute_metrics returned a
    2-tuple, the caller unpacked 3).  This exercises the real summary
    path against the real metrics module so a contract change fails at
    test time, not at end-of-run.
    """

    def test_format_summary_against_live_corpus_metrics(self):
        rows = [
            _result_row("a.c:f", "clean", "clean"),
            dict(_result_row("b.c:g", "finding", "error"),
                 error="pipeline crashed"),
            dict(_result_row("c.c:h", "clean", "clean"),
                 skipped=True, evidence_tool="triage:classifier",
                 expected_mechanism="refutation:contract",
                 expected_mode_results={"security": "clean"},
                 mode="security"),
        ]
        out, _gates = run_corpus._format_summary(rows, wall_s=1.0, model="test")
        # compute_metrics 3-tuple contract
        assert "Aggregate:" in out
        assert "1 error(s) excluded from P/R" in out
        # format_report skipped kwarg contract
        assert "mechanically skipped" in out
        # attribution + mode blocks and the gate section rendered
        assert "Mechanism attribution" in out
        assert "Mode expectations" in out
        assert "GATE FAIL" in out or "All gates passed." in out


class TestEmitSummary:
    def test_success_returns_zero(self, capsys):
        rc = _emit_summary(
            [_result_row()], 1.0, "test", Path("results.json"),
        )
        out = capsys.readouterr().out
        assert rc == 0
        assert "Corpus run complete" in out
        assert "All gates passed." in out

    def test_gate_failure_returns_exit_gate_fail(self, capsys):
        # An errored label on a 1-label run trips the error-fraction
        # gate (100% > 10%) — the process must exit 2, not 0.
        rows = [dict(
            _result_row("a.c:f", "clean", "error"),
            error_reason="not_reviewed:function_not_in_checklist",
        )]
        rc = _emit_summary(rows, 1.0, "test", Path("results.json"))
        out = capsys.readouterr().out
        assert rc == run_corpus.EXIT_GATE_FAIL == 2
        assert "GATE FAIL" in out

    def test_help_documents_exit_semantics(self, capsys):
        with pytest.raises(SystemExit) as exc:
            run_corpus.main(["--help"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "exit codes:" in out
        assert "calibration gate failed" in out

    def test_scoring_crash_preserves_results_pointer(
        self, monkeypatch, capsys,
    ):
        def boom(*args, **kwargs):
            raise ValueError("not enough values to unpack")

        monkeypatch.setattr(run_corpus, "_format_summary", boom)
        rc = _emit_summary(
            [_result_row()], 1.0, "test", Path("/tmp/results.json"),
        )
        captured = capsys.readouterr()
        assert rc == 1
        # full traceback for diagnosis
        assert "not enough values to unpack" in captured.err
        assert "Traceback" in captured.err
        # and the pointer to the surviving results + recompute command
        assert "/tmp/results.json" in captured.err
        assert "core.audit.corpus.corpus_metrics" in captured.err


class TestFetchSourceEnv:
    """The re-fetch path must dial the remote with the proxy route
    preserved — a stripped env has no route on egress-proxy hosts."""

    def test_fetch_uses_proxy_env(self, tmp_path, monkeypatch):
        import subprocess as real_subprocess

        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
        dest = tmp_path / "fixtures" / "test"
        (dest / ".git").mkdir(parents=True)
        monkeypatch.setattr(
            run_corpus, "FIXTURES_DIR", tmp_path / "fixtures",
        )

        calls = []

        def fake_run(cmd, **kw):
            calls.append((cmd, kw))
            # rev-parse HEAD and rev-parse <ref> must disagree so the
            # mismatch branch (fetch + checkout) is taken.
            out = "curr" if "HEAD" in cmd else "want"
            return real_subprocess.CompletedProcess(cmd, 0, out, "")

        monkeypatch.setattr(run_corpus.subprocess, "run", fake_run)
        run_corpus._fetch_source("test", "v1.0.0")

        fetch_calls = [
            (cmd, kw) for cmd, kw in calls if "fetch" in cmd
        ]
        assert fetch_calls, "no fetch subprocess was spawned"
        for _, kw in fetch_calls:
            assert kw["env"].get("HTTPS_PROXY") == (
                "http://proxy.invalid:3128"
            )


def _mk_label(fid="a.c:f", file="a.c", repo="test"):
    return SimpleNamespace(
        function_id=fid,
        bug_class="auth",
        expected_status="clean",
        expected_mechanism="",
        expected_mode_results={},
        source=SimpleNamespace(
            repo=repo, sha="x", file=file, line_start=1, line_end=5,
        ),
    )


class TestAccountResults:
    """Conservation invariant: every selected label lands in exactly
    one bucket per model, and bucket counts sum to labels x models.
    This must catch ANY silent-loss path, not just known ones."""

    def test_all_accounted(self):
        labels = [_mk_label("a.c:f"), _mk_label("a.c:g"), _mk_label("a.c:h")]
        results = [
            _result_row("a.c:f"),
            dict(_result_row("a.c:g"), skipped=True,
                 evidence_tool="dead-code-gate"),
            dict(_result_row("a.c:h", actual="error"),
                 error_reason="llm_error:boom"),
        ]
        violations, census = run_corpus._account_results(
            labels, results, models=["test"],
        )
        assert violations == []
        assert census == {
            "reviewed": 1,
            "skipped:dead-code-gate": 1,
            "error:llm_error:boom": 1,
        }
        assert sum(census.values()) == len(labels)

    def test_dropped_label_is_violation(self):
        labels = [_mk_label("a.c:f"), _mk_label("a.c:g")]
        violations, _ = run_corpus._account_results(
            labels, [_result_row("a.c:f")], models=["test"],
        )
        assert len(violations) == 1
        assert "a.c:g" in violations[0]
        assert "silently dropped" in violations[0]

    def test_double_counted_label_is_violation(self):
        labels = [_mk_label("a.c:f")]
        violations, _ = run_corpus._account_results(
            labels, [_result_row("a.c:f"), _result_row("a.c:f")],
            models=["test"],
        )
        assert len(violations) == 1
        assert "double-counted" in violations[0]

    def test_phantom_row_is_violation(self):
        labels = [_mk_label("a.c:f")]
        violations, _ = run_corpus._account_results(
            labels, [_result_row("a.c:f"), _result_row("a.c:ghost")],
            models=["test"],
        )
        assert len(violations) == 1
        assert "phantom" in violations[0]

    def test_pre_skipped_labels_accounted_without_rows(self):
        labels = [_mk_label("a.c:f"), _mk_label("big/b.c:g", repo="big")]
        violations, census = run_corpus._account_results(
            labels, [_result_row("a.c:f")], models=["test"],
            pre_skipped={"big/b.c:g": "quick_scope:big"},
        )
        assert violations == []
        assert census["skipped:quick_scope:big"] == 1

    def test_pre_skipped_label_with_rows_is_violation(self):
        labels = [_mk_label("a.c:f")]
        violations, _ = run_corpus._account_results(
            labels, [_result_row("a.c:f")], models=["test"],
            pre_skipped={"a.c:f": "quick_scope:test"},
        )
        assert len(violations) == 1
        assert "excluded before the run" in violations[0]

    def test_multi_model_probe_accounted_per_model(self):
        labels = [_mk_label("a.c:f")]
        rows = [
            dict(_result_row("a.c:f"), model="m1"),
            dict(_result_row("a.c:f"), model="m2"),
        ]
        violations, census = run_corpus._account_results(
            labels, rows, models=["m1", "m2"],
        )
        assert violations == []
        assert census == {"reviewed": 2}

    def test_missing_model_slot_is_violation(self):
        labels = [_mk_label("a.c:f")]
        rows = [dict(_result_row("a.c:f"), model="m1")]
        violations, _ = run_corpus._account_results(
            labels, rows, models=["m1", "m2"],
        )
        assert len(violations) == 1
        assert "m2" in violations[0]

    def test_rows_for_unran_model_is_violation(self):
        labels = [_mk_label("a.c:f")]
        rows = [
            dict(_result_row("a.c:f"), model="m1"),
            dict(_result_row("a.c:f"), model="stray"),
        ]
        violations, _ = run_corpus._account_results(
            labels, rows, models=["m1"],
        )
        assert len(violations) == 1
        assert "never ran" in violations[0]


class TestConservationInMain:
    """A run whose results silently lose a label must exit 1 (infra),
    with the lost function_ids printed — regardless of gate status."""

    def _main_with_stub(self, tmp_path, monkeypatch, rows):
        from contextlib import contextmanager

        import core.audit.corpus.label as label_mod

        @contextmanager
        def fake_project(run_tag):
            yield f"corpus-{run_tag}"

        src = tmp_path / "repo"
        src.mkdir(exist_ok=True)
        (src / "a.c").write_text(
            "int f(void) { return 0; }\n"
            "int g(void) { return 0; }\n"
            "int pad1;\nint pad2;\nint pad3;\n",
        )
        labels = [_mk_label("a.c:f"), _mk_label("a.c:g")]
        monkeypatch.setattr(
            label_mod, "load_all_labels",
            lambda bug_class=None: labels,
        )
        monkeypatch.setattr(
            run_corpus, "_resolve_source_dirs",
            lambda labels, do_fetch=False: {"test": src},
        )
        monkeypatch.setattr(
            run_corpus, "_corpus_project_context", fake_project,
        )
        monkeypatch.setattr(
            run_corpus, "_run_ensemble_audit",
            lambda labels, dirs, **kw: (rows, []),
        )
        out = tmp_path / "results.json"
        rc = run_corpus.main(["--output", str(out)])
        return rc, out

    def test_lost_label_exits_one_and_names_it(
        self, tmp_path, monkeypatch, capsys,
    ):
        rc, out = self._main_with_stub(
            tmp_path, monkeypatch,
            [dict(_result_row("a.c:f"), model="")],
        )
        assert rc == 1
        captured = capsys.readouterr()
        assert "CONSERVATION VIOLATION" in captured.err
        assert "a.c:g" in captured.err
        # Results still made it to disk before the failure.
        assert out.is_file()

    def test_conserved_run_passes_and_prints_census(
        self, tmp_path, monkeypatch, capsys,
    ):
        rc, _ = self._main_with_stub(
            tmp_path, monkeypatch,
            [dict(_result_row("a.c:f"), model=""),
             dict(_result_row("a.c:g"), model="")],
        )
        assert rc == 0
        captured = capsys.readouterr()
        assert "Accounting: 2 label(s)" in captured.out
        assert "2 reviewed" in captured.out
        assert "CONSERVATION" not in captured.err


class TestSpendGate:
    """Drifted pins refuse the run BEFORE any LLM cost is spent."""

    def _run_main(self, tmp_path, monkeypatch, checks, argv=None):
        from contextlib import contextmanager

        import core.audit.corpus.label as label_mod
        import core.audit.corpus.lint as lint_mod

        @contextmanager
        def fake_project(run_tag):
            yield f"corpus-{run_tag}"

        src = tmp_path / "repo"
        src.mkdir(exist_ok=True)
        (src / "a.c").write_text("int f(void) { return 0; }\n" * 5)

        labels = [_mk_label("a.c:f")]
        monkeypatch.setattr(
            label_mod, "load_all_labels",
            lambda bug_class=None: labels,
        )
        monkeypatch.setattr(
            run_corpus, "_resolve_source_dirs",
            lambda labels, do_fetch=False: {"test": src},
        )
        monkeypatch.setattr(
            run_corpus, "_corpus_project_context", fake_project,
        )
        monkeypatch.setattr(
            lint_mod, "verify_pins",
            lambda pairs, **kw: [
                lint_mod.PinCheck(label=lb, path=None, **check_kw)
                for (_, lb), check_kw in zip(pairs, checks)
            ],
        )
        ran = []

        def fake_ensemble(labels, dirs, **kw):
            ran.append(True)
            return (
                [dict(_result_row("a.c:f"), model="")], [],
            )

        monkeypatch.setattr(
            run_corpus, "_run_ensemble_audit", fake_ensemble,
        )
        out = tmp_path / "results.json"
        rc = run_corpus.main(["--output", str(out), *(argv or [])])
        return rc, ran

    def test_drifted_pin_refuses_before_run(
        self, tmp_path, monkeypatch, capsys,
    ):
        rc, ran = self._run_main(
            tmp_path, monkeypatch,
            [{"outcome": "missing", "detail": "gone"}],
        )
        assert rc == 2
        assert ran == [], "LLM run started despite drifted pins"
        err = capsys.readouterr().err
        assert "SPEND GATE" in err
        assert "a.c:f" in err

    def test_relocatable_pin_also_refuses(self, tmp_path, monkeypatch):
        rc, ran = self._run_main(
            tmp_path, monkeypatch,
            [{"outcome": "relocatable", "detail": "moved"}],
        )
        assert rc == 2
        assert ran == []

    def test_allow_drift_overrides(self, tmp_path, monkeypatch):
        rc, ran = self._run_main(
            tmp_path, monkeypatch,
            [{"outcome": "missing", "detail": "gone"}],
            argv=["--allow-drift"],
        )
        assert rc == 0
        assert ran == [True]

    def test_ok_pin_runs(self, tmp_path, monkeypatch):
        rc, ran = self._run_main(
            tmp_path, monkeypatch, [{"outcome": "ok"}],
        )
        assert rc == 0
        assert ran == [True]

    def test_no_fixture_warns_and_runs(
        self, tmp_path, monkeypatch, capsys,
    ):
        rc, ran = self._run_main(
            tmp_path, monkeypatch,
            [{"outcome": "no-fixture", "detail": "no fixture"}],
        )
        assert rc == 0
        assert ran == [True]
        assert "not pin-verified" in capsys.readouterr().err

    def test_require_fixtures_refuses_no_fixture(
        self, tmp_path, monkeypatch,
    ):
        rc, ran = self._run_main(
            tmp_path, monkeypatch,
            [{"outcome": "no-fixture", "detail": "no fixture"}],
            argv=["--require-fixtures"],
        )
        assert rc == 2
        assert ran == []

    def test_dry_run_prints_census_without_refusing(
        self, tmp_path, monkeypatch, capsys,
    ):
        rc, ran = self._run_main(
            tmp_path, monkeypatch,
            [{"outcome": "missing", "detail": "gone"}],
            argv=["--dry-run"],
        )
        assert rc == 0
        assert ran == []
        out = capsys.readouterr().out
        assert "Pin census:" in out
        assert "1 missing" in out


class TestRefireLoop:
    """Selective-refire ergonomics: --label is repeatable, composes
    with --class, records a subset selection in history, and prints
    per-label deltas against the latest prior history."""

    def _label_for(self, fid, bug_class="auth", file="a.c"):
        return SimpleNamespace(
            function_id=fid,
            bug_class=bug_class,
            expected_status="finding",
            expected_mechanism="",
            expected_mode_results={},
            source=SimpleNamespace(
                repo="test", sha="x", file=file, line_start=1, line_end=6,
            ),
        )

    def _wire(self, tmp_path, monkeypatch, labels, actual_by_fid):
        from contextlib import contextmanager

        import core.audit.corpus.history as history_mod
        import core.audit.corpus.label as label_mod

        @contextmanager
        def fake_project(run_tag):
            yield f"corpus-{run_tag}"

        src = tmp_path / "repo"
        src.mkdir(exist_ok=True)
        (src / "a.c").write_text("int f(void) { return 0; }\n")

        monkeypatch.setattr(
            label_mod, "load_all_labels",
            lambda bug_class=None: [
                lb for lb in labels
                if bug_class is None or lb.bug_class == bug_class
            ],
        )
        monkeypatch.setattr(
            run_corpus, "_resolve_source_dirs",
            lambda labels, do_fetch=False: {"test": src},
        )
        monkeypatch.setattr(
            run_corpus, "_corpus_project_context", fake_project,
        )
        monkeypatch.setenv(
            history_mod.HISTORY_ENV, str(tmp_path / "history.jsonl"),
        )
        seen = {}

        def fake_ensemble(run_labels, dirs, **kw):
            seen["fids"] = [lb.function_id for lb in run_labels]
            return ([
                dict(
                    _result_row(
                        lb.function_id, "finding",
                        actual_by_fid.get(lb.function_id, "clean"),
                    ),
                    model="",
                )
                for lb in run_labels
            ], [])

        monkeypatch.setattr(
            run_corpus, "_run_ensemble_audit", fake_ensemble,
        )
        return seen

    def test_label_is_repeatable_and_composes_with_class(
        self, tmp_path, monkeypatch,
    ):
        labels = [
            self._label_for("a.c:f", bug_class="auth"),
            self._label_for("a.c:g", bug_class="auth"),
            self._label_for("a.c:h", bug_class="lifecycle"),
        ]
        seen = self._wire(tmp_path, monkeypatch, labels, {})
        out = tmp_path / "r1.json"
        rc = run_corpus.main([
            "--output", str(out),
            "--class", "auth",
            "--label", "a.c:f",
            "--label", "a.c:g",
            "--label", "a.c:h",  # filtered out by --class
        ])
        assert rc in (0, 2)  # gates may fail on tiny synthetic runs
        assert seen["fids"] == ["a.c:f", "a.c:g"]

    def test_subset_selection_recorded_in_history(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.corpus.history as history_mod

        labels = [self._label_for("a.c:f"), self._label_for("a.c:g")]
        self._wire(
            tmp_path, monkeypatch, labels, {"a.c:f": "finding"},
        )
        run_corpus.main([
            "--output", str(tmp_path / "r1.json"), "--label", "a.c:f",
        ])
        runs, _ = history_mod.load_store(tmp_path / "history.jsonl")
        assert runs[-1]["selection"] == {"class": None, "labels": ["a.c:f"]}

        self._wire(tmp_path, monkeypatch, labels,
                   {"a.c:f": "finding", "a.c:g": "finding"})
        run_corpus.main(["--output", str(tmp_path / "r2.json")])
        runs, _ = history_mod.load_store(tmp_path / "history.jsonl")
        assert runs[-1]["selection"] == "full"

    def test_refire_prints_delta_against_prior_run(
        self, tmp_path, monkeypatch, capsys,
    ):
        labels = [self._label_for("a.c:f"), self._label_for("a.c:g")]

        # Run 1 (full): label misses — clean where finding expected.
        self._wire(tmp_path, monkeypatch, labels, {})
        run_corpus.main(["--output", str(tmp_path / "r1.json")])
        capsys.readouterr()

        # Run 2 (refire of the fixed label): now a finding.
        self._wire(tmp_path, monkeypatch, labels, {"a.c:f": "finding"})
        run_corpus.main([
            "--output", str(tmp_path / "r2.json"), "--label", "a.c:f",
        ])
        out = capsys.readouterr().out
        assert "Refire deltas" in out
        assert (
            "a.c:f: clean -> finding (expected finding) — "
            "IMPROVED, now matches [vs r1]" in out
        )

    def test_full_runs_print_no_delta_block(
        self, tmp_path, monkeypatch, capsys,
    ):
        labels = [self._label_for("a.c:f")]
        self._wire(tmp_path, monkeypatch, labels, {})
        run_corpus.main(["--output", str(tmp_path / "r1.json")])
        self._wire(tmp_path, monkeypatch, labels, {"a.c:f": "finding"})
        run_corpus.main(["--output", str(tmp_path / "r2.json")])
        assert "Refire deltas" not in capsys.readouterr().out


class TestRaptorDirPin:
    """main() pins RAPTOR_DIR to this tree for its OWN process — the
    in-process orchestrator resolves engine assets (standing cocci
    rules) through os.environ, and an ambient value from the launching
    shell can point at a different checkout (whose rule set would then
    silently replace this tree's)."""

    def test_main_pins_own_tree(self, monkeypatch, tmp_path):
        import os

        import core.config as cfg

        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path / "other-checkout"))
        # Label loading happens after the pin; an unmatched --label
        # exits non-zero without spending anything.
        rc = run_corpus.main(["--dry-run", "--label", "no/such:label"])
        assert rc != 0
        own = str(Path(cfg.__file__).resolve().parents[2])
        assert os.environ["RAPTOR_DIR"] == own


class TestLlmCacheKnob:
    """--no-llm-cache must arm RAPTOR_LLM_CACHE=off before the audit
    runs (every LLMConfig constructed downstream reads it) and record
    the setting in results.json meta — a refire graded against cache
    replays proves nothing about the fix being measured."""

    def _label_for(self, fid="a.c:f", file="a.c"):
        return SimpleNamespace(
            function_id=fid,
            bug_class="auth",
            expected_status="clean",
            expected_mechanism="",
            expected_mode_results={},
            source=SimpleNamespace(
                repo="test", sha="x", file=file, line_start=1, line_end=6,
            ),
        )

    def _run_main(self, tmp_path, monkeypatch, argv):
        from contextlib import contextmanager

        import os

        import core.audit.corpus.label as label_mod

        @contextmanager
        def fake_project(run_tag):
            yield f"corpus-{run_tag}"

        src = tmp_path / "repo"
        src.mkdir(exist_ok=True)
        (src / "a.c").write_text("int f(void) { return 0; }\n")

        monkeypatch.setattr(
            label_mod, "load_all_labels",
            lambda bug_class=None: [self._label_for()],
        )
        monkeypatch.setattr(
            run_corpus, "_resolve_source_dirs",
            lambda labels, do_fetch=False: {"test": src},
        )
        monkeypatch.setattr(
            run_corpus, "_corpus_project_context", fake_project,
        )
        captured = {}

        def fake_ensemble(labels, dirs, **kw):
            captured["env"] = os.environ.get("RAPTOR_LLM_CACHE")
            return (
                [dict(_result_row("a.c:f", "clean", "clean"), model="")],
                [],
            )

        monkeypatch.setattr(
            run_corpus, "_run_ensemble_audit", fake_ensemble,
        )
        out = tmp_path / "results.json"
        run_corpus.main(["--output", str(out), *argv])
        return json.loads(out.read_text())["meta"], captured

    def test_default_records_cache_on(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_CACHE", "")
        meta, captured = self._run_main(tmp_path, monkeypatch, [])
        assert meta["llm_cache"] == "on"
        assert captured["env"] == ""  # untouched by the runner

    def test_no_llm_cache_arms_env_and_meta(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAPTOR_LLM_CACHE", "")
        meta, captured = self._run_main(
            tmp_path, monkeypatch, ["--no-llm-cache"],
        )
        assert meta["llm_cache"] == "off"
        assert captured["env"] == "off", (
            "cache bypass must be armed in the environment BEFORE "
            "the audit pipeline runs"
        )

    def test_bypassed_config_disables_caching(self, tmp_path, monkeypatch):
        # The armed environment reaches a fresh LLMConfig — the whole
        # point of the knob.
        monkeypatch.setenv("RAPTOR_LLM_CACHE", "off")
        from core.llm.config import LLMConfig
        assert LLMConfig().enable_caching is False


class TestPhase2Calibration:
    """The corpus phase-2 pass and the in-run classifier must judge
    with the SAME calibrated ruleset — an uncalibrated twin of the
    prompt reliably demotes CWE-362 shared-state races to quality."""

    def test_corpus_prompt_carries_shared_calibration(self):
        import inspect

        from core.audit.security_classifier import CALIBRATION_RULES

        src = inspect.getsource(run_corpus._run_phase2_classify)
        assert "CALIBRATION_RULES" in src
        # The shared rules cover both the stream-consumer and the
        # check-then-create shared-registry race mechanisms.
        assert "check-then-create" in CALIBRATION_RULES
        assert "concurrent" in CALIBRATION_RULES

    def test_in_run_classifier_carries_same_rules(self):
        from core.audit.security_classifier import (
            CALIBRATION_RULES,
            _CLASSIFICATION_SYSTEM,
        )

        assert CALIBRATION_RULES in _CLASSIFICATION_SYSTEM

    def test_classify_sends_calibrated_system_prompt(self, monkeypatch):
        captured = {}

        class _Resp:
            cost = 0.0
            content = '{"is_security": true}'

        class _Client:
            class config:  # noqa: N801 - stand-in namespace
                @staticmethod
                def config_for_model(name):
                    raise ValueError

            def generate_structured(self, prompt, schema, *,
                                    system_prompt="", **kw):
                captured["system"] = system_prompt
                return _Resp()

        monkeypatch.setattr(
            "core.llm.client.LLMClient", lambda *a, **kw: _Client(),
        )
        monkeypatch.setattr(
            run_corpus, "structured_result",
            lambda *a, **kw: {
                "classification": "security_finding",
                "is_security": True,
                "primitive": "corruption",
            },
        )
        rows = [{
            "function_id": "a.go:W",
            "actual": "suspicious",
            "expected": "finding",
            "hypothesis": "unsynchronized concurrent write",
        }]
        run_corpus._run_phase2_classify(rows)
        from core.audit.security_classifier import CALIBRATION_RULES
        assert CALIBRATION_RULES in captured["system"]
        assert rows[0]["phase2_is_security"] is True


class TestQualitySuppressionNullPrimitive:
    """A null primitive from the classifier is the same ruling as the
    string "none" — it must not exempt a quality finding from
    suppression."""

    def _row(self, primitive):
        return {
            "function_id": "a.go:NS.Scan",
            "expected": "clean",
            "actual": "suspicious",
            "evidence_tool": "",
            "phase2_classification": "quality_finding",
            "phase2_is_security": False,
            "phase2_primitive": primitive,
        }

    def test_null_primitive_suppressed(self):
        rows = [self._row(None)]
        assert run_corpus._suppress_quality_findings(rows) == 1
        assert rows[0]["actual"] == "clean"

    def test_real_primitive_not_suppressed(self):
        rows = [self._row("write")]
        assert run_corpus._suppress_quality_findings(rows) == 0
        assert rows[0]["actual"] == "suspicious"


class TestReceiptFlooredSuppressionExemption:
    """A deterministic gate floor is mechanical evidence — the phase-2
    quality suppression must not un-do it."""

    def _row(self, floored):
        return {
            "function_id": "a.go:W",
            "expected": "finding",
            "actual": "suspicious",
            "evidence_tool": "",
            "receipt_floored": floored,
            "phase2_classification": "quality_finding",
            "phase2_is_security": False,
            "phase2_primitive": "none",
        }

    def test_floored_row_survives(self):
        rows = [self._row(True)]
        assert run_corpus._suppress_quality_findings(rows) == 0
        assert rows[0]["actual"] == "suspicious"

    def test_unfloored_row_suppressed(self):
        rows = [self._row(False)]
        assert run_corpus._suppress_quality_findings(rows) == 1

    def test_flag_threaded_from_gate_rows(self, tmp_path):
        import json

        from core.audit.corpus.run_corpus import (
            _parse_audit_log_outcomes,
        )
        log = tmp_path / ".audit-log.jsonl"
        rows = [
            {"action": "orchestrator_review", "key": "a.go:W:5",
             "status": "clean"},
            {"action": "refutation_gate", "key": "a.go:W:5",
             "gate": "receipt_corroborated_hypothesis",
             "applied": True, "demote_to": "suspicious"},
            {"action": "orchestrator_review", "key": "a.go:W:5",
             "status": "suspicious", "final_status_correction": True},
        ]
        log.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        o, _ = _parse_audit_log_outcomes(log)
        assert o["a.go:W"]["receipt_floored"] is True
        assert o["a.go:W"]["status"] == "suspicious"


class TestExcerptTreeKeepalive:
    """Excerpt trees are reaper-listed (corpus-excerpt-): written once,
    then read for a possibly multi-day run — mtime-quiet while live —
    so the builder holds a scratch keepalive per tree until the corpus
    loop releases it."""

    @pytest.fixture(autouse=True)
    def _isolated(self, monkeypatch, tmp_path):
        import tempfile

        from core.run import scratch as scratch_mod
        monkeypatch.setattr(scratch_mod, "_keepalive_paths", set())
        # Keep the mkdtemp inside the test's private tmp.
        monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    def test_registered_until_release(self, tmp_path):
        from core.run import scratch as scratch_mod

        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text("int x;")
        dirs = run_corpus._build_excerpt_tree(
            [_label(repo="r", file="a.c")], {"r": src})
        assert dirs, "excerpt tree not built"
        for d in dirs.values():
            assert str(d) in scratch_mod._keepalive_paths
        run_corpus._release_excerpt_trees(dirs)
        for d in dirs.values():
            assert str(d) not in scratch_mod._keepalive_paths
            assert not d.exists()
