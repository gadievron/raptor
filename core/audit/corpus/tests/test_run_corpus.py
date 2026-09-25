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


_RXKAD_KEY = "net/rxrpc/rxkad.c:rxkad_verify_packet_2"

_RXKAD_RECEIPT = {
    "file": "net/rxrpc/rxkad.c",
    "function": "rxkad_verify_packet_2",
    "detector": "cocci:scatterlist_frag_undersize",
    "line": 510,
    "description": (
        "scatterlist sized from bare fragment count "
        "'skb_shinfo(skb)->nr_frags' at line 510 but 'skb' is mapped "
        "via skb_to_sgvec at line 520"
    ),
}


def _fence_lane(tmp_path, name, mech, suppressions=None):
    import json

    lane = tmp_path / name
    grp = lane / "linux-kernel"
    grp.mkdir(parents=True)
    (grp / "mechanical-findings.json").write_text(json.dumps(mech))
    if suppressions:
        with (grp / "suppressions.jsonl").open("w") as fh:
            for rec in suppressions:
                fh.write(json.dumps(rec) + "\n")
    return lane


class TestMergeFenceReceiptStands:
    """Merge-lane receipt fence: a standing floor-class detector
    receipt with no mechanical refutation blocks the Phase-2
    quality suppression from minting clean — prose may not override
    a standing receipt; a recorded proof-grade refutation may."""

    def _row(self, **over):
        row = {
            "function_id": _RXKAD_KEY,
            "expected": "suspicious",
            "actual": "suspicious",
            "evidence_tool": "",
            "receipt_floored": False,
            "phase2_classification": "quality_finding",
            "phase2_is_security": False,
            "phase2_primitive": "none",
        }
        row.update(over)
        return row

    def _index(self, tmp_path, suppressions=None):
        from core.audit.merge_fence import load_standing_receipts

        lane = _fence_lane(
            tmp_path, "lane-sec", {_RXKAD_KEY: [_RXKAD_RECEIPT]},
            suppressions=suppressions,
        )
        return load_standing_receipts([lane])

    def test_unrefuted_receipt_blocks_clean(self, tmp_path):
        import json

        rows = [self._row()]
        n = run_corpus._suppress_quality_findings(
            rows,
            receipt_index=self._index(tmp_path),
            record_dir=tmp_path / "merged",
        )
        assert n == 0
        assert rows[0]["actual"] == "suspicious"
        assert rows[0]["merge_fence"] == "receipt_stands"
        assert not rows[0].get("phase2_suppressed")
        sink = tmp_path / "merged" / "suppressions.jsonl"
        recs = [json.loads(ln) for ln in sink.read_text().splitlines()]
        assert [r["verdict"] for r in recs] == [
            "merge_fence_receipt_stands",
        ]
        assert recs[0]["dropped"] is False
        assert recs[0]["receipts"] == [
            "cocci:scatterlist_frag_undersize",
        ]

    def test_tool_refuted_receipt_allows_clean(self, tmp_path):
        from core.audit.refutation import DOMINANCE_VERDICT

        dominance = {
            "file_path": "net/rxrpc/rxkad.c",
            "function": "rxkad_verify_packet_2",
            "verdict": DOMINANCE_VERDICT,
            "receipt": "cocci:scatterlist_frag_undersize",
            "dropped": False,
        }
        rows = [self._row()]
        n = run_corpus._suppress_quality_findings(
            rows,
            receipt_index=self._index(
                tmp_path, suppressions=[dominance],
            ),
            record_dir=tmp_path / "merged",
        )
        assert n == 1
        assert rows[0]["actual"] == "clean"
        assert "merge_fence" not in rows[0]
        assert not (tmp_path / "merged" / "suppressions.jsonl").exists()

    def test_no_receipt_untouched_by_fence(self, tmp_path):
        rows = [self._row(
            function_id="net/ipv4/esp4.c:esp_output_tail",
        )]
        n = run_corpus._suppress_quality_findings(
            rows,
            receipt_index=self._index(tmp_path),
            record_dir=tmp_path / "merged",
        )
        assert n == 1
        assert rows[0]["actual"] == "clean"
        assert "merge_fence" not in rows[0]
        assert not (tmp_path / "merged" / "suppressions.jsonl").exists()

    def test_grade_above_suspicious_never_lowered(self, tmp_path):
        rows = [self._row(actual="finding", expected="finding")]
        n = run_corpus._suppress_quality_findings(
            rows,
            receipt_index=self._index(tmp_path),
            record_dir=tmp_path / "merged",
        )
        assert n == 0
        assert rows[0]["actual"] == "finding"
        assert rows[0]["merge_fence"] == "receipt_stands"

    def test_security_ruling_never_engages_fence(self, tmp_path):
        # Phase 2 does not attempt a demotion — the fence has nothing
        # to block and must not touch the row.
        rows = [self._row(
            phase2_classification="security_finding",
            phase2_is_security=True,
        )]
        n = run_corpus._suppress_quality_findings(
            rows,
            receipt_index=self._index(tmp_path),
            record_dir=tmp_path / "merged",
        )
        assert n == 0
        assert rows[0]["actual"] == "suspicious"
        assert "merge_fence" not in rows[0]
        assert not (tmp_path / "merged" / "suppressions.jsonl").exists()

    def test_record_failure_fence_still_holds(self, tmp_path, caplog):
        import logging

        blocker = tmp_path / "merged"
        blocker.write_text("a file where the record dir should be")
        rows = [self._row()]
        with caplog.at_level(
            logging.WARNING, "core.audit.merge_fence",
        ):
            n = run_corpus._suppress_quality_findings(
                rows,
                receipt_index=self._index(tmp_path),
                record_dir=blocker,
            )
        assert n == 0
        assert rows[0]["actual"] == "suspicious"
        assert rows[0]["merge_fence"] == "receipt_stands"
        assert any(
            "fence still holds" in r.message for r in caplog.records
        )

    def test_unarmed_call_keeps_prior_behavior(self):
        # Without a receipt index (legacy call shape) the suppression
        # demotes exactly as before — the fence is merge-lane opt-in.
        rows = [self._row()]
        assert run_corpus._suppress_quality_findings(rows) == 1
        assert rows[0]["actual"] == "clean"


class TestMergeFenceRxkadMergeCleanRegression:
    """The rxkad merge-level wrong-clean shape: both lanes graded
    rxkad_verify_packet_2 suspicious with the
    cocci:scatterlist_frag_undersize receipt standing in BOTH lanes'
    mechanical findings and no lane floor fired; the ensemble Phase-2
    quality classification then minted a merge-level clean from prose
    (callee-enforced bound).  The fence must hold the merged grade at
    suspicious with an audit record — and must not shield the
    receipt-free sibling (esp_output_tail) from the same Phase-2
    demotion."""

    def test_merge_clean_attempt_holds_suspicious(self, tmp_path):
        import json

        from core.audit.merge_fence import load_standing_receipts

        leak_hits = [
            {"file": "net/rxrpc/rxkad.c",
             "function": "rxkad_verify_packet_2",
             "detector": "cocci:resource_leak_err", "line": 516},
            {"file": "net/rxrpc/rxkad.c",
             "function": "rxkad_verify_packet_2",
             "detector": "cocci:resource_leak_err", "line": 541},
        ]
        mech = {_RXKAD_KEY: [*leak_hits, _RXKAD_RECEIPT]}
        sec = _fence_lane(tmp_path, "run-out-sec", mech)
        bf = _fence_lane(tmp_path, "run-out-bf", mech)
        base_out = tmp_path / "run-out"
        base_out.mkdir()

        rxkad = {
            "function_id": _RXKAD_KEY,
            "bug_class": "variant",
            "repo": "linux-kernel",
            "expected": "suspicious",
            "mode": "ensemble",
            "actual": "suspicious",
            "match": True,
            "hypothesis": (
                "The scatterlist table sized from nr_frags+1 (line "
                "510) can be overrun by skb_to_sgvec when the skb "
                "carries a frag_list, causing an out-of-bounds write."
            ),
            "evidence_tool": (
                "llm-claimed:cocci:scatterlist_frag_undersize L510 — "
                "structural match confirmed (nsg omits frag_list), "
                "exploit conclusion refuted by callee-enforced "
                "-EMSGSIZE bound in skb_to_sgvec, handled at line 521"
            ),
            "receipt_floored": False,
            "ensemble_source": "both_agree",
            "security_actual": "suspicious",
            "bug_first_actual": "suspicious",
            # Phase-2 clean attempt: quality ruling, no primitive —
            # the exact shape that minted the wrong clean.
            "phase2_classification": "quality_finding",
            "phase2_is_security": False,
            "phase2_primitive": "none",
        }
        esp = {
            "function_id": "net/ipv4/esp4.c:esp_output_tail",
            "expected": "clean",
            "actual": "suspicious",
            "evidence_tool": "",
            "receipt_floored": False,
            "phase2_classification": "quality_finding",
            "phase2_is_security": False,
            "phase2_primitive": "none",
        }
        rows = [rxkad, esp]

        n = run_corpus._suppress_quality_findings(
            rows,
            receipt_index=load_standing_receipts([sec, bf]),
            record_dir=base_out,
        )

        # rxkad: held at suspicious over the standing receipt.
        assert rxkad["actual"] == "suspicious"
        assert rxkad["merge_fence"] == "receipt_stands"
        assert rxkad["merge_fence_receipts"] == [
            "cocci:scatterlist_frag_undersize",
        ]
        # esp: no floor-class receipt — the Phase-2 demotion stands.
        assert n == 1
        assert esp["actual"] == "clean"
        assert "merge_fence" not in esp

        recs = [
            json.loads(ln)
            for ln in (base_out / "suppressions.jsonl")
            .read_text().splitlines()
        ]
        assert len(recs) == 1
        assert recs[0]["verdict"] == "merge_fence_receipt_stands"
        assert recs[0]["dropped"] is False
        assert recs[0]["function"] == "rxkad_verify_packet_2"
        assert recs[0]["held_status"] == "suspicious"


class _FenceLabel:
    def __init__(self, fid):
        self.function_id = fid


def _ensemble_row(fid, actual, **over):
    r = {"function_id": fid, "expected": "clean", "actual": actual,
         "evidence_tool": "", "cost_usd": 0.0, "duration_s": 0.0,
         "match": False, "counter_hypothesis": "",
         "hypothesis": "structural overflow claim", "model": "stub"}
    r.update(over)
    return r


def _live_ensemble_merge(
    tmp_path, monkeypatch, sec_rows, bf_rows,
    mech_sec=None, mech_bf=None, phase2=None, shape="fresh",
):
    """Drive the REAL _run_ensemble_audit with stubbed lane passes
    and a stubbed Phase-2 classifier.

    *shape* selects which faithful path shape the stubbed lane pass
    reproduces — the fence must engage on BOTH:

    * ``"fresh"`` (the primary path): ``_run_audit`` returns the
      PER-GROUP audit dirs (``<lane>/grp``) as its run dirs, and
      fresh rows carry ``repo=<group>`` (callers stamp them);
    * ``"resume"``: the checkpoint-resume branch has only the lane
      ROOTS, and legacy checkpoint rows may carry no repo.
    """
    import core.llm.concurrency as conc

    out = tmp_path / "ens-out"
    sec_dir = Path(str(out) + "-sec")
    bf_dir = Path(str(out) + "-bf")
    for d, mech in ((sec_dir, mech_sec), (bf_dir, mech_bf)):
        (d / "grp").mkdir(parents=True, exist_ok=True)
        if mech is not None:
            (d / "grp" / "mechanical-findings.json").write_text(
                json.dumps(mech),
            )
    sec_ret = sec_dir / "grp" if shape == "fresh" else sec_dir
    bf_ret = bf_dir / "grp" if shape == "fresh" else bf_dir

    def fake_run_audit(labels, source_dirs, **kw):
        if kw.get("mode") == "security":
            return [dict(r) for r in sec_rows], [sec_ret]
        wanted = {lb.function_id for lb in labels}
        return [
            dict(r) for r in bf_rows if r["function_id"] in wanted
        ], [bf_ret]

    def fake_phase2(findings, *, model=""):
        for f in findings:
            over = (phase2 or {}).get(f["function_id"], {})
            f["phase2_classification"] = over.get(
                "cls", "quality_finding",
            )
            f["phase2_is_security"] = over.get("sec", False)
            f["phase2_primitive"] = over.get("prim", "none")
        return 0.0

    monkeypatch.setattr(run_corpus, "_run_audit", fake_run_audit)
    monkeypatch.setattr(
        run_corpus, "_run_phase2_classify", fake_phase2,
    )
    monkeypatch.setattr(
        run_corpus, "_start_shared_joern", lambda dirs: None,
    )
    monkeypatch.setattr(conc, "derive_max_workers", lambda model: 1)
    labels = [_FenceLabel(r["function_id"]) for r in sec_rows]
    merged, _run_dirs = run_corpus._run_ensemble_audit(
        labels, {"grp": tmp_path / "nonexistent-src"},
        model="stub", out_dir=out,
    )
    return merged, out


class TestMergeFloorFlagSurvivesMerge:
    """A lane floor that fired (receipt_floored) is mechanical
    evidence; the ensemble merge must carry it on the merged row
    regardless of which lane's row wins — a winner copied from the
    other lane used to drop the flag, letting Phase-2 mint clean over
    a FIRED structural floor."""

    def test_bf_winner_keeps_sec_lane_floor_flag(
        self, tmp_path, monkeypatch,
    ):
        sec_rows = [_ensemble_row(
            "x.c:victim", "suspicious", receipt_floored=True,
        )]
        bf_rows = [_ensemble_row("x.c:victim", "finding")]
        merged, _out = _live_ensemble_merge(
            tmp_path, monkeypatch, sec_rows, bf_rows,
        )
        (m,) = merged
        assert m["receipt_floored"] is True
        assert m["actual"] != "clean"
        assert not m.get("phase2_suppressed")

    def test_floored_winner_still_exempt(self, tmp_path, monkeypatch):
        # Control: the floored row itself wins the merge.
        sec_rows = [_ensemble_row(
            "x.c:victim", "suspicious", receipt_floored=True,
        )]
        bf_rows = [_ensemble_row("x.c:victim", "suspicious")]
        merged, _out = _live_ensemble_merge(
            tmp_path, monkeypatch, sec_rows, bf_rows,
        )
        assert merged[0]["actual"] == "suspicious"

    def test_unfloored_rows_unaffected(self, tmp_path, monkeypatch):
        # No lane floor fired: the Phase-2 demotion proceeds as
        # before.
        sec_rows = [_ensemble_row("x.c:victim", "suspicious")]
        bf_rows = [_ensemble_row("x.c:victim", "finding")]
        merged, _out = _live_ensemble_merge(
            tmp_path, monkeypatch, sec_rows, bf_rows,
        )
        assert merged[0]["actual"] == "clean"
        assert merged[0]["receipt_floored"] is False


class TestMergeFenceLiveEnsemble:
    """The fence through the REAL ensemble merge: standing receipt in
    the lanes' artifacts + Phase-2 clean attempt.  Exercised on BOTH
    faithful path shapes — the fresh path (per-group run dirs,
    repo-stamped rows: the incident's own path) and the
    checkpoint-resume path (lane roots, legacy repo-less rows)."""

    def _assert_fenced(self, merged, out):
        import json as _json

        (m,) = merged
        assert m["actual"] == "suspicious"
        assert m["merge_fence"] == "receipt_stands"
        sink = out / "suppressions.jsonl"
        recs = [
            _json.loads(ln) for ln in sink.read_text().splitlines()
        ]
        fence = [
            r for r in recs
            if r.get("verdict") == "merge_fence_receipt_stands"
        ]
        assert len(fence) == 1
        assert fence[0]["dropped"] is False

    def test_fresh_path_receipt_holds(self, tmp_path, monkeypatch):
        # The primary path: _run_audit returns per-group dirs and
        # stamps rows with their repo group.  A group-resolution
        # regression here unarms the fence on every fresh run.
        mech = {_RXKAD_KEY: [_RXKAD_RECEIPT]}
        sec_rows = [_ensemble_row(
            _RXKAD_KEY, "suspicious", repo="grp",
        )]
        bf_rows = [_ensemble_row(
            _RXKAD_KEY, "suspicious", repo="grp",
        )]
        merged, out = _live_ensemble_merge(
            tmp_path, monkeypatch, sec_rows, bf_rows,
            mech_sec=mech, mech_bf=mech, shape="fresh",
        )
        self._assert_fenced(merged, out)

    def test_resume_path_receipt_holds(self, tmp_path, monkeypatch):
        mech = {_RXKAD_KEY: [_RXKAD_RECEIPT]}
        sec_rows = [_ensemble_row(_RXKAD_KEY, "suspicious")]
        bf_rows = [_ensemble_row(_RXKAD_KEY, "suspicious")]
        merged, out = _live_ensemble_merge(
            tmp_path, monkeypatch, sec_rows, bf_rows,
            mech_sec=mech, mech_bf=mech, shape="resume",
        )
        self._assert_fenced(merged, out)


class TestMergeFenceUnarmedNotice:
    """Resume with the lane out-dirs deleted: the fence cannot read
    receipts — it unarms with a printed notice (never silently) and
    Phase-2 behaves as before the fence existed."""

    def test_notice_printed_and_demotion_proceeds(
        self, tmp_path, monkeypatch, capsys,
    ):
        import core.llm.concurrency as conc

        out = tmp_path / "run-out"
        out.mkdir()
        stamp = {
            "model": "stub", "profile": "deployed",
            "triage": True, "prefilter": True,
        }
        rows = [_ensemble_row(_RXKAD_KEY, "suspicious")]
        for name in ("checkpoint-sec.json", "checkpoint-bf.json"):
            (out / name).write_text(
                json.dumps({"stamp": stamp, "rows": rows}),
            )
        # lane out dirs (run-out-sec / run-out-bf) deliberately absent

        def fake_phase2(findings, *, model=""):
            for f in findings:
                f["phase2_classification"] = "quality_finding"
                f["phase2_is_security"] = False
                f["phase2_primitive"] = "none"
            return 0.0

        monkeypatch.setattr(
            run_corpus, "_run_phase2_classify", fake_phase2,
        )
        monkeypatch.setattr(
            run_corpus, "_start_shared_joern", lambda dirs: None,
        )
        monkeypatch.setattr(
            conc, "derive_max_workers", lambda model: 1,
        )
        merged, _dirs = run_corpus._run_ensemble_audit(
            [_FenceLabel(_RXKAD_KEY)],
            {"grp": out / "nosrc"}, model="stub", out_dir=out,
        )
        assert "fence unarmed" in capsys.readouterr().out
        assert merged[0]["actual"] == "clean"


class TestExcerptIncludeClosure:
    """Excerpt trees carry the headers each labelled C file includes,
    so source-level macro-expansion witnesses behave the same in
    excerpt and full scope."""

    def _repo(self, tmp_path):
        src = tmp_path / "repo"
        (src / "include" / "mini").mkdir(parents=True)
        (src / "drivers").mkdir()
        (src / "include" / "mini" / "iter.h").write_text(
            "#include <mini/base.h>\n#define ITER(x) for (;;)\n",
        )
        (src / "include" / "mini" / "base.h").write_text(
            "#define BASE 1\n",
        )
        (src / "include" / "mini" / "unrelated.h").write_text(
            "#define OTHER 2\n",
        )
        (src / "drivers" / "d.c").write_text(
            "#include <mini/iter.h>\nint f(void) { return BASE; }\n",
        )
        return src

    def test_labelled_c_file_brings_its_closure(self, tmp_path):
        src = self._repo(tmp_path)
        dirs = run_corpus._build_excerpt_tree(
            [_label(repo="r", file="drivers/d.c", fid="drivers/d.c:f")],
            {"r": src},
        )
        try:
            tree = dirs["r"]
            assert (tree / "drivers" / "d.c").is_file()
            assert (tree / "include" / "mini" / "iter.h").is_file()
            assert (tree / "include" / "mini" / "base.h").is_file()
            # Only the closure, not the whole header tree.
            assert not (
                tree / "include" / "mini" / "unrelated.h"
            ).exists()
        finally:
            run_corpus._release_excerpt_trees(dirs)

    def test_non_c_labels_copy_nothing_extra(self, tmp_path):
        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.go").write_text("package p\n")
        dirs = run_corpus._build_excerpt_tree(
            [_label(repo="r", file="a.go", fid="a.go:f")], {"r": src},
        )
        try:
            assert sorted(
                p.name for p in dirs["r"].rglob("*") if p.is_file()
            ) == ["a.go"]
        finally:
            run_corpus._release_excerpt_trees(dirs)

    def test_unresolvable_closure_is_best_effort(self, tmp_path):
        src = tmp_path / "repo"
        src.mkdir()
        (src / "a.c").write_text(
            "#include <nowhere/gone.h>\nint f(void) { return 0; }\n",
        )
        dirs = run_corpus._build_excerpt_tree(
            [_label(repo="r", file="a.c", fid="a.c:f")], {"r": src},
        )
        try:
            assert (dirs["r"] / "a.c").is_file()
        finally:
            run_corpus._release_excerpt_trees(dirs)


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

def _stub_main_run(
    tmp_path,
    monkeypatch,
    *,
    rows=None,
    run_dirs=None,
    argv=None,
    source_present=True,
    resolve=lambda m: "",
    labels=None,
    source_text=None,
    ensemble=None,
):
    """Drive main() with the LLM run stubbed out.

    Sets up one label (a.c:f in repo "test", overridable via
    *labels* / *source_text*), a fake project context, stubbed pin
    verification, deterministic model resolution (*resolve*, so run
    stamps never depend on the host's LLM config), and an isolated
    history store; the ensemble stub returns *rows* and *run_dirs*
    (or use *ensemble* for a capturing stub).  Returns
    ``(rc, results_path, history_path)``.
    """
    from contextlib import contextmanager

    import core.audit.corpus.history as history_mod
    import core.audit.corpus.label as label_mod
    import core.audit.corpus.lint as lint_mod

    @contextmanager
    def fake_project(run_tag):
        yield f"corpus-{run_tag}"

    src = tmp_path / "repo"
    if source_present:
        src.mkdir(exist_ok=True)
        (src / "a.c").write_text(
            source_text
            if source_text is not None else
            "int f(void) { return 0; }\n"
            "int pad1;\nint pad2;\nint pad3;\nint pad4;\n",
        )
    if labels is None:
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
        run_corpus, "_resolve_model_label", resolve, raising=False,
    )
    monkeypatch.setattr(
        lint_mod, "verify_pins",
        lambda pairs, **kw: [
            lint_mod.PinCheck(
                label=lb, path=None, outcome="no-fixture", detail="",
            )
            for _, lb in pairs
        ],
    )
    monkeypatch.setattr(
        run_corpus, "_run_ensemble_audit",
        ensemble if ensemble is not None else (
            lambda labels, dirs, **kw: (
                list(rows or []), list(run_dirs or []),
            )
        ),
    )
    history_path = tmp_path / "history.jsonl"
    monkeypatch.setenv(history_mod.HISTORY_ENV, str(history_path))
    out = tmp_path / "results.json"
    rc = run_corpus.main(["--output", str(out), *(argv or [])])
    return rc, out, history_path


def _run_stamp(**overrides):
    """The run stamp main() derives under _stub_main_run's defaults."""
    stamp = {
        "mode": "ensemble",
        "model": "default",
        "model_resolved": "default",
        "profile": "cold",
        "triage": "off",
        "prefilter": "off",
        "scope": "excerpt",
    }
    stamp.update(overrides)
    return stamp


def _meta_of(results_path):
    data = json.loads(results_path.read_text())
    assert isinstance(data, dict), "results file has no meta wrapper"
    return data["meta"]


class TestResolvedModelBanner:
    """The transport actually used must be stated before any prep or
    spend, and recorded resolved in meta — the first provider line
    used to appear only once group 1 started, and meta said
    model="default"."""

    def test_resolved_model_printed_early_and_recorded_in_meta(
        self, tmp_path, monkeypatch, capsys,
    ):
        rc, out, _ = _stub_main_run(
            tmp_path, monkeypatch,
            rows=[dict(_result_row("a.c:f"), model="")],
            resolve=lambda m: "prov/model-x",
        )
        assert rc == 0
        stdout = capsys.readouterr().out
        banner = "Primary model: prov/model-x (default resolution)"
        assert banner in stdout
        assert stdout.index(banner) < stdout.index("Pin verification")
        assert _meta_of(out)["model_resolved"] == "prov/model-x"

    def test_resolution_failure_falls_back_to_requested_name(
        self, tmp_path, monkeypatch, capsys,
    ):
        rc, out, _ = _stub_main_run(
            tmp_path, monkeypatch,
            rows=[dict(_result_row("a.c:f"), model="")],
            resolve=lambda m: "",
        )
        assert rc == 0
        assert "Primary model: default" in capsys.readouterr().out
        assert _meta_of(out)["model_resolved"] == "default"


class TestDryRunSourceCensus:
    """--dry-run must account for fixture sources explicitly: pins can
    verify against git history while zero fixtures are checked out, and
    a "verified, exit 0" dry run invites launching a run in which every
    missing-source label scores error."""

    def test_missing_sources_exit_nonzero_and_point_at_fetch(
        self, tmp_path, monkeypatch, capsys,
    ):
        rc, _, _ = _stub_main_run(
            tmp_path, monkeypatch,
            argv=["--dry-run"], source_present=False,
        )
        assert rc == 1
        captured = capsys.readouterr()
        assert "Sources: 0/1 present, 1 missing" in captured.out
        assert "--fetch" in captured.err
        assert "1/1 label source(s) missing" in captured.err

    def test_present_sources_keep_verified_exit_zero(
        self, tmp_path, monkeypatch, capsys,
    ):
        rc, _, _ = _stub_main_run(
            tmp_path, monkeypatch, argv=["--dry-run"],
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "Sources: 1/1 present, 0 missing" in out
        assert "labels verified" in out


class TestSpendMetaBreakdown:
    """meta carries all three spend figures under distinct names:
    label-attributed (row sums), telemetry total (money actually
    spent), and infra (their difference) — they can disagree by 3x
    and a ceiling decision needs to know which one it is comparing."""

    def test_meta_records_attributed_infra_total(
        self, tmp_path, monkeypatch,
    ):
        gdir = tmp_path / "run" / "test"
        gdir.mkdir(parents=True)
        telemetry = gdir / "llm-telemetry.jsonl"
        telemetry.write_text(
            json.dumps({"cost_usd": 2.5, "call_class": "review"}) + "\n"
            + json.dumps({"cost_usd": 2.5, "call_class": "study"}) + "\n",
        )
        rows = [
            dict(_result_row("a.c:f"), model="", cost_usd=2.0),
        ]
        rc, out, _ = _stub_main_run(
            tmp_path, monkeypatch,
            rows=rows, run_dirs=[tmp_path / "run"],
        )
        assert rc == 0
        meta = _meta_of(out)
        assert meta["label_attributed_usd"] == 2.0
        assert meta["cost_usd"] == 2.0  # legacy name, same figure
        assert meta["total_spend_usd"] == 5.0
        assert meta["infra_usd"] == 3.0

    def test_infra_measures_this_runs_rows_under_splice(
        self, tmp_path, monkeypatch,
    ):
        # --splice merges prior rows (with their costs) into the
        # headline attributed figure, but this run's telemetry only
        # covers this run's calls: infra must subtract the FRESH
        # rows, not the merged set.
        gdir = tmp_path / "run" / "test"
        gdir.mkdir(parents=True)
        (gdir / "llm-telemetry.jsonl").write_text(
            json.dumps({"cost_usd": 5.0, "call_class": "review"}) + "\n",
        )
        prior = tmp_path / "prior.json"
        prior.write_text(json.dumps([
            dict(_result_row("z.c:old"), model="", cost_usd=100.0),
        ]))
        rows = [dict(_result_row("a.c:f"), model="", cost_usd=2.0)]
        rc, out, _ = _stub_main_run(
            tmp_path, monkeypatch,
            rows=rows, run_dirs=[tmp_path / "run"],
            argv=["--splice", str(prior)],
        )
        assert rc == 0
        meta = _meta_of(out)
        # Headline attributed keeps its documented merged-set
        # semantics; infra reflects this run only (5 - 2), not a
        # clamp against the merged 102.
        assert meta["label_attributed_usd"] == 102.0
        assert meta["infra_usd"] == 3.0
        # The refire's own attributed spend is recorded explicitly.
        assert meta["label_attributed_fresh_usd"] == 2.0

    def test_group_progress_prints_attributed_running_total(
        self, tmp_path, monkeypatch, capsys,
    ):
        (tmp_path / "r1").mkdir()
        (tmp_path / "r2").mkdir()
        labels = [
            _mk_label("a.c:f", repo="r1"),
            _mk_label("b.c:g", file="b.c", repo="r2"),
        ]
        costs = {"r1": 1.5, "r2": 1.0}

        def fake_target_run(target_dir, repo_labels, **kw):
            cost = costs[repo_labels[0].source.repo]
            return (
                {
                    lb.function_id: {
                        "status": "clean",
                        "cost_usd": cost,
                        "duration_s": 0.1,
                    }
                    for lb in repo_labels
                },
                {},
                None,
            )

        monkeypatch.setattr(
            run_corpus, "_run_audit_on_target", fake_target_run,
        )
        run_corpus._run_audit(
            labels,
            {"r1": tmp_path / "r1", "r2": tmp_path / "r2"},
            joern_server=object(),
        )
        stdout = capsys.readouterr().out
        assert "$1.5000 this group, $1.5000 running total" in stdout
        assert "$1.0000 this group, $2.5000 running total" in stdout


class TestRunLevelRunningTotal:
    """The printed attributed running total is RUN-level: pass 2 of
    the ensemble seeds it with pass 1's spend, so a mid-pass-2 cost
    ceiling decision never compares against a per-pass fragment."""

    def test_attributed_start_seeds_running_total(
        self, tmp_path, monkeypatch, capsys,
    ):
        (tmp_path / "r1").mkdir()

        def fake_target_run(target_dir, repo_labels, **kw):
            return (
                {
                    lb.function_id: {
                        "status": "clean", "cost_usd": 1.5,
                        "duration_s": 0.1,
                    }
                    for lb in repo_labels
                },
                {}, None,
            )

        monkeypatch.setattr(
            run_corpus, "_run_audit_on_target", fake_target_run,
        )
        run_corpus._run_audit(
            [_mk_label("a.c:f", repo="r1")],
            {"r1": tmp_path / "r1"},
            joern_server=object(), attributed_start=10.0,
        )
        stdout = capsys.readouterr().out
        assert "$1.5000 this group, $11.5000 running total" in stdout

    def test_ensemble_seeds_pass2_with_pass1_spend(
        self, tmp_path, monkeypatch,
    ):
        starts = []

        def fake_run_audit(
            labels, dirs, *, mode=None, attributed_start=0.0, **kw,
        ):
            starts.append((mode, attributed_start))
            return (
                [
                    dict(
                        _result_row(lb.function_id, actual="suspicious"),
                        model="", cost_usd=3.0,
                    )
                    for lb in labels
                ],
                [],
            )

        monkeypatch.setattr(run_corpus, "_run_audit", fake_run_audit)
        monkeypatch.setattr(
            run_corpus, "_start_shared_joern", lambda dirs: None,
        )
        monkeypatch.setattr(
            run_corpus, "_run_phase2_classify",
            lambda findings, model="": 0.0,
        )
        (tmp_path / "r1").mkdir()
        (tmp_path / "r2").mkdir()
        labels = [
            _mk_label("a.c:f", repo="r1"),
            _mk_label("b.c:g", file="b.c", repo="r2"),
        ]
        run_corpus._run_ensemble_audit(
            labels,
            {"r1": tmp_path / "r1", "r2": tmp_path / "r2"},
            out_dir=tmp_path / "out",
        )
        assert starts[0] == ("security", 0.0)
        assert starts[1] == ("bug_first", 6.0)


def _stamped_ckpt(groups, **overrides):
    """Checkpoint payload carrying the default _run_audit stamp
    (mode security, default model, deployed profile, triage and
    prefilter on) — what a prior segment of the same run would have
    written."""
    stamp = {
        "mode": "security", "model": "", "profile": "deployed",
        "triage": True, "prefilter": True,
    }
    stamp.update(overrides)
    return {"stamp": stamp, "groups": groups}


class TestPerGroupCheckpoint:
    """A mid-pass stop loses at most the in-flight group: completed
    groups are checkpointed as they finish, and a resume replays their
    rows exactly once (no re-run, no double-counted spend)."""

    def _labels(self):
        return [
            _mk_label("a.c:f", repo="r1"),
            _mk_label("b.c:g", file="b.c", repo="r2"),
        ]

    def _dirs(self, tmp_path):
        (tmp_path / "r1").mkdir(exist_ok=True)
        (tmp_path / "r2").mkdir(exist_ok=True)
        return {"r1": tmp_path / "r1", "r2": tmp_path / "r2"}

    @staticmethod
    def _ckpt_row(fid, cost=2.0):
        return dict(
            _result_row(fid), model="", cost_usd=cost, duration_s=1.0,
        )

    def test_resume_skips_checkpointed_group_and_counts_rows_once(
        self, tmp_path, monkeypatch,
    ):
        ckpt = tmp_path / "ckpt.json"
        ckpt.write_text(json.dumps(
            _stamped_ckpt({"r1": [self._ckpt_row("a.c:f")]}),
        ))
        ran = []

        def fake_target_run(target_dir, repo_labels, **kw):
            ran.append(repo_labels[0].source.repo)
            return (
                {
                    lb.function_id: {
                        "status": "clean", "cost_usd": 0.5,
                        "duration_s": 0.1,
                    }
                    for lb in repo_labels
                },
                {}, None,
            )

        monkeypatch.setattr(
            run_corpus, "_run_audit_on_target", fake_target_run,
        )
        results, _ = run_corpus._run_audit(
            self._labels(), self._dirs(tmp_path),
            joern_server=object(), checkpoint=ckpt,
        )
        assert ran == ["r2"], "checkpointed group was re-run"
        fids = [r["function_id"] for r in results]
        assert sorted(fids) == ["a.c:f", "b.c:g"]
        # Resumed spend enters exactly once, at its original figure.
        assert sum(r["cost_usd"] for r in results) == 2.5
        # The checkpoint now covers both groups.
        saved = json.loads(ckpt.read_text())
        assert sorted(saved["groups"]) == ["r1", "r2"]

    def test_checkpoint_persists_after_each_group(
        self, tmp_path, monkeypatch,
    ):
        ckpt = tmp_path / "ckpt.json"

        def fake_target_run(target_dir, repo_labels, **kw):
            if repo_labels[0].source.repo == "r2":
                raise RuntimeError("simulated mid-pass stop")
            return (
                {
                    lb.function_id: {
                        "status": "clean", "cost_usd": 0.5,
                        "duration_s": 0.1,
                    }
                    for lb in repo_labels
                },
                {}, None,
            )

        monkeypatch.setattr(
            run_corpus, "_run_audit_on_target", fake_target_run,
        )
        with pytest.raises(RuntimeError):
            run_corpus._run_audit(
                self._labels(), self._dirs(tmp_path),
                joern_server=object(), checkpoint=ckpt,
            )
        saved = json.loads(ckpt.read_text())
        assert list(saved["groups"]) == ["r1"]
        assert saved["groups"]["r1"][0]["function_id"] == "a.c:f"

    def test_stale_checkpoint_with_different_label_set_reruns(
        self, tmp_path, monkeypatch,
    ):
        ckpt = tmp_path / "ckpt.json"
        ckpt.write_text(json.dumps(
            _stamped_ckpt({"r1": [self._ckpt_row("a.c:OTHER")]}),
        ))
        ran = []

        def fake_target_run(target_dir, repo_labels, **kw):
            ran.append(repo_labels[0].source.repo)
            return (
                {
                    lb.function_id: {
                        "status": "clean", "cost_usd": 0.5,
                        "duration_s": 0.1,
                    }
                    for lb in repo_labels
                },
                {}, None,
            )

        monkeypatch.setattr(
            run_corpus, "_run_audit_on_target", fake_target_run,
        )
        results, _ = run_corpus._run_audit(
            self._labels(), self._dirs(tmp_path),
            joern_server=object(), checkpoint=ckpt,
        )
        assert ran == ["r1", "r2"], "stale checkpoint was trusted"
        fids = sorted(r["function_id"] for r in results)
        assert fids == ["a.c:f", "b.c:g"]


class TestCheckpointModelGuard:
    """A checkpoint written under a different --model must never be
    resumed: its rows would mislabel another model's verdicts as this
    run's measurements."""

    def test_checkpoint_from_different_model_is_not_resumed(
        self, tmp_path, monkeypatch,
    ):
        (tmp_path / "r1").mkdir()
        ckpt = tmp_path / "ckpt.json"
        ckpt.write_text(json.dumps(_stamped_ckpt({"r1": [
            dict(_result_row("a.c:f"), model="other-model", cost_usd=9.0),
        ]})))
        ran = []

        def fake_target_run(target_dir, repo_labels, **kw):
            ran.append(repo_labels[0].source.repo)
            return (
                {
                    lb.function_id: {
                        "status": "clean", "cost_usd": 0.5,
                        "duration_s": 0.1,
                    }
                    for lb in repo_labels
                },
                {}, None,
            )

        monkeypatch.setattr(
            run_corpus, "_run_audit_on_target", fake_target_run,
        )
        results, _ = run_corpus._run_audit(
            [_mk_label("a.c:f", repo="r1")],
            {"r1": tmp_path / "r1"},
            joern_server=object(), checkpoint=ckpt,
        )
        assert ran == ["r1"], "foreign-model checkpoint was resumed"
        assert results[0]["model"] == ""
        assert results[0]["cost_usd"] == 0.5



class TestGroupHeartbeat:
    """The runner signals every completed group so the caller's
    wall-segment accounting stays accurate to the last group even
    when the process is killed mid-pass."""

    def _labels(self):
        return [
            _mk_label("a.c:f", repo="r1"),
            _mk_label("b.c:g", file="b.c", repo="r2"),
        ]

    def _dirs(self, tmp_path):
        (tmp_path / "r1").mkdir(exist_ok=True)
        (tmp_path / "r2").mkdir(exist_ok=True)
        return {"r1": tmp_path / "r1", "r2": tmp_path / "r2"}

    def test_heartbeat_invoked_per_group(self, tmp_path, monkeypatch):
        beats = []

        def fake_target_run(target_dir, repo_labels, **kw):
            return (
                {
                    lb.function_id: {
                        "status": "clean", "cost_usd": 0.0,
                        "duration_s": 0.0,
                    }
                    for lb in repo_labels
                },
                {}, None,
            )

        monkeypatch.setattr(
            run_corpus, "_run_audit_on_target", fake_target_run,
        )
        run_corpus._run_audit(
            self._labels(), self._dirs(tmp_path),
            joern_server=object(),
            heartbeat=lambda: beats.append(1),
        )
        assert len(beats) == 2


class TestWallSegments:
    """meta wall time accumulates across stop/resume segments — a
    resumed run used to report only the final process's wall."""

    def test_wall_accumulates_across_resume_segments(
        self, tmp_path, monkeypatch,
    ):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        (out_dir / "wall-segments.json").write_text(json.dumps(
            {
                "stamp": _run_stamp(),
                "segments": [{"start": 1000.0, "end": 1100.0}],
            },
        ))
        rc, out, _ = _stub_main_run(
            tmp_path, monkeypatch,
            rows=[dict(_result_row("a.c:f"), model="")],
            argv=["--out", str(out_dir)],
        )
        assert rc == 0
        meta = _meta_of(out)
        assert meta["wall_s"] >= 100.0
        assert len(meta["wall_segments"]) == 2
        assert meta["wall_segments"][0]["wall_s"] == 100.0
        # This process alone stays visible, and is clearly shorter
        # than the accumulated figure.
        assert meta["wall_s_segment"] < 100.0
        # The run finalized: its resume state (sidecar included) is
        # cleared — the accumulated record lives on in meta.
        assert not (out_dir / "wall-segments.json").exists()

    def test_foreign_run_segments_not_inherited(
        self, tmp_path, monkeypatch,
    ):
        # A crashed DIFFERENT run (any knob changed) left segments in
        # the same --out: this run's wall must not absorb them.
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        (out_dir / "wall-segments.json").write_text(json.dumps(
            {
                "stamp": _run_stamp(profile="deployed"),
                "segments": [{"start": 1000.0, "end": 1100.0}],
            },
        ))
        rc, out, _ = _stub_main_run(
            tmp_path, monkeypatch,
            rows=[dict(_result_row("a.c:f"), model="")],
            argv=["--out", str(out_dir)],
        )
        assert rc == 0
        meta = _meta_of(out)
        assert len(meta["wall_segments"]) == 1
        assert meta["wall_s"] < 100.0

    def test_single_process_run_records_one_segment(
        self, tmp_path, monkeypatch,
    ):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        rc, out, _ = _stub_main_run(
            tmp_path, monkeypatch,
            rows=[dict(_result_row("a.c:f"), model="")],
            argv=["--out", str(out_dir)],
        )
        assert rc == 0
        meta = _meta_of(out)
        assert len(meta["wall_segments"]) == 1
        assert meta["wall_s"] < 100.0



class TestLabelOverlayHash:
    """The run stamps a content hash of the loaded label files into
    meta and the history header, so any archived results file or
    history row can be tied to its exact label overlay."""

    def _labels_dir(self, tmp_path):
        d = tmp_path / "labels" / "auth"
        d.mkdir(parents=True)
        (d / "one.label.json").write_text(
            json.dumps({"function_id": "a.c:f", "expected": "clean"}),
        )
        (d / "two.label.json").write_text(
            json.dumps({"function_id": "b.c:g", "expected": "finding"}),
        )
        return tmp_path / "labels"

    def test_meta_and_history_stamp_overlay_hash(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.corpus.history as history_mod

        labels_dir = self._labels_dir(tmp_path)
        monkeypatch.setattr(run_corpus, "LABELS_DIR", labels_dir)
        rc, out, history_path = _stub_main_run(
            tmp_path, monkeypatch,
            rows=[dict(_result_row("a.c:f"), model="")],
        )
        assert rc == 0
        expected = run_corpus._label_files_sha256(labels_dir)
        assert expected
        assert _meta_of(out)["label_files_sha256"] == expected
        runs, _ = history_mod.load_store(history_path)
        assert runs, "run was not recorded in history"
        assert runs[-1]["label_files_sha256"] == expected

    def test_hash_is_content_canonical_not_formatting(self, tmp_path):
        labels_dir = self._labels_dir(tmp_path)
        before = run_corpus._label_files_sha256(labels_dir)
        target = labels_dir / "auth" / "one.label.json"
        # Reformat only: same JSON content, different bytes.
        target.write_text(json.dumps(
            {"expected": "clean", "function_id": "a.c:f"}, indent=4,
        ))
        assert run_corpus._label_files_sha256(labels_dir) == before
        # A content change must move the hash.
        target.write_text(json.dumps(
            {"function_id": "a.c:f", "expected": "finding"},
        ))
        assert run_corpus._label_files_sha256(labels_dir) != before

    def test_hash_empty_when_no_label_files(self, tmp_path):
        assert run_corpus._label_files_sha256(tmp_path) == ""

    def test_non_utf8_label_file_hashes_without_crashing(
        self, tmp_path,
    ):
        # A single undecodable byte anywhere under labels/ must not
        # kill the run at startup — the loader reports it properly;
        # the hash covers the raw bytes deterministically.
        labels_dir = self._labels_dir(tmp_path)
        bad = labels_dir / "auth" / "bad.label.json"
        bad.write_bytes(b"\xff\xfe{not json}")
        first = run_corpus._label_files_sha256(labels_dir)
        assert first and first == run_corpus._label_files_sha256(
            labels_dir,
        )
        bad.write_bytes(b"\xff\xfe{changed}")
        assert run_corpus._label_files_sha256(labels_dir) != first


class TestEnsembleAttributedConsistency:
    """The final attributed figure equals the running total the run
    printed: ensemble rows carry BOTH passes' review spend — the
    losing pass's cost is attributed money, not infra, and a ceiling
    enforced against the printed total must match what meta records."""

    def test_merged_rows_carry_both_passes_spend(
        self, tmp_path, monkeypatch,
    ):
        def fake_run_audit(
            labels, dirs, *, mode=None, attributed_start=0.0, **kw,
        ):
            return (
                [
                    dict(
                        _result_row(lb.function_id, actual="suspicious"),
                        model="", cost_usd=1.0, duration_s=2.0,
                    )
                    for lb in labels
                ],
                [],
            )

        monkeypatch.setattr(run_corpus, "_run_audit", fake_run_audit)
        monkeypatch.setattr(
            run_corpus, "_start_shared_joern", lambda dirs: None,
        )
        monkeypatch.setattr(
            run_corpus, "_run_phase2_classify",
            lambda findings, model="": 0.0,
        )
        (tmp_path / "r1").mkdir()
        labels = [
            _mk_label("a.c:f", repo="r1"),
            _mk_label("a.c:g", repo="r1"),
        ]
        merged, _ = run_corpus._run_ensemble_audit(
            labels, {"r1": tmp_path / "r1"}, out_dir=tmp_path / "out",
        )
        # Each label was reviewed by both passes at $1.00/2.0s each.
        assert sorted(r["cost_usd"] for r in merged) == [2.0, 2.0]
        assert sorted(r["duration_s"] for r in merged) == [4.0, 4.0]
        # Run-level attributed sum == what the running total printed
        # (security $2.00 seed + bug_first $2.00).
        assert sum(r["cost_usd"] for r in merged) == 4.0


class TestCheckpointConfigStamp:
    """A checkpoint written under a different run configuration
    (profile, triage, prefilter, mode, scope, resolved model) must be
    ignored wholesale — a config flip between segments must never
    smuggle rows measured under one regime into another's results."""

    def _fake_target_run(self, ran):
        def fake(target_dir, repo_labels, **kw):
            ran.append(repo_labels[0].source.repo)
            return (
                {
                    lb.function_id: {
                        "status": "clean", "cost_usd": 0.5,
                        "duration_s": 0.1,
                    }
                    for lb in repo_labels
                },
                {}, None,
            )
        return fake

    def test_profile_flip_invalidates_group_checkpoint(
        self, tmp_path, monkeypatch,
    ):
        (tmp_path / "r1").mkdir()
        ckpt = tmp_path / "ckpt.json"
        ckpt.write_text(json.dumps(_stamped_ckpt(
            {"r1": [dict(_result_row("a.c:f"), model="")]},
            profile="deployed",
        )))
        ran = []
        monkeypatch.setattr(
            run_corpus, "_run_audit_on_target",
            self._fake_target_run(ran),
        )
        run_corpus._run_audit(
            [_mk_label("a.c:f", repo="r1")],
            {"r1": tmp_path / "r1"},
            joern_server=object(), checkpoint=ckpt, profile="cold",
        )
        assert ran == ["r1"], "deployed-profile checkpoint resumed cold"

    def test_caller_stamp_axes_guard_resume(self, tmp_path, monkeypatch):
        (tmp_path / "r1").mkdir()
        ckpt = tmp_path / "ckpt.json"
        ckpt.write_text(json.dumps(_stamped_ckpt(
            {"r1": [dict(_result_row("a.c:f"), model="")]},
            scope="excerpt",
        )))
        ran = []
        monkeypatch.setattr(
            run_corpus, "_run_audit_on_target",
            self._fake_target_run(ran),
        )
        run_corpus._run_audit(
            [_mk_label("a.c:f", repo="r1")],
            {"r1": tmp_path / "r1"},
            joern_server=object(), checkpoint=ckpt,
            checkpoint_stamp={"scope": "full"},
        )
        assert ran == ["r1"], "excerpt-scope checkpoint resumed as full"

    def test_matching_stamp_resumes(self, tmp_path, monkeypatch):
        (tmp_path / "r1").mkdir()
        ckpt = tmp_path / "ckpt.json"
        ckpt.write_text(json.dumps(_stamped_ckpt(
            {"r1": [dict(_result_row("a.c:f"), model="")]},
            scope="full",
        )))
        ran = []
        monkeypatch.setattr(
            run_corpus, "_run_audit_on_target",
            self._fake_target_run(ran),
        )
        results, _ = run_corpus._run_audit(
            [_mk_label("a.c:f", repo="r1")],
            {"r1": tmp_path / "r1"},
            joern_server=object(), checkpoint=ckpt,
            checkpoint_stamp={"scope": "full"},
        )
        assert ran == []
        assert [r["function_id"] for r in results] == ["a.c:f"]


class TestPassCheckpointGuards:
    """Pass-level checkpoints (checkpoint-sec/bf/merged.json) get the
    same defence as group checkpoints: a config stamp on the envelope
    plus label-set and per-row model guards. A resume with any
    flipped knob re-runs the pass instead of adopting rows that
    would mislabel the measurement."""

    @staticmethod
    def _envelope(rows, **overrides):
        stamp = {
            "model": "", "profile": "deployed",
            "triage": True, "prefilter": True,
        }
        stamp.update(overrides)
        return {"stamp": stamp, "rows": rows}

    def _run(self, tmp_path, monkeypatch, labels, **ensemble_kw):
        modes = []

        def fake_run_audit(
            labels, dirs, *, mode=None, attributed_start=0.0, **kw,
        ):
            modes.append(mode)
            return (
                [
                    dict(_result_row(lb.function_id), model="")
                    for lb in labels
                ],
                [],
            )

        monkeypatch.setattr(run_corpus, "_run_audit", fake_run_audit)
        monkeypatch.setattr(
            run_corpus, "_start_shared_joern", lambda dirs: None,
        )
        (tmp_path / "r1").mkdir(exist_ok=True)
        run_corpus._run_ensemble_audit(
            labels, {"r1": tmp_path / "r1"}, out_dir=tmp_path / "out",
            **ensemble_kw,
        )
        return modes

    def test_foreign_model_pass_checkpoint_reruns(
        self, tmp_path, monkeypatch,
    ):
        out = tmp_path / "out"
        out.mkdir()
        (out / "checkpoint-sec.json").write_text(json.dumps(
            self._envelope(
                [dict(_result_row("a.c:f"), model="other-model")],
            ),
        ))
        modes = self._run(
            tmp_path, monkeypatch, [_mk_label("a.c:f", repo="r1")],
        )
        assert "security" in modes, "foreign-model pass rows adopted"

    def test_label_selection_change_reruns_pass(
        self, tmp_path, monkeypatch,
    ):
        out = tmp_path / "out"
        out.mkdir()
        (out / "checkpoint-sec.json").write_text(json.dumps(
            self._envelope([dict(_result_row("a.c:OTHER"), model="")]),
        ))
        modes = self._run(
            tmp_path, monkeypatch, [_mk_label("a.c:f", repo="r1")],
        )
        assert "security" in modes

    def test_matching_pass_checkpoint_still_resumes(
        self, tmp_path, monkeypatch,
    ):
        out = tmp_path / "out"
        out.mkdir()
        (out / "checkpoint-sec.json").write_text(json.dumps(
            self._envelope([dict(_result_row("a.c:f"), model="")]),
        ))
        (out / "checkpoint-bf.json").write_text(json.dumps(
            self._envelope([dict(_result_row("a.c:f"), model="")]),
        ))
        modes = self._run(
            tmp_path, monkeypatch, [_mk_label("a.c:f", repo="r1")],
        )
        assert modes == [], "valid pass checkpoints were not resumed"

    def test_config_flip_on_pass_checkpoint_reruns(
        self, tmp_path, monkeypatch,
    ):
        # Kill-after-pass-1, resume with a flipped knob: the whole
        # security pass must re-run, not merge deployed-regime rows
        # into a cold measurement.
        out = tmp_path / "out"
        out.mkdir()
        (out / "checkpoint-sec.json").write_text(json.dumps(
            self._envelope(
                [dict(_result_row("a.c:f"), model="")],
                profile="deployed",
            ),
        ))
        modes = self._run(
            tmp_path, monkeypatch, [_mk_label("a.c:f", repo="r1")],
            profile="cold",
        )
        assert "security" in modes, "deployed pass rows adopted cold"

    def test_legacy_bare_list_pass_checkpoint_discarded(
        self, tmp_path, monkeypatch,
    ):
        # A pre-envelope checkpoint carries no config stamp — there
        # is no way to tell which regime produced it, so it re-runs.
        out = tmp_path / "out"
        out.mkdir()
        (out / "checkpoint-sec.json").write_text(json.dumps(
            [dict(_result_row("a.c:f"), model="")],
        ))
        modes = self._run(
            tmp_path, monkeypatch, [_mk_label("a.c:f", repo="r1")],
        )
        assert "security" in modes


class TestResumeStateClearedOnCompletion:
    """Checkpoints and wall segments exist for interrupted runs; once
    results.json is finalized and recorded, they must go — otherwise a
    re-invocation of the same --out replays the run for free and
    appends a duplicate full-cost history record."""

    def test_completed_run_clears_checkpoints_and_segments(
        self, tmp_path, monkeypatch,
    ):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        for name in (
            "checkpoint-sec.json",
            "checkpoint-bf.json",
            "checkpoint-merged.json",
            "checkpoint-sec-groups.json",
            "wall-segments.json",
        ):
            (out_dir / name).write_text("{}")
        rc, _, _ = _stub_main_run(
            tmp_path, monkeypatch,
            rows=[dict(_result_row("a.c:f"), model="")],
            argv=["--out", str(out_dir)],
        )
        assert rc == 0
        leftovers = sorted(
            p.name for p in out_dir.iterdir()
            if p.name.startswith("checkpoint-")
            or p.name == "wall-segments.json"
        )
        assert leftovers == [], f"resume state left behind: {leftovers}"

    def test_reinvocation_records_fresh_spend_not_a_replay(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.corpus.history as history_mod

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        rc1, _, history_path = _stub_main_run(
            tmp_path, monkeypatch,
            rows=[dict(_result_row("a.c:f"), model="", cost_usd=2.0)],
            argv=["--out", str(out_dir)],
        )
        rc2, _, _ = _stub_main_run(
            tmp_path, monkeypatch,
            rows=[dict(_result_row("a.c:f"), model="", cost_usd=2.0)],
            argv=["--out", str(out_dir)],
        )
        assert (rc1, rc2) == (0, 0)
        runs, _ = history_mod.load_store(history_path)
        assert len(runs) == 2
        # Each record carries its own single-invocation wall — the
        # second run does not inherit the first's segments.
        for rec in runs:
            assert len(rec["totals"]) >= 1
        metas = [rec["cost_usd"] for rec in runs]
        assert metas == [2.0, 2.0]


class TestSaveDebugHostileRows:
    """Run dirs are sandbox-writable: planted journal lines must not
    crash the debug-reasoning dump."""

    def test_non_dict_and_wrong_typed_rows_degrade(self, tmp_path):
        run = tmp_path / "run"
        run.mkdir()
        (run / "review-journal.jsonl").write_text(
            "5\n"                      # non-dict: no .get
            "[1, 2]\n"                 # non-dict: no .get
            '{"file": 5, "function": "f"}\n'   # non-str file: no crash
            + json.dumps({
                "file": "a.c", "function": "f", "verdict": "clean",
                "verdict_rationale": "ok",
            }) + "\n",
            encoding="utf-8",
        )
        out = tmp_path / "results.json"
        results = [{"function_id": "a.c:f"}]

        run_corpus._save_debug(results, [run], out)

        lines = [
            json.loads(line)
            for line in out.with_suffix(".debug.jsonl")
            .read_text(encoding="utf-8").splitlines()
        ]
        assert len(lines) == 1
        assert lines[0]["function_id"] == "a.c:f"
        assert lines[0]["verdict"] == "clean"


MUTANT_SRC = (
    "int f(char *p)\n"
    "{\n"
    "    if (!p)\n"
    "        return -1;\n"
    "    p[0] = 1;\n"
    "    return 0;\n"
    "}\n"
)


def _mutant_label(src=MUTANT_SRC):
    from core.audit.corpus.label import (
        FunctionLabel,
        SourcePin,
        compute_span_sha,
    )
    from core.audit.corpus.mutation import build_mutation_spec

    spec = build_mutation_spec(
        MUTANT_SRC,
        line_start=1, line_end=7,
        operator="drop-guard", site_line=3,
        edits=[(3, 4, [])],
    )
    return FunctionLabel(
        function_id="a.c:f",
        bug_class="consistency",
        expected_status="finding",
        rationale="Synthetic drop-guard mutant.",
        source=SourcePin(
            repo="test", sha="x", file="a.c",
            line_start=1, line_end=7,
            span_sha=compute_span_sha(src, 1, 7),
        ),
        labeler="mutation-generator",
        labeled_at="2026-09-23",
        provenance_kind="synthetic_mutant",
        mutation=spec,
        expected_mechanism="consistency",
        excerpt_scope="peer_set",
    )


class TestSyntheticMutantRuns:
    """Single-kind runs, refusal gates, and the mutation-application
    step: the shared fixture stays clean, the run-private excerpt
    copy gets the verified mutation, and every artifact (rows, meta,
    history) is kind-stamped."""

    def _row(self):
        # model "" = the run's default-model slot (conservation
        # accounting joins rows to the model that actually ran).
        return dict(
            _result_row("a.c:f", expected="finding", actual="finding"),
            model="",
        )

    def test_mixed_kind_label_set_refused(
        self, tmp_path, monkeypatch, capsys,
    ):
        rc, out, _ = _stub_main_run(
            tmp_path, monkeypatch,
            labels=[_mk_label("b.c:g", file="b.c"), _mutant_label()],
            source_text=MUTANT_SRC,
        )
        assert rc == 1
        assert "mixes synthetic_mutant and real" in (
            capsys.readouterr().err
        )
        assert not out.exists()

    def test_probe_refused_for_mutants(
        self, tmp_path, monkeypatch, capsys,
    ):
        rc, _, _ = _stub_main_run(
            tmp_path, monkeypatch,
            labels=[_mutant_label()], source_text=MUTANT_SRC,
            argv=["--probe"],
        )
        assert rc == 1
        assert "never applies mutation specs" in (
            capsys.readouterr().err
        )

    def test_non_excerpt_scope_refused(
        self, tmp_path, monkeypatch, capsys,
    ):
        rc, _, _ = _stub_main_run(
            tmp_path, monkeypatch,
            labels=[_mutant_label()], source_text=MUTANT_SRC,
            argv=["--scope", "full"],
        )
        assert rc == 1
        assert "require --scope excerpt" in capsys.readouterr().err

    def test_splice_cross_kind_refused(
        self, tmp_path, monkeypatch, capsys,
    ):
        prior = tmp_path / "real-results.json"
        prior.write_text(json.dumps({
            "meta": {"label_kind": "real"},
            "results": [],
        }))
        rc, _, _ = _stub_main_run(
            tmp_path, monkeypatch,
            labels=[_mutant_label()], source_text=MUTANT_SRC,
            argv=["--splice", str(prior)],
        )
        assert rc == 1
        assert "refusing to merge across kinds" in (
            capsys.readouterr().err
        )

    def test_real_run_refuses_mutant_splice_target(
        self, tmp_path, monkeypatch, capsys,
    ):
        prior = tmp_path / "mutant-results.json"
        prior.write_text(json.dumps({
            "meta": {"label_kind": "synthetic_mutant"},
            "results": [],
        }))
        rc, _, _ = _stub_main_run(
            tmp_path, monkeypatch,
            rows=[_result_row("a.c:f")],
            argv=["--splice", str(prior)],
        )
        assert rc == 1
        assert "refusing to merge across kinds" in (
            capsys.readouterr().err
        )

    def test_mutation_applied_and_kind_stamped(
        self, tmp_path, monkeypatch,
    ):
        captured = {}

        def ensemble(labels, dirs, **kw):
            tree = dirs["test"]
            captured["text"] = (
                Path(tree) / "a.c"
            ).read_text(encoding="utf-8")
            return [self._row()], []

        rc, out, hist = _stub_main_run(
            tmp_path, monkeypatch,
            labels=[_mutant_label()], source_text=MUTANT_SRC,
            ensemble=ensemble,
        )
        assert rc == 0
        # The audited tree got the mutation; content-verified apply
        # dropped the guard and kept the dereference.
        assert "if (!p)" not in captured["text"]
        assert "p[0] = 1;" in captured["text"]
        # The shared fixture clone stays clean — mutations only ever
        # land on the run-private excerpt copy.
        assert (tmp_path / "repo" / "a.c").read_text() == MUTANT_SRC
        data = json.loads(out.read_text())
        assert data["meta"]["label_kind"] == "synthetic_mutant"
        assert data["results"][0]["label_kind"] == "synthetic_mutant"
        recs = [
            json.loads(line)
            for line in hist.read_text().splitlines()
        ]
        run_recs = [r for r in recs if r["record"] == "run"]
        label_recs = [r for r in recs if r["record"] == "label"]
        assert run_recs[0]["label_kind"] == "synthetic_mutant"
        assert label_recs[0]["label_kind"] == "synthetic_mutant"

    def test_apply_failure_refuses_before_review(
        self, tmp_path, monkeypatch, capsys,
    ):
        # The fixture drifted after the mutant was generated: parent
        # span verification must refuse the whole run (exit 1) before
        # any review spend, and never half-mutate.
        called = {}

        def ensemble(labels, dirs, **kw):
            called["ran"] = True
            return [self._row()], []

        drifted = MUTANT_SRC.replace("p[0] = 1;", "p[1] = 2;")
        rc, out, _ = _stub_main_run(
            tmp_path, monkeypatch,
            labels=[_mutant_label(src=drifted)], source_text=drifted,
            ensemble=ensemble,
        )
        assert rc == 1
        assert "mutation application error" in capsys.readouterr().err
        assert "ran" not in called
        assert not out.exists()

    def test_real_run_meta_stamped_real(self, tmp_path, monkeypatch):
        rc, out, hist = _stub_main_run(
            tmp_path, monkeypatch,
            rows=[dict(_result_row("a.c:f"), model="")],
        )
        assert rc == 0
        data = json.loads(out.read_text())
        assert data["meta"]["label_kind"] == "real"
        assert data["results"][0]["label_kind"] == "real"
        recs = [
            json.loads(line)
            for line in hist.read_text().splitlines()
        ]
        assert [
            r["label_kind"] for r in recs if r["record"] == "run"
        ] == ["real"]
