"""Tests for the corpus run-history store and reporting CLI."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import core.audit.corpus.history as history
import core.audit.corpus.run_corpus as run_corpus


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path, monkeypatch):
    """Every test writes to a tmp store, never the operator's real one."""
    monkeypatch.setenv(
        history.HISTORY_ENV, str(tmp_path / "history.jsonl"),
    )


def _label(fid="a.c:f", span_sha="0123456789ab", expected="clean"):
    return SimpleNamespace(
        function_id=fid,
        bug_class="auth",
        expected_status=expected,
        expected_mechanism="",
        expected_mode_results={},
        source=SimpleNamespace(
            repo="test", sha="x", file="a.c",
            line_start=1, line_end=6, span_sha=span_sha,
        ),
    )


def _row(fid="a.c:f", expected="clean", actual="clean", **kw):
    row = {
        "function_id": fid,
        "bug_class": "auth",
        "expected": expected,
        "actual": actual,
        "match": expected == actual,
        "hypothesis": "",
        "evidence_tool": "",
        "model": "",
        "cost_usd": 0.0,
        "duration_s": 0.0,
        "error_reason": "",
    }
    row.update(kw)
    return row


def _label_rec(fid, actual, *, match=None, run_id="r", expected="clean",
               **kw):
    rec = {
        "record": "label",
        "run_id": run_id,
        "function_id": fid,
        "span_sha": "",
        "bug_class": "auth",
        "expected": expected,
        "actual": actual,
        "match": (expected == actual) if match is None else match,
        "skipped": False,
        "attribution": "",
        "observed_mechanisms": [],
        "error_reason": "",
        "model": "",
        "cost_usd": 0.0,
        "duration_s": 0.0,
    }
    rec.update(kw)
    return rec


def _run_rec(run_id, *, tree="", config=None, timestamp="", **kw):
    rec = {
        "record": "run",
        "run_id": run_id,
        "timestamp": timestamp,
        "pipeline_tree_sha": tree,
        "config": config or {},
        "label_set_hash": "",
        "gates": {"passed": True, "failures": []},
        "totals": {"labels": 0, "reviewed": 0, "matched": 0,
                   "errors": 0, "skipped": 0, "wall_s": 0, "llm_s": 0},
        "cost_usd": 0.0,
        "imported": False,
    }
    rec.update(kw)
    return rec


class TestStorePath:
    def test_env_override_wins(self, monkeypatch, tmp_path):
        override = tmp_path / "elsewhere.jsonl"
        monkeypatch.setenv(history.HISTORY_ENV, str(override))
        assert history.store_path() == override

    def test_default_under_local_share(self, monkeypatch):
        monkeypatch.delenv(history.HISTORY_ENV, raising=False)
        path = history.store_path()
        assert path.name == "corpus-history.jsonl"
        assert ".local" in str(path)


class TestLabelSetHash:
    def test_order_independent(self):
        a = [_label("a.c:f"), _label("b.c:g", span_sha="ba9876543210")]
        assert history.label_set_hash(a) == history.label_set_hash(
            list(reversed(a)),
        )

    def test_span_sha_changes_hash(self):
        assert history.label_set_hash(
            [_label(span_sha="0123456789ab")],
        ) != history.label_set_hash([_label(span_sha="ba9876543210")])

    def test_missing_span_sha_tolerated(self):
        lb = _label()
        del lb.source.span_sha
        assert len(history.label_set_hash([lb])) == 64


class TestRecordRun:
    def test_round_trip(self, tmp_path):
        store = tmp_path / "store.jsonl"
        out = tmp_path / "corpus-full-v9" / "results.json"
        out.parent.mkdir()
        out.write_text("{}")
        ok = history.record_run(
            [_row()], {"wall_s": 5.0, "cost_usd": 1.25, "model": "m"},
            output_path=out, run_tag="1700000000",
            labels=[_label()],
            config={"mode": "ensemble", "triage": "off"},
            store=store,
        )
        assert ok is True
        runs, labels_by_run = history.load_store(store)
        assert len(runs) == 1
        run = runs[0]
        assert run["run_id"] == "corpus-full-v9"
        assert run["timestamp"].startswith("2023-11-14")
        assert run["config"] == {"mode": "ensemble", "triage": "off"}
        assert len(run["label_set_hash"]) == 64
        assert run["cost_usd"] == 1.25
        assert run["totals"]["labels"] == 1
        assert run["totals"]["matched"] == 1
        assert run["imported"] is False
        assert run["gates"]["passed"] is True
        recs = labels_by_run["corpus-full-v9"]
        assert len(recs) == 1
        assert recs[0]["function_id"] == "a.c:f"
        assert recs[0]["span_sha"] == "0123456789ab"
        assert recs[0]["match"] is True

    def test_gate_failures_recorded(self, tmp_path):
        store = tmp_path / "store.jsonl"
        out = tmp_path / "results.json"
        out.write_text("{}")
        # A missed finding fails the class-recall gate.
        history.record_run(
            [_row(expected="finding", actual="clean", match=False)],
            {"model": ""}, output_path=out, store=store,
        )
        runs, _ = history.load_store(store)
        assert runs[0]["gates"]["passed"] is False
        assert runs[0]["gates"]["failures"]

    def test_append_only(self, tmp_path):
        store = tmp_path / "store.jsonl"
        out = tmp_path / "results.json"
        out.write_text("{}")
        for _ in range(2):
            history.record_run([_row()], {}, output_path=out, store=store)
        runs, labels_by_run = history.load_store(store)
        assert len(runs) == 2
        assert len(labels_by_run[runs[0]["run_id"]]) == 2

    def test_failure_warns_never_raises(self, tmp_path, capsys):
        blocker = tmp_path / "blocker"
        blocker.write_text("")  # store parent is a file -> OSError
        out = tmp_path / "results.json"
        out.write_text("{}")
        ok = history.record_run(
            [_row()], {}, output_path=out,
            store=blocker / "store.jsonl",
        )
        assert ok is False
        assert "not recorded" in capsys.readouterr().err

    def test_row_without_function_id_skipped(self, tmp_path, capsys):
        store = tmp_path / "store.jsonl"
        out = tmp_path / "results.json"
        out.write_text("{}")
        history.record_run(
            [_row(), {"bug_class": "auth"}], {},
            output_path=out, store=store,
        )
        _, labels_by_run = history.load_store(store)
        assert len(next(iter(labels_by_run.values()))) == 1
        assert "without function_id" in capsys.readouterr().err


class TestRunIdForOutput:
    def test_generic_stem_uses_directory(self, tmp_path):
        assert history.run_id_for_output(
            tmp_path / "corpus-full-v3" / "results.json",
        ) == "corpus-full-v3"

    def test_named_output_uses_stem(self, tmp_path):
        assert history.run_id_for_output(
            tmp_path / "my-experiment.json",
        ) == "my-experiment"


class TestIterRecords:
    def test_malformed_lines_skipped_with_warning(self, tmp_path, capsys):
        store = tmp_path / "store.jsonl"
        store.write_text(
            json.dumps(_run_rec("r1")) + "\n"
            + "{corrupt json\n"
            + json.dumps({"no": "record field"}) + "\n"
            + json.dumps(_label_rec("a.c:f", "clean", run_id="r1")) + "\n"
        )
        recs = list(history.iter_records(store))
        assert [r["record"] for r in recs] == ["run", "label"]
        err = capsys.readouterr().err
        assert "malformed history line skipped" in err
        assert "unrecognized history record" in err

    def test_missing_store_yields_nothing(self, tmp_path):
        assert list(history.iter_records(tmp_path / "nope.jsonl")) == []


class TestClassifyFlip:
    def test_errored(self):
        assert history.classify_flip(
            _label_rec("f", "clean"), _label_rec("f", "error", match=False),
        ) == "errored"

    def test_recovered(self):
        assert history.classify_flip(
            _label_rec("f", "error", match=False),
            _label_rec("f", "clean", match=True),
        ) == "recovered"

    def test_error_to_mismatch_is_regressed(self):
        assert history.classify_flip(
            _label_rec("f", "error", match=False),
            _label_rec("f", "finding", match=False),
        ) == "regressed"

    def test_improved(self):
        assert history.classify_flip(
            _label_rec("f", "clean", expected="finding", match=False),
            _label_rec("f", "finding", expected="finding", match=True),
        ) == "improved"

    def test_regressed(self):
        assert history.classify_flip(
            _label_rec("f", "clean", match=True),
            _label_rec("f", "finding", match=False),
        ) == "regressed"

    def test_lateral_keeps_match(self):
        assert history.classify_flip(
            _label_rec("f", "finding", expected="finding", match=True),
            _label_rec("f", "suspicious", expected="finding", match=True),
        ) == "lateral"


class TestCompareRuns:
    def test_flips_attribution_and_cost(self):
        run_a = _run_rec("va", cost_usd=1.0)
        run_b = _run_rec("vb", cost_usd=3.0)
        labels_a = {
            "a.c:f": _label_rec(
                "a.c:f", "clean", expected="finding", match=False,
                attribution="wrong_verdict",
            ),
            "b.c:g": _label_rec("b.c:g", "clean", match=True),
            "c.c:h": _label_rec(
                "c.c:h", "clean", match=True, skipped=True,
            ),
            "only_a.c:x": _label_rec("only_a.c:x", "clean"),
        }
        labels_b = {
            "a.c:f": _label_rec(
                "a.c:f", "finding", expected="finding", match=True,
                attribution="attributed",
                observed_mechanisms=["smt"],
            ),
            "b.c:g": _label_rec(
                "b.c:g", "error", match=False,
                error_reason="llm_error:boom",
            ),
            "c.c:h": _label_rec("c.c:h", "clean", match=True),
            "only_b.c:y": _label_rec("only_b.c:y", "clean"),
        }
        diff = history.compare_runs(run_a, run_b, labels_a, labels_b)
        assert diff["common"] == 3
        assert diff["only_in_a"] == ["only_a.c:x"]
        assert diff["only_in_b"] == ["only_b.c:y"]
        flips = diff["flips"]
        assert [f["function_id"] for f in flips["improved"]] == ["a.c:f"]
        assert [f["function_id"] for f in flips["errored"]] == ["b.c:g"]
        assert flips["errored"][0]["error_reason"] == "llm_error:boom"
        # skipped rows are excluded from the matched/reviewed counts
        assert (diff["matched_a"], diff["reviewed_a"]) == (2, 3)
        assert (diff["matched_b"], diff["reviewed_b"]) == (3, 4)
        assert diff["cost_delta"] == pytest.approx(2.0)
        changes = {c["function_id"] for c in diff["attribution_changes"]}
        assert "a.c:f" in changes

        report = history.format_compare(diff)
        assert "improved (1)" in report
        assert "errored (1)" in report
        assert "clean -> finding" in report
        assert "wrong_verdict -> attributed" in report

    def test_no_flips(self):
        run = _run_rec("v")
        labels = {"a.c:f": _label_rec("a.c:f", "clean")}
        diff = history.compare_runs(run, run, labels, dict(labels))
        assert diff["flips"] == {}
        assert "No verdict flips." in history.format_compare(diff)


class TestResolveRun:
    def _runs(self):
        return [
            _run_rec("corpus-full-v2", timestamp="t1"),
            _run_rec("corpus-full-v3", timestamp="t2"),
            _run_rec("corpus-full-v3", timestamp="t3"),
        ]

    def test_exact_match_latest_wins(self):
        run = history.resolve_run(self._runs(), "corpus-full-v3")
        assert run["timestamp"] == "t3"

    def test_unique_substring(self):
        assert history.resolve_run(
            self._runs(), "v2",
        )["run_id"] == "corpus-full-v2"

    def test_ambiguous_raises(self):
        with pytest.raises(ValueError, match="ambiguous"):
            history.resolve_run(self._runs(), "corpus-full")

    def test_no_match_raises(self):
        with pytest.raises(ValueError, match="no run matches"):
            history.resolve_run(self._runs(), "v9")


class TestImport:
    def _write(self, tmp_path, name, payload):
        d = tmp_path / name
        d.mkdir()
        path = d / "results.json"
        path.write_text(json.dumps(payload))
        return path

    def test_wrapped_shape_with_meta(self, tmp_path):
        store = tmp_path / "store.jsonl"
        path = self._write(tmp_path, "corpus-full-v3", {
            "meta": {"wall_s": 9.0, "cost_usd": 3.6, "model": "default",
                     "count": 1, "triage": "off"},
            "results": [_row(actual="suspicious", match=False,
                             attribution="wrong_verdict",
                             observed_mechanisms=["smt"])],
        })
        run_id = history.import_results(path, store)
        assert run_id == "corpus-full-v3"
        runs, labels_by_run = history.load_store(store)
        run = runs[0]
        assert run["imported"] is True
        assert run["config"]["triage"] == "off"
        assert run["config"]["model"] == "default"
        assert run["pipeline_tree_sha"] == ""
        assert run["label_set_hash"] == ""
        assert run["timestamp"]  # synthesized from file mtime
        rec = labels_by_run["corpus-full-v3"][0]
        assert rec["attribution"] == "wrong_verdict"
        assert rec["span_sha"] == ""

    def test_older_shape_missing_fields(self, tmp_path):
        # v2-era rows: no error_reason, meta without triage/prefilter;
        # even older: a bare list with rows missing match/skipped.
        store = tmp_path / "store.jsonl"
        row = _row()
        del row["error_reason"]
        v2 = self._write(tmp_path, "corpus-full-v2", {
            "meta": {"wall_s": 1.0, "cost_usd": 0.0, "model": "default",
                     "count": 1},
            "results": [row],
        })
        bare = self._write(tmp_path, "corpus-bare", [
            {"function_id": "a.c:f", "bug_class": "auth",
             "expected": "clean", "actual": "clean"},
        ])
        history.import_results(v2, store)
        history.import_results(bare, store)
        runs, labels_by_run = history.load_store(store)
        assert [r["run_id"] for r in runs] == [
            "corpus-full-v2", "corpus-bare",
        ]
        assert runs[0]["config"]["triage"] is None
        assert labels_by_run["corpus-full-v2"][0]["error_reason"] == ""
        assert labels_by_run["corpus-bare"][0]["match"] is False

    def test_unrecognized_shape_raises(self, tmp_path):
        store = tmp_path / "store.jsonl"
        path = self._write(tmp_path, "not-results", {"foo": "bar"})
        with pytest.raises(ValueError, match="not a corpus results"):
            history.import_results(path, store)


class TestStability:
    def _store(self):
        config = {"mode": "ensemble", "triage": "off"}
        runs = [
            _run_rec("r1", tree="t" * 40, config=config),
            _run_rec("r2", tree="t" * 40, config=config),
            _run_rec("r3", tree="u" * 40, config=config),
            _run_rec("imported", tree="", config=config),
        ]
        labels_by_run = {
            "r1": [_label_rec("a.c:f", "clean", run_id="r1"),
                   _label_rec("b.c:g", "clean", run_id="r1")],
            "r2": [_label_rec("a.c:f", "finding", run_id="r2",
                              match=False),
                   _label_rec("b.c:g", "clean", run_id="r2")],
            "r3": [_label_rec("a.c:f", "clean", run_id="r3")],
            "imported": [_label_rec("a.c:f", "error", run_id="imported",
                                    match=False)],
        }
        return runs, labels_by_run

    def test_same_tree_same_config_variance(self):
        runs, labels_by_run = self._store()
        groups = history.stability_groups(runs, labels_by_run)
        # r3 has a different tree, imported has none: one group.
        assert len(groups) == 1
        g = groups[0]
        assert g["run_ids"] == ["r1", "r2"]
        assert g["comparable_labels"] == 2
        assert set(g["unstable"]) == {"a.c:f"}
        report = history.format_stability(groups)
        assert "1/2 comparable label(s) unstable" in report
        assert "r1=clean, r2=finding" in report

    def test_config_split_prevents_grouping(self):
        runs, labels_by_run = self._store()
        runs[1]["config"] = {"mode": "security", "triage": "off"}
        assert history.stability_groups(runs, labels_by_run) == []

    def test_no_groups_message(self):
        report = history.format_stability([])
        assert "No comparable run groups" in report


class TestTrend:
    def test_label_history_in_run_order(self):
        runs = [
            _run_rec("r1", timestamp="2026-01-01T00:00:00+00:00"),
            _run_rec("r2", timestamp="2026-01-02T00:00:00+00:00"),
        ]
        labels_by_run = {
            "r1": [_label_rec("a.c:f", "clean", run_id="r1")],
            "r2": [_label_rec("a.c:f", "error", run_id="r2", match=False,
                              error_reason="llm_error:x")],
        }
        report = history.format_trend("a.c:f", runs, labels_by_run)
        lines = report.splitlines()
        assert lines[0] == "History for a.c:f:"
        assert "r1" in report and "r2" in report
        assert "llm_error:x" in report

    def test_unknown_label(self):
        assert history.format_trend("nope", [], {}).startswith(
            "No history",
        )


class TestCli:
    def test_runs_on_empty_store(self, tmp_path, capsys):
        rc = history.main(
            ["--store", str(tmp_path / "none.jsonl"), "runs"],
        )
        assert rc == 0
        assert "No runs recorded." in capsys.readouterr().out

    def test_compare_unknown_run_fails(self, tmp_path, capsys):
        rc = history.main(
            ["--store", str(tmp_path / "none.jsonl"),
             "compare", "a", "b"],
        )
        assert rc == 1
        assert "no run matches" in capsys.readouterr().err

    def test_import_then_compare(self, tmp_path, capsys):
        store = tmp_path / "store.jsonl"
        for name, actual in (("run-v1", "clean"), ("run-v2", "finding")):
            d = tmp_path / name
            d.mkdir()
            (d / "results.json").write_text(json.dumps({
                "meta": {"model": "default", "cost_usd": 0.0},
                "results": [_row(
                    expected="finding", actual=actual,
                    match=actual == "finding",
                )],
            }))
            assert history.main(
                ["--store", str(store), "import",
                 str(d / "results.json")],
            ) == 0
        rc = history.main(["--store", str(store), "compare", "v1", "v2"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "improved (1)" in out
        assert "clean -> finding" in out

    def test_import_bad_path_fails(self, tmp_path, capsys):
        rc = history.main(
            ["--store", str(tmp_path / "s.jsonl"),
             "import", str(tmp_path / "missing.json")],
        )
        assert rc == 1
        assert "import failed" in capsys.readouterr().err

    def test_trend_unknown_label_exits_nonzero(self, tmp_path):
        assert history.main(
            ["--store", str(tmp_path / "none.jsonl"),
             "trend", "--label", "a.c:f"],
        ) == 1

    def test_env_var_resolves_store(self, tmp_path, monkeypatch, capsys):
        store = tmp_path / "env-store.jsonl"
        monkeypatch.setenv(history.HISTORY_ENV, str(store))
        store.write_text(json.dumps(_run_rec("env-run")) + "\n")
        assert history.main(["runs"]) == 0
        assert "env-run" in capsys.readouterr().out


class TestWriterHook:
    """The run_corpus hook records after results.json is finalized;
    probes are opt-in via --record-probe; failure never fails the run."""

    def _patch_common(self, tmp_path, monkeypatch):
        from contextlib import contextmanager

        import core.audit.corpus.label as label_mod

        @contextmanager
        def fake_project(run_tag):
            yield f"corpus-{run_tag}"

        src = tmp_path / "repo"
        src.mkdir(exist_ok=True)
        (src / "a.c").write_text("int f(void) { return 0; }\n")
        monkeypatch.setattr(
            label_mod, "load_all_labels",
            lambda bug_class=None: [_label()],
        )
        monkeypatch.setattr(
            run_corpus, "_resolve_source_dirs",
            lambda labels, do_fetch=False: {"test": src},
        )
        monkeypatch.setattr(
            run_corpus, "_corpus_project_context", fake_project,
        )

    def test_audit_run_records_history(self, tmp_path, monkeypatch):
        self._patch_common(tmp_path, monkeypatch)
        monkeypatch.setattr(
            run_corpus, "_run_ensemble_audit",
            lambda labels, dirs, **kw: ([_row()], []),
        )
        store = tmp_path / "hook-store.jsonl"
        monkeypatch.setenv(history.HISTORY_ENV, str(store))
        out = tmp_path / "corpus-hook-run" / "results.json"
        out.parent.mkdir()
        rc = run_corpus.main(["--output", str(out)])
        assert rc == 0
        runs, labels_by_run = history.load_store(store)
        assert len(runs) == 1
        run = runs[0]
        assert run["run_id"] == "corpus-hook-run"
        assert run["config"]["mode"] == "ensemble"
        assert run["config"]["triage"] == "off"
        assert run["config"]["prefilter"] == "off"
        assert run["config"]["scope"] == "excerpt"
        assert len(run["label_set_hash"]) == 64
        assert run["imported"] is False
        recs = labels_by_run["corpus-hook-run"]
        assert [r["function_id"] for r in recs] == ["a.c:f"]
        assert recs[0]["span_sha"] == "0123456789ab"

    def test_gate_fail_run_still_records(self, tmp_path, monkeypatch):
        self._patch_common(tmp_path, monkeypatch)
        monkeypatch.setattr(
            run_corpus, "_run_ensemble_audit",
            lambda labels, dirs, **kw: (
                [_row(expected="finding", actual="clean", match=False)],
                [],
            ),
        )
        monkeypatch.setattr(
            "core.audit.corpus.label.load_all_labels",
            lambda bug_class=None: [_label(expected="finding")],
        )
        store = tmp_path / "hook-store.jsonl"
        monkeypatch.setenv(history.HISTORY_ENV, str(store))
        out = tmp_path / "results.json"
        rc = run_corpus.main(["--output", str(out)])
        assert rc == run_corpus.EXIT_GATE_FAIL
        runs, _ = history.load_store(store)
        assert len(runs) == 1
        assert runs[0]["gates"]["passed"] is False

    def test_probe_not_recorded_by_default(self, tmp_path, monkeypatch):
        self._patch_common(tmp_path, monkeypatch)
        monkeypatch.setattr(
            run_corpus, "_run_probe",
            lambda labels, dirs, **kw: [
                _row(evidence_tool="probe"),
            ],
        )
        store = tmp_path / "hook-store.jsonl"
        monkeypatch.setenv(history.HISTORY_ENV, str(store))
        out = tmp_path / "results.json"
        rc = run_corpus.main(["--probe", "--output", str(out)])
        assert rc == 0
        assert not store.exists()

    def test_probe_recorded_with_flag(self, tmp_path, monkeypatch):
        self._patch_common(tmp_path, monkeypatch)
        monkeypatch.setattr(
            run_corpus, "_run_probe",
            lambda labels, dirs, **kw: [
                _row(evidence_tool="probe"),
            ],
        )
        store = tmp_path / "hook-store.jsonl"
        monkeypatch.setenv(history.HISTORY_ENV, str(store))
        out = tmp_path / "results.json"
        rc = run_corpus.main(
            ["--probe", "--record-probe", "--output", str(out)],
        )
        assert rc == 0
        runs, _ = history.load_store(store)
        assert len(runs) == 1
        assert runs[0]["config"]["mode"] == "probe"
        assert runs[0]["config"]["triage"] is None

    def test_store_failure_does_not_fail_run(
        self, tmp_path, monkeypatch, capsys,
    ):
        self._patch_common(tmp_path, monkeypatch)
        monkeypatch.setattr(
            run_corpus, "_run_ensemble_audit",
            lambda labels, dirs, **kw: ([_row()], []),
        )
        blocker = tmp_path / "blocker"
        blocker.write_text("")
        monkeypatch.setenv(
            history.HISTORY_ENV, str(blocker / "store.jsonl"),
        )
        out = tmp_path / "results.json"
        rc = run_corpus.main(["--output", str(out)])
        assert rc == 0
        assert "not recorded" in capsys.readouterr().err


class TestProfileField:
    """RUN records carry the knowledge profile; pre-profile records
    read as deployed everywhere."""

    def test_build_run_record_stamps_profile(self):
        rec = history.build_run_record(
            [_row()], {},
            run_id="r", timestamp="", tree_sha="t",
            config={}, labels_hash="", profile="cold",
        )
        assert rec["profile"] == "cold"

    def test_default_profile_is_deployed(self):
        rec = history.build_run_record(
            [_row()], {},
            run_id="r", timestamp="", tree_sha="t",
            config={}, labels_hash="",
        )
        assert rec["profile"] == "deployed"

    def test_old_records_read_as_deployed(self):
        rec = _run_rec("old")
        rec.pop("profile", None)
        assert history.run_profile(rec) == "deployed"
        assert history.run_profile({"profile": ""}) == "deployed"
        assert history.run_profile({"profile": "cold"}) == "cold"

    def test_record_run_threads_profile(self, tmp_path):
        store = tmp_path / "s.jsonl"
        out = tmp_path / "results.json"
        out.write_text("{}")
        assert history.record_run(
            [_row()], {}, output_path=out, labels=[_label()],
            config={"mode": "ensemble"}, store=store, profile="cold",
        )
        runs, _ = history.load_store(store)
        assert runs[0]["profile"] == "cold"

    def test_stability_never_mixes_profiles(self):
        config = {"mode": "ensemble"}
        runs = [
            _run_rec("c1", tree="t" * 40, config=config, profile="cold"),
            _run_rec("c2", tree="t" * 40, config=config, profile="cold"),
            _run_rec("d1", tree="t" * 40, config=config,
                     profile="deployed"),
            _run_rec("old", tree="t" * 40, config=config),
        ]
        runs[3].pop("profile", None)
        labels_by_run = {
            rid: [_label_rec("a.c:f", "clean", run_id=rid)]
            for rid in ("c1", "c2", "d1", "old")
        }
        groups = history.stability_groups(runs, labels_by_run)
        by_profile = {g["profile"]: g["run_ids"] for g in groups}
        assert by_profile["cold"] == ["c1", "c2"]
        # The pre-profile record groups with deployed runs.
        assert by_profile["deployed"] == ["d1", "old"]
        report = history.format_stability(groups)
        assert "profile cold" in report
        assert "profile deployed" in report

    def test_format_runs_shows_profile_column(self):
        rec = _run_rec("r1", tree="t" * 40, config={"mode": "ensemble"},
                       profile="cold")
        old = _run_rec("r0", tree="t" * 40, config={"mode": "ensemble"})
        old.pop("profile", None)
        out = history.format_runs([rec, old])
        assert "Profile" in out
        assert "cold" in out
        assert "deployed" in out

    def test_import_reads_profile_from_meta(self, tmp_path):
        store = tmp_path / "s.jsonl"
        results = tmp_path / "results.json"
        results.write_text(json.dumps({
            "meta": {"model": "m", "profile": "cold"},
            "results": [_row()],
        }))
        history.import_results(results, store)
        runs, _ = history.load_store(store)
        assert runs[0]["profile"] == "cold"

    def test_import_without_profile_reads_deployed(self, tmp_path):
        store = tmp_path / "s.jsonl"
        results = tmp_path / "results.json"
        results.write_text(json.dumps({
            "meta": {"model": "m"},
            "results": [_row()],
        }))
        history.import_results(results, store)
        runs, _ = history.load_store(store)
        assert runs[0]["profile"] == "deployed"

    def test_compare_flags_profile_mismatch(self):
        a = _run_rec("cold-run", profile="cold")
        b = _run_rec("dep-run", profile="deployed")
        diff = history.compare_runs(a, b, {}, {})
        out = history.format_compare(diff)
        assert "Profiles: cold -> deployed" in out
        assert "PROFILES DIFFER" in out

    def test_compare_silent_for_deployed_pair(self):
        a = _run_rec("r1")
        b = _run_rec("r2")
        a.pop("profile", None)
        b.pop("profile", None)
        out = history.format_compare(history.compare_runs(a, b, {}, {}))
        assert "Profiles:" not in out


class TestSelectionField:
    """Subset refires must be distinguishable from full runs."""

    def test_default_selection_is_full(self):
        rec = history.build_run_record(
            [_row()], {}, run_id="r", timestamp="", tree_sha="t",
            config={}, labels_hash="",
        )
        assert rec["selection"] == "full"

    def test_refire_selection_recorded(self, tmp_path):
        store = tmp_path / "s.jsonl"
        out = tmp_path / "results.json"
        out.write_text("{}")
        history.record_run(
            [_row()], {}, output_path=out, labels=[_label()],
            config={}, store=store,
            selection={"class": None, "labels": ["a.c:f"]},
        )
        runs, _ = history.load_store(store)
        assert runs[0]["selection"] == {
            "class": None, "labels": ["a.c:f"],
        }

    def test_describe_selection(self):
        assert history.describe_selection({"selection": "full"}) == "full"
        assert history.describe_selection({}) == ""  # pre-selection record
        assert history.describe_selection(
            {"selection": {"class": "auth", "labels": []}},
        ) == "refire: class=auth"
        assert history.describe_selection(
            {"selection": {"class": None, "labels": ["a", "b"]}},
        ) == "refire: 2 label(s)"

    def test_compare_flags_refire_runs(self):
        a = _run_rec("full-run")
        b = _run_rec("refire-run")
        b["selection"] = {"class": None, "labels": ["a.c:f"]}
        out = history.format_compare(history.compare_runs(a, b, {}, {}))
        assert "selective refire" in out
        assert "not a full-run regression" in out

    def test_compare_silent_for_full_and_old_records(self):
        a = _run_rec("r1")  # pre-selection record (no field)
        b = _run_rec("r2")
        b["selection"] = "full"
        out = history.format_compare(history.compare_runs(a, b, {}, {}))
        assert "selective refire" not in out


class TestRefireDeltas:
    def _store_with(self, tmp_path, records):
        store = tmp_path / "s.jsonl"
        history.append_records(store, records)
        return store

    def test_flip_is_phrased_with_prior_run(self, tmp_path):
        store = self._store_with(tmp_path, [
            _run_rec("v1"),
            _label_rec("a.c:f", "clean", run_id="v1",
                       expected="finding", match=False),
            _run_rec("v2"),
            _label_rec("a.c:f", "finding", run_id="v2",
                       expected="finding", match=True),
        ])
        lines = history.refire_deltas(
            store, ["a.c:f"], current_run_id="v2",
        )
        assert lines == [
            "a.c:f: clean -> finding (expected finding) — "
            "IMPROVED, now matches [vs v1]",
        ]

    def test_unchanged_label_says_so(self, tmp_path):
        store = self._store_with(tmp_path, [
            _run_rec("v1"),
            _label_rec("a.c:f", "clean", run_id="v1",
                       expected="finding", match=False),
            _run_rec("v2"),
            _label_rec("a.c:f", "clean", run_id="v2",
                       expected="finding", match=False),
        ])
        lines = history.refire_deltas(
            store, ["a.c:f"], current_run_id="v2",
        )
        assert lines == [
            "a.c:f: clean — unchanged since v1 (still mismatched)",
        ]

    def test_no_prior_history(self, tmp_path):
        store = self._store_with(tmp_path, [
            _run_rec("v1"),
            _label_rec("a.c:f", "finding", run_id="v1",
                       expected="finding", match=True),
        ])
        lines = history.refire_deltas(
            store, ["a.c:f"], current_run_id="v1",
        )
        assert lines == [
            "a.c:f: finding (expected finding, matches) — "
            "no prior history",
        ]

    def test_prior_found_across_intervening_runs(self, tmp_path):
        """The latest PRIOR record wins even when the label skipped
        the run in between."""
        store = self._store_with(tmp_path, [
            _run_rec("v1"),
            _label_rec("a.c:f", "error", run_id="v1",
                       expected="finding", match=False),
            _run_rec("v2"),  # refire of some OTHER label
            _label_rec("b.c:g", "clean", run_id="v2"),
            _run_rec("v3"),
            _label_rec("a.c:f", "finding", run_id="v3",
                       expected="finding", match=True),
        ])
        lines = history.refire_deltas(
            store, ["a.c:f"], current_run_id="v3",
        )
        assert lines == [
            "a.c:f: error -> finding (expected finding) — "
            "RECOVERED, now matches [vs v1]",
        ]

    def test_missing_store_or_run_returns_empty(self, tmp_path):
        assert history.refire_deltas(
            tmp_path / "absent.jsonl", ["a.c:f"], current_run_id="x",
        ) == []
        store = self._store_with(tmp_path, [_run_rec("v1")])
        assert history.refire_deltas(
            store, ["a.c:f"], current_run_id="nope",
        ) == []

    def test_reused_output_path_takes_last_header(self, tmp_path):
        """Same --output twice -> same run id; the newest header is
        the current run."""
        store = self._store_with(tmp_path, [
            _run_rec("same"),
            _label_rec("a.c:f", "clean", run_id="same"),
            _run_rec("same"),
            _label_rec("a.c:f", "finding", run_id="same",
                       expected="clean", match=False),
        ])
        lines = history.refire_deltas(
            store, ["a.c:f"], current_run_id="same",
        )
        # Merged label records degrade to "unchanged" — but never a
        # crash and never a phantom prior run.
        assert len(lines) == 1
        assert "unchanged" in lines[0] or "no prior history" in lines[0]


class TestFullRunDelta:
    def _store_with(self, tmp_path, records):
        store = tmp_path / "s.jsonl"
        history.append_records(store, records)
        return store

    def test_full_run_gets_a_compare_vs_latest_prior(self, tmp_path):
        store = self._store_with(tmp_path, [
            _run_rec("v4"),
            _label_rec("a.c:f", "clean", run_id="v4",
                       expected="finding", match=False),
            _label_rec("a.c:g", "clean", run_id="v4",
                       expected="clean", match=True),
            _run_rec("v5"),
            _label_rec("a.c:f", "finding", run_id="v5",
                       expected="finding", match=True),
            _label_rec("a.c:g", "clean", run_id="v5",
                       expected="clean", match=True),
        ])
        out = history.full_run_delta(store, "v5")
        assert out is not None
        assert "Compare v4" in out
        assert "a.c:f" in out

    def test_no_prior_run_returns_none(self, tmp_path):
        store = self._store_with(tmp_path, [
            _run_rec("v1"),
            _label_rec("a.c:f", "clean", run_id="v1"),
        ])
        assert history.full_run_delta(store, "v1") is None

    def test_unknown_run_or_missing_store_return_none(self, tmp_path):
        store = self._store_with(tmp_path, [_run_rec("v1")])
        assert history.full_run_delta(store, "ghost") is None
        assert history.full_run_delta(tmp_path / "absent.jsonl", "v1") is None

    def test_disjoint_label_sets_return_none(self, tmp_path):
        store = self._store_with(tmp_path, [
            _run_rec("v1"),
            _label_rec("a.c:f", "clean", run_id="v1"),
            _run_rec("v2"),
            _label_rec("b.c:g", "clean", run_id="v2"),
        ])
        assert history.full_run_delta(store, "v2") is None
