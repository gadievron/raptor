"""Witness-backlog drain — hermetic tests.

The synthesis lane is stubbed at the ``synthesize_verification_rule``
seam (LLM plumbing is exercised by the real-engine round-trip file);
everything else — artifact load/validate/write-back, ranking,
study-first ordering, budget/attempt caps, the journal write through
``collector.append_journal_for_outcome``, and the drain report — runs
for real against tmp dirs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core.audit.backlog_drain import (
    BACKLOG_FILENAME,
    DRAIN_REPORT_FILENAME,
    MAX_ROW_ATTEMPTS,
    BacklogError,
    DarkRow,
    drain,
    load_backlog,
    load_pending_questions,
    plan_rows,
    rank,
)
from core.audit.checker_synthesis import OnDemandSynthesisResult


def _write_backlog(run_dir: Path, clusters, total=None, extra=None):
    run_dir.mkdir(parents=True, exist_ok=True)
    n = sum(c.get("count", len(c.get("sites", []))) for c in clusters)
    data = {
        "source_file": "findings-graded.json",
        "total": total if total is not None else n,
        "note": "dark items",
        "clusters": clusters,
        "provenance": {"generator": "validation-helper", "untrusted": True},
        "raptor_schema_version": 2,
        # Additive-key tolerance: consumers must ignore what they
        # don't know.
        "future_key": {"nested": True},
    }
    if extra:
        data.update(extra)
    (run_dir / BACKLOG_FILENAME).write_text(
        json.dumps(data), encoding="utf-8",
    )
    return run_dir / BACKLOG_FILENAME


def _site(file, function, line, title, **kw):
    return {
        "id": f"{file}:{function}:{line}",
        "file": file,
        "function": function,
        "line": line,
        "title": title,
        **kw,
    }


def _cmd_injection_cluster(**site_kw):
    return {
        "class": "CWE-78",
        "count": 1,
        "sites": [_site(
            "app/run.py", "launch", 12,
            "user-controlled cmd reaches os.system (command injection)",
            **site_kw,
        )],
    }


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    (target / "app").mkdir(parents=True, exist_ok=True)
    (target / "app" / "run.py").write_text(
        "import os\n" + "\n" * 9
        + "def launch(cmd):\n    os.system(cmd)\n",
        encoding="utf-8",
    )
    return target


def _stub_synth(monkeypatch, results):
    """Replace the synthesis lane with canned results (popped in call
    order); records every call's (row-file, function, cwe, count)."""
    calls = []
    queue = list(results)

    def fake(outcome, config, **kwargs):
        calls.append({
            "file": outcome.file,
            "function": outcome.function,
            "status": outcome.status,
            "cwe": kwargs.get("cwe"),
            "synthesis_count": kwargs.get("synthesis_count"),
        })
        return queue.pop(0) if queue else None

    monkeypatch.setattr(
        "core.audit.checker_synthesis.synthesize_verification_rule", fake,
    )
    return calls


def _self_match_stamp(file: str, function: str, cwe: str = "CWE-78") -> str:
    from packages.checker_synthesis.synthesise import _slugify
    return (
        f"semgrep:synth-{_slugify(file)}.{_slugify(function)}"
        f".{_slugify(cwe)}.0"
    )


def _confirmed(stamp: str, cost=0.05) -> OnDemandSynthesisResult:
    return OnDemandSynthesisResult(
        stamp=stamp,
        rule_id=stamp.split(":synth-", 1)[1],
        tool="semgrep",
        content="rules: []",
        cwe="CWE-78",
        confirmed=True,
        cost_usd=cost,
    )


def _unconfirmed(cost=0.05) -> OnDemandSynthesisResult:
    return OnDemandSynthesisResult(cwe="CWE-78", confirmed=False,
                                   cost_usd=cost)


def _journal_entries(run_dir: Path) -> list[dict]:
    path = run_dir / "review-journal.jsonl"
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


class TestLoadBacklog:
    def test_valid_rows_and_additive_keys(self, tmp_path):
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [_cmd_injection_cluster(extra_site_key=1)])
        artifact, rows, malformed = load_backlog(run_dir)
        assert len(rows) == 1
        assert not malformed
        assert rows[0].file == "app/run.py"
        assert rows[0].function == "launch"
        assert rows[0].cluster_class == "CWE-78"
        # Unknown keys preserved on the live artifact.
        assert artifact["future_key"] == {"nested": True}
        assert rows[0].site["extra_site_key"] == 1

    def test_missing_artifact_refused_loudly(self, tmp_path):
        with pytest.raises(BacklogError, match="nothing to drain"):
            load_backlog(tmp_path)

    def test_non_dict_artifact_refused(self, tmp_path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / BACKLOG_FILENAME).write_text("[1, 2]", encoding="utf-8")
        with pytest.raises(BacklogError, match="no clusters list"):
            load_backlog(run_dir)

    def test_malformed_json_refused(self, tmp_path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / BACKLOG_FILENAME).write_text("{nope", encoding="utf-8")
        with pytest.raises(BacklogError, match="unreadable|malformed"):
            load_backlog(run_dir)

    def test_oversized_artifact_refused(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [_cmd_injection_cluster()])
        monkeypatch.setattr(
            "core.audit.backlog_drain.MAX_BACKLOG_BYTES", 10,
        )
        with pytest.raises(BacklogError, match="oversized|malformed"):
            load_backlog(run_dir)

    @pytest.mark.skipif(
        not hasattr(os, "mkfifo"), reason="platform has no mkfifo",
    )
    def test_planted_fifo_refused_without_open(self, tmp_path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        os.mkfifo(run_dir / BACKLOG_FILENAME)
        # Must refuse via lstat, never open (an open would hang).
        with pytest.raises(BacklogError, match="not a regular file"):
            load_backlog(run_dir)

    def test_malformed_rows_refused_per_row_not_fatal(self, tmp_path):
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [{
            "class": "CWE-78",
            "count": 5,
            "sites": [
                "not-a-dict",
                {"file": "", "function": "f", "line": 1, "title": "t"},
                {"file": "/abs/path.py", "function": "f", "line": 1,
                 "title": "t"},
                {"file": "a/../../etc/passwd", "function": "f", "line": 1,
                 "title": "t"},
                _site("app/ok.py", "f", 3, "fine"),
            ],
        }])
        _artifact, rows, malformed = load_backlog(run_dir)
        assert [r.file for r in rows] == ["app/ok.py"]
        assert len(malformed) == 4
        reasons = " | ".join(m["reason"] for m in malformed)
        assert "not an object" in reasons
        assert "no file" in reasons
        assert "traversal" in reasons

    def test_hostile_line_and_attempts_coerced(self, tmp_path):
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [{
            "class": "CWE-78", "count": 1,
            "sites": [_site("app/a.py", "f", {"evil": 1}, "t",
                            drain_attempts="99")],
        }])
        _artifact, rows, _malformed = load_backlog(run_dir)
        assert rows[0].line == 0
        assert rows[0].attempts == 0

    def test_hostile_id_and_title_escaped_at_intake(self, tmp_path):
        """The free-prose fields (id, title) quote the scanned target:
        control bytes are escaped when the row is BUILT, not just at
        the render sites."""
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [{
            "class": "CWE-78", "count": 1,
            "sites": [{
                "id": "evil\x1b]0;pwn\x07id",
                "file": "app/a.py", "function": "f", "line": 1,
                "title": "cmd injection\x1b[2Jvia os.system",
            }],
        }])
        _artifact, rows, _malformed = load_backlog(run_dir)
        assert "\x1b" not in rows[0].id
        assert "\\x1b" in rows[0].id
        assert "\x1b" not in rows[0].title
        assert "\\x1b" in rows[0].title

    def test_duplicate_sites_collapse_at_intake(self, tmp_path):
        """Identical (file, function, line, title) listings are ONE
        site: one kept row carrying the duplicates, attempts = the max
        across copies (a hostile artifact zeroing one copy's counter
        buys nothing)."""
        run_dir = tmp_path / "run"
        copies = [
            _site("app/run.py", "launch", 12,
                  "cmd injection via os.system",
                  drain_attempts=n)
            for n in (0, 2, 1, 0, 0)
        ]
        _write_backlog(run_dir, [{
            "class": "CWE-78", "count": 5, "sites": copies,
        }])
        _artifact, rows, malformed = load_backlog(run_dir)
        assert len(rows) == 1
        assert not malformed
        assert len(rows[0].dups) == 4
        assert rows[0].attempts == 2


class TestStudyQuestions:
    def test_explicit_ledger_wins(self, tmp_path):
        ledger = tmp_path / "answers.json"
        ledger.write_text(json.dumps({"answers": [
            {"question": "q1", "source_file": "a.py", "status": "pending"},
            {"question": "q2", "source_file": "a.py", "status": "resolved"},
        ]}), encoding="utf-8")
        pending, source = load_pending_questions(tmp_path, ledger)
        assert [q["question"] for q in pending] == ["q1"]
        assert source == str(ledger)

    def test_explicit_ledger_unreadable_is_loud(self, tmp_path):
        with pytest.raises(BacklogError, match="study-answers"):
            load_pending_questions(tmp_path, tmp_path / "missing.json")

    def test_sibling_discovery_newest_first(self, tmp_path):
        run_dir = tmp_path / "proj" / "validate-1"
        old = tmp_path / "proj" / "audit-old"
        new = tmp_path / "proj" / "audit-new"
        for d in (run_dir, old, new):
            d.mkdir(parents=True)
        (old / "study-answers.json").write_text(json.dumps({"answers": [
            {"question": "old", "source_file": "a.py", "status": "pending"},
        ]}), encoding="utf-8")
        (new / "study-answers.json").write_text(json.dumps({"answers": [
            {"question": "new", "source_file": "a.py", "status": "pending"},
        ]}), encoding="utf-8")
        os.utime(old / "study-answers.json", (1, 1))
        pending, source = load_pending_questions(run_dir)
        assert [q["question"] for q in pending] == ["new"]
        assert source == str(new / "study-answers.json")

    def test_no_ledger_degrades_quietly(self, tmp_path):
        run_dir = tmp_path / "solo"
        run_dir.mkdir()
        pending, source = load_pending_questions(run_dir)
        assert pending == []
        assert source == ""


class TestPlanning:
    def _rows(self):
        return [
            DarkRow(id="1", file="app/a.py", function="f", line=1,
                    title="user input reaches os.system (command injection)",
                    cluster_class="unclassified", attempts=0),
            DarkRow(id="2", file="app/b.py", function="g", line=2,
                    title="buffer overflow when copying attacker data",
                    cluster_class="CWE-120", attempts=0),
            DarkRow(id="3", file="app/c.py", function="h", line=3,
                    title="free-form claim naming no mechanism",
                    cluster_class="unclassified", attempts=0),
            DarkRow(id="4", file="app/d.bin", function="i", line=4,
                    title="command injection in blob",
                    cluster_class="CWE-78", attempts=0),
        ]

    def test_ranking_cluster_before_inferred_before_refused(self):
        plans = plan_rows(self._rows(), [])
        ids = [p.row.id for p in plans]
        # Declared cluster CWE (2) before inferred (1); no-mechanism
        # (3) and no-engine (4) refused at the tail.
        assert ids[:2] == ["2", "1"]
        assert set(ids[2:]) == {"3", "4"}
        by_id = {p.row.id: p for p in plans}
        assert by_id["2"].cwe_source == "cluster"
        assert by_id["1"].cwe_source == "inferred"
        assert not by_id["3"].attemptable
        assert not by_id["4"].attemptable
        assert "no synthesis engine" in by_id["4"].refusal

    def test_study_held_ranks_behind_unheld(self):
        pending = [
            {"question": "what is f's contract?",
             "source_file": "app/b.py", "source_function": "g",
             "status": "pending"},
        ]
        plans = plan_rows(self._rows(), pending)
        ids = [p.row.id for p in plans if p.attemptable]
        # Row 2 (cluster CWE) is held by its question, so the
        # inferred-CWE row 1 outranks it: questions first.
        assert ids == ["1", "2"]
        held = next(p for p in plans if p.row.id == "2")
        assert held.held
        assert held.held_by == ["what is f's contract?"]

    def test_file_scoped_question_holds_whole_file(self):
        pending = [
            {"question": "file-level contract?",
             "source_file": "app/b.py",
             "source_function": "interstitial:1-100",
             "status": "pending"},
        ]
        plans = plan_rows(self._rows(), pending)
        assert next(p for p in plans if p.row.id == "2").held

    def test_other_functions_question_does_not_hold(self):
        pending = [
            {"question": "about someone else",
             "source_file": "app/b.py", "source_function": "unrelated_fn",
             "status": "pending"},
        ]
        plans = plan_rows(self._rows(), pending)
        assert not next(p for p in plans if p.row.id == "2").held

    def test_not_tool_verifiable_class_refused(self):
        rows = [DarkRow(
            id="log", file="app/a.py", function="f", line=1,
            title="operations are not logged for audit",
            cluster_class="CWE-778", attempts=0,
        )]
        plans = plan_rows(rows, [])
        assert not plans[0].attemptable
        assert "not tool-verifiable" in plans[0].refusal


class TestRank:
    def test_rank_spends_nothing_and_writes_nothing(self, tmp_path):
        run_dir = tmp_path / "run"
        path = _write_backlog(run_dir, [_cmd_injection_cluster()])
        before = path.read_bytes()
        plans, report = rank(run_dir)
        assert len(plans) == 1
        assert report.backlog["listed"] == 1
        assert path.read_bytes() == before
        assert not (run_dir / DRAIN_REPORT_FILENAME).exists()

    def test_truncated_listing_is_reported_honestly(self, tmp_path):
        run_dir = tmp_path / "run"
        cluster = _cmd_injection_cluster()
        cluster["count"] = 200
        cluster["sites_truncated"] = True
        _write_backlog(run_dir, [cluster], total=200)
        _plans, report = rank(run_dir)
        assert report.backlog["total"] == 200
        assert report.backlog["listed"] == 1
        assert report.backlog["listing_truncated"] is True

    def test_lied_total_never_hides_listed_rows(self, tmp_path):
        """The artifact's self-declared total is hostile-influenceable
        and is only ever trusted UPWARDS: with 3 listed rows behind a
        declared total of 1, the report says 3."""
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [{
            "class": "CWE-78", "count": 1,
            "sites": [
                _site(f"app/m{i}.py", f"f{i}", i + 1,
                      "cmd injection via os.system")
                for i in range(3)
            ],
        }], total=1)
        _plans, report = rank(run_dir)
        assert report.backlog["total"] == 3
        assert report.backlog["listed"] == 3
        assert report.backlog["listing_truncated"] is False

    def test_duplicates_collapsed_reported(self, tmp_path):
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [{
            "class": "CWE-78", "count": 4,
            "sites": [_site("app/run.py", "launch", 12,
                            "cmd injection via os.system")] * 4,
        }])
        plans, report = rank(run_dir)
        assert len(plans) == 1
        assert report.backlog["total"] == 4
        assert report.backlog["listed"] == 1
        assert report.backlog["duplicates_collapsed"] == 3


class TestDrain:
    def test_witnessed_row_lands_in_journal_and_leaves_backlog(
        self, tmp_path, monkeypatch,
    ):
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        _write_backlog(run_dir, [_cmd_injection_cluster()])
        stamp = _self_match_stamp("app/run.py", "launch")
        calls = _stub_synth(monkeypatch, [_confirmed(stamp, cost=0.03)])

        report = drain(run_dir, target, 1.0)

        assert [c["status"] for c in calls] == ["dark"]
        assert report.witnessed == 1
        assert report.attempted == 0
        assert abs(report.spent_usd - 0.03) < 1e-9

        entries = _journal_entries(run_dir)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["verdict"] == "suspicious"
        assert entry["producer"] == "backlog-drain"
        assert entry["file"] == "app/run.py"
        assert entry["function"] == "launch"
        assert entry["run_id"].startswith("backlog-drain-")
        # Self-matched receipt: never a confirming-evidence stamp.
        assert not entry.get("evidence_tools")
        assert stamp in entry["body"]

        artifact = json.loads(
            (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
        assert artifact["total"] == 0
        assert artifact["clusters"][0]["count"] == 0
        assert artifact["clusters"][0]["sites"] == []
        assert artifact["drained"]["witnessed_total"] == 1
        # Unknown keys survive the write-back.
        assert artifact["future_key"] == {"nested": True}

        report_data = json.loads(
            (run_dir / DRAIN_REPORT_FILENAME).read_text(encoding="utf-8"))
        row = next(r for r in report_data["rows"]
                   if r.get("action") == "witnessed")
        assert row["receipt"] == stamp
        assert row["self_match"] is True
        assert row["journal"] == "appended"

    def test_non_self_match_receipt_is_confirming_evidence(
        self, tmp_path, monkeypatch,
    ):
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        _write_backlog(run_dir, [_cmd_injection_cluster()])
        stamp = "semgrep:synth-library-replay.CWE-78.7"
        _stub_synth(monkeypatch, [_confirmed(stamp)])

        report = drain(run_dir, target, 1.0)

        assert report.witnessed == 1
        entry = _journal_entries(run_dir)[0]
        assert entry["verdict"] == "suspicious"
        assert entry.get("evidence_tools") == [stamp]

    def test_failed_synthesis_leaves_row_dark_with_attempt_record(
        self, tmp_path, monkeypatch,
    ):
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        _write_backlog(run_dir, [_cmd_injection_cluster()])
        _stub_synth(monkeypatch, [_unconfirmed(cost=0.02)])

        report = drain(run_dir, target, 1.0)

        assert report.witnessed == 0
        assert report.attempted == 1
        assert _journal_entries(run_dir) == []

        artifact = json.loads(
            (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
        assert artifact["total"] == 1
        site = artifact["clusters"][0]["sites"][0]
        assert site["drain_attempts"] == 1

        report_data = json.loads(
            (run_dir / DRAIN_REPORT_FILENAME).read_text(encoding="utf-8"))
        row = next(r for r in report_data["rows"]
                   if r.get("action") == "attempted")
        assert "still dark" in row["reason"]
        assert abs(row["cost_usd"] - 0.02) < 1e-9

    def test_attempt_cap_parks_row_without_dispatch(
        self, tmp_path, monkeypatch,
    ):
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        _write_backlog(
            run_dir,
            [_cmd_injection_cluster(drain_attempts=MAX_ROW_ATTEMPTS)],
        )
        calls = _stub_synth(monkeypatch, [_unconfirmed()])

        report = drain(run_dir, target, 1.0)

        assert calls == []
        assert report.dispatched == 0
        report_data = json.loads(
            (run_dir / DRAIN_REPORT_FILENAME).read_text(encoding="utf-8"))
        assert any(r.get("action") == "attempt-capped"
                   for r in report_data["rows"])

    def test_attempt_counter_accumulates_across_drains(
        self, tmp_path, monkeypatch,
    ):
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        _write_backlog(run_dir, [_cmd_injection_cluster()])
        for expected in (1, 2, 3):
            _stub_synth(monkeypatch, [_unconfirmed()])
            drain(run_dir, target, 1.0)
            artifact = json.loads(
                (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
            assert (artifact["clusters"][0]["sites"][0]["drain_attempts"]
                    == expected)
        calls = _stub_synth(monkeypatch, [_unconfirmed()])
        report = drain(run_dir, target, 1.0)
        assert calls == []
        assert report.dispatched == 0

    def test_budget_is_a_stop_condition(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        clusters = [{
            "class": "CWE-78",
            "count": 3,
            "sites": [
                _site(f"app/m{i}.py", f"f{i}", i + 1,
                      "cmd injection via os.system")
                for i in range(3)
            ],
        }]
        _write_backlog(run_dir, clusters)
        calls = _stub_synth(monkeypatch, [
            _unconfirmed(cost=0.06),
            _unconfirmed(cost=0.06),
            _unconfirmed(cost=0.06),
        ])

        report = drain(run_dir, target, 0.10)

        # 0.06 < 0.10 -> second dispatch; 0.12 >= 0.10 -> stop.
        assert len(calls) == 2
        assert report.dispatched == 2
        assert report.stopped == "budget"
        report_data = json.loads(
            (run_dir / DRAIN_REPORT_FILENAME).read_text(encoding="utf-8"))
        assert any(r.get("reason") == "stopped: budget"
                   for r in report_data["rows"])

    def test_dispatch_cap_stops_the_pass(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        clusters = [{
            "class": "CWE-78",
            "count": 3,
            "sites": [
                _site(f"app/m{i}.py", f"f{i}", i + 1,
                      "cmd injection via os.system")
                for i in range(3)
            ],
        }]
        _write_backlog(run_dir, clusters)
        calls = _stub_synth(monkeypatch, [_unconfirmed()] * 3)

        report = drain(run_dir, target, 10.0, max_dispatch=1)

        assert len(calls) == 1
        assert report.stopped == "dispatch-cap"

    def test_no_llm_channel_stops_loudly(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        _write_backlog(run_dir, [_cmd_injection_cluster()])
        _stub_synth(monkeypatch, [None])

        report = drain(run_dir, target, 1.0)

        assert report.stopped == "no-llm"
        assert report.witnessed == 0
        assert report.dispatched == 0

    def test_unlanded_journal_write_keeps_row_dark(
        self, tmp_path, monkeypatch,
    ):
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        _write_backlog(run_dir, [_cmd_injection_cluster()])
        stamp = _self_match_stamp("app/run.py", "launch")
        _stub_synth(monkeypatch, [_confirmed(stamp)])
        # The collector API is best-effort by contract: simulate a
        # swallowed write failure.
        monkeypatch.setattr(
            "core.audit.collector.append_journal_for_outcome",
            lambda **kwargs: None,
        )

        report = drain(run_dir, target, 1.0)

        assert report.witnessed == 0
        assert report.attempted == 1
        artifact = json.loads(
            (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
        assert artifact["total"] == 1
        assert artifact["clusters"][0]["sites"]
        report_data = json.loads(
            (run_dir / DRAIN_REPORT_FILENAME).read_text(encoding="utf-8"))
        row = next(r for r in report_data["rows"]
                   if r.get("action") == "attempted")
        assert "did not land" in row["reason"]

    def test_sample_is_seeded_and_recorded(self, tmp_path, monkeypatch):
        clusters = [{
            "class": "CWE-78",
            "count": 5,
            "sites": [
                _site(f"app/m{i}.py", f"f{i}", i + 1,
                      "cmd injection via os.system")
                for i in range(5)
            ],
        }]
        drawn = []
        for attempt in range(2):
            run_dir = tmp_path / f"run{attempt}"
            target = _target(tmp_path)
            _write_backlog(run_dir, [json.loads(json.dumps(clusters[0]))])
            calls = _stub_synth(monkeypatch, [_unconfirmed()] * 5)
            report = drain(run_dir, target, 10.0, sample=2, sample_seed=7)
            assert report.sample == {
                "requested": 2, "drawn": 2, "seed": 7, "population": 5,
            }
            drawn.append([c["file"] for c in calls])
        assert drawn[0] == drawn[1]
        assert len(drawn[0]) == 2

    def test_study_held_rows_attempted_after_unheld(
        self, tmp_path, monkeypatch,
    ):
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        clusters = [{
            "class": "CWE-78",
            "count": 2,
            "sites": [
                _site("app/held.py", "f", 1,
                      "cmd injection via os.system"),
                _site("app/free.py", "g", 2,
                      "cmd injection via os.system"),
            ],
        }]
        _write_backlog(run_dir, clusters)
        (run_dir / "study-answers.json").write_text(json.dumps({
            "answers": [{
                "question": "held?", "source_file": "app/held.py",
                "source_function": "f", "status": "pending",
            }],
        }), encoding="utf-8")
        calls = _stub_synth(monkeypatch, [_unconfirmed(), _unconfirmed()])

        report = drain(run_dir, target, 10.0)

        assert [c["file"] for c in calls] == ["app/free.py", "app/held.py"]
        assert report.held_rows == 1

    def test_refused_and_malformed_rows_reported_never_dispatched(
        self, tmp_path, monkeypatch,
    ):
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        _write_backlog(run_dir, [{
            "class": "unclassified",
            "count": 2,
            "sites": [
                _site("app/x.py", "f", 1, "free-form claim, no mechanism"),
                {"file": 42},
            ],
        }])
        calls = _stub_synth(monkeypatch, [_unconfirmed()])

        report = drain(run_dir, target, 1.0)

        assert calls == []
        assert report.refused == 1
        assert report.malformed == 1
        report_data = json.loads(
            (run_dir / DRAIN_REPORT_FILENAME).read_text(encoding="utf-8"))
        assert any(r.get("action") == "refused"
                   for r in report_data["rows"])
        assert any(r.get("malformed") for r in report_data["rows"])

    def test_rejects_non_positive_budget_and_bad_target(self, tmp_path):
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [_cmd_injection_cluster()])
        with pytest.raises(BacklogError, match="budget"):
            drain(run_dir, _target(tmp_path), 0.0)
        with pytest.raises(BacklogError, match="not a directory"):
            drain(run_dir, tmp_path / "nope", 1.0)

    @pytest.mark.parametrize(
        "budget", [float("nan"), float("inf"), float("-inf")],
    )
    def test_rejects_non_finite_budget_fail_closed(
        self, tmp_path, monkeypatch, budget,
    ):
        """nan passes every ``<=`` comparison (all False) — a plain
        sign check would run an unmetered pass behind a "$nan" cap and
        crash in the JSON report write AFTER mutating the backlog. The
        guard must be finite-and-positive, before any read."""
        run_dir = tmp_path / "run"
        path = _write_backlog(run_dir, [_cmd_injection_cluster()])
        before = path.read_bytes()
        calls = _stub_synth(monkeypatch, [_unconfirmed()])
        with pytest.raises(BacklogError, match="finite"):
            drain(run_dir, _target(tmp_path), budget)
        assert calls == []
        assert path.read_bytes() == before
        assert not (run_dir / DRAIN_REPORT_FILENAME).exists()

    def test_duplicate_rows_share_one_dispatch_and_one_counter(
        self, tmp_path, monkeypatch,
    ):
        """10 listings of one site are ONE site: one synthesis per
        drain, the failed-attempt counter lands on every copy, and
        cap-3 parks the site regardless of which copy a future import
        lists first."""
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        dup = [_site("app/run.py", "launch", 12,
                     "cmd injection via os.system") for _ in range(10)]
        _write_backlog(run_dir, [{
            "class": "CWE-78", "count": 10, "sites": dup,
        }])
        for expected in (1, 2, 3):
            calls = _stub_synth(monkeypatch, [_unconfirmed()] * 10)
            drain(run_dir, target, 100.0)
            assert len(calls) == 1
            artifact = json.loads(
                (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
            counters = [s["drain_attempts"]
                        for s in artifact["clusters"][0]["sites"]]
            assert counters == [expected] * 10
        # Parked at the cap: no further dispatch, ever.
        calls = _stub_synth(monkeypatch, [_unconfirmed()])
        report = drain(run_dir, target, 100.0)
        assert calls == []
        assert report.dispatched == 0

    def test_witnessed_duplicates_leave_together_one_journal_row(
        self, tmp_path, monkeypatch,
    ):
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        dup = [_site("app/run.py", "launch", 12,
                     "cmd injection via os.system") for _ in range(4)]
        _write_backlog(run_dir, [{
            "class": "CWE-78", "count": 4, "sites": dup,
        }])
        stamp = _self_match_stamp("app/run.py", "launch")
        _stub_synth(monkeypatch, [_confirmed(stamp)])

        report = drain(run_dir, target, 1.0)

        assert report.witnessed == 1
        assert len(_journal_entries(run_dir)) == 1
        artifact = json.loads(
            (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
        assert artifact["clusters"][0]["sites"] == []
        assert artifact["clusters"][0]["count"] == 0
        assert artifact["total"] == 0
        assert report.backlog["total_before"] == 4
        assert report.backlog["total_after"] == 0

    def test_title_variants_get_one_dispatch_per_site_per_drain(
        self, tmp_path, monkeypatch,
    ):
        """Near-duplicates (same file:function, varied title) survive
        the intake collapse but the journal is function-grained: one
        drain buys at most one synthesis — and at most one journal row
        — per site identity."""
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        _write_backlog(run_dir, [{
            "class": "CWE-78", "count": 3,
            "sites": [
                _site("app/run.py", "launch", 12,
                      f"cmd injection via os.system (variant {i})")
                for i in range(3)
            ],
        }])
        stamp = _self_match_stamp("app/run.py", "launch")
        calls = _stub_synth(monkeypatch, [_confirmed(stamp)] * 3)

        report = drain(run_dir, target, 100.0)

        assert len(calls) == 1
        assert report.witnessed == 1
        assert len(_journal_entries(run_dir)) == 1
        report_data = json.loads(
            (run_dir / DRAIN_REPORT_FILENAME).read_text(encoding="utf-8"))
        skipped = [r for r in report_data["rows"]
                   if r.get("reason", "").startswith(
                       "site already dispatched")]
        assert len(skipped) == 2

    def test_lied_total_reported_honestly_after_witness(
        self, tmp_path, monkeypatch,
    ):
        """A declared total of 1 over 3 listed rows must not let the
        drain print an empty queue: totals are floored by the rows the
        drain actually walked."""
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        _write_backlog(run_dir, [{
            "class": "CWE-78", "count": 1,
            "sites": [
                _site("app/run.py", "launch", 12,
                      "cmd injection via os.system"),
                _site("app/m1.py", "f1", 1,
                      "cmd injection via os.system"),
                _site("app/m2.py", "f2", 2,
                      "cmd injection via os.system"),
            ],
        }], total=1)
        stamp = _self_match_stamp("app/run.py", "launch")
        _stub_synth(monkeypatch,
                    [_confirmed(stamp), _unconfirmed(), _unconfirmed()])

        report = drain(run_dir, target, 100.0)

        assert report.witnessed == 1
        assert report.backlog["total_before"] == 3
        assert report.backlog["total_after"] == 2

    def test_live_run_refused(self, tmp_path):
        """Drains are post-run passes: a run dir whose recorded worker
        is still alive is refused before any read or write."""
        from core.run.metadata import RUN_METADATA_FILE
        run_dir = tmp_path / "run"
        path = _write_backlog(run_dir, [_cmd_injection_cluster()])
        (run_dir / RUN_METADATA_FILE).write_text(json.dumps({
            "command": "validate",
            "status": "running",
            "tool_pid": os.getpid(),
            "timestamp": "2026-09-20T00:00:00+00:00",
        }), encoding="utf-8")
        before = path.read_bytes()
        with pytest.raises(BacklogError, match="in flight"):
            drain(run_dir, _target(tmp_path), 1.0)
        assert path.read_bytes() == before

    def test_dead_worker_running_status_drains(
        self, tmp_path, monkeypatch,
    ):
        """A stale 'running' stamp with a dead pid (crashed producer)
        must not wedge the queue forever."""
        from core.run.metadata import RUN_METADATA_FILE
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [_cmd_injection_cluster()])
        (run_dir / RUN_METADATA_FILE).write_text(json.dumps({
            "command": "validate",
            "status": "running",
            "tool_pid": 2 ** 22 + 12345,   # beyond default pid_max
            "timestamp": "2026-09-20T00:00:00+00:00",
        }), encoding="utf-8")
        calls = _stub_synth(monkeypatch, [_unconfirmed()])
        report = drain(run_dir, _target(tmp_path), 1.0)
        assert len(calls) == 1
        assert report.dispatched == 1

    def test_corrupt_run_metadata_refused(self, tmp_path):
        """A ``.raptor-run.json`` that exists but does not parse fails
        CLOSED: run-dir content any writer can corrupt must not be
        able to disable the live-run refusal."""
        from core.run.metadata import RUN_METADATA_FILE
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [_cmd_injection_cluster()])
        (run_dir / RUN_METADATA_FILE).write_bytes(b"{torn json")
        with pytest.raises(BacklogError, match="cannot be read"):
            drain(run_dir, _target(tmp_path), 1.0)

    def test_terminal_status_metadata_drains(
        self, tmp_path, monkeypatch,
    ):
        """A completed run's metadata (the normal case for a post-run
        pass) stays permissive."""
        from core.run.metadata import RUN_METADATA_FILE
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [_cmd_injection_cluster()])
        (run_dir / RUN_METADATA_FILE).write_text(json.dumps({
            "command": "validate",
            "status": "completed",
            "tool_pid": os.getpid(),
            "timestamp": "2026-09-20T00:00:00+00:00",
        }), encoding="utf-8")
        calls = _stub_synth(monkeypatch, [_unconfirmed()])
        drain(run_dir, _target(tmp_path), 1.0)
        assert len(calls) == 1


class TestCoverageDoctrine:
    def test_drain_producer_is_finding_grade(self):
        from core.coverage.journal import (
            PRODUCER_BACKLOG_DRAIN,
            ReviewJournalEntry,
            is_function_grade,
        )
        entry = ReviewJournalEntry(
            ts="2026-01-01T00:00:00Z",
            run_id="backlog-drain-20260101-000000",
            file="a.py",
            function="f",
            verdict="suspicious",
            source_hash="",
            producer=PRODUCER_BACKLOG_DRAIN,
        )
        # Drains are not coverage: never a function review, never a
        # gap suppressor, never a reusable $0 verdict.
        assert is_function_grade(entry) is False

    def test_journaled_drain_row_is_finding_grade(
        self, tmp_path, monkeypatch,
    ):
        run_dir = tmp_path / "run"
        target = _target(tmp_path)
        _write_backlog(run_dir, [_cmd_injection_cluster()])
        stamp = _self_match_stamp("app/run.py", "launch")
        _stub_synth(monkeypatch, [_confirmed(stamp)])
        drain(run_dir, target, 1.0)

        from core.coverage.journal import load_entries
        entries = load_entries(run_dir)
        assert len(entries) == 1
        from core.coverage.journal import is_function_grade
        assert is_function_grade(entries[0]) is False


class TestCLI:
    """The ``raptor-audit backlog`` surface: exit codes and terminal
    display integrity (row fields are hostile-artifact bytes)."""

    def _run(self, *argv, cwd=None):
        import subprocess
        import sys
        repo = Path(__file__).resolve().parents[3]
        env = dict(os.environ, _RAPTOR_TRUSTED="1")
        return subprocess.run(
            [sys.executable, str(repo / "libexec" / "raptor-audit"),
             "backlog", *argv],
            capture_output=True, text=True, env=env, cwd=cwd or repo,
            timeout=120, check=False,
        )

    def test_list_ranks_and_escapes_hostile_bytes(self, tmp_path):
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [{
            "class": "CWE-78",
            "count": 1,
            "sites": [_site(
                "app/\x1b]0;evil\x07run.py", "launch", 12,
                "cmd injection via os.system",
            )],
        }])
        cp = self._run("list", "--out", str(run_dir))
        assert cp.returncode == 0, cp.stderr
        assert "1 dark row(s)" in cp.stdout
        # The hostile file name reaches the terminal escaped, never raw.
        assert "\x1b]" not in cp.stdout
        assert "\\x1b" in cp.stdout

    def test_list_missing_artifact_exits_nonzero(self, tmp_path):
        cp = self._run("list", "--out", str(tmp_path))
        assert cp.returncode == 1
        assert "nothing to drain" in cp.stderr

    @pytest.mark.parametrize(
        "budget", ["0", "-1", "nan", "inf", "-inf", "not-a-number"],
    )
    def test_drain_refuses_bad_budget_at_parse_time(
        self, tmp_path, budget,
    ):
        """Synthesis dispatch spends LLM money: a zero, negative,
        non-finite, or non-numeric --budget is refused by the parser
        (exit 2), before the artifact is even read."""
        run_dir = tmp_path / "run"
        path = _write_backlog(run_dir, [_cmd_injection_cluster()])
        before = path.read_bytes()
        cp = self._run(
            "drain", "--out", str(run_dir),
            "--target", str(tmp_path), "--budget", budget,
        )
        assert cp.returncode == 2
        assert "--budget" in cp.stderr
        assert path.read_bytes() == before

    @pytest.mark.parametrize("cap", ["0", "-3", "x"])
    def test_drain_refuses_bad_max_attempts_at_parse_time(
        self, tmp_path, cap,
    ):
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [_cmd_injection_cluster()])
        cp = self._run(
            "drain", "--out", str(run_dir),
            "--target", str(tmp_path), "--budget", "1",
            "--max-attempts", cap,
        )
        assert cp.returncode == 2
        assert "--max-attempts" in cp.stderr

    def test_missing_subcommand_is_usage_error(self, tmp_path):
        cp = self._run()
        assert cp.returncode == 1
        assert "usage" in cp.stderr


class TestDarkEligibility:
    """The one-line retarget: ``synthesize_verification_rule`` accepts
    candidate-grade dark outcomes; clean stays excluded."""

    def _config(self, tmp_path):
        from types import SimpleNamespace
        out = tmp_path / "out"
        out.mkdir(exist_ok=True)
        return SimpleNamespace(
            target_path=tmp_path, out_dir=out, models=["default"],
        )

    def _outcome(self, status):
        from types import SimpleNamespace
        return SimpleNamespace(
            file="a.py", function="f", status=status,
            hypothesis="cmd injection via os.system",
            hypotheses=None,
            review_result={"hypothesis": "cmd injection via os.system"},
            line=3,
        )

    def _stub_substrate(self, monkeypatch):
        from packages.checker_synthesis.models import (
            CheckerSynthesisResult,
            SeedBug,
        )
        cs = CheckerSynthesisResult(seed=SeedBug(
            file="a.py", function="f", line_start=3, line_end=3,
            cwe="CWE-78", reasoning="r", snippet="",
        ))

        def fake_callable(prompt, schema, system_prompt):
            return None
        fake_callable.cost_usd = 0.0
        from types import SimpleNamespace
        monkeypatch.setattr(
            "core.audit.checker_synthesis._build_llm_callable",
            lambda config: (
                fake_callable, SimpleNamespace(model_name="stub"),
            ),
        )
        monkeypatch.setattr(
            "packages.checker_synthesis.synthesise.synthesise_and_run",
            lambda seed, **kw: cs,
        )

    def test_dark_outcome_is_eligible(self, tmp_path, monkeypatch):
        from core.audit.checker_synthesis import (
            synthesize_verification_rule,
        )
        self._stub_substrate(monkeypatch)
        result = synthesize_verification_rule(
            self._outcome("dark"), self._config(tmp_path), cwe="CWE-78",
        )
        # An attempt happened (rule=None -> unconfirmed result, not a
        # skipped-None).
        assert result is not None
        assert result.confirmed is False

    def test_clean_outcome_stays_ineligible(self, tmp_path, monkeypatch):
        from core.audit.checker_synthesis import (
            synthesize_verification_rule,
        )
        self._stub_substrate(monkeypatch)
        assert synthesize_verification_rule(
            self._outcome("clean"), self._config(tmp_path), cwe="CWE-78",
        ) is None
