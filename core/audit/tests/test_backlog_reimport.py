"""Witness-backlog ``reimport`` — additive re-listing of dark rows.

The backlog is the drain's only row source: a listing the producer
truncated on disk leaves the unlisted identities undrainable, and the
graded findings export is where they still live. ``reimport`` merges
them back — additively by contract: existing site dicts are never
modified (``drain_attempts`` preserved), the ``drained`` ledger is
never touched, no row is ever removed, already-listed identities are
never listed twice, and witnessed rows never resurrect (refusing
loudly when their identities are unrecoverable). Synthetic fixtures
throughout — no LLM calls anywhere in this lane.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from core.audit.backlog_drain import (
    BACKLOG_FILENAME,
    DRAIN_REPORT_FILENAME,
    BacklogError,
    ReimportReport,
    load_backlog,
    rank,
    reimport,
)


def _site(file: str, function: str, line: int, title: str,
          **kw: Any) -> dict[str, Any]:
    return {
        "id": f"{file}:{function}:{line}",
        "file": file,
        "function": function,
        "line": line,
        "title": title,
        **kw,
    }


def _graded_row(i: int, *, status: str = "dark",
                **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": f"src/app.py:fn{i}:{i + 1}",
        "file": "src/app.py",
        "function": f"fn{i}",
        "line": i + 1,
        "status": status,
        "hypothesis": f"hypothesis {i}: user input reaches sink",
    }
    base.update(overrides)
    return base


def _site_for(row: dict[str, Any]) -> dict[str, Any]:
    return _site(row["file"], row["function"], row["line"],
                 row["hypothesis"])


def _write_backlog(run_dir: Path, clusters: list[dict[str, Any]],
                   total: int | None = None,
                   extra: dict[str, Any] | None = None) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    n = sum(c.get("count", len(c.get("sites", []))) for c in clusters)
    data: dict[str, Any] = {
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
    path = run_dir / BACKLOG_FILENAME
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _write_graded(run_dir: Path, rows: list[dict[str, Any]],
                  name: str = "findings-graded.json") -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / name
    path.write_text(json.dumps({"findings": rows}), encoding="utf-8")
    return path


def _truncated_fixture(
    run_dir: Path, *, n_dark: int = 5, n_listed: int = 2,
) -> tuple[Path, list[dict[str, Any]]]:
    """A legacy producer-truncated artifact plus its graded export:
    ``n_dark`` graded dark rows, the first ``n_listed`` listed (one
    carrying a drain attempt), the rest counted-but-unlisted."""
    graded = [_graded_row(i) for i in range(n_dark)]
    listed = [_site_for(r) for r in graded[:n_listed]]
    listed[0]["drain_attempts"] = 2
    _write_backlog(run_dir, [{
        "class": "unclassified",
        "count": n_dark,
        "sites": listed,
        "sites_truncated": True,
    }], extra={"drained": {
        "last_run_id": "backlog-drain-0001",
        "last_report": DRAIN_REPORT_FILENAME,
        "witnessed_total": 0,
    }})
    graded_path = _write_graded(
        run_dir, graded + [_graded_row(99, status="finding")])
    return graded_path, graded


class TestReimportMerge:
    def test_appends_unlisted_identities_additively(self, tmp_path):
        run_dir = tmp_path / "run"
        graded_path, _graded = _truncated_fixture(run_dir)
        before = json.loads(
            (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))

        report = reimport(run_dir, graded_path)

        assert isinstance(report, ReimportReport)
        assert report.dark_rows == 5
        assert report.already_listed == 2
        assert report.appended == 3
        assert report.listed_before == 2
        assert report.listed_after == 5
        assert report.total_before == 5
        assert report.total_after == 5
        assert report.changed is True

        after = json.loads(
            (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
        # Existing site dicts byte-untouched (drain_attempts included).
        assert after["clusters"][0]["sites"] == \
            before["clusters"][0]["sites"]
        assert after["clusters"][0]["sites"][0]["drain_attempts"] == 2
        # The drained ledger is never touched.
        assert after["drained"] == before["drained"]
        # Unknown keys survive the rewrite.
        assert after["future_key"] == before["future_key"]
        # The legacy cluster now lists what it counts — marker dropped,
        # count debited by the newly listed rows.
        assert after["clusters"][0]["count"] == 2
        assert "sites_truncated" not in after["clusters"][0]
        # Appended rows ride same-class chunk clusters; total exact.
        assert after["total"] == 5
        appended = [c for c in after["clusters"][1:]]
        assert all(c["class"] == "unclassified" for c in appended)
        assert sum(len(c["sites"]) for c in appended) == 3
        assert all(c["count"] == len(c["sites"]) for c in appended)

    def test_no_row_lost_and_rank_reports_full_listing(self, tmp_path):
        run_dir = tmp_path / "run"
        graded_path, graded = _truncated_fixture(run_dir)
        reimport(run_dir, graded_path)

        _artifact, rows, malformed = load_backlog(run_dir)
        assert malformed == []
        assert {(r.file, r.function, r.line) for r in rows} == {
            (r["file"], r["function"], r["line"]) for r in graded
        }
        _plans, report = rank(run_dir)
        assert report.backlog["total"] == 5
        assert report.backlog["listed"] == 5
        assert report.backlog["listing_truncated"] is False

    def test_idempotent_second_run_leaves_bytes_alone(self, tmp_path):
        run_dir = tmp_path / "run"
        graded_path, _graded = _truncated_fixture(run_dir)
        first = reimport(run_dir, graded_path)
        assert first.appended == 3
        bytes_after_first = (run_dir / BACKLOG_FILENAME).read_bytes()

        second = reimport(run_dir, graded_path)
        assert second.appended == 0
        assert second.already_listed == 5
        assert second.changed is False
        assert (run_dir / BACKLOG_FILENAME).read_bytes() == \
            bytes_after_first

    def test_chunks_stay_within_write_cap(self, tmp_path):
        from core.audit.backlog_drain import _SITES_PER_CLUSTER_WRITE
        run_dir = tmp_path / "run"
        n = _SITES_PER_CLUSTER_WRITE * 2 + 5
        graded = [_graded_row(i) for i in range(n)]
        _write_backlog(run_dir, [{
            "class": "unclassified",
            "count": n,
            "sites": [_site_for(graded[0])],
            "sites_truncated": True,
        }])
        graded_path = _write_graded(run_dir, graded)

        report = reimport(run_dir, graded_path)
        assert report.appended == n - 1
        after = json.loads(
            (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
        assert all(len(c["sites"]) <= _SITES_PER_CLUSTER_WRITE
                   for c in after["clusters"])
        assert after["total"] == n
        _artifact, rows, _malformed = load_backlog(run_dir)
        assert len(rows) == n

    def test_total_rises_only_for_uncounted_rows(self, tmp_path):
        # No truncated remainder to debit: rows the artifact never
        # counted raise the total, keeping it exact.
        run_dir = tmp_path / "run"
        listed = _graded_row(0)
        _write_backlog(run_dir, [{
            "class": "unclassified",
            "count": 1,
            "sites": [_site_for(listed)],
        }])
        graded_path = _write_graded(
            run_dir, [listed, _graded_row(1), _graded_row(2)])

        report = reimport(run_dir, graded_path)
        assert report.appended == 2
        assert report.total_before == 1
        assert report.total_after == 3
        after = json.loads(
            (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
        assert after["total"] == 3

    def test_unusable_graded_rows_never_listed(self, tmp_path):
        run_dir = tmp_path / "run"
        graded_path, _graded = _truncated_fixture(run_dir, n_dark=2,
                                                  n_listed=2)
        bad = [
            _graded_row(10, file="/etc/passwd"),          # absolute
            _graded_row(11, file="../escape.py"),          # traversal
            _graded_row(12, file=""),                      # no file
        ]
        graded_path = _write_graded(
            run_dir, [_graded_row(0), _graded_row(1), *bad])

        report = reimport(run_dir, graded_path)
        assert report.skipped_unusable == 3
        assert report.appended == 0
        assert report.changed is False

    def test_non_dark_rows_never_enter_the_backlog(self, tmp_path):
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [{
            "class": "unclassified", "count": 1,
            "sites": [_site_for(_graded_row(0))],
        }])
        graded_path = _write_graded(run_dir, [
            _graded_row(0),
            _graded_row(1, status="finding"),
            _graded_row(2, status="suspicious"),
        ])
        report = reimport(run_dir, graded_path)
        assert report.graded_total == 3
        assert report.dark_rows == 1
        assert report.appended == 0

    def test_appended_rows_cluster_per_class(self, tmp_path):
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [{
            "class": "unclassified", "count": 3,
            "sites": [_site_for(_graded_row(0))],
            "sites_truncated": True,
        }])
        graded_path = _write_graded(run_dir, [
            _graded_row(0),
            _graded_row(1, cwe_id="CWE-78"),
            _graded_row(2, vuln_type="XSS"),
        ])
        report = reimport(run_dir, graded_path)
        assert report.appended == 2
        after = json.loads(
            (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
        classes = [c["class"] for c in after["clusters"][1:]]
        assert sorted(classes) == ["CWE-78", "xss"]


class TestTotalReconciliation:
    """Artifact-level total reconciliation — the truncation surplus.

    The producer's truncation comes in two shapes: whole clusters
    dropped by the cluster cap (``clusters_truncated`` — the dropped
    rows appear in NO cluster) and the legacy per-cluster
    ``sites_truncated`` marker. Both leave rows counted in ``total``
    but unlisted; reimport debits appended rows against that surplus
    (declared total minus rows listed on disk) so re-listing a counted
    row never re-counts it.
    """

    def test_cluster_cap_recovery_keeps_total_exact(self, tmp_path):
        # New-producer shape: rows dropped by the cluster cap are
        # counted in total but carry no cluster and no marker. Their
        # recovery must not inflate total nor leave the truncation
        # signal stuck on a fully-listed queue.
        run_dir = tmp_path / "run"
        graded = [_graded_row(i, cwe_id=f"CWE-{100 + i}")
                  for i in range(6)]
        _write_backlog(run_dir, [
            {"class": f"CWE-{100 + i}", "count": 1,
             "sites": [_site_for(graded[i])]}
            for i in range(4)
        ], total=6, extra={"clusters_truncated": True,
                           "cluster_classes_total": 6})
        graded_path = _write_graded(run_dir, graded)

        report = reimport(run_dir, graded_path)
        assert report.appended == 2
        assert report.already_listed == 4
        assert report.total_before == 6
        assert report.total_after == 6
        after = json.loads(
            (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
        assert after["total"] == 6

        _plans, ranked = rank(run_dir)
        assert ranked.backlog["total"] == 6
        assert ranked.backlog["listed"] == 6
        assert ranked.backlog["listing_truncated"] is False

        bytes_after = (run_dir / BACKLOG_FILENAME).read_bytes()
        second = reimport(run_dir, graded_path)
        assert second.appended == 0
        assert second.changed is False
        assert (run_dir / BACKLOG_FILENAME).read_bytes() == bytes_after

    def test_overlong_class_capped_identically_on_both_debit_sides(
            self, tmp_path):
        # A class longer than the cap (hostile artifacts only — both
        # writers cap classes) must still match its own truncated
        # cluster: both sides of the class comparison go through the
        # one capping function.
        cls_raw = "a" * 150
        run_dir = tmp_path / "run"
        graded = [_graded_row(i, vuln_type=cls_raw) for i in range(3)]
        _write_backlog(run_dir, [{
            "class": cls_raw,
            "count": 3,
            "sites": [_site_for(graded[0])],
            "sites_truncated": True,
        }], total=3)
        graded_path = _write_graded(run_dir, graded)

        report = reimport(run_dir, graded_path)
        assert report.appended == 2
        after = json.loads(
            (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))
        assert after["total"] == 3
        assert after["clusters"][0]["count"] == 1
        assert "sites_truncated" not in after["clusters"][0]
        assert all(c["class"] == "a" * 100 for c in after["clusters"][1:])

    def test_class_key_idempotent_on_its_own_output(self):
        from core.audit.backlog_drain import _class_key
        raw = "b" * 99 + " " + "c" * 60  # the cap lands on a space
        key = _class_key(raw)
        assert _class_key(key) == key
        assert len(key) <= 100

    def test_divergent_export_debit_is_attribution_blind(self, tmp_path):
        # Documented heuristic, not an exactness contract: the surplus
        # is a COUNT, not identities, so a divergent export's
        # never-counted rows consume it — the truncation signal clears
        # while the originally counted identities stay unlisted.
        # Pinned invariants: listed counts stay exact, total never
        # decreases, and a later reimport of the original export
        # re-lists the missing rows, raising total for the surplus
        # already consumed.
        run_dir = tmp_path / "run"
        real = [_graded_row(i, cwe_id="CWE-79") for i in range(5)]
        _write_backlog(run_dir, [{
            "class": "CWE-79", "count": 5,
            "sites": [_site_for(real[0]), _site_for(real[1])],
            "sites_truncated": True,
        }], total=5)
        divergent = [_graded_row(10 + i, cwe_id="CWE-79")
                     for i in range(3)]
        divergent_path = _write_graded(
            run_dir, divergent, name="divergent.json")

        first = reimport(run_dir, divergent_path)
        assert first.appended == 3
        assert first.total_after == 5  # surplus consumed — the residual
        _plans, ranked = rank(run_dir)
        assert ranked.backlog["listing_truncated"] is False

        original_path = _write_graded(run_dir, real, name="original.json")
        second = reimport(run_dir, original_path)
        assert second.appended == 3
        assert second.total_after == 8  # converges upward, never down
        assert second.listed_after == 8
        _plans, ranked = rank(run_dir)
        assert ranked.backlog["total"] == 8
        assert ranked.backlog["listed"] == 8


class TestWitnessedGuard:
    def _witnessed_setup(self, run_dir: Path,
                         witnessed_total: int = 1,
                         report_rows: list[dict[str, Any]] | None = None,
                         ) -> Path:
        witnessed = _graded_row(0)
        _write_backlog(run_dir, [{
            "class": "unclassified",
            "count": 1,
            "sites": [_site_for(_graded_row(1))],
        }], total=1, extra={"drained": {
            "last_run_id": "backlog-drain-0002",
            "last_report": DRAIN_REPORT_FILENAME,
            "witnessed_total": witnessed_total,
        }})
        if report_rows is not None:
            (run_dir / DRAIN_REPORT_FILENAME).write_text(
                json.dumps({"schema": 1, "witnessed": len(report_rows),
                            "rows": report_rows}),
                encoding="utf-8",
            )
        return _write_graded(
            run_dir, [witnessed, _graded_row(1), _graded_row(2)])

    def test_witnessed_identities_never_resurrect(self, tmp_path):
        run_dir = tmp_path / "run"
        w = _graded_row(0)
        graded_path = self._witnessed_setup(run_dir, report_rows=[{
            "action": "witnessed", "file": w["file"],
            "function": w["function"], "line": w["line"],
        }])
        report = reimport(run_dir, graded_path)
        assert report.witnessed_excluded == 1
        assert report.appended == 1  # only the genuinely new row
        _artifact, rows, _malformed = load_backlog(run_dir)
        assert (w["file"], w["function"], w["line"]) not in {
            (r.file, r.function, r.line) for r in rows
        }

    def test_refuses_when_report_is_missing(self, tmp_path):
        run_dir = tmp_path / "run"
        graded_path = self._witnessed_setup(run_dir, report_rows=None)
        before = (run_dir / BACKLOG_FILENAME).read_bytes()
        with pytest.raises(BacklogError, match="not\\s+recoverable"):
            reimport(run_dir, graded_path)
        assert (run_dir / BACKLOG_FILENAME).read_bytes() == before

    def test_refuses_when_report_undercounts_the_ledger(self, tmp_path):
        # Two witnessed removals accumulated across drains, only the
        # last drain's row recoverable — refuse, never guess.
        run_dir = tmp_path / "run"
        w = _graded_row(0)
        graded_path = self._witnessed_setup(
            run_dir, witnessed_total=2, report_rows=[{
                "action": "witnessed", "file": w["file"],
                "function": w["function"], "line": w["line"],
            }])
        before = (run_dir / BACKLOG_FILENAME).read_bytes()
        with pytest.raises(BacklogError, match="not\\s+recoverable"):
            reimport(run_dir, graded_path)
        assert (run_dir / BACKLOG_FILENAME).read_bytes() == before


class TestReimportRefusals:
    def test_missing_graded_file_refused(self, tmp_path):
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [{
            "class": "unclassified", "count": 1,
            "sites": [_site_for(_graded_row(0))],
        }])
        with pytest.raises(BacklogError, match="nothing to reimport"):
            reimport(run_dir, run_dir / "no-such.json")

    def test_shapeless_graded_file_refused(self, tmp_path):
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [{
            "class": "unclassified", "count": 1,
            "sites": [_site_for(_graded_row(0))],
        }])
        bad = run_dir / "bad.json"
        bad.write_text(json.dumps({"not_findings": []}), encoding="utf-8")
        with pytest.raises(BacklogError, match="no findings list"):
            reimport(run_dir, bad)

    def test_missing_artifact_refused(self, tmp_path):
        run_dir = tmp_path / "run"
        graded_path = _write_graded(run_dir, [_graded_row(0)])
        with pytest.raises(BacklogError, match="nothing to drain"):
            reimport(run_dir, graded_path)

    def test_cluster_read_bound_refused_not_silently_unread(
            self, tmp_path, monkeypatch):
        import core.audit.backlog_drain as mod
        monkeypatch.setattr(mod, "_MAX_CLUSTERS_READ", 2)
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [
            {"class": "unclassified", "count": 2,
             "sites": [_site_for(_graded_row(0))],
             "sites_truncated": True},
            {"class": "CWE-78", "count": 1,
             "sites": [_site_for(_graded_row(5))]},
        ])
        graded_path = _write_graded(
            run_dir, [_graded_row(0), _graded_row(1)])
        before = (run_dir / BACKLOG_FILENAME).read_bytes()
        with pytest.raises(BacklogError, match="read bound"):
            reimport(run_dir, graded_path)
        assert (run_dir / BACKLOG_FILENAME).read_bytes() == before

    def test_live_run_refused(self, tmp_path, monkeypatch):
        import core.audit.backlog_drain as mod

        def _boom(run_dir: Path) -> None:
            raise BacklogError("still in flight")

        monkeypatch.setattr(mod, "_refuse_live_run", _boom)
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [{
            "class": "unclassified", "count": 1,
            "sites": [_site_for(_graded_row(0))],
        }])
        graded_path = _write_graded(run_dir, [_graded_row(0)])
        with pytest.raises(BacklogError, match="in flight"):
            reimport(run_dir, graded_path)


class TestCLI:
    """The ``raptor-audit backlog reimport`` surface."""

    def _run(self, *argv: str) -> subprocess.CompletedProcess[str]:
        repo = Path(__file__).resolve().parents[3]
        env = dict(os.environ, _RAPTOR_TRUSTED="1")
        return subprocess.run(
            [sys.executable, str(repo / "libexec" / "raptor-audit"),
             "backlog", *argv],
            capture_output=True, text=True, env=env, cwd=repo,
            timeout=120, check=False,
        )

    def test_reimport_then_list_drops_truncation_notice(self, tmp_path):
        run_dir = tmp_path / "run"
        graded_path, _graded = _truncated_fixture(run_dir)

        listed = self._run("list", "--out", str(run_dir))
        assert listed.returncode == 0, listed.stderr
        assert "listing truncated by the producer" in listed.stdout

        cp = self._run("reimport", "--out", str(run_dir),
                       "--graded", str(graded_path))
        assert cp.returncode == 0, cp.stderr
        assert "appended: 3" in cp.stdout
        assert "listed: 2 -> 5" in cp.stdout

        relisted = self._run("list", "--out", str(run_dir))
        assert relisted.returncode == 0, relisted.stderr
        assert "5 dark row(s), 5 listed" in relisted.stdout
        assert "listing truncated by the producer" not in relisted.stdout

    def test_missing_graded_arg_is_parse_error(self, tmp_path):
        run_dir = tmp_path / "run"
        _write_backlog(run_dir, [{
            "class": "unclassified", "count": 1,
            "sites": [_site_for(_graded_row(0))],
        }])
        cp = self._run("reimport", "--out", str(run_dir))
        assert cp.returncode == 2
        assert "--graded" in cp.stderr

    def test_refusal_exits_nonzero(self, tmp_path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        graded_path = _write_graded(run_dir, [_graded_row(0)])
        cp = self._run("reimport", "--out", str(run_dir),
                       "--graded", str(graded_path))
        assert cp.returncode == 1
        assert "nothing to drain" in cp.stderr

    def test_usage_names_reimport(self):
        cp = self._run()
        assert cp.returncode == 1
        assert "reimport" in cp.stderr
