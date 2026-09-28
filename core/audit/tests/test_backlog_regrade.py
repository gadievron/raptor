"""Witness-backlog ``regrade`` — moving unclassified rows to a CWE.

An unclassified dark row has no synthesis channel of its own: the
drain's ranking only dispatches rows with a concrete cluster-class CWE
or an inferable mechanism. ``regrade`` is the sanctioned way to give a
listed unclassified row that channel: a grading overlay names the CWE
and the matched site dict MOVES — same object, byte-identical, every
key untouched — into a cluster of that class. Move semantics by
contract: the ``drained`` ledger is never touched, ``total`` is
unchanged, overlay prose (``justification``/``id``) never enters the
artifact, identities listed under any concrete class never move, and a
no-op pass leaves the file byte-identical (re-running the same overlay
is a no-op). Synthetic fixtures throughout — no LLM calls anywhere in
these tests.
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
    BacklogError,
    RegradeReport,
    load_backlog,
    rank,
    regrade,
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


def _dark_site(i: int, **overrides: Any) -> dict[str, Any]:
    base = _site("src/app.py", f"fn{i}", i + 1,
                 f"hypothesis {i}: user input reaches sink")
    base.update(overrides)
    return base


def _overlay_row(site: dict[str, Any], cwe_id: Any = "CWE-79",
                 **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": site["id"],
        "file": site["file"],
        "function": site["function"],
        "line": site["line"],
        "title": site["title"],
        "cwe_id": cwe_id,
        "justification": "graded by a later review pass",
    }
    row.update(overrides)
    return row


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


def _write_overlay(run_dir: Path, rows: list[Any],
                   name: str = "overlay.json", *,
                   container: bool = False) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / name
    payload: Any = {"rows": rows} if container else rows
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _regrade_fixture(run_dir: Path) -> list[dict[str, Any]]:
    """Three unclassified sites (one carrying a drain attempt) plus one
    already-concrete listing; a ``drained`` ledger rides along so the
    never-touched invariant is observable."""
    sites = [_dark_site(0, drain_attempts=2), _dark_site(1), _dark_site(2)]
    concrete = _dark_site(3)
    _write_backlog(run_dir, [
        {"class": "unclassified", "count": 3, "sites": sites},
        {"class": "CWE-78", "count": 1, "sites": [concrete]},
    ], extra={"drained": {
        "last_run_id": "backlog-drain-0001",
        "last_report": "drain-report.json",
        "witnessed_total": 0,
    }})
    return [*sites, concrete]


def _artifact(run_dir: Path) -> dict[str, Any]:
    return json.loads(
        (run_dir / BACKLOG_FILENAME).read_text(encoding="utf-8"))


def _all_sites(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for c in artifact["clusters"] for s in c["sites"]]


class TestRegradeMove:
    def test_matched_unclassified_row_moves_byte_identical(self, tmp_path):
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        before = _artifact(run_dir)

        report = regrade(
            run_dir, _write_overlay(run_dir, [_overlay_row(sites[0])]))

        assert isinstance(report, RegradeReport)
        assert report.overlay_rows == 1
        assert report.moved == 1
        assert report.sites_moved == 1
        assert report.changed is True
        assert report.listed_before == 4
        assert report.listed_after == 4
        assert report.clusters_before == 2
        assert report.clusters_after == 3

        after = _artifact(run_dir)
        # The moved site dict is byte-identical — every key untouched,
        # drain_attempts included.
        dest = [c for c in after["clusters"] if c["class"] == "CWE-79"]
        assert len(dest) == 1
        assert dest[0]["count"] == 1
        assert dest[0]["sites"] == [before["clusters"][0]["sites"][0]]
        assert dest[0]["sites"][0]["drain_attempts"] == 2
        # Source bookkeeping: sites list lost the object, count
        # decremented; total is UNCHANGED (a move, not a remove).
        assert after["clusters"][0]["count"] == 2
        assert len(after["clusters"][0]["sites"]) == 2
        assert after["total"] == before["total"]
        # The drained ledger is never touched.
        assert after["drained"] == before["drained"]
        # Unknown keys survive the rewrite.
        assert after["future_key"] == before["future_key"]
        # Listed identity count unchanged.
        _art, rows, malformed = load_backlog(run_dir)
        assert malformed == []
        assert len(rows) == 4

    def test_move_reaches_rank_as_declared_cluster_cwe(self, tmp_path):
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        regrade(run_dir, _write_overlay(run_dir, [_overlay_row(sites[0])]))

        _plans, report = rank(run_dir)
        moved = [r for r in report.rows
                 if r.get("function") == sites[0]["function"]]
        assert moved
        assert moved[0]["cwe"] == "CWE-79"
        assert moved[0]["cwe_source"] == "cluster"

    def test_idempotent_second_run_leaves_bytes_alone(self, tmp_path):
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        overlay = _write_overlay(
            run_dir, [_overlay_row(sites[0]), _overlay_row(sites[1])])

        first = regrade(run_dir, overlay)
        assert first.moved == 2
        bytes_after_first = (run_dir / BACKLOG_FILENAME).read_bytes()

        second = regrade(run_dir, overlay)
        assert second.moved == 0
        # Already-regraded rows are no longer listed unclassified —
        # they report as unmatched, never as an error.
        assert second.unmatched == 2
        assert second.changed is False
        assert (run_dir / BACKLOG_FILENAME).read_bytes() == \
            bytes_after_first

    def test_noop_overlay_never_writes(self, tmp_path):
        run_dir = tmp_path / "run"
        _regrade_fixture(run_dir)
        before = (run_dir / BACKLOG_FILENAME).read_bytes()
        overlay = _write_overlay(
            run_dir, [_overlay_row(_dark_site(42))])  # unlisted identity

        report = regrade(run_dir, overlay)
        assert report.moved == 0
        assert report.unmatched == 1
        assert report.changed is False
        assert (run_dir / BACKLOG_FILENAME).read_bytes() == before

    def test_container_rows_shape_accepted(self, tmp_path):
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        overlay = _write_overlay(
            run_dir, [_overlay_row(sites[0])], container=True)
        report = regrade(run_dir, overlay)
        assert report.overlay_rows == 1
        assert report.moved == 1

    def test_moves_into_existing_cluster_with_room(self, tmp_path):
        run_dir = tmp_path / "run"
        resident = _dark_site(50)
        moving = _dark_site(0)
        _write_backlog(run_dir, [
            {"class": "unclassified", "count": 1, "sites": [moving]},
            {"class": "CWE-79", "count": 1, "sites": [resident]},
        ])
        report = regrade(
            run_dir, _write_overlay(run_dir, [_overlay_row(moving)]))
        assert report.moved == 1
        assert report.clusters_after == report.clusters_before == 2
        after = _artifact(run_dir)
        dest = after["clusters"][1]
        assert dest["class"] == "CWE-79"
        assert dest["count"] == 2
        assert [s["id"] for s in dest["sites"]] == \
            [resident["id"], moving["id"]]

    def test_chunking_when_over_write_cap(self, tmp_path, monkeypatch):
        import core.audit.backlog_drain as mod
        monkeypatch.setattr(mod, "_SITES_PER_CLUSTER_WRITE", 2)
        run_dir = tmp_path / "run"
        resident = _dark_site(50)
        moving = [_dark_site(i) for i in range(5)]
        _write_backlog(run_dir, [
            {"class": "unclassified", "count": 5, "sites": moving},
            {"class": "CWE-79", "count": 1, "sites": [resident]},
        ])
        report = regrade(run_dir, _write_overlay(
            run_dir, [_overlay_row(s) for s in moving]))
        assert report.moved == 5
        after = _artifact(run_dir)
        dest = [c for c in after["clusters"] if c["class"] == "CWE-79"]
        # Existing cluster filled to the cap first, then new chunks of
        # at most the cap.
        assert [len(c["sites"]) for c in dest] == [2, 2, 2]
        assert all(c["count"] == len(c["sites"]) for c in dest)
        assert after["clusters"][0]["sites"] == []
        assert after["clusters"][0]["count"] == 0
        assert after["total"] == 6

    def test_duplicate_listings_travel_together(self, tmp_path):
        # Collapsed duplicates share one identity; a regrade moves
        # every copy or none — a half-moved identity would break
        # idempotency (the leftover copy would move again next run).
        run_dir = tmp_path / "run"
        a = _dark_site(0, drain_attempts=1)
        b = _dark_site(0, drain_attempts=1)
        _write_backlog(run_dir, [
            {"class": "unclassified", "count": 1, "sites": [a]},
            {"class": "unclassified", "count": 1, "sites": [b]},
        ], total=2)
        overlay = _write_overlay(run_dir, [_overlay_row(a)])

        report = regrade(run_dir, overlay)
        assert report.moved == 1
        assert report.sites_moved == 2
        after = _artifact(run_dir)
        assert after["total"] == 2
        assert after["clusters"][0]["sites"] == []
        assert after["clusters"][0]["count"] == 0
        assert after["clusters"][1]["sites"] == []
        assert after["clusters"][1]["count"] == 0
        dest = [c for c in after["clusters"] if c["class"] == "CWE-79"]
        assert len(dest) == 1
        assert len(dest[0]["sites"]) == 2

        bytes_after = (run_dir / BACKLOG_FILENAME).read_bytes()
        second = regrade(run_dir, overlay)
        assert second.moved == 0
        assert (run_dir / BACKLOG_FILENAME).read_bytes() == bytes_after

    def test_identity_coercions_shared_with_intake(self, tmp_path):
        # Identity is computed with EXACTLY the intake coercions: a
        # title carrying a control byte is escaped identically on both
        # sides, so the overlay row still matches its listing.
        run_dir = tmp_path / "run"
        hot = _dark_site(0, title="hypothesis 0: \x1b[31mescaped\x1b[0m")
        _write_backlog(run_dir, [
            {"class": "unclassified", "count": 1, "sites": [hot]},
        ])
        report = regrade(
            run_dir, _write_overlay(run_dir, [_overlay_row(hot)]))
        assert report.moved == 1


class TestUnclassifiedGate:
    def test_concrete_class_listing_never_moves(self, tmp_path):
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        before = (run_dir / BACKLOG_FILENAME).read_bytes()
        # sites[3] is listed under CWE-78: the declared cluster CWE
        # outranks the overlay, even when the overlay disagrees.
        report = regrade(run_dir, _write_overlay(
            run_dir, [_overlay_row(sites[3], cwe_id="CWE-79")]))
        assert report.moved == 0
        assert report.unmatched == 1
        assert report.changed is False
        assert (run_dir / BACKLOG_FILENAME).read_bytes() == before

    def test_mixed_listing_never_moves(self, tmp_path):
        # One copy unclassified, one under a concrete class: the
        # concrete listing vetoes the whole identity — copies travel
        # together or not at all.
        run_dir = tmp_path / "run"
        a = _dark_site(0)
        b = _dark_site(0)
        _write_backlog(run_dir, [
            {"class": "unclassified", "count": 1, "sites": [a]},
            {"class": "CWE-78", "count": 1, "sites": [b]},
        ], total=2)
        before = (run_dir / BACKLOG_FILENAME).read_bytes()
        report = regrade(
            run_dir, _write_overlay(run_dir, [_overlay_row(a)]))
        assert report.moved == 0
        assert report.unmatched == 1
        assert (run_dir / BACKLOG_FILENAME).read_bytes() == before


class TestPerRowSkips:
    def test_no_cwe_rows_counted_and_skipped(self, tmp_path):
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        absent = _overlay_row(sites[0])
        del absent["cwe_id"]
        report = regrade(run_dir, _write_overlay(run_dir, [
            _overlay_row(sites[0], cwe_id=None),
            absent,
            _overlay_row(sites[1], cwe_id=""),
            _overlay_row(sites[2], cwe_id="   "),
        ]))
        assert report.no_cwe == 4
        assert report.moved == 0
        assert report.changed is False

    def test_malformed_cwe_is_per_row_refusal_not_a_crash(self, tmp_path):
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        report = regrade(run_dir, _write_overlay(run_dir, [
            _overlay_row(sites[0], cwe_id="CWE-79x"),
            _overlay_row(sites[0], cwe_id="79"),
            _overlay_row(sites[0], cwe_id="injection"),
            _overlay_row(sites[0], cwe_id=79),
            # ... while a well-formed row in the same overlay still
            # moves: one bad row must not deny the overlay.
            _overlay_row(sites[1], cwe_id="CWE-89"),
        ]))
        assert report.malformed_cwe == 4
        assert report.moved == 1
        after = _artifact(run_dir)
        assert any(c["class"] == "CWE-89" for c in after["clusters"])

    def test_cwe_case_folds_upward(self, tmp_path):
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        report = regrade(run_dir, _write_overlay(
            run_dir, [_overlay_row(sites[0], cwe_id="cwe-79")]))
        assert report.moved == 1
        after = _artifact(run_dir)
        assert any(c["class"] == "CWE-79" for c in after["clusters"])

    def test_unusable_identity_counted(self, tmp_path):
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        report = regrade(run_dir, _write_overlay(run_dir, [
            _overlay_row(sites[0], file="/etc/passwd"),   # absolute
            _overlay_row(sites[0], file="../escape.py"),  # traversal
            _overlay_row(sites[0], file=""),              # no file
            _overlay_row(sites[0], function=7),           # non-string
            "not an object",                              # non-dict row
        ]))
        assert report.skipped_unusable == 5
        assert report.moved == 0
        assert report.changed is False

    def test_unmatched_identity_counted(self, tmp_path):
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        report = regrade(run_dir, _write_overlay(run_dir, [
            _overlay_row(_dark_site(77)),                       # unlisted
            _overlay_row(sites[0], line=sites[0]["line"] + 1),  # no fuzz
            _overlay_row(sites[1], title="a different claim"),  # no fuzz
        ]))
        assert report.unmatched == 3
        assert report.moved == 0
        assert report.changed is False


class TestInvariants:
    """Two-direction pins: the wrong-implementation details asserted
    ABSENT, not just the right ones present."""

    def test_move_is_not_a_copy(self, tmp_path):
        # A copy-instead-of-move implementation would leave the
        # identity listed twice and inflate the on-disk site count.
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        before = _artifact(run_dir)
        sites_before = len(_all_sites(before))

        regrade(run_dir, _write_overlay(run_dir, [_overlay_row(sites[0])]))

        after = _artifact(run_dir)
        assert len(_all_sites(after)) == sites_before
        listings = [s for s in _all_sites(after)
                    if s["function"] == sites[0]["function"]]
        assert len(listings) == 1
        # ... and no copy lingers in any unclassified cluster.
        assert all(
            s["function"] != sites[0]["function"]
            for c in after["clusters"] if c["class"] == "unclassified"
            for s in c["sites"]
        )

    def test_overlay_prose_never_enters_the_artifact(self, tmp_path):
        # The destination cluster class carries the whole semantic
        # effect: an implementation that stamps cwe_id/justification
        # (or any bookkeeping) onto the site dict is wrong — the moved
        # dict's serialization must equal its pre-move serialization.
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        before_site = json.dumps(
            _artifact(run_dir)["clusters"][0]["sites"][0], sort_keys=True)

        regrade(run_dir, _write_overlay(run_dir, [_overlay_row(sites[0])]))

        after = _artifact(run_dir)
        dest = [c for c in after["clusters"] if c["class"] == "CWE-79"]
        assert json.dumps(dest[0]["sites"][0], sort_keys=True) == \
            before_site
        for s in _all_sites(after):
            assert "cwe_id" not in s
            assert "justification" not in s
            assert "regraded" not in s

    def test_ledger_and_total_untouched_even_on_moves(self, tmp_path):
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        before = _artifact(run_dir)

        regrade(run_dir, _write_overlay(run_dir, [
            _overlay_row(sites[0]), _overlay_row(sites[1]),
            _overlay_row(sites[2], cwe_id="CWE-89"),
        ]))

        after = _artifact(run_dir)
        assert after["drained"] == before["drained"]
        assert after["total"] == before["total"]


class TestRefusals:
    def test_live_run_refused(self, tmp_path, monkeypatch):
        import core.audit.backlog_drain as mod

        def _boom(run_dir: Path) -> None:
            raise BacklogError("still in flight")

        monkeypatch.setattr(mod, "_refuse_live_run", _boom)
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        overlay = _write_overlay(run_dir, [_overlay_row(sites[0])])
        before = (run_dir / BACKLOG_FILENAME).read_bytes()
        with pytest.raises(BacklogError, match="in flight"):
            regrade(run_dir, overlay)
        assert (run_dir / BACKLOG_FILENAME).read_bytes() == before

    def test_missing_overlay_refused(self, tmp_path):
        run_dir = tmp_path / "run"
        _regrade_fixture(run_dir)
        with pytest.raises(BacklogError, match="nothing to regrade"):
            regrade(run_dir, run_dir / "no-such.json")

    def test_non_regular_overlay_refused(self, tmp_path):
        run_dir = tmp_path / "run"
        _regrade_fixture(run_dir)
        special = run_dir / "overlay-dir.json"
        special.mkdir()
        with pytest.raises(BacklogError, match="not a regular file"):
            regrade(run_dir, special)

    def test_symlinked_overlay_refused(self, tmp_path):
        # lstat by contract: even a symlink to a legitimate regular
        # file is refused — the link itself is the planted artifact.
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        real = _write_overlay(run_dir, [_overlay_row(sites[0])])
        link = run_dir / "overlay-link.json"
        link.symlink_to(real)
        with pytest.raises(BacklogError, match="not a regular file"):
            regrade(run_dir, link)

    def test_oversized_overlay_refused(self, tmp_path, monkeypatch):
        import core.audit.backlog_drain as mod
        monkeypatch.setattr(mod, "MAX_OVERLAY_BYTES", 16)
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        overlay = _write_overlay(run_dir, [_overlay_row(sites[0])])
        with pytest.raises(BacklogError,
                           match="unreadable/malformed/oversized"):
            regrade(run_dir, overlay)

    def test_malformed_overlay_json_refused(self, tmp_path):
        run_dir = tmp_path / "run"
        _regrade_fixture(run_dir)
        bad = run_dir / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        with pytest.raises(BacklogError,
                           match="unreadable/malformed/oversized"):
            regrade(run_dir, bad)

    def test_shapeless_overlay_refused(self, tmp_path):
        run_dir = tmp_path / "run"
        _regrade_fixture(run_dir)
        for payload in ({"not_rows": []}, {"rows": "x"}, "rows", 7):
            bad = run_dir / "shapeless.json"
            bad.write_text(json.dumps(payload), encoding="utf-8")
            with pytest.raises(BacklogError, match="no row list"):
                regrade(run_dir, bad)

    def test_missing_artifact_refused(self, tmp_path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        overlay = _write_overlay(
            run_dir, [_overlay_row(_dark_site(0))])
        with pytest.raises(BacklogError, match="nothing to drain"):
            regrade(run_dir, overlay)

    def test_no_clusters_artifact_refused(self, tmp_path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / BACKLOG_FILENAME).write_text(
            json.dumps({"total": 1}), encoding="utf-8")
        overlay = _write_overlay(
            run_dir, [_overlay_row(_dark_site(0))])
        with pytest.raises(BacklogError, match="no clusters list"):
            regrade(run_dir, overlay)

    def test_cluster_read_bound_refused_not_silently_unread(
            self, tmp_path, monkeypatch):
        # A move that would grow the listing past the consumer read
        # bound refuses BEFORE writing — the moved rows would be
        # unreadable at the next intake.
        import core.audit.backlog_drain as mod
        monkeypatch.setattr(mod, "_MAX_CLUSTERS_READ", 2)
        run_dir = tmp_path / "run"
        moving = _dark_site(0)
        _write_backlog(run_dir, [
            {"class": "unclassified", "count": 1, "sites": [moving]},
            {"class": "CWE-78", "count": 1, "sites": [_dark_site(1)]},
        ])
        overlay = _write_overlay(run_dir, [_overlay_row(moving)])
        before = (run_dir / BACKLOG_FILENAME).read_bytes()
        with pytest.raises(BacklogError, match="read bound"):
            regrade(run_dir, overlay)
        assert (run_dir / BACKLOG_FILENAME).read_bytes() == before


class TestCLI:
    """The ``raptor-audit backlog regrade`` surface."""

    def _run(self, *argv: str) -> subprocess.CompletedProcess[str]:
        repo = Path(__file__).resolve().parents[3]
        env = dict(os.environ, _RAPTOR_TRUSTED="1")
        return subprocess.run(
            [sys.executable, str(repo / "libexec" / "raptor-audit"),
             "backlog", *argv],
            capture_output=True, text=True, env=env, cwd=repo,
            timeout=120, check=False,
        )

    def test_regrade_moves_and_list_reflects_the_class(self, tmp_path):
        run_dir = tmp_path / "run"
        sites = _regrade_fixture(run_dir)
        overlay = _write_overlay(
            run_dir, [_overlay_row(sites[0]),
                      _overlay_row(_dark_site(77))])

        cp = self._run("regrade", "--out", str(run_dir),
                       "--overlay", str(overlay))
        assert cp.returncode == 0, cp.stderr
        assert "moved: 1" in cp.stdout
        assert "unmatched: 1" in cp.stdout
        assert "listed: 4 -> 4" in cp.stdout
        assert "clusters: 2 -> 3" in cp.stdout
        # Per-row dispositions echoed.
        assert "CWE-79  moved" in cp.stdout

        listed = self._run("list", "--out", str(run_dir))
        assert listed.returncode == 0, listed.stderr
        assert "CWE-79" in listed.stdout

    def test_noop_prints_artifact_unchanged(self, tmp_path):
        run_dir = tmp_path / "run"
        _regrade_fixture(run_dir)
        overlay = _write_overlay(
            run_dir, [_overlay_row(_dark_site(77))])
        cp = self._run("regrade", "--out", str(run_dir),
                       "--overlay", str(overlay))
        assert cp.returncode == 0, cp.stderr
        assert "artifact unchanged" in cp.stdout

    def test_missing_overlay_arg_is_parse_error(self, tmp_path):
        run_dir = tmp_path / "run"
        _regrade_fixture(run_dir)
        cp = self._run("regrade", "--out", str(run_dir))
        assert cp.returncode == 2
        assert "--overlay" in cp.stderr

    def test_refusal_exits_nonzero(self, tmp_path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        overlay = _write_overlay(
            run_dir, [_overlay_row(_dark_site(0))])
        cp = self._run("regrade", "--out", str(run_dir),
                       "--overlay", str(overlay))
        assert cp.returncode == 1
        assert "nothing to drain" in cp.stderr

    def test_usage_names_regrade(self):
        cp = self._run()
        assert cp.returncode == 1
        assert "regrade" in cp.stderr
