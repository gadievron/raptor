"""link_finding / function_verdict scale discipline.

findings.json is sandbox-writable run-dir input, and the findings
import runs under the cross-process ``coverage_store_lock`` at every
run completion — so per-insert cost is availability-relevant: a
linear dedup scan per insert made one large or hostile findings.json
quadratic, stalling the completing run AND every sibling run's
snapshot behind the lock. These tests pin the O(1) id-index insert,
the bisect-backed verdict query, and the semantics both must
preserve.
"""

from __future__ import annotations

import time

import pytest

from core.coverage.importer import import_findings
from core.coverage.store import CoverageStore


class _CountingList(list):
    """A list that counts how often it is iterated.

    The pre-index dedup iterated the whole findings list once PER
    INSERT (the quadratic); the id index never re-walks it after the
    one lazy build. Counting ``__iter__`` calls turns the complexity
    class into a deterministic assertion (wall-clock-free,
    loaded-runner safe).
    """

    iters = 0

    def __iter__(self):
        _CountingList.iters += 1
        return super().__iter__()


class TestLinkFindingScale:
    def test_insert_does_not_rescan_findings_list(self, tmp_path):
        n = 300
        store = CoverageStore(tmp_path / "coverage.json")
        # First link builds whatever lazy lookup the store keeps;
        # then swap in the counting list so only POST-warmup rescans
        # are measured.
        store.link_finding("src/a.c", "F0", line=5)
        entry = store._files["src/a.c"]
        entry["findings"] = _CountingList(entry["findings"])
        _CountingList.iters = 0
        for i in range(1, n):
            store.link_finding("src/a.c", f"F{i}", line=5)
        assert _CountingList.iters == 0, (
            f"findings list iterated {_CountingList.iters} times for "
            f"{n - 1} inserts — per-insert dedup is scanning it"
        )
        assert len(store._findings("src/a.c")) == n

    @pytest.mark.slow
    def test_import_findings_scales_linearly(self, tmp_path):
        # Perf baseline (slow tier): doubling the row count must not
        # quadruple the time. Sizes chosen so the linear case is well
        # under a second while the quadratic one measured seconds.
        def _run(n: int) -> float:
            store = CoverageStore(tmp_path / f"coverage-{n}.json")
            findings = [
                {"id": f"F{i}", "file": "src/a.c", "line": 5}
                for i in range(n)
            ]
            t0 = time.perf_counter()
            import_findings(store, findings)
            return time.perf_counter() - t0

        t1 = _run(10_000)
        t2 = _run(40_000)
        assert t2 < max(t1, 0.01) * 10, (
            f"4x rows took {t2:.2f}s vs {t1:.2f}s — super-linear import"
        )


class TestLinkFindingSemantics:
    def test_relink_refreshes_line_and_retained(self, tmp_path):
        store = CoverageStore(tmp_path / "coverage.json")
        store.link_finding("a.c", "F1", line=5, retained=True)
        store.link_finding("a.c", "F1", line=7, retained=False)
        (f,) = store._findings("a.c")
        assert (f["line"], f["retained"]) == (7, False)

    def test_relink_with_no_line_keeps_old_line(self, tmp_path):
        store = CoverageStore(tmp_path / "coverage.json")
        store.link_finding("a.c", "F1", line=5)
        store.link_finding("a.c", "F1", line=None, retained=False)
        (f,) = store._findings("a.c")
        assert (f["line"], f["retained"]) == (5, False)

    def test_duplicate_id_legacy_store_updates_first(self, tmp_path):
        # A legacy store can carry duplicate ids (no load-side dedup);
        # the pre-index scan updated the FIRST occurrence — the index
        # must keep doing so.
        store = CoverageStore(tmp_path / "coverage.json")
        store._entry("a.c")["findings"].extend([
            {"id": "F1", "line": 1, "retained": True},
            {"id": "F1", "line": 2, "retained": True},
        ])
        store.link_finding("a.c", "F1", line=9, retained=False)
        rows = store._findings("a.c")
        assert (rows[0]["line"], rows[0]["retained"]) == (9, False)
        assert (rows[1]["line"], rows[1]["retained"]) == (2, True)
        assert len(rows) == 2

    def test_verdict_reflects_relink_after_query(self, tmp_path):
        # The bisect cache must invalidate on mutation: query, flip
        # retained, query again.
        store = CoverageStore(tmp_path / "coverage.json")
        store.link_finding("a.c", "F1", line=5, retained=True)
        assert store.function_verdict("a.c", 1, 10) == "open"
        store.link_finding("a.c", "F1", retained=False)
        assert store.function_verdict("a.c", 1, 10) == "found_then_lost"

    def test_verdict_line_edges_and_mixed_retained(self, tmp_path):
        store = CoverageStore(tmp_path / "coverage.json")
        store.link_finding("a.c", "lost", line=10, retained=False)
        store.link_finding("a.c", "open", line=20, retained=True)
        # Range covering only the lost finding.
        assert store.function_verdict("a.c", 10, 10) == "found_then_lost"
        # Range covering both: any retained finding wins.
        assert store.function_verdict("a.c", 5, 25) == "open"
        # Range covering neither, no coverage: unexamined.
        assert store.function_verdict("a.c", 11, 19) == "unexamined"
        # Lineless findings never attribute to a function.
        store.link_finding("a.c", "nolines", line=None)
        assert store.function_verdict("a.c", 11, 19) == "unexamined"
