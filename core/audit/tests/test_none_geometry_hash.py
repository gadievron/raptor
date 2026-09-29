"""None-geometry source hashing covers the fallback read window.

A checklist item with no measured ``line_end`` is reviewed over the
``SOURCE_SPAN_FALLBACK_LINES`` read window
(``core.audit.context._read_source``), but its staleness hash used to
cover only the single header line — so body edits below the header
never flipped the hash and changed code was silently reused as
reviewed. The hash now covers the SAME window the prompt showed
(``core.audit.context.fallback_span_end``), on the stamp side
(``core.audit.record._compute_hash``) and on every verify side (the
journal fold's span candidates, the resume drift gate, the
coverage-record import gate) — a verify side left on the single line
would read every window-stamped row as permanent drift and re-buy the
same review on every fold.

Measured-``line_end`` spans are byte-identical to the pre-fix hashes
(pinned literals below): only None geometry changes, so existing
measured-span stamps keep verifying. Existing None-geometry stamps
mismatch once and re-review once — the intended fail-closed
migration.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.context import SOURCE_SPAN_FALLBACK_LINES, _read_source
from core.audit.record import _compute_hash
from core.audit.resume import compute_drift
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    merge_into_index,
    now_iso,
)
from core.staleness import hash_span

# Header at line 10; the fallback read window is lines 10..59
# (SOURCE_SPAN_FALLBACK_LINES = 50, header line included).
_HEADER_LINE = 10
_LAST_IN_WINDOW = _HEADER_LINE + SOURCE_SPAN_FALLBACK_LINES - 1  # 59
_FIRST_PAST_WINDOW = _LAST_IN_WINDOW + 1                         # 60


def _write_file(target: Path, edits: dict[int, str] | None = None) -> None:
    """120 distinct lines; ``edits`` replaces 1-indexed lines."""
    lines = [f"// filler {i}" for i in range(1, 121)]
    lines[_HEADER_LINE - 1] = "int handler(struct req *r) {"
    lines[_LAST_IN_WINDOW - 1] = "    last_line_inside_window();"
    lines[_FIRST_PAST_WINDOW - 1] = "    first_line_past_window();"
    for lineno, text in (edits or {}).items():
        lines[lineno - 1] = text
    (target / "a.c").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    _write_file(target)
    return target


class TestComputeHashNoneGeometry:
    def test_body_change_inside_window_flips_hash(self, tmp_path: Path):
        # The defect: with line_end=None only the header line was
        # hashed, so a body edit inside the reviewed window kept the
        # hash stable and staleness gating treated changed code as
        # unchanged.
        target = _target(tmp_path)
        before = _compute_hash(target, "a.c", _HEADER_LINE, None)
        _write_file(target, {20: "    int n = r->len + OVERFLOW;"})
        after = _compute_hash(target, "a.c", _HEADER_LINE, None)
        assert before and after
        assert before != after, (
            "a body edit inside the fallback read window must flip "
            "the None-geometry source hash — a header-only hash makes "
            "body changes invisible to staleness/reuse gating"
        )

    def test_unchanged_source_keeps_stable_hash(self, tmp_path: Path):
        target = _target(tmp_path)
        first = _compute_hash(target, "a.c", _HEADER_LINE, None)
        _write_file(target)  # byte-identical rewrite
        second = _compute_hash(target, "a.c", _HEADER_LINE, None)
        assert first and first == second

    def test_change_past_window_keeps_hash(self, tmp_path: Path):
        # Reuse stays cheap: edits beyond the reviewed window (lines
        # the prompt never showed) must not invalidate the review.
        target = _target(tmp_path)
        before = _compute_hash(target, "a.c", _HEADER_LINE, None)
        _write_file(target, {100: "    unrelated_change();"})
        after = _compute_hash(target, "a.c", _HEADER_LINE, None)
        assert before and before == after

    def test_measured_span_hashes_pinned(self, tmp_path: Path):
        # Stability contract: measured-line_end hashes are
        # byte-identical to the pre-window-fix values (literals
        # captured before the fix), so every existing measured-span
        # stamp keeps verifying across the upgrade.
        target = tmp_path / "target"
        target.mkdir()
        (target / "m.c").write_text(
            "int check(const char *s) {\n"
            "    if (!s)\n"
            "        return -1;\n"
            "    return validate(s);\n"
            "}\n",
            encoding="utf-8",
        )
        assert _compute_hash(target, "m.c", 1, 5) == "2eed3f7448b9"
        assert _compute_hash(target, "m.c", 2, 2) == "efc6626c662d"


class TestReadHashWindowCoupling:
    """The hash must cover exactly the lines the prompt showed."""

    def test_fallback_span_end_rule(self):
        # Local import: the helper is the fix's shared window rule —
        # importing it at module level would turn every defect test
        # in this file into a collection error on a pre-fix tree.
        from core.audit.context import fallback_span_end
        assert fallback_span_end(10, 42) == 42
        assert fallback_span_end(10, None) == (
            10 + SOURCE_SPAN_FALLBACK_LINES - 1)
        # Degenerate line_start: same 50-line slice _read_source
        # takes from the top of the file.
        assert fallback_span_end(0, None) == SOURCE_SPAN_FALLBACK_LINES

    def test_window_boundary_agrees_both_directions(self, tmp_path: Path):
        target = _target(tmp_path)
        shown = _read_source(target, "a.c", _HEADER_LINE, None)
        assert "last_line_inside_window" in shown
        assert "first_line_past_window" not in shown

        base = _compute_hash(target, "a.c", _HEADER_LINE, None)
        _write_file(
            target, {_LAST_IN_WINDOW: "    edited_inside_window();"})
        assert _compute_hash(target, "a.c", _HEADER_LINE, None) != base, (
            "the window's last prompted line is hash-covered"
        )
        _write_file(
            target, {_FIRST_PAST_WINDOW: "    edited_past_window();"})
        assert _compute_hash(target, "a.c", _HEADER_LINE, None) == base, (
            "the first line the prompt never showed is not hash-covered"
        )


def _checklist(target: Path) -> dict:
    # No line_end on the item — the None-geometry inventory shape.
    return {
        "target_path": str(target),
        "files": [{
            "path": "a.c",
            "language": "c",
            "items": [{
                "name": "handler",
                "kind": "function",
                "line_start": _HEADER_LINE,
            }],
        }],
    }


def _project_with_entry(tmp_path: Path, source_hash: str) -> Path:
    project = tmp_path / "project"
    run_dir = project / "run1"
    run_dir.mkdir(parents=True, exist_ok=True)
    append_entry(run_dir, ReviewJournalEntry(
        ts=now_iso(),
        run_id="run1",
        file="a.c",
        function="handler",
        verdict="clean",
        source_hash=source_hash,
        line_start=_HEADER_LINE,
        line_end=None,
    ))
    merge_into_index(project, run_dir)
    return project


def _gap_keys(gaps: list[dict]) -> set[str]:
    return {f"{g['file']}:{g['name']}" for g in gaps}


class TestFoldRoundTrip:
    """A window-stamped None-geometry row verifies in the fold when
    the source is unchanged (no permanent re-review) and resurfaces
    when the body changes (the staleness the stamp exists to catch)."""

    def test_unchanged_none_row_stays_covered(self, tmp_path: Path):
        from core.audit.gaps import compute_gaps
        target = _target(tmp_path)
        stored = _compute_hash(target, "a.c", _HEADER_LINE, None)
        project = _project_with_entry(tmp_path, stored)
        gaps = compute_gaps(_checklist(target), [], project_dir=project)
        assert "a.c:handler" not in _gap_keys(gaps), (
            "the fold must hash the same window the stamp covered — "
            "hashing the normalised single line makes every "
            "window-stamped row permanent drift"
        )

    def test_body_edit_inside_window_resurfaces(self, tmp_path: Path):
        from core.audit.gaps import compute_gaps
        target = _target(tmp_path)
        stored = _compute_hash(target, "a.c", _HEADER_LINE, None)
        project = _project_with_entry(tmp_path, stored)
        _write_file(target, {20: "    int n = r->len + OVERFLOW;"})
        gaps = compute_gaps(_checklist(target), [], project_dir=project)
        assert "a.c:handler" in _gap_keys(gaps), (
            "a None-geometry function whose body changed inside the "
            "reviewed window must be re-reviewed, not suppressed"
        )

    def test_legacy_header_only_stamp_re_reviews_once(self, tmp_path: Path):
        # Migration contract: rows stamped pre-fix (header line only)
        # mismatch the window recompute and re-review ONCE; the fresh
        # entry re-records the window hash and verifies from then on
        # (the unchanged-row test above).
        from core.audit.gaps import compute_gaps
        target = _target(tmp_path)
        legacy = hash_span(target / "a.c", _HEADER_LINE, _HEADER_LINE)
        project = _project_with_entry(tmp_path, legacy)
        gaps = compute_gaps(_checklist(target), [], project_dir=project)
        assert "a.c:handler" in _gap_keys(gaps)


class TestResumeDriftGate:
    def test_unchanged_none_row_reports_no_drift(self, tmp_path: Path):
        target = _target(tmp_path)
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        append_entry(run_dir, ReviewJournalEntry(
            ts=now_iso(), run_id="run1", file="a.c", function="handler",
            verdict="clean",
            source_hash=_compute_hash(target, "a.c", _HEADER_LINE, None),
            line_start=_HEADER_LINE, line_end=None,
        ))
        drifted, checked = compute_drift(run_dir, target)
        assert checked == 1
        assert drifted == [], (
            "a fresh window stamp must verify on resume — a "
            "single-line recompute re-buys every None-geometry "
            "review on every resume"
        )

    def test_body_edit_inside_window_reports_drift(self, tmp_path: Path):
        target = _target(tmp_path)
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        append_entry(run_dir, ReviewJournalEntry(
            ts=now_iso(), run_id="run1", file="a.c", function="handler",
            verdict="clean",
            source_hash=_compute_hash(target, "a.c", _HEADER_LINE, None),
            line_start=_HEADER_LINE, line_end=None,
        ))
        _write_file(target, {20: "    int n = r->len + OVERFLOW;"})
        drifted, checked = compute_drift(run_dir, target)
        assert checked == 1
        assert [(d.file, d.function) for d in drifted] == [
            ("a.c", "handler"),
        ]


class TestCoverageImportGate:
    """The unstamped-row source-currency gate hashes the same window
    the stamp covered — and withdraws credit when the body changed."""

    def _import(self, tmp_path: Path, target: Path, rows: list[dict]):
        from core.coverage.importer import (
            _function_ranges,
            _inventory_paths,
            import_functions_analysed,
        )
        from core.coverage.store import CoverageStore
        store = CoverageStore(tmp_path / "coverage.json", target="zip:abc")
        checklist = _checklist(target)
        record = {"tool": "llm", "timestamp": now_iso(),
                  "functions_analysed": rows}
        marked = import_functions_analysed(
            store, record, _function_ranges(checklist),
            _inventory_paths(checklist),
            checklist_target=str(target))
        return store, marked

    def test_current_window_hash_earns_review_credit(self, tmp_path: Path):
        target = _target(tmp_path)
        row = {"file": "a.c", "function": "handler",
               "hash": _compute_hash(target, "a.c", _HEADER_LINE, None)}
        store, marked = self._import(tmp_path, target, [row])
        assert marked == 1
        labels = store.tool_coverage_of_range(
            "a.c", _HEADER_LINE, _HEADER_LINE)
        assert "llm" in labels

    def test_body_edit_inside_window_demotes(self, tmp_path: Path):
        target = _target(tmp_path)
        row = {"file": "a.c", "function": "handler",
               "hash": _compute_hash(target, "a.c", _HEADER_LINE, None)}
        _write_file(target, {20: "    int n = r->len + OVERFLOW;"})
        store, marked = self._import(tmp_path, target, [row])
        assert marked == 1
        labels = store.tool_coverage_of_range(
            "a.c", _HEADER_LINE, _HEADER_LINE)
        assert "llm:machine" in labels, (
            "an unstamped row whose reviewed window changed must "
            "demote to machine tier, not keep review credit"
        )
        assert "llm" not in labels
