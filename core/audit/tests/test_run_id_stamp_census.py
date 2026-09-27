"""Run-attribution stamping: journal writers and the
resolved-identity helper.

Contract under test: every journal writer that derives ``run_id``
from a run-directory path stamps the RESOLVED basename via the shared
resolver (``core.coverage.journal.resolved_run_id``; the orchestrator
through its ``_resolved_run_id`` delegate) — the exact identity
``export_graded_from_journal`` compares MAC-covered receipts against.
An unresolved stamp inverts for every relative spelling ("." from
inside the run dir has ``Path(".").name == ""``): rows read as
carrying no attribution and the run's own record can never grade
run-scoped.

The census here is a write-site tripwire, not a security boundary: a
literal-shape census is evadable by a determined respelling (the
variable could be renamed, the basename re-derived through ``str``
slicing). The guarded property is producer-side dev-time correctness
— a new journal writer reaching for the obvious ``out_dir.name`` /
``run_dir.name`` spelling — so the census plus the helper being the
one importable spelling is proportionate for that risk class.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.audit.orchestrator as orch
from core.audit.findings_export import export_graded_from_journal
from core.coverage.journal import RUN_ID_UNATTRIBUTED

REPO_ROOT = Path(__file__).resolve().parents[3]
ORCH_PATH = REPO_ROOT / "core" / "audit" / "orchestrator.py"
EMIT_PATH = REPO_ROOT / "packages" / "llm_analysis" / "journal_emit.py"
SUMMARY_PATH = REPO_ROOT / "libexec" / "raptor-coverage-summary"

#: Accepted routed spellings: the shared resolver and the
#: orchestrator's module-local delegate to it.
HELPERS = frozenset({"_resolved_run_id", "resolved_run_id"})

#: Run-directory variable names a ``run_id`` stamp may derive from.
#: The orchestrator and the agentic emit seam spell it ``out_dir``;
#: the coverage-summary mark journaling spells it ``run_dir``.
_DERIVATION_ROOTS = ("out_dir", "run_dir")

#: Swept files with their routed-site floors: the orchestrator's
#: seven writer sites (Collector construction, decomp-tree sweep,
#: prompt-leak + consistency mechanical rows, _commit_outcome, the
#: per-review append, the post-loop promotion append), the agentic
#: per-finding emit, and coverage-summary's mark + unmark-withdrawal
#: appends. A new writer raises the count — the floors only guard the
#: census against going vacuous.
_CENSUS_FILES = [
    pytest.param(ORCH_PATH, 7, id="orchestrator"),
    pytest.param(EMIT_PATH, 1, id="journal_emit"),
    pytest.param(SUMMARY_PATH, 2, id="coverage-summary"),
]


def _run_id_stamp_sites(source: str) -> tuple[list[int], list[str]]:
    """Classify every ``run_id`` stamp whose value derives from a
    run-directory variable (``_DERIVATION_ROOTS``): (routed
    helper-call line numbers, direct-derivation violations). Both
    keyword-argument stamps (``run_id=...``) and variable assignments
    (``run_id = ...``) are swept.
    """
    tree = ast.parse(source)
    routed: list[int] = []
    direct: list[str] = []

    def classify(value: ast.expr, lineno: int) -> None:
        segment = ast.get_source_segment(source, value) or ""
        if not any(root in segment for root in _DERIVATION_ROOTS):
            return
        if (isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id in HELPERS):
            routed.append(lineno)
        else:
            direct.append(f"line {lineno}: run_id={segment[:60]}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "run_id":
                    classify(kw.value, node.lineno)
        elif isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "run_id"
                   for t in node.targets):
                classify(node.value, node.lineno)
        elif isinstance(node, ast.AnnAssign):
            if (isinstance(node.target, ast.Name)
                    and node.target.id == "run_id"
                    and node.value is not None):
                classify(node.value, node.lineno)

    return routed, direct


class TestWriteSiteCensus:
    @pytest.mark.parametrize(("path", "floor"), _CENSUS_FILES)
    def test_every_run_dir_stamp_routes_through_helper(self, path, floor):
        routed, direct = _run_id_stamp_sites(path.read_text())
        assert not direct, (
            f"{path.name}: run_id stamps deriving from a run-dir "
            "variable outside the resolver (stamp the resolved "
            f"identity — route through the helper): {direct}"
        )
        # Non-vacuity: the census must keep seeing the swept writers.
        assert len(routed) >= floor

    @pytest.mark.parametrize(
        "path",
        [pytest.param(ORCH_PATH, id="orchestrator"),
         pytest.param(EMIT_PATH, id="journal_emit")],
    )
    def test_no_raw_basename_derivation(self, path):
        # Belt-and-braces token tripwire for the pre-sweep spellings:
        # ``out_dir.name`` / ``Path(out_dir).name`` must not reappear —
        # the resolver derives from its own local.
        # libexec/raptor-coverage-summary is deliberately absent here:
        # its ``run_dir.name`` appears in operator-facing display
        # strings, so the AST census above owns its stamps instead.
        assert not re.search(r"out_dir\s*\)?\s*\.\s*name\b", path.read_text())

    def test_census_trips_on_direct_kwarg_spelling(self):
        # Mutant shape: one site reverted to the pre-sweep spelling.
        routed, direct = _run_id_stamp_sites(
            "collector = Collector(\n"
            "    out_dir=config.out_dir,\n"
            '    run_id=config.out_dir.name if config.out_dir else "",\n'
            ")\n",
        )
        assert direct and not routed

    def test_census_trips_on_direct_assignment_spelling(self):
        routed, direct = _run_id_stamp_sites(
            'run_id = config.out_dir.name if config.out_dir else ""\n',
        )
        assert direct and not routed

    def test_census_trips_on_run_dir_kwarg_spelling(self):
        # Mutant shape: the coverage-summary sites' pre-fix spelling.
        routed, direct = _run_id_stamp_sites(
            "append_entry(run_dir, ReviewJournalEntry(\n"
            "    ts=now_iso(), run_id=run_dir.name,\n"
            "))\n",
        )
        assert direct and not routed

    def test_census_accepts_routed_spelling(self):
        routed, direct = _run_id_stamp_sites(
            "append_journal_for_outcome(\n"
            "    run_id=_resolved_run_id(config.out_dir),\n"
            ")\n",
        )
        assert routed and not direct

    def test_census_accepts_shared_helper_spelling(self):
        # The non-orchestrator sites route through the shared resolver
        # under its importable name.
        routed, direct = _run_id_stamp_sites(
            "entry = ReviewJournalEntry(\n"
            "    run_id=resolved_run_id(Path(out_dir)),\n"
            ")\n"
            "row = ReviewJournalEntry(run_id=resolved_run_id(run_dir))\n",
        )
        assert len(routed) == 2 and not direct

    def test_census_ignores_stamps_not_derived_from_out_dir(self):
        # Pass-through and literal stamps are other identities'
        # business (entry.run_id re-stamps, sentinel constants) — the
        # census only owns the out_dir derivation.
        routed, direct = _run_id_stamp_sites(
            "f(run_id=entry.run_id)\n"
            'g(run_id="")\n',
        )
        assert not routed and not direct


class TestResolvedRunIdHelper:
    def test_relative_out_dir_stamps_resolved_name(
            self, tmp_path, monkeypatch):
        # The seam this sweep closes: "." from inside the run dir has
        # name == "" unresolved.
        run = tmp_path / "runX"
        run.mkdir()
        monkeypatch.chdir(run)
        assert orch._resolved_run_id(Path(".")) == "runX"

    def test_absolute_out_dir_stamp_unchanged(self, tmp_path):
        # Differential pin for the normal shape: lifecycle passes
        # absolute, already-resolved run dirs, and there the helper
        # returns exactly the pre-sweep ``out_dir.name`` stamp — rows
        # for such runs are byte-identical to what the old spelling
        # wrote (run_id is the only field this sweep touches).
        run = tmp_path / "audit_20260926"
        run.mkdir()
        assert orch._resolved_run_id(run) == run.name == "audit_20260926"

    def test_none_out_dir_keeps_empty_stamp(self):
        # The historical no-run-dir spelling: "" is the consumer-side
        # equivalent of the sentinel (marked install tier), kept so
        # the None arm stays byte-identical too.
        assert orch._resolved_run_id(None) == ""

    def test_filesystem_root_falls_back_to_sentinel(self):
        assert orch._resolved_run_id(Path("/")) == RUN_ID_UNATTRIBUTED

    def test_resolution_failure_falls_back_to_unresolved_name(
            self, monkeypatch):
        # The OSError arm keeps whatever name the unresolved path
        # carries; only a name-less path lands on the sentinel — the
        # sentinel is reachable through the fallback arms alone.
        def _boom(self, strict=False):
            raise OSError("resolution failed")

        monkeypatch.setattr(type(Path()), "resolve", _boom)
        assert orch._resolved_run_id(Path("/x/runZ")) == "runZ"
        assert orch._resolved_run_id(Path("")) == RUN_ID_UNATTRIBUTED

    def test_happy_path_never_stamps_sentinel(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path.parent)
        for spelling in (tmp_path, Path(tmp_path.name)):
            assert orch._resolved_run_id(spelling) == tmp_path.name


class TestJournalRoundTrip:
    """Producer↔consumer identity: a row written through the shared
    journal writer with the helper's stamp round-trips run-scoped
    through ``export_graded_from_journal`` — receipts intact, no
    install marker, no foreign arm. This pin fails if the helper stops
    resolving (a relative spelling would stamp "" → the marked
    grandfather tier)."""

    @staticmethod
    def _write_row(out_dir: Path, target: Path) -> None:
        from core.audit.collector import append_journal_for_outcome

        outcome = SimpleNamespace(
            file="src/a.c", function="foo", status="suspicious",
            body="executed taint rule confirms source-to-sink flow",
            model=None, hypothesis=None, hypotheses=None,
            evidence_tool="semgrep", tools_dispatched=None,
            review_result=None, cost_usd=None, duration_s=None,
        )
        append_journal_for_outcome(
            out_dir=out_dir,
            target_path=target,
            run_id=orch._resolved_run_id(out_dir),
            outcome=outcome,
            gap={"line_start": 5, "line_end": None, "strategies": []},
        )

    def test_relative_out_dir_row_exports_run_scoped(
            self, tmp_path, monkeypatch):
        run = tmp_path / "runR"
        run.mkdir()
        target = tmp_path / "target"
        target.mkdir()
        monkeypatch.chdir(run)
        self._write_row(Path("."), target)
        graded = export_graded_from_journal(Path("."))
        assert graded is not None
        assert graded["derivation"]["foreign_run_rows"] == 0
        assert graded["derivation"]["unscoped_run_rows"] == 0
        rec = graded["findings"][0]
        assert rec["discovery"]["evidence_tool"] == "semgrep"
        assert "receipt_scope" not in rec["provenance"]

    def test_absolute_out_dir_row_exports_run_scoped(self, tmp_path):
        run = tmp_path / "runS"
        run.mkdir()
        target = tmp_path / "target"
        target.mkdir()
        self._write_row(run, target)
        graded = export_graded_from_journal(run)
        assert graded is not None
        assert graded["derivation"]["unscoped_run_rows"] == 0
        rec = graded["findings"][0]
        assert rec["discovery"]["evidence_tool"] == "semgrep"
        assert "receipt_scope" not in rec["provenance"]
