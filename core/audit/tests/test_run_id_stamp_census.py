"""Run-attribution stamping: orchestrator journal writers and the
resolved-identity helper.

Contract under test: every orchestrator journal-writer stamps
``run_id`` with the RESOLVED run-dir basename via ``_resolved_run_id``
— the exact identity ``export_graded_from_journal`` compares
MAC-covered receipts against. An unresolved stamp inverts for every
relative ``out_dir`` spelling ("." from inside the run dir has
``Path(".").name == ""``): rows read as carrying no attribution and
the run's own record can never grade run-scoped.

The census here is a write-site tripwire, not a security boundary: a
literal-shape census is evadable by a determined respelling (the
variable could be renamed, the basename re-derived through ``str``
slicing). The guarded property is producer-side dev-time correctness
— a new journal writer reaching for the obvious ``out_dir.name``
spelling — so the census plus the helper being the one importable
spelling is proportionate for that risk class.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from types import SimpleNamespace

import core.audit.orchestrator as orch
from core.audit.findings_export import export_graded_from_journal
from core.coverage.journal import RUN_ID_UNATTRIBUTED

REPO_ROOT = Path(__file__).resolve().parents[3]
ORCH_PATH = REPO_ROOT / "core" / "audit" / "orchestrator.py"
HELPER = "_resolved_run_id"

#: The seven journal-writer sites the sweep routed (Collector
#: construction, decomp-tree sweep, prompt-leak + consistency
#: mechanical rows, _commit_outcome, the per-review append, and the
#: post-loop promotion append). A new writer raises the count — the
#: floor only guards the census against going vacuous.
_KNOWN_ROUTED_SITES = 7


def _run_id_stamp_sites(source: str) -> tuple[list[int], list[str]]:
    """Classify every ``run_id`` stamp whose value derives from
    ``out_dir``: (routed helper-call line numbers, direct-derivation
    violations). Both keyword-argument stamps (``run_id=...``) and
    variable assignments (``run_id = ...``) are swept.
    """
    tree = ast.parse(source)
    routed: list[int] = []
    direct: list[str] = []

    def classify(value: ast.expr, lineno: int) -> None:
        segment = ast.get_source_segment(source, value) or ""
        if "out_dir" not in segment:
            return
        if (isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == HELPER):
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
    def test_every_out_dir_stamp_routes_through_helper(self):
        routed, direct = _run_id_stamp_sites(ORCH_PATH.read_text())
        assert not direct, (
            "orchestrator run_id stamps deriving from out_dir outside "
            f"{HELPER} (stamp the resolved identity — route through "
            f"the helper): {direct}"
        )
        # Non-vacuity: the census must keep seeing the swept writers.
        assert len(routed) >= _KNOWN_ROUTED_SITES

    def test_no_raw_basename_derivation(self):
        # Belt-and-braces token tripwire for the pre-sweep spelling:
        # ``<anything>out_dir.name`` must not reappear anywhere in the
        # orchestrator — the helper derives from its own local.
        source = ORCH_PATH.read_text()
        assert not re.search(r"out_dir\s*\.\s*name\b", source)

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

    def test_census_accepts_routed_spelling(self):
        routed, direct = _run_id_stamp_sites(
            "append_journal_for_outcome(\n"
            "    run_id=_resolved_run_id(config.out_dir),\n"
            ")\n",
        )
        assert routed and not direct

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
