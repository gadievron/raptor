"""Audit-log rows carry authority only when their run-bound MAC verifies.

The ``.audit-log.jsonl`` trail lives in the target-writable run dir.
Consumers whose read SUPPRESSES work or RELAXES a gate must judge only
rows whose per-purpose, run-bound integrity token verifies
(``journal_mac.verify_audit_log_row``), failing toward NOT-suppressing
— the direction contract the resume reader (``get_reviewed_set``)
established. These tests pin the remaining authority-bearing
consumers, and the census class derives the full reader set
mechanically so a new consumer must classify itself as authority
(verifying) or telemetry (allowlisted with rationale) before it can
land.
"""

from __future__ import annotations

import ast
import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _plant_raw_row(out_dir: Path, row: dict) -> None:
    """Append a row WITHOUT the integrity stamp — the forged /
    legacy shape (an attacker holding the run-dir write grant can
    append any bytes; they cannot mint a token)."""
    import json

    log = out_dir / ".audit-log.jsonl"
    with log.open("a") as fh:
        fh.write(json.dumps(row) + "\n")


class TestFailOpenAdjudicatedSites:
    """Deferral SUPPRESSES CWE-252 census sites — a planted
    ``fail_open_check`` row must never earn it."""

    ROW = {
        "action": "fail_open_check",
        "outcome": "confirmed",
        "file": "src/a.c",
        "handler": {"line": 12},
    }

    def test_forged_row_does_not_defer(self, tmp_path: Path):
        from core.audit.orchestrator import _fail_open_adjudicated_sites

        _plant_raw_row(tmp_path, self.ROW)
        assert _fail_open_adjudicated_sites(tmp_path) == set()

    def test_stamped_row_defers(self, tmp_path: Path):
        from core.audit.orchestrator import _fail_open_adjudicated_sites
        from core.audit.record import append_audit_log

        append_audit_log(tmp_path, self.ROW)
        assert _fail_open_adjudicated_sites(tmp_path) == {("src/a.c", 12)}

    def test_cross_run_replay_does_not_defer(self, tmp_path: Path):
        # A row minted for a SIBLING run dir fails the run binding.
        from core.audit.orchestrator import _fail_open_adjudicated_sites
        from core.audit.record import append_audit_log

        other = tmp_path / "other"
        other.mkdir()
        append_audit_log(other, self.ROW)
        here = tmp_path / "here"
        here.mkdir()
        (here / ".audit-log.jsonl").write_bytes(
            (other / ".audit-log.jsonl").read_bytes())
        assert _fail_open_adjudicated_sites(here) == set()


class TestRelogForgedLastRow:
    """The re-log join decides which corrective final-status rows are
    appended. A planted LAST row matching the final status would
    suppress the correction and stay the last word for every
    last-row-per-key consumer — forged rows must be invisible to the
    join."""

    def _config(self, tmp_path: Path):
        from core.audit.orchestrator import OrchestratorConfig

        target = tmp_path / "target"
        target.mkdir()
        (target / "a.c").write_text("int f(int x) { return x + 1; }\n")
        out = tmp_path / "out"
        out.mkdir()
        return OrchestratorConfig(target_path=target, out_dir=out)

    def test_forged_matching_row_does_not_suppress_correction(
        self, tmp_path: Path,
    ):
        from core.audit.orchestrator import (
            OrchestratorResult,
            ReviewOutcome,
            _relog_final_statuses,
        )
        from core.audit.record import append_audit_log, load_audit_log

        config = self._config(tmp_path)
        # Genuine mid-loop row (stamped by the production writer).
        append_audit_log(config.out_dir, {
            "action": "orchestrator_review", "key": "a.c:f:1",
            "status": "suspicious",
        })
        # Forged last row already spelling the final status.
        _plant_raw_row(config.out_dir, {
            "action": "orchestrator_review", "key": "a.c:f:1",
            "status": "clean",
        })
        final = ReviewOutcome(
            file="a.c", function="f", status="clean",
            body="resolved", hypothesis="h", line=1,
        )
        result = OrchestratorResult()
        result.outcomes = [final]
        # The genuine history says "suspicious" — the correction must
        # be appended regardless of the forged row.
        assert _relog_final_statuses(result, config) == 1
        rows = [
            e for e in load_audit_log(config.out_dir)
            if e.get("final_status_correction")
        ]
        assert rows and rows[-1]["status"] == "clean"


class TestRecordGatesVerified:
    """cmd_record's G5 READ-FIRST and G2 sweep-receipt gates relax on
    matching rows — planted rows must not satisfy them; rows written
    by the production subcommands (stamped) must."""

    def _load_cli(self):
        script = _REPO_ROOT / "libexec" / "raptor-audit"
        loader = SourceFileLoader("raptor_audit_cli_auth", str(script))
        spec = importlib.util.spec_from_loader(
            "raptor_audit_cli_auth", loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        return mod

    def _args(self, out_dir: Path, target: Path, **overrides):
        base = dict(
            out=str(out_dir), target=str(target),
            file="src/a.c", function="foo", status="clean",
            body="reviewed", line_start=None, line_end=None,
            cwe=None, strategies=None, evidence_tool=None,
            hypothesis=None, vuln_type=None, related_to=None,
            reach_via=None,
        )
        base.update(overrides)
        return SimpleNamespace(**base)

    def _target(self, tmp_path: Path) -> Path:
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "a.c").write_text(
            "int foo(char *p) { return p[0]; }\n")
        return target

    def test_forged_context_row_fails_read_first(
        self, tmp_path: Path, capsys,
    ):
        mod = self._load_cli()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        target = self._target(tmp_path)
        _plant_raw_row(out_dir, {
            "action": "context", "key": "src/a.c:foo",
        })
        rc = mod.cmd_record(self._args(out_dir, target))
        assert rc == 1
        assert "G5 READ-FIRST" in capsys.readouterr().err

    def test_stamped_context_row_passes_read_first(
        self, tmp_path: Path, capsys,
    ):
        from core.audit.record import append_audit_log

        mod = self._load_cli()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        target = self._target(tmp_path)
        append_audit_log(out_dir, {
            "action": "context", "key": "src/a.c:foo",
        })
        rc = mod.cmd_record(self._args(out_dir, target))
        assert rc == 0, capsys.readouterr().err

    def test_forged_sweep_receipt_fails_g2(self, tmp_path: Path, capsys):
        from core.audit.record import append_audit_log

        mod = self._load_cli()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        target = self._target(tmp_path)
        append_audit_log(out_dir, {
            "action": "context", "key": "src/a.c:foo",
        })
        # Forged confirmed receipt: without it G2 refuses anyway; the
        # point is it must STILL refuse with the plant present.
        _plant_raw_row(out_dir, {
            "action": "sweep", "key": "src/a.c:foo",
            "tool": "semgrep", "outcome": "confirmed",
        })
        rc = mod.cmd_record(self._args(
            out_dir, target, status="finding",
            evidence_tool="semgrep", vuln_type="buffer_overflow",
            body="tool output", hypothesis="if p unbounded, CWE-787",
        ))
        assert rc == 1
        assert "G2 TOOL-GROUNDED" in capsys.readouterr().err


class TestG3ResumeFeedVerified:
    """The G3 re-recording gate DEMOTES findings on prior
    finding/suspicious rows — a planted prior row must never earn
    that. Behavioral twin of the census's substring assertion: a
    revert of the feed to the tolerant loader passes the substring
    check (the name can survive in a comment) but fails these."""

    ROW = {
        "action": "record", "key": "src/a.c:foo",
        "status": "finding",
    }

    def _outcome(self):
        from core.audit.orchestrator import ReviewOutcome

        # Re-record with NO new tool evidence — the exact shape G3
        # demotes when a prior row exists.
        return ReviewOutcome(
            file="src/a.c", function="foo", status="finding",
            body="b", hypothesis="if x unchecked, CWE-787", line=1,
        )

    def _violations(self, out_dir: Path):
        from core.audit.orchestrator import (
            _check_finding_gates,
            _g3_prior_review_rows,
        )

        config = SimpleNamespace(resume=True, out_dir=out_dir)
        rows = _g3_prior_review_rows(config)
        return _check_finding_gates(self._outcome(), audit_log=rows)

    def test_forged_prior_row_demotes_nothing(self, tmp_path: Path):
        _plant_raw_row(tmp_path, self.ROW)
        violations = self._violations(tmp_path)
        assert not any(v.startswith("G3") for v in violations)

    def test_stamped_prior_row_fires_g3(self, tmp_path: Path):
        from core.audit.record import append_audit_log

        append_audit_log(tmp_path, self.ROW)
        violations = self._violations(tmp_path)
        assert any(v.startswith("G3") for v in violations)

    def test_cross_run_replayed_row_demotes_nothing(self, tmp_path: Path):
        from core.audit.record import append_audit_log

        other = tmp_path / "other"
        other.mkdir()
        append_audit_log(other, self.ROW)
        here = tmp_path / "here"
        here.mkdir()
        (here / ".audit-log.jsonl").write_bytes(
            (other / ".audit-log.jsonl").read_bytes())
        violations = self._violations(here)
        assert not any(v.startswith("G3") for v in violations)

    def test_non_resume_feeds_nothing(self, tmp_path: Path):
        from core.audit.orchestrator import _g3_prior_review_rows
        from core.audit.record import append_audit_log

        append_audit_log(tmp_path, self.ROW)
        config = SimpleNamespace(resume=False, out_dir=tmp_path)
        assert _g3_prior_review_rows(config) == []


# ── consumer census ──────────────────────────────────────────────────
#
# Mechanically derived reader set: every call site of load_audit_log /
# load_verified_audit_log in runtime code must be classified below.
# AUTHORITY sites feed a suppression / gate decision and must verify
# (route through load_verified_audit_log or call verify_audit_log_row
# in the same function). TELEMETRY sites are allowlisted with a
# rationale. An unlisted site fails the census until classified —
# the totality claim has an oracle instead of a hand-audit.

_SCAN_ROOTS = ("core", "packages", "plugins")
_SCAN_SCRIPTS = ("libexec/raptor-audit",)

#: (file, enclosing function) → why the row read carries authority.
_AUTHORITY_READERS = {
    ("core/audit/orchestrator.py", "get_reviewed_set"):
        "resume review-suppression (drops functions from the workqueue)",
    ("core/audit/orchestrator.py", "_fail_open_adjudicated_sites"):
        "defers (suppresses) CWE-252 census sites",
    ("core/audit/orchestrator.py", "_relog_final_statuses"):
        "decides which corrective final-status rows reach the log",
    ("core/audit/orchestrator.py", "_g3_prior_review_rows"):
        "feeds _check_finding_gates G3 (prior rows demote findings)",
    ("libexec/raptor-audit", "cmd_record"):
        "G5 READ-FIRST / G2 sweep-receipt gates relax on matching rows"
        " (documented unverified degrade only when no MAC key is"
        " usable — a state the target cannot force)",
}

#: (file, enclosing function) → why an unverified read is acceptable.
_TELEMETRY_READERS = {
    ("core/audit/record.py", "load_verified_audit_log"):
        "the strict loader implementation itself",
    ("core/audit/binary_honesty.py", "summarize_gate_engagement"):
        "display-only per-gate engagement counters (no verdict or"
        " suppression flows from them)",
    ("libexec/raptor-audit", "cmd_critique"):
        "operator-facing critique report; surfaces gaps, grants"
        " nothing",
}


def _call_sites() -> dict[tuple[str, str], list[str]]:
    """{(relpath, enclosing function): [callee names]} for every
    load_audit_log / load_verified_audit_log call in runtime code."""
    targets = {"load_audit_log", "load_verified_audit_log"}
    files: list[Path] = []
    for root in _SCAN_ROOTS:
        for p in (_REPO_ROOT / root).rglob("*.py"):
            if "tests" in p.parts or "scripts" in p.parts:
                continue
            files.append(p)
    files.extend(_REPO_ROOT / s for s in _SCAN_SCRIPTS)

    sites: dict[tuple[str, str], list[str]] = {}
    for path in files:
        try:
            text = path.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        if not any(t in text for t in targets):
            continue
        tree = ast.parse(text)
        funcs = [
            n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]

        def _enclosing(lineno: int) -> str:
            best = "<module>"
            best_span = None
            for f in funcs:
                if f.lineno <= lineno <= (f.end_lineno or f.lineno):
                    span = (f.end_lineno or f.lineno) - f.lineno
                    if best_span is None or span < best_span:
                        best, best_span = f.name, span
            return best

        rel = str(path.relative_to(_REPO_ROOT))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name in targets:
                sites.setdefault(
                    (rel, _enclosing(node.lineno)), []).append(name)
    return sites


class TestConsumerCensus:
    def test_every_reader_is_classified(self):
        sites = _call_sites()
        known = set(_AUTHORITY_READERS) | set(_TELEMETRY_READERS)
        unclassified = set(sites) - known
        assert not unclassified, (
            "unclassified audit-log reader(s) — decide whether each "
            "read grants rows authority (suppression / gate "
            "relaxation: route through load_verified_audit_log) or "
            "is pure telemetry (allowlist with rationale): "
            f"{sorted(unclassified)}"
        )
        # Classified-but-vanished entries mean the table is stale.
        stale = known - set(sites)
        assert not stale, f"census table lists dead reader(s): {stale}"

    @pytest.mark.parametrize("site", sorted(_AUTHORITY_READERS))
    def test_authority_reader_verifies(self, site):
        rel, func = site
        text = (_REPO_ROOT / rel).read_text()
        tree = ast.parse(text)
        seg = ""
        for node in ast.walk(tree):
            if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == func):
                seg = ast.get_source_segment(text, node) or ""
                break
        assert seg, f"{rel}:{func} not found"
        assert (
            "load_verified_audit_log" in seg
            or "verify_audit_log_row" in seg
        ), (
            f"{rel}:{func} consumes audit-log rows with authority "
            f"({_AUTHORITY_READERS[site]}) but neither routes through "
            "load_verified_audit_log nor calls verify_audit_log_row"
        )
