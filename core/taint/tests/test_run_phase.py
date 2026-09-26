"""Battery for the cross-file taint pipeline phase.

Runs the WHOLE lane — a real target tree on disk, no pre-built
inventory — and pins the artifacts, the summary line, the honest
zero-finding shape, and the phase's non-scanner posture (no scan
SARIF joined, no suppression records ever written)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.sarif.parser import parse_sarif_findings
from core.taint.emission import PRODUCER
from core.taint.run import (
    FINDINGS_FILENAME,
    SARIF_FILENAME,
    TaintPhaseReport,
    _load_inventory,
    run_crossfile_taint,
)

_CHAIN = {
    "app/__init__.py": "",
    "app/exec_layer.py": (
        "import subprocess\n"
        "\n"
        "def launch(payload):\n"
        "    subprocess.run(payload, shell=True)\n"
        "    return None\n"
    ),
    "app/views.py": (
        "from flask import Flask\n"
        "from .helpers import prepare\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/run/<cmd>')\n"
        "def run_cmd(cmd):\n"
        "    return prepare(cmd)\n"
    ),
    "app/helpers.py": (
        "from .exec_layer import launch\n"
        "\n"
        "def prepare(text):\n"
        "    staged = 'prefix-' + text\n"
        "    return launch(staged)\n"
    ),
}


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


@pytest.fixture()
def dirs(tmp_path) -> tuple[Path, Path]:
    target = tmp_path / "target"
    out = tmp_path / "out"
    target.mkdir()
    out.mkdir()
    return target, out


class TestPhaseRun:
    def test_full_lane_writes_both_artifacts(self, dirs) -> None:
        target, out = dirs
        _write_tree(target, _CHAIN)
        report = run_crossfile_taint(target, out)
        assert report.candidates == 1
        assert report.emitted == 1
        assert report.refused == 0
        assert report.sarif_path == out / SARIF_FILENAME
        assert report.findings_path == out / FINDINGS_FILENAME
        parsed = parse_sarif_findings(report.sarif_path)
        assert len(parsed) == 1
        assert parsed[0]["tool"] == PRODUCER
        assert parsed[0]["cwe_id"] == "CWE-78"
        assert parsed[0]["has_dataflow"] is True

        data = json.loads(report.findings_path.read_text())
        assert data["tool"] == PRODUCER
        assert len(data["findings"]) == 1
        assert data["findings"][0]["dataflow_path"] is not None
        assert "stats" in data and "caps_hit" in data

    def test_summary_line_counts_and_caps_only(self, dirs) -> None:
        target, out = dirs
        _write_tree(target, _CHAIN)
        report = run_crossfile_taint(target, out)
        line = report.summary_line()
        assert "1 finding(s) emitted (1 candidate(s))" in line
        assert "frontier 0 unresolved call site(s)" in line
        assert "caps: none" in line
        # No target-derived text on the terminal surface.
        assert "app/" not in line and "run_cmd" not in line

    def test_zero_finding_run_still_writes_honest_artifacts(
            self, dirs) -> None:
        """Artifacts land even with nothing found — downstream reads
        counters, never infers from absence (and zero findings is
        never a clean claim: the JSON carries caps/frontier/stats)."""
        target, out = dirs
        _write_tree(target, {"pkg/__init__.py": "",
                             "pkg/mod.py": "def f():\n    return 1\n"})
        report = run_crossfile_taint(target, out)
        assert report.emitted == 0 and report.candidates == 0
        assert (out / SARIF_FILENAME).exists()
        data = json.loads((out / FINDINGS_FILENAME).read_text())
        assert data["findings"] == []
        assert "stats" in data
        assert "0 finding(s) emitted" in report.summary_line()

    def test_phase_writes_no_suppressions_and_no_scan_sarif(
            self, dirs) -> None:
        """The non-scanner posture: exactly the two named artifacts —
        no suppressions.jsonl (the phase has no suppression surface)
        and no file a scanner-side SARIF collection would pick up
        (the postpass input set is scanner outputs; crossfile-taint
        SARIF is named outside every scanner pattern)."""
        target, out = dirs
        _write_tree(target, _CHAIN)
        run_crossfile_taint(target, out)
        written = sorted(p.name for p in out.iterdir())
        assert written == [FINDINGS_FILENAME, SARIF_FILENAME]
        assert not (out / "suppressions.jsonl").exists()
        assert not list(out.glob("codeql_*.sarif"))
        assert not list(out.glob("semgrep*.sarif"))
        assert not (out / "combined.sarif").exists()

    def test_report_metrics_shape(self, dirs) -> None:
        target, out = dirs
        _write_tree(target, _CHAIN)
        report = run_crossfile_taint(target, out)
        metrics = report.metrics()
        assert metrics["total_findings"] == 1
        assert metrics["candidates"] == 1
        assert metrics["frontier_records"] == 0
        assert metrics["caps_hit"] == []
        # Present-only keys stay absent on a healthy run.
        assert "records_refused_budget" not in metrics
        assert "learned_specs_admitted" not in metrics


class TestFrontierTwinRail:
    def test_frontier_bloat_shape_stays_bounded_in_the_twin(
            self, dirs) -> None:
        """The frontier-regression shape: route handlers whose bodies
        call 64 KiB-named unresolvable callees. Raw FrontierRecords
        would put megabytes of name bytes into the twin file
        (measured 13.1 MB at 200 records pre-rail); the bounded block
        holds the whole twin to KB-class with the per-field markers
        and the byte accounting covering it."""
        target, out = dirs
        name_len = 65536
        files = {"app/__init__.py": ""}
        for i in range(3):
            lines = [
                "from flask import Flask",
                "",
                "app = Flask(__name__)",
                "",
                f"@app.route('/run{i}/<cmd>')",
                f"def run_cmd_{i}(cmd):",
            ]
            for j in range(6):
                big = f"callee_{i}_{j}_" + "z" * (name_len - 12)
                lines.append(f"    {big}(cmd)")
            lines.append("    return cmd")
            files[f"app/views_{i}.py"] = "\n".join(lines) + "\n"
        _write_tree(target, files)
        report = run_crossfile_taint(target, out)
        assert report.frontier > 0  # the shape really pops frontier
        data = json.loads((out / FINDINGS_FILENAME).read_text())
        assert data["frontier"], "twin must carry the bounded block"
        max_callee = max(len(r["callee"]) for r in data["frontier"])
        assert max_callee < 1024  # bounded + marker, not 64 KiB
        assert any(r["callee"].endswith("chars]")
                   for r in data["frontier"])
        twin_bytes = (out / FINDINGS_FILENAME).stat().st_size
        assert twin_bytes < 256 * 1024
        assert report.stats["frontier_bytes_emitted"] > 0
        assert report.stats["name_fields_capped"] > 0

    def test_twin_frontier_is_the_emission_block(self, dirs) -> None:
        """run.py writes the emission's bounded frontier — never the
        raw records."""
        target, out = dirs
        _write_tree(target, {
            "pkg/__init__.py": "",
            "pkg/views.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                "@app.route('/x/<v>')\n"
                "def handler(v):\n"
                "    mystery_dispatch(v)\n"
                "    return v\n"
            ),
        })
        report = run_crossfile_taint(target, out)
        data = json.loads((out / FINDINGS_FILENAME).read_text())
        assert data["frontier"]
        for record in data["frontier"]:
            assert set(record) == {"function", "line", "callee",
                                   "resolution", "taint_class",
                                   "derived_from_target"}
        # The summary's frontier figure is the FULL occurrence count;
        # the twin block can never exceed it.
        assert len(data["frontier"]) <= report.frontier


class TestInventoryReuse:
    def test_checklist_reused_when_present(self, dirs,
                                           monkeypatch) -> None:
        """A pipeline-built checklist.json is the inventory — the
        phase must not rebuild (pinned by poisoning the builder)."""
        target, out = dirs
        _write_tree(target, _CHAIN)
        from core.inventory import build_inventory
        inv = build_inventory(str(target))
        (out / "checklist.json").write_text(json.dumps(inv))

        import core.inventory as inventory_mod

        def boom(*a, **k):  # pragma: no cover - must not be reached
            raise AssertionError("inventory rebuilt despite checklist")

        monkeypatch.setattr(inventory_mod, "build_inventory", boom)
        report = run_crossfile_taint(target, out)
        assert report.emitted == 1

    def test_drifted_checklist_falls_back_to_rebuild(self,
                                                     dirs) -> None:
        target, out = dirs
        _write_tree(target, _CHAIN)
        (out / "checklist.json").write_text('{"files": "not-a-list"}')
        inv = _load_inventory(target, out)
        assert isinstance(inv.get("files"), list)

    def test_explicit_inventory_bypasses_disk(self, dirs) -> None:
        target, out = dirs
        _write_tree(target, _CHAIN)
        from core.inventory import build_inventory
        inv = build_inventory(str(target))
        report = run_crossfile_taint(target, out, inventory=inv)
        assert report.emitted == 1


class TestSummaryReport:
    def test_refused_and_learned_ride_the_line(self) -> None:
        report = TaintPhaseReport(
            candidates=5, emitted=3, refused=2, frontier=1,
            learned_admitted=4, caps_hit=("artifact_budget",))
        line = report.summary_line()
        assert "3 finding(s) emitted (5 candidate(s))" in line
        assert "frontier 1 unresolved call site(s)" in line
        assert "2 record(s) past byte budget" in line
        assert "4 learned spec(s)" in line
        assert "caps: artifact_budget" in line
        metrics = report.metrics()
        assert metrics["records_refused_budget"] == 2
        assert metrics["learned_specs_admitted"] == 4
        assert metrics["caps_hit"] == ["artifact_budget"]
