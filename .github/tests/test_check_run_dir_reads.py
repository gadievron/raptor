"""Tests for .github/scripts/check_run_dir_reads.py — the run-dir
raw-read census and its baseline gate.

Both directions are pinned on planted synthetic trees (via the
detector's ``--root``): a raw read of a run-artifact-shaped filename
must fire, and each documented non-finding shape (hardened loader,
inline adjudication marker, write-mode open, curated non-artifact
name, cross-function name isolation) must stay silent. The baseline
arms (honored key, stale key) are pinned through ``main()`` exit
codes, and the shipped tree itself must be gate-clean.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from check_run_dir_reads import finding_key, main, run_census


def _plant(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, src in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
    return tmp_path


def _raw(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    raw, _hardened = run_census(_plant(tmp_path, files))
    return raw


class TestDetector:
    def test_raw_read_of_run_artifact_fires(self, tmp_path):
        raw = _raw(tmp_path, {"core/reader.py": (
            "import json\n"
            "from pathlib import Path\n"
            "def load(out_dir):\n"
            "    return json.loads(\n"
            "        (Path(out_dir) / 'findings.json')"
            ".read_text(encoding='utf-8'))\n"
        )})
        assert {f["artifact"] for f in raw} == {"findings.json"}
        assert {f["primitive"] for f in raw} == {"json.loads", "read_text"}

    def test_raw_open_fires_and_fstring_carries_artifact(self, tmp_path):
        raw = _raw(tmp_path, {"core/reader.py": (
            "def load(out_dir):\n"
            "    with open(f'{out_dir}/scan_report.json') as fh:\n"
            "        return fh.read()\n"
        )})
        assert [(f["artifact"], f["primitive"]) for f in raw] == [
            ("scan_report.json", "open"),
        ]

    def test_one_hop_name_assignment_is_attributed(self, tmp_path):
        raw = _raw(tmp_path, {"core/reader.py": (
            "def load(run_dir):\n"
            "    trail = run_dir / 'suppressions.jsonl'\n"
            "    with open(trail) as fh:\n"
            "        return fh.readlines()\n"
        )})
        assert {f["artifact"] for f in raw} == {"suppressions.jsonl"}
        assert {f["primitive"] for f in raw} == {"open"}

    def test_hardened_loader_is_not_a_finding(self, tmp_path):
        root = _plant(tmp_path, {"core/reader.py": (
            "from core.json import load_json\n"
            "def load(out_dir):\n"
            "    return load_json(out_dir / 'findings.json')\n"
        )})
        raw, hardened = run_census(root)
        assert raw == []
        assert [(h["artifact"], h["helper"]) for h in hardened] == [
            ("findings.json", "load_json"),
        ]

    def test_adjudication_marker_suppresses(self, tmp_path):
        raw = _raw(tmp_path, {"core/reader.py": (
            "import json\n"
            "def load(p):\n"
            "    return json.loads((p / 'findings.json')"
            ".read_text())  # raw-open: pinned fixture\n"
        )})
        assert raw == []

    def test_write_mode_opens_do_not_fire(self, tmp_path):
        # Both mode-slot spellings: builtin open(path, mode) carries
        # the mode at index 1, Path.open(mode) at index 0 — the
        # detector once misread Path.open('w') as a read.
        raw = _raw(tmp_path, {"core/writer.py": (
            "from pathlib import Path\n"
            "def dump(out_dir, text):\n"
            "    with open(out_dir / 'findings.json', 'w') as fh:\n"
            "        fh.write(text)\n"
            "    with (out_dir / 'suppressions.jsonl').open('a') as fh:\n"
            "        fh.write(text)\n"
        )})
        assert raw == []

    def test_curated_non_artifact_names_do_not_fire(self, tmp_path):
        raw = _raw(tmp_path, {"core/reader.py": (
            "import json\n"
            "def load(repo):\n"
            "    return json.loads((repo / 'package.json')"
            ".read_text())\n"
        )})
        assert raw == []

    def test_function_locals_do_not_leak_across_functions(self, tmp_path):
        # A findings.json assignment in one helper must not attribute
        # an unrelated open() in a sibling function.
        raw = _raw(tmp_path, {"core/reader.py": (
            "def a(out_dir):\n"
            "    path = out_dir / 'findings.json'\n"
            "    return path\n"
            "def b(path):\n"
            "    with open(path, 'rb') as fh:\n"
            "        return fh.read(4)\n"
        )})
        assert raw == []

    def test_module_level_name_stays_visible_in_functions(self, tmp_path):
        raw = _raw(tmp_path, {"core/reader.py": (
            "TRAIL = 'review-journal.jsonl'\n"
            "def load(run_dir):\n"
            "    with open(run_dir / TRAIL) as fh:\n"
            "        return fh.read()\n"
        )})
        assert {f["artifact"] for f in raw} == {"review-journal.jsonl"}

    def test_class_loader_load_is_not_a_deserialiser(self, tmp_path):
        # Project class loaders named .load() are censused at their
        # own internal read primitive, not at every call site.
        raw = _raw(tmp_path, {"core/reader.py": (
            "from core.concepts.model import DomainModel\n"
            "def load(out_dir):\n"
            "    return DomainModel.load(out_dir / 'domain-model.json')\n"
        )})
        assert raw == []


class TestBaselineGate:
    def _tree(self, tmp_path: Path) -> Path:
        return _plant(tmp_path, {"core/reader.py": (
            "import json\n"
            "def load(p):\n"
            "    return json.loads((p / 'findings.json').read_text())\n"
        )})

    def test_new_finding_fails(self, tmp_path, capsys):
        root = self._tree(tmp_path)
        baseline = tmp_path / "baseline.json"
        baseline.write_text(json.dumps({"keys": []}))
        rc = main(["--root", str(root), "--baseline", str(baseline)])
        assert rc == 1
        assert "findings.json" in capsys.readouterr().out

    def test_baselined_finding_passes(self, tmp_path, capsys):
        root = self._tree(tmp_path)
        raw, _ = run_census(root)
        baseline = tmp_path / "baseline.json"
        baseline.write_text(json.dumps(
            {"keys": sorted({finding_key(f) for f in raw})}))
        rc = main(["--root", str(root), "--baseline", str(baseline)])
        assert rc == 0
        capsys.readouterr()

    def test_stale_baseline_entry_warns_but_passes(self, tmp_path, capsys):
        root = self._tree(tmp_path)
        raw, _ = run_census(root)
        keys = sorted({finding_key(f) for f in raw})
        keys.append("core/gone.py::findings.json::open")
        baseline = tmp_path / "baseline.json"
        baseline.write_text(json.dumps({"keys": keys}))
        rc = main(["--root", str(root), "--baseline", str(baseline)])
        assert rc == 0
        assert "STALE" in capsys.readouterr().out

    def test_write_baseline_round_trips(self, tmp_path, capsys):
        root = self._tree(tmp_path)
        baseline = tmp_path / "baseline.json"
        rc = main(["--root", str(root), "--baseline", str(baseline),
                   "--write-baseline"])
        assert rc == 0
        data = json.loads(baseline.read_text())
        assert data["keys"] == [
            "core/reader.py::findings.json::json.loads",
            "core/reader.py::findings.json::read_text",
        ]
        rc = main(["--root", str(root), "--baseline", str(baseline)])
        assert rc == 0
        capsys.readouterr()


class TestShippedTree:
    def test_repo_is_gate_clean(self, capsys):
        # The gate as wired in CI: the shipped tree plus the shipped
        # baseline must be clean, and the census must be non-vacuous
        # in both columns.
        rc = main([])
        out = capsys.readouterr().out
        assert rc == 0, out
        assert "census clean" in out

    def test_repo_census_is_non_vacuous(self):
        raw, hardened = run_census(
            Path(__file__).resolve().parents[2])
        assert len(hardened) > 50, "hardened-reader extraction went vacuous"
        # Raw readers surviving on the tree are exactly the shipped
        # baseline's keys — nothing silently out of scope.
        shipped = json.loads(
            (Path(__file__).resolve().parents[1] / "scripts"
             / "run_dir_reads_baseline.json").read_text())
        assert {finding_key(f) for f in raw} == set(shipped["keys"])
