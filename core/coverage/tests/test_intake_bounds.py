"""Byte budgets on the run-dir intake lanes.

Every artifact here lives inside the sandbox write grant, so its SIZE
is attacker-writable like every other property — a sparse multi-GiB
plant costs no disk and OOM-killed the consumer the containment
boundary keeps alive.  These tests plant sparse over-budget files
(``truncate``, no real bytes) and assert each lane refuses without
materialising the payload, while a small valid sibling keeps flowing.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

from core.coverage.record import RUN_ARTIFACT_MAX_BYTES


def _sparse(path: Path, size: int) -> None:
    with path.open("wb") as f:
        f.truncate(size)


class TestFindingsBudget:
    def test_oversize_findings_refused_valid_sibling_flows(self, tmp_path):
        from core.coverage.importer import load_run_findings
        _sparse(tmp_path / "findings.json", RUN_ARTIFACT_MAX_BYTES + 1)
        (tmp_path / "validation").mkdir()
        (tmp_path / "validation" / "findings.json").write_text(
            json.dumps([{"file": "a.c", "line": 3, "rule_id": "R1"}]))
        out = load_run_findings(tmp_path)
        assert out == [{"file": "a.c", "line": 3, "rule_id": "R1"}]


class TestUnderstandBudget:
    def test_oversize_context_map_refused(self, tmp_path):
        from core.coverage.importer import _understand_points
        _sparse(tmp_path / "context-map.json", RUN_ARTIFACT_MAX_BYTES + 1)
        assert list(_understand_points(tmp_path)) == []

    def test_oversize_flow_trace_refused_valid_flows(self, tmp_path):
        from core.coverage.importer import _understand_points
        _sparse(tmp_path / "flow-trace-big.json",
                RUN_ARTIFACT_MAX_BYTES + 1)
        (tmp_path / "flow-trace-ok.json").write_text(json.dumps(
            {"steps": [{"file": "a.c", "line": 4}]}))
        assert list(_understand_points(tmp_path)) == [("a.c", 4)]

    def test_flow_trace_glob_count_capped(self, tmp_path, monkeypatch):
        import core.coverage.importer as importer
        monkeypatch.setattr(importer, "_MAX_FLOW_TRACE_FILES", 3)
        for i in range(6):
            (tmp_path / f"flow-trace-{i}.json").write_text(json.dumps(
                {"steps": [{"file": f"f{i}.c", "line": 1}]}))
        pts = list(importer._understand_points(tmp_path))
        assert len(pts) == 3


class TestRecordBudget:
    def test_oversize_record_skipped_valid_flows(self, tmp_path):
        from core.coverage.record import load_records
        _sparse(tmp_path / "coverage-big.json", RUN_ARTIFACT_MAX_BYTES + 1)
        (tmp_path / "coverage-good.json").write_text(json.dumps(
            {"tool": "goodtool", "files_examined": ["a.c"]}))
        recs = load_records(tmp_path)
        assert [r.get("tool") for r in recs] == ["goodtool"]

    def test_oversize_legacy_record_refused(self, tmp_path):
        from core.coverage.record import load_records
        _sparse(tmp_path / "coverage-record.json",
                RUN_ARTIFACT_MAX_BYTES + 1)
        assert load_records(tmp_path) == []


class TestDomainModelBudget:
    def test_oversize_hash_refused(self, tmp_path):
        from core.coverage.journal import (
            _MAX_DOMAIN_MODEL_BYTES,
            compute_domain_model_hash,
        )
        _sparse(tmp_path / "domain-model.json",
                _MAX_DOMAIN_MODEL_BYTES + 1)
        assert compute_domain_model_hash(tmp_path) is None

    def test_valid_hash_still_computed(self, tmp_path):
        from core.coverage.journal import compute_domain_model_hash
        (tmp_path / "domain-model.json").write_text(
            json.dumps({"concepts": []}))
        h = compute_domain_model_hash(tmp_path)
        assert isinstance(h, str) and len(h) == 8

    def test_oversize_context_refused(self, tmp_path):
        from core.coverage.journal import (
            _MAX_DOMAIN_MODEL_BYTES,
            domain_model_context,
        )
        _sparse(tmp_path / "domain-model.json",
                _MAX_DOMAIN_MODEL_BYTES + 1)
        assert domain_model_context(tmp_path) is None

    def test_valid_context_still_loads(self, tmp_path):
        from core.coverage.journal import domain_model_context
        (tmp_path / "domain-model.json").write_text(json.dumps(
            {"concepts": [{"id": "c1", "related_strategies": ["s1"]}],
             "invariants": []}))
        ctx = domain_model_context(tmp_path)
        assert ctx is not None
        assert ctx["concepts"] == {"c1": ["s1"]}


class TestBinaryCoverageBudget:
    def test_oversize_drcov_refused(self, tmp_path):
        from core.coverage.collect import _MAX_BINARY_COV_BYTES, parse_drcov
        p = tmp_path / "big.drcov"
        _sparse(p, _MAX_BINARY_COV_BYTES + 1)
        assert parse_drcov(p) == {}

    def test_oversize_sancov_refused(self, tmp_path):
        from core.coverage.collect import _MAX_BINARY_COV_BYTES, parse_sancov
        p = tmp_path / "big.sancov"
        _sparse(p, _MAX_BINARY_COV_BYTES + 1)
        assert parse_sancov(p) == set()

    def test_valid_sancov_still_parses(self, tmp_path):
        from core.coverage.collect import parse_sancov
        p = tmp_path / "ok.sancov"
        p.write_bytes(struct.pack("<QQQ", 0xC0BFFFFFFFFFFF64,
                                  0x1000, 0x2000))
        assert parse_sancov(p) == {0x1000, 0x2000}


class TestRunMetadataBudget:
    def test_oversize_metadata_refused(self, tmp_path):
        from core.run.metadata import RUN_METADATA_FILE, load_run_metadata
        _sparse(tmp_path / RUN_METADATA_FILE, 1024 * 1024 + 1)
        assert load_run_metadata(tmp_path) is None

    def test_valid_metadata_still_loads(self, tmp_path):
        from core.run.metadata import RUN_METADATA_FILE, load_run_metadata
        (tmp_path / RUN_METADATA_FILE).write_text(
            json.dumps({"status": "completed"}))
        meta = load_run_metadata(tmp_path)
        assert meta == {"status": "completed"}


class TestOversizedArtifactMemory:
    """The mechanism proof (the sparse-file tests above also pass on
    an UNBOUNDED reader whose parse merely fails after materialising
    the payload): the stat-gated budget must bound the consumer's own
    peak memory. One representative arm over the shared
    load_json(max_bytes=...) enforcement, VmHWM-measured in a child
    like the journal containment suite."""

    def test_oversize_findings_never_materialise(self, tmp_path):
        import os
        import subprocess
        import sys

        import pytest
        if sys.platform != "linux":
            pytest.skip("/proc/self/status VmHWM is Linux-specific")
        _sparse(tmp_path / "findings.json", RUN_ARTIFACT_MAX_BYTES + 1)
        code = (
            "import logging, sys\n"
            "from pathlib import Path\n"
            "logging.disable(logging.CRITICAL)\n"
            "from core.coverage.importer import load_run_findings\n"
            "def hwm():\n"
            "    with open('/proc/self/status') as f:\n"
            "        for line in f:\n"
            "            if line.startswith('VmHWM:'):\n"
            "                return int(line.split()[1]) * 1024\n"
            "    raise RuntimeError('no VmHWM in /proc/self/status')\n"
            "hwm0 = hwm()\n"
            "out = load_run_findings(Path(sys.argv[1]))\n"
            "hwm1 = hwm()\n"
            "print(hwm1 - hwm0)\n"
            "print(len(out))\n"
        )
        repo_root = Path(__file__).resolve().parents[3]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(repo_root)
        proc = subprocess.run(
            [sys.executable, "-c", code, str(tmp_path)],
            capture_output=True, text=True, env=env, check=True,
            timeout=120,
        )
        hwm_delta, n = (int(x) for x in proc.stdout.split())
        assert n == 0
        # The stat gate refuses BEFORE any read: the only allocation
        # is import/runtime noise, far below the 256 MiB artifact. An
        # unbounded reader materialises the full payload (and its
        # decoded str twin) and lands two orders of magnitude past
        # this bound.
        assert hwm_delta < 32 * 1024 * 1024, (
            f"load_run_findings peak-RSS delta {hwm_delta} bytes for "
            f"an over-budget findings.json — the byte budget is not "
            f"bounding reader memory"
        )
