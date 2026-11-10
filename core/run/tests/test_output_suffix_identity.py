"""Run output identities survive repeated clock residues in one process."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from itertools import count

import pytest

from core.run import output
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def fixed_identity(monkeypatch):
    patch_module_attribute(monkeypatch, output, "time", "strftime", lambda fmt: "20260102_030405" if "_" in fmt else "20260102-030405")
    patch_module_attribute(monkeypatch, output, "time", "monotonic_ns", lambda: 4321)
    patch_module_attribute(monkeypatch, output, "os", "getpid", lambda: 11001)
    # Own the process-sequence state if present; never reset a borrowed counter.
    monkeypatch.setattr(output, "_run_sequence", count(), raising=False)


@pytest.mark.parametrize("project_mode", [False, True], ids=["standalone", "project"])
@pytest.mark.parametrize("ticks", [(4321, 14321), (4321, 4321)], ids=["residue-wrap", "same-tick"])
def test_same_process_runs_keep_their_own_files(tmp_path, monkeypatch, fixed_identity, project_mode, ticks):
    target = tmp_path / "target"
    target.mkdir()
    project = tmp_path / "project"
    project.mkdir()

    class LocalConfig(output.RaptorConfig):
        @staticmethod
        def get_out_dir():
            return tmp_path / "out"

    monkeypatch.setattr(output, "RaptorConfig", LocalConfig)
    monkeypatch.setattr(output, "_resolve_active_project", lambda: (str(project), "demo", str(target)) if project_mode else None)
    clock = iter(ticks)
    patch_module_attribute(monkeypatch, output, "time", "monotonic_ns", lambda: next(clock))
    first = output.get_output_dir("scan", target_name="target", target_path=str(target))
    first.mkdir(parents=True, exist_ok=True)
    (first / "report.txt").write_text("first run evidence")
    second = output.get_output_dir("scan", target_name="target", target_path=str(target))
    second.mkdir(parents=True, exist_ok=True)
    (second / "report.txt").write_text("second run evidence")

    assert (first / "report.txt").read_text() == "first run evidence"
    assert (second / "report.txt").read_text() == "second run evidence"
    assert first != second


def test_suffix_identity_does_not_wrap_at_ten_thousand_calls(fixed_identity):
    names = [output.unique_run_suffix() for _ in range(10_002)]
    assert len(set(names)) == len(names)
    assert all(name.startswith("20260102_030405_pid11001_") for name in names)
    assert all(len(name.rsplit("_", 1)[1]) >= 4 for name in names)


def test_concurrent_same_process_suffixes_are_distinct(fixed_identity):
    with ThreadPoolExecutor(max_workers=4) as pool:
        names = list(pool.map(lambda _: output.unique_run_suffix("-"), range(1000)))
    assert len(set(names)) == len(names)
