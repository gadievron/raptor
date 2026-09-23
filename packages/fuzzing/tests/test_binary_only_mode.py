"""Tests for AFL++ binary-only mode selection (QEMU -Q / FRIDA -O).

Uninstrumented targets need a binary-only tracer; the runner resolves
one up front (clear failure with install guidance instead of
per-instance afl-fuzz deaths) and exports AFL_PATH when the tracer
lives outside afl-fuzz's own directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.fuzzing import capability
from packages.fuzzing.afl_runner import AFLRunner


def _make_runner(
    binary_only_mode: str = "auto",
    sandbox_rootfs: Path | None = None,
) -> AFLRunner:
    # __init__ bypass (established pattern in test_afl_runner): the
    # methods under test only touch these attributes.
    runner = AFLRunner.__new__(AFLRunner)
    runner.binary_only_mode = binary_only_mode
    runner.sandbox_rootfs = sandbox_rootfs
    runner.afl_fuzz = "/usr/bin/afl-fuzz"
    runner._binary_only_support_dir = None
    return runner


def _patch_support(monkeypatch, *, qemu: str | None, frida: str | None):
    def fake_find(name: str, afl_fuzz=None):
        if name == "afl-qemu-trace":
            return qemu
        if name == "afl-frida-trace.so":
            return frida
        raise AssertionError(f"unexpected probe: {name}")
    monkeypatch.setattr(capability, "find_afl_support_file", fake_find)


class TestResolveBinaryOnlyMode:
    def test_auto_prefers_qemu(self, monkeypatch):
        _patch_support(monkeypatch, qemu="/usr/bin/afl-qemu-trace",
                       frida="/usr/lib/afl/afl-frida-trace.so")
        runner = _make_runner()
        assert runner._resolve_binary_only_mode() == "qemu"
        assert runner._binary_only_support_dir == "/usr/bin"

    def test_auto_falls_back_to_frida(self, monkeypatch):
        _patch_support(monkeypatch, qemu=None,
                       frida="/usr/lib/afl/afl-frida-trace.so")
        runner = _make_runner()
        assert runner._resolve_binary_only_mode() == "frida"
        assert runner._binary_only_support_dir == "/usr/lib/afl"

    def test_neither_available_raises_with_guidance(self, monkeypatch):
        _patch_support(monkeypatch, qemu=None, frida=None)
        runner = _make_runner()
        with pytest.raises(RuntimeError) as exc:
            runner._resolve_binary_only_mode()
        # The message must tell the operator every way out.
        text = str(exc.value)
        assert "afl-cc" in text
        assert "qemu_mode" in text
        assert "frida_mode" in text

    def test_forced_frida_honoured(self, monkeypatch):
        _patch_support(monkeypatch, qemu="/usr/bin/afl-qemu-trace",
                       frida="/usr/lib/afl/afl-frida-trace.so")
        runner = _make_runner(binary_only_mode="frida")
        assert runner._resolve_binary_only_mode() == "frida"

    def test_forced_frida_missing_raises(self, monkeypatch):
        _patch_support(monkeypatch, qemu="/usr/bin/afl-qemu-trace",
                       frida=None)
        runner = _make_runner(binary_only_mode="frida")
        with pytest.raises(RuntimeError, match="afl-frida-trace.so"):
            runner._resolve_binary_only_mode()

    def test_forced_qemu_missing_raises(self, monkeypatch):
        _patch_support(monkeypatch, qemu=None,
                       frida="/usr/lib/afl/afl-frida-trace.so")
        runner = _make_runner(binary_only_mode="qemu")
        with pytest.raises(RuntimeError, match="afl-qemu-trace"):
            runner._resolve_binary_only_mode()

    def test_rootfs_campaigns_keep_qemu_without_probing(self, monkeypatch):
        def explode(name: str, afl_fuzz=None):
            raise AssertionError("host probing must not run in rootfs mode")
        monkeypatch.setattr(capability, "find_afl_support_file", explode)
        runner = _make_runner(sandbox_rootfs=Path("/nonexistent-rootfs"))
        assert runner._resolve_binary_only_mode() == "qemu"
        assert runner._binary_only_support_dir is None


class TestBuildCommandBinaryMode:
    def _command_runner(self, tmp_path: Path) -> AFLRunner:
        runner = AFLRunner.__new__(AFLRunner)
        runner.afl_fuzz = "/usr/bin/afl-fuzz"
        runner.binary = tmp_path / "target"
        runner.corpus_dir = tmp_path / "corpus"
        runner.output_dir = tmp_path / "out"
        runner.dict_path = None
        runner.input_mode = "stdin"
        runner.power_schedule = "fast"
        runner.deterministic = False
        runner.cmplog_binary = None
        runner.cmplog_in_rootfs = None
        runner.custom_mutator = None
        runner.extra_afl_flags = []
        runner.sandbox_rootfs = None
        runner.binary_in_rootfs = None
        return runner

    def test_qemu_mode_appends_Q(self, tmp_path):
        cmd = self._command_runner(tmp_path)._build_afl_command(
            "main", is_main=True, timeout_ms=1000, binary_mode="qemu")
        assert "-Q" in cmd
        assert "-O" not in cmd

    def test_frida_mode_appends_O(self, tmp_path):
        cmd = self._command_runner(tmp_path)._build_afl_command(
            "main", is_main=True, timeout_ms=1000, binary_mode="frida")
        assert "-O" in cmd
        assert "-Q" not in cmd

    def test_instrumented_target_gets_neither(self, tmp_path):
        cmd = self._command_runner(tmp_path)._build_afl_command(
            "main", is_main=True, timeout_ms=1000, binary_mode=None)
        assert "-Q" not in cmd
        assert "-O" not in cmd


class TestCtorValidation:
    def test_invalid_mode_rejected(self, tmp_path, monkeypatch):
        binary = tmp_path / "target"
        binary.write_bytes(b"\x7fELF")
        binary.chmod(0o755)
        import packages.fuzzing.afl_runner as afl_runner_mod
        monkeypatch.setattr(
            afl_runner_mod.shutil, "which", lambda _n: "/usr/bin/afl-fuzz")
        monkeypatch.setattr(
            AFLRunner, "_validate_afl_command", lambda _self: None)
        with pytest.raises(ValueError, match="binary-only mode"):
            AFLRunner(
                binary_path=binary,
                corpus_dir=tmp_path,
                output_dir=tmp_path / "out",
                binary_only_mode="nyx",
            )


class TestFindAflSupportFile:
    def test_which_hit_used_without_afl_fuzz_context(self, monkeypatch):
        monkeypatch.delenv("AFL_PATH", raising=False)
        monkeypatch.setattr(
            capability.shutil, "which",
            lambda name: f"/usr/bin/{name}")
        assert (capability.find_afl_support_file("afl-qemu-trace")
                == "/usr/bin/afl-qemu-trace")

    def test_afl_fuzz_adjacent_tracer_beats_path(self, tmp_path, monkeypatch):
        # Pairing: a tracer from a DIFFERENT install (PATH) can be
        # shmem-protocol incompatible with the afl-fuzz that runs it.
        monkeypatch.delenv("AFL_PATH", raising=False)
        (tmp_path / "afl-qemu-trace").write_bytes(b"")
        monkeypatch.setattr(
            capability.shutil, "which",
            lambda name: f"/usr/bin/{name}")
        assert (capability.find_afl_support_file(
            "afl-qemu-trace", afl_fuzz=str(tmp_path / "afl-fuzz"))
            == str(tmp_path / "afl-qemu-trace"))

    def test_afl_path_env_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(capability.shutil, "which", lambda _n: None)
        (tmp_path / "afl-frida-trace.so").write_bytes(b"")
        monkeypatch.setenv("AFL_PATH", str(tmp_path))
        assert (capability.find_afl_support_file("afl-frida-trace.so")
                == str(tmp_path / "afl-frida-trace.so"))

    def test_afl_fuzz_sibling_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(capability.shutil, "which", lambda _n: None)
        monkeypatch.delenv("AFL_PATH", raising=False)
        (tmp_path / "afl-frida-trace.so").write_bytes(b"")
        assert (capability.find_afl_support_file(
            "afl-frida-trace.so", afl_fuzz=str(tmp_path / "afl-fuzz"))
            == str(tmp_path / "afl-frida-trace.so"))

    def test_missing_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(capability.shutil, "which", lambda _n: None)
        monkeypatch.delenv("AFL_PATH", raising=False)
        # Neutralise the conventional install dirs — the runner host
        # may legitimately ship the tracer there.
        monkeypatch.setattr(capability, "_AFL_SUPPORT_DIRS", ())
        assert capability.find_afl_support_file(
            "afl-frida-trace.so", afl_fuzz=str(tmp_path / "afl-fuzz")) is None


class TestProbeHardening:
    def test_rootfs_with_forced_frida_warns(self, monkeypatch, caplog):
        import logging
        def explode(name: str, afl_fuzz=None):
            raise AssertionError("host probing must not run in rootfs mode")
        monkeypatch.setattr(capability, "find_afl_support_file", explode)
        runner = _make_runner(binary_only_mode="frida",
                              sandbox_rootfs=Path("/nonexistent-rootfs"))
        with caplog.at_level(logging.WARNING):
            assert runner._resolve_binary_only_mode() == "qemu"
        assert any("rootfs" in r.message for r in caplog.records)

    def test_relative_which_result_pinned_absolute(self, tmp_path, monkeypatch):
        # which() honours relative PATH entries; the result feeds an
        # AFL_PATH export resolved by the child against ITS cwd.
        sub = tmp_path / "sub"
        sub.mkdir()
        tracer = sub / "afl-qemu-trace"
        tracer.write_bytes(b"")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            capability.shutil, "which", lambda _n: "sub/afl-qemu-trace")
        found = capability.find_afl_support_file("afl-qemu-trace")
        assert Path(found).is_absolute()
        assert found == str(tracer)

    def test_symlinked_afl_fuzz_probes_real_binary_dir(
            self, tmp_path, monkeypatch):
        # Source builds shimmed onto PATH keep tracers next to the
        # REAL afl-fuzz; probe the resolved parent too.
        real = tmp_path / "build"
        real.mkdir()
        (real / "afl-fuzz").write_bytes(b"")
        (real / "afl-frida-trace.so").write_bytes(b"")
        shim_dir = tmp_path / "bin"
        shim_dir.mkdir()
        shim = shim_dir / "afl-fuzz"
        shim.symlink_to(real / "afl-fuzz")
        monkeypatch.setattr(capability.shutil, "which", lambda _n: None)
        monkeypatch.delenv("AFL_PATH", raising=False)
        monkeypatch.setattr(capability, "_AFL_SUPPORT_DIRS", ())
        assert (capability.find_afl_support_file(
            "afl-frida-trace.so", afl_fuzz=str(shim))
            == str(real / "afl-frida-trace.so"))


class TestOrchestratorThreading:
    def test_run_afl_passes_binary_only_mode(self, tmp_path, monkeypatch):
        # --afl-mode must reach the orchestrator-constructed runner,
        # not just the legacy path.
        from types import SimpleNamespace

        import packages.fuzzing.afl_runner as afl_runner_mod
        from packages.fuzzing.orchestrator import FuzzingOrchestrator

        captured: dict = {}

        class _FakeRunner:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self.telemetry = None
                self.input_mode = "stdin"

            def run_fuzzing(self, duration):
                return 0, None

            def get_stats(self):
                return {}

        monkeypatch.setattr(afl_runner_mod, "AFLRunner", _FakeRunner)
        orch = FuzzingOrchestrator.__new__(FuzzingOrchestrator)
        plan = SimpleNamespace(target=SimpleNamespace(path=tmp_path / "t"))
        orch._run_afl(plan, tmp_path, 1, None, None,
                      afl_binary_mode="frida")
        assert captured.get("binary_only_mode") == "frida"


class TestRunnerPathResolution:
    def test_relative_out_and_corpus_resolved(self, tmp_path, monkeypatch):
        # The sandboxed afl-fuzz children run with a different cwd; a
        # relative --out/--corpus dies there ("Unable to create <dir>")
        # while looking valid from the parent.
        binary = tmp_path / "t"
        binary.write_bytes(b"\x7fELF")
        binary.chmod(0o755)
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        (corpus / "seed").write_bytes(b"a")
        import packages.fuzzing.afl_runner as afl_runner_mod
        monkeypatch.setattr(
            afl_runner_mod.shutil, "which", lambda _n: "/usr/bin/afl-fuzz")
        monkeypatch.setattr(
            AFLRunner, "_validate_afl_command", lambda _self: None)
        monkeypatch.chdir(tmp_path)
        runner = AFLRunner(
            binary_path="t",
            corpus_dir="corpus",
            output_dir="out/run",
        )
        assert runner.output_dir.is_absolute()
        assert runner.corpus_dir.is_absolute()
        assert runner.output_dir == (tmp_path / "out/run").resolve()

class TestPlanTimeTracerHint:
    def test_uninstrumented_binary_without_tracers_gets_hint(
            self, tmp_path, monkeypatch):
        from types import SimpleNamespace

        import packages.fuzzing.orchestrator as orch_mod
        from packages.fuzzing.orchestrator import FuzzingOrchestrator

        binary = tmp_path / "plain"
        binary.write_bytes(b"\x7fELF-no-markers-here")
        caps = SimpleNamespace(afl_qemu_trace=None, afl_frida_trace=None)
        fake = SimpleNamespace(returncode=0,
                               stdout="printable strings only", stderr="")
        monkeypatch.setattr(orch_mod, "_inspect_binary",
                            lambda *a, **k: fake)
        # The availability gate consults the host PATH before the
        # (mocked) probe runs — pin it so the test is independent of
        # whether the runner ships binutils.
        monkeypatch.setattr(orch_mod.shutil, "which",
                            lambda name: f"/usr/bin/{name}")
        plan = SimpleNamespace(hints=[])
        FuzzingOrchestrator._hint_binary_only_gap(plan, caps, binary)
        assert any("binary-only tracer" in h for h in plan.hints)

    def test_tracer_present_or_instrumented_stays_quiet(
            self, tmp_path, monkeypatch):
        from types import SimpleNamespace

        import packages.fuzzing.orchestrator as orch_mod
        from packages.fuzzing.orchestrator import FuzzingOrchestrator

        binary = tmp_path / "plain"
        binary.write_bytes(b"x")
        plan = SimpleNamespace(hints=[])
        caps_with_tracer = SimpleNamespace(
            afl_qemu_trace="/usr/bin/afl-qemu-trace", afl_frida_trace=None)
        FuzzingOrchestrator._hint_binary_only_gap(
            plan, caps_with_tracer, binary)
        assert plan.hints == []

        caps_none = SimpleNamespace(afl_qemu_trace=None, afl_frida_trace=None)
        fake = SimpleNamespace(returncode=0,
                               stdout="__AFL_SHM_ID present", stderr="")
        monkeypatch.setattr(orch_mod, "_inspect_binary",
                            lambda *a, **k: fake)
        FuzzingOrchestrator._hint_binary_only_gap(plan, caps_none, binary)
        assert plan.hints == []
