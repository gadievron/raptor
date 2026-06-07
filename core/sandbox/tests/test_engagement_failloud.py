"""Regression tests for the fail-loud sandbox-engagement invariant.

The bug this guards against: on rootless podman / distrobox the narrow
availability probe (`unshare --user --net`) passes while the real,
flag-richer invocation (`unshare --user --pid --fork --ipc [--net]`)
fails. The wrapper then exits BEFORE exec, the target never runs, and the
call returns empty output that a consumer reads as "0 findings in 0
files" — a silent failure.

The invariant: when the requested isolation cannot engage, the sandbox
RAISES SandboxSetupError rather than returning a benign empty result, and
the error names the explicit operator escape hatch. RAPTOR never silently
downgrades.
"""

import pytest

from core.sandbox import SandboxSetupError, check_unshare_engages, sandbox
from core.sandbox import state


def _poison(flags, reason="unshare: Operation not permitted"):
    """Force a flag-set's engagement verdict to FAILED in the cache."""
    state._unshare_engage_cache[tuple(flags)] = (False, reason)


class TestEngagementGateRaises:
    def test_block_network_engagement_failure_raises(self):
        # The gate probes --user --pid --fork --ipc --net when block_network.
        _poison(["--user", "--pid", "--fork", "--ipc", "--net"])
        with sandbox(block_network=True) as run:
            with pytest.raises(SandboxSetupError) as ei:
                run(["echo", "hi"], capture_output=True, text=True)
        assert "Operation not permitted" in str(ei.value)

    def test_error_names_the_escape_hatch(self):
        _poison(["--user", "--pid", "--fork", "--ipc", "--net"])
        with sandbox(block_network=True) as run:
            with pytest.raises(SandboxSetupError) as ei:
                run(["echo", "hi"], capture_output=True, text=True)
        msg = str(ei.value)
        # Actionable, explicit-downgrade-only guidance. For a NAMESPACE
        # engagement failure, network-only ALSO needs the namespace, so the
        # message must point to `--sandbox none` and must NOT offer
        # network-only as a fix (it would fail the same way).
        assert "--sandbox none" in msg
        assert "NOT help" in msg  # explicitly disclaims network-only
        assert "will not silently downgrade" in msg

    def test_instruction_strings_route_by_failure_kind(self):
        """The three downgrade-guidance strings must give the right remedy:
        namespace failure -> none (network-only disclaimed); hardening-layer
        failure -> network-only is valid; macOS seatbelt -> none."""
        from core.sandbox.probes import (
            ENGAGE_FAIL_INSTRUCTIONS,
            LAYER_FAIL_INSTRUCTIONS,
            SEATBELT_FAIL_INSTRUCTIONS,
        )
        # Namespace can't engage: only `none` avoids it; network-only disclaimed.
        assert "--sandbox none" in ENGAGE_FAIL_INSTRUCTIONS
        assert "NOT help" in ENGAGE_FAIL_INSTRUCTIONS
        # Landlock/seccomp apply failure: network-only IS a real downgrade.
        assert "--sandbox network-only" in LAYER_FAIL_INSTRUCTIONS
        assert "NOT help" not in LAYER_FAIL_INSTRUCTIONS
        # macOS seatbelt: no layering to fall back to -> none.
        assert "--sandbox none" in SEATBELT_FAIL_INSTRUCTIONS
        assert "network-only" not in SEATBELT_FAIL_INSTRUCTIONS

    def test_failure_does_not_return_empty_result(self):
        # The whole point: a setup failure must NOT come back as a
        # CompletedProcess the caller could mistake for "ran, no output".
        _poison(["--user", "--pid", "--fork", "--ipc", "--net"])
        returned = None
        with sandbox(block_network=True) as run:
            try:
                returned = run(["echo", "hi"], capture_output=True, text=True)
            except SandboxSetupError:
                pass
        assert returned is None, "setup failure leaked as a normal result"

    def test_engaging_flagset_still_runs(self):
        # Negative control: a flag-set marked as engaging runs normally,
        # so the gate doesn't break the happy path.
        state._unshare_engage_cache[("--user", "--pid", "--fork", "--ipc", "--net")] = (True, "")
        with sandbox(block_network=True) as run:
            r = run(["echo", "ok"], capture_output=True, text=True)
        assert r.returncode == 0
        assert "ok" in (r.stdout or "")

    def test_indeterminate_probe_does_not_abort(self):
        # A probe that COULDN'T RUN (None — transient timeout/OSError, not a
        # definitive refusal) must NOT fail loud: aborting a working scan on
        # a load blip is the worse failure. Proceed; a real namespace failure
        # still surfaces at spawn.
        state._unshare_engage_cache[("--user", "--pid", "--fork", "--ipc", "--net")] = (None, "probe could not run: timeout")
        raised = False
        try:
            with sandbox(block_network=True) as run:
                run(["echo", "lenient"], capture_output=True, text=True)
        except SandboxSetupError:
            raised = True
        assert not raised, "indeterminate probe must NOT fail loud"


class TestEngagementProbe:
    def test_cached_verdict_is_returned(self):
        flags = ["--user", "--net", "--probe-test-marker"]
        state._unshare_engage_cache[tuple(flags)] = (False, "cached reason")
        engages, reason = check_unshare_engages(flags)
        assert engages is False
        assert reason == "cached reason"

    def test_real_probe_succeeds_for_supported_flagset(self):
        # On a host where namespaces work (CI/dev), the real flag-set the
        # gate uses must actually engage — otherwise every sandboxed run
        # here would (correctly) fail loud. This pins that the probe isn't
        # spuriously fail-closing on a capable host.
        engages, reason = check_unshare_engages(
            ["--user", "--pid", "--fork", "--ipc"]
        )
        if not engages:
            pytest.skip(f"host cannot engage base namespaces: {reason}")
        assert engages is True


class TestSubprocessBoundaryTranslation:
    """The subprocess boundary: a child analysis process exits with
    SANDBOX_ENGAGE_EXIT_CODE; the parent must translate that into a raised
    SandboxSetupError (BaseException can't cross a process boundary)."""

    def test_run_codeql_translates_engage_exit_code(self, monkeypatch, tmp_path):
        import importlib.util as iu
        from pathlib import Path as _P
        from core.sandbox import SANDBOX_ENGAGE_EXIT_CODE
        # Absolute, __file__-anchored — cwd-independent (a sibling suite may
        # have left the process in a different cwd).
        _repo = _P(__file__).resolve().parents[3]  # tests→sandbox→core→repo
        spec = iu.spec_from_file_location(
            "scanner_xlate", str(_repo / "packages/static-analysis/scanner.py"))
        scanner = iu.module_from_spec(spec)
        spec.loader.exec_module(scanner)

        class _FakeProc:
            returncode = SANDBOX_ENGAGE_EXIT_CODE
            pid = 4242
            def communicate(self, timeout=None):
                return ("", "RAPTOR: sandbox could not engage")

        monkeypatch.setattr(scanner.subprocess, "Popen",
                            lambda *a, **k: _FakeProc())
        # run_codeql returns [] early if `codeql` isn't on PATH (the case in
        # CI), never reaching the Popen + exit-code translation under test.
        # Force it "present" so the real path runs regardless of host.
        _real_which = scanner.shutil.which
        monkeypatch.setattr(
            scanner.shutil, "which",
            lambda name: "/usr/bin/codeql" if name == "codeql" else _real_which(name),
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(SandboxSetupError) as ei:
            scanner.run_codeql(repo, out)
        assert "network-only" in str(ei.value)

    def test_engage_exit_code_value(self):
        from core.sandbox import SANDBOX_ENGAGE_EXIT_CODE
        # Distinct from success/findings/argparse/SIGINT.
        assert SANDBOX_ENGAGE_EXIT_CODE not in (0, 1, 2, 130)


class TestLayerFunctionalSelfTests:
    """Caveat-2 closure: the per-layer probes functionally TEST application
    (fork + apply), not just presence — so a layer that loads but can't
    engage at runtime reports unavailable (→ skip / degrade) instead of
    dying mid-spawn with empty output."""

    def test_seccomp_selftest_consistent_with_probe(self):
        from core.sandbox.seccomp import (
            _seccomp_functional_selftest, check_seccomp_available)
        from core.sandbox import state
        avail = check_seccomp_available()  # populates the cache
        assert isinstance(avail, bool)
        if avail:
            # Probe reports available ONLY when the functional self-test
            # passed — so a direct self-test must also pass.
            assert _seccomp_functional_selftest(state._libseccomp_cache) is True

    def test_mount_ns_selftest_returns_bool(self):
        from core.sandbox.probes import _mount_ns_functional_selftest
        assert isinstance(_mount_ns_functional_selftest(), bool)


class TestExecStatusPipe:
    """The exec-status pipe: an unspoofable, per-step signal of whether the
    target execed and, if not, which setup step failed — replacing the
    exit-code + stderr-emptiness heuristics."""

    def test_parse_setup_status(self):
        from core.sandbox._spawn import _parse_setup_status
        assert _parse_setup_status(b"") is None          # EOF → execed
        assert _parse_setup_status(b"M:mount denied") == ("M", "mount denied")
        assert _parse_setup_status(b"L:") == ("L", "")
        assert _parse_setup_status(b"U:Operation not permitted") == (
            "U", "Operation not permitted")
        assert _parse_setup_status(b"X:exec: file not found")[0] == "X"

    def test_mount_failure_degrades_to_landlock_and_runs(self):
        # Force the mount-ns spawn path. On a mount-capable host it engages;
        # on an AppArmor/nested host mount() is denied → status 'M' → degrade
        # to Landlock-only. EITHER way the command must actually RUN (real
        # output), never return a silent rc-126 empty result.
        import os
        import tempfile
        ok, _ = check_unshare_engages(["--user", "--pid", "--fork", "--ipc"])
        if not ok:
            pytest.skip("host cannot engage namespaces at all")
        state._mount_available_cache = True
        state._mount_ns_available_cache = True
        tgt = tempfile.mkdtemp()
        out = tempfile.mkdtemp()
        with open(os.path.join(tgt, "f.txt"), "w") as f:
            f.write("hi")
        with sandbox(block_network=True, target=tgt, output=out) as run:
            r = run(["/bin/echo", "ran-OK"], capture_output=True, text=True)
        assert r.returncode == 0
        assert "ran-OK" in (r.stdout or "")

    def test_core_layer_apply_failure_fails_loud(self, monkeypatch):
        # If the spawn child reports a Landlock/seccomp/unshare APPLY failure
        # (probe passed but apply failed), context must fail loud, not degrade.
        import subprocess as _sp
        from core.sandbox import _spawn as _spawn_mod
        ok, _ = check_unshare_engages(["--user", "--pid", "--fork", "--ipc"])
        if not ok:
            pytest.skip("host cannot engage namespaces at all")

        def _fake_spawn(*a, **k):
            cp = _sp.CompletedProcess(args=["x"], returncode=126,
                                      stdout="", stderr="")
            cp._setup_status = ("L", "landlock_restrict_self: EINVAL")
            return cp

        monkeypatch.setattr(_spawn_mod, "run_sandboxed", _fake_spawn)
        state._mount_available_cache = True
        state._mount_ns_available_cache = True
        import tempfile
        tgt = tempfile.mkdtemp()
        out = tempfile.mkdtemp()
        with pytest.raises(SandboxSetupError) as ei:
            with sandbox(block_network=True, target=tgt, output=out) as run:
                run(["/bin/echo", "x"], capture_output=True, text=True)
        assert "Landlock" in str(ei.value)

    def test_status_pipe_unspoofable_invariant(self):
        # The status pipe's unspoofability rests on os.pipe() returning
        # close-on-exec (non-inheritable) fds (PEP 446) — so status_w is
        # gone before the target execs. Pin that platform assumption; if it
        # ever changed, the target could inherit status_w and forge status.
        import os
        r, w = os.pipe()
        try:
            assert os.get_inheritable(w) is False
            assert os.get_inheritable(r) is False
        finally:
            os.close(r)
            os.close(w)
