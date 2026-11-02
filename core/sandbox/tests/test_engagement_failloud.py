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


import sys
from unittest.mock import patch

import pytest

from core.sandbox import SandboxSetupError, check_unshare_engages, sandbox, state
from core.sandbox.tests.capability import requires_landlock, requires_userns

# unshare engagement is Linux-only
# Real-Linux-kernel binding: these tests carry the linux_native
# marker (pytest.ini) instead of an ad hoc skipif — honest skip on
# other native platforms, deselected under the darwin-emulation gate.


def _poison(flags, reason="unshare: Operation not permitted"):
    """Force a flag-set's engagement verdict to FAILED in the cache."""
    state._unshare_engage_cache[tuple(flags)] = (False, reason)


def _gate_flags(block_network=True):
    """The EXACT flag-set the production gate probes for this shape —
    mirrors the construction in context.run() (incl. the conditional
    --cgroup) so cache poisoning hits the key the gate looks up."""
    from core.sandbox.probes import unshare_supports_cgroup
    flags = ["--user", "--pid", "--fork", "--ipc"]
    if block_network:
        flags.append("--net")
    if unshare_supports_cgroup():
        flags.append("--cgroup")
    return flags


@pytest.mark.linux_native
class TestEngagementGateRaises:
    @requires_userns
    def test_block_network_engagement_failure_raises(self):
        # The gate probes the exact production flag-set (see _gate_flags).
        _poison(_gate_flags())
        with sandbox(block_network=True) as run, \
                pytest.raises(SandboxSetupError) as ei:
            run(["echo", "hi"], capture_output=True, text=True)
        assert "Operation not permitted" in str(ei.value)

    @requires_userns
    def test_error_names_the_escape_hatch(self):
        _poison(_gate_flags())
        with sandbox(block_network=True) as run, \
                pytest.raises(SandboxSetupError) as ei:
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

    @requires_userns
    def test_failure_does_not_return_empty_result(self):
        # The whole point: a setup failure must NOT come back as a
        # CompletedProcess the caller could mistake for "ran, no output".
        _poison(_gate_flags())
        returned = None
        with sandbox(block_network=True) as run:
            try:
                returned = run(["echo", "hi"], capture_output=True, text=True)
            except SandboxSetupError:
                pass
        assert returned is None, "setup failure leaked as a normal result"

    @requires_landlock
    def test_engaging_flagset_still_runs(self):
        # Negative control: a flag-set marked as engaging runs normally,
        # so the gate doesn't break the happy path.
        state._unshare_engage_cache[tuple(_gate_flags())] = (True, "")
        with sandbox(block_network=True) as run:
            r = run(["echo", "ok"], capture_output=True, text=True)
        assert r.returncode == 0
        assert "ok" in (r.stdout or "")

    @requires_landlock
    def test_indeterminate_probe_does_not_abort(self):
        # A probe that COULDN'T RUN (None — transient timeout/OSError, not a
        # definitive refusal) must NOT fail loud: aborting a working scan on
        # a load blip is the worse failure. Proceed; a real namespace failure
        # still surfaces at spawn.
        state._unshare_engage_cache[tuple(_gate_flags())] = (None, "probe could not run: timeout")
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
        with patch.object(sys, "path", sys.path.copy()):
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
        from core.sandbox import state
        from core.sandbox.seccomp import (
            _seccomp_functional_selftest,
            check_seccomp_available,
        )
        avail = check_seccomp_available()  # populates the cache
        assert isinstance(avail, bool)
        if avail:
            # Probe reports available ONLY when the functional self-test
            # passed — so a direct self-test must also pass.
            assert _seccomp_functional_selftest(state._libseccomp_cache) is True

    def test_mount_ns_selftest_returns_bool(self):
        from core.sandbox.probes import _mount_ns_functional_selftest
        assert isinstance(_mount_ns_functional_selftest(), bool)

    def test_mount_ns_selftest_fails_on_mount_denial_exit_codes(
            self, monkeypatch):
        # The child exits 2/3 when namespace CREATION worked but the
        # in-namespace mount operations were refused — the shape where
        # an outer seccomp EPERMs the mount family while unshare stays
        # allowed. A creation-only self-test reported such hosts as
        # mount-capable and every spawn then died on its bind tree
        # mid-flight; the probe must map those exits to unavailable.
        import os as _os

        from core.sandbox.probes import _mount_ns_functional_selftest

        for child_exit, expected in ((0, True), (1, False), (2, False),
                                     (3, False), (4, False)):
            monkeypatch.setattr(_os, "fork", lambda: 12345)
            monkeypatch.setattr(
                _os, "waitpid",
                lambda pid, opts, _s=child_exit << 8: (12345, _s))
            assert _mount_ns_functional_selftest() is expected, child_exit

    def test_staged_pidns_selftest_maps_child_exits(self, monkeypatch):
        # Exit 0 = staged creation engaged; 190 = the userns itself
        # refused (the flat CLI probe's case to diagnose — not a
        # staged refusal, so it must NOT flip this helper); any errno
        # = the staged unshare(CLONE_NEWPID) was refused (the
        # restricted-userns class live-confirmed on GitHub runners).
        import os as _os

        from core.sandbox.probes import _staged_pidns_selftest

        for child_exit, expected in ((0, True), (190, True), (1, False),
                                     (13, False), (250, False)):
            monkeypatch.setattr(_os, "fork", lambda: 12345)
            monkeypatch.setattr(
                _os, "waitpid",
                lambda pid, opts, _s=child_exit << 8: (12345, _s))
            assert _staged_pidns_selftest() is expected, child_exit

    def test_net_probe_keys_on_staged_selftest(self):
        # The namespace-backend foundation probe must agree with the
        # staged self-test: on hosts that allow single-call namespace
        # creation but refuse the spawn backend's staged
        # unshare(CLONE_NEWPID), check_net_available() must report the
        # backend unavailable so backend selection routes to the
        # degraded lanes instead of dying mid-child on every run
        # (live-confirmed failure mode on GitHub runners).
        from core.sandbox.probes import (
            _staged_pidns_selftest,
            check_net_available,
        )
        if not _staged_pidns_selftest():
            assert check_net_available() is False
        # (On staged-capable hosts the CLI creation probe owns the
        # verdict — True or a host-specific False both legal.)

    def test_mount_probe_consistent_with_selftest(self):
        # Mirrors the seccomp consistency test: the cached availability
        # verdict may report True only on hosts where the functional
        # self-test (namespace creation AND a real in-namespace mount)
        # passes right now.
        from core.sandbox.probes import (
            _mount_ns_functional_selftest,
            check_mount_available,
        )
        if check_mount_available():
            assert _mount_ns_functional_selftest() is True


class TestExecStatusPipe:
    """The exec-status pipe: an unspoofable, per-step signal of whether the
    target execed and, if not, which setup step failed — replacing the
    exit-code + stderr-emptiness heuristics."""

    def test_parse_setup_status(self):
        from core.sandbox._spawn import _parse_setup_status
        # Only the positive exec confirmation reads as "execed";
        # bare EOF is an unreported child death ('!'), never genuine.
        assert _parse_setup_status(b"G:") is None
        assert _parse_setup_status(b"")[0] == "!"
        assert _parse_setup_status(b"M:mount denied") == ("M", "mount denied")
        assert _parse_setup_status(b"L:") == ("L", "")
        assert _parse_setup_status(b"U:Operation not permitted") == (
            "U", "Operation not permitted")
        assert _parse_setup_status(b"X:exec: file not found")[0] == "X"

    @requires_landlock
    def test_mount_failure_retries_mountless_and_runs(self, tmp_path):
        # Force the mount-ns spawn path. On a mount-capable host it
        # engages; on an AppArmor/nested host the bind tree is denied →
        # status 'M' → the ladder KEEPS the namespace backend and
        # retries without the bind tree (mountless: Landlock + PID ns +
        # fresh procfs where the kernel allows). EITHER way the command
        # must actually RUN (real output), never return a silent rc-126
        # empty result. The old 'M' → Landlock-only-subprocess demotion
        # no longer exists: when the mountless retry cannot engage
        # either, the designed outcome is a TYPED fail-loud
        # SandboxSetupError (unit-covered by
        # test_secure_namespace_retry_fails_closed) — treat that as the
        # host lacking the lane, not as the silent-empty regression
        # this test guards against.
        ok, _ = check_unshare_engages(["--user", "--pid", "--fork", "--ipc"])
        if not ok:
            pytest.skip("host cannot engage namespaces at all")
        state._mount_available_cache = True
        state._mount_ns_available_cache = True
        tgt = tmp_path / "tgt"
        out = tmp_path / "out"
        tgt.mkdir()
        out.mkdir()
        (tgt / "f.txt").write_text("hi")
        tgt, out = str(tgt), str(out)
        try:
            with sandbox(block_network=True, target=tgt, output=out) as run:
                r = run(["/bin/echo", "ran-OK"],
                        capture_output=True, text=True)
        except SandboxSetupError as e:
            pytest.skip(
                f"mountless namespace retry cannot engage on this host "
                f"(typed fail-loud refusal, not a silent degrade): {e}"
            )
        if r.returncode == -9:
            pytest.skip(
                "subprocess degrade path hit EBADF (death-pipe fd "
                "inheritance gap in CI containers)"
            )
        assert r.returncode == 0
        assert "ran-OK" in (r.stdout or "")
        info = getattr(r, "sandbox_info", None) or {}
        if info.get("mount_ns_degraded"):
            # The 'M' retry actually fired: the run must record the
            # mountless posture, not claim bind-tree isolation.
            assert info.get("mount_ns_active") is not True

    # The premise (context enters the spawn path so the faked APPLY
    # failure can surface) is unbuildable when the namespace backend is
    # unavailable: the context degrades to Landlock-only up front and
    # the faked spawn is never reached — the forced mount caches below
    # cannot override that decision.
    @requires_userns
    # Exercises the Linux spawn ladder's 'L' apply-failure arm via the
    # Linux spawn seam — on any darwin dispatch the seam is inert.
    @pytest.mark.linux_native
    def test_core_layer_apply_failure_fails_loud(self, monkeypatch, tmp_path):
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
        tgt = tmp_path / "tgt"
        out = tmp_path / "out"
        tgt.mkdir()
        out.mkdir()
        tgt, out = str(tgt), str(out)
        with pytest.raises(SandboxSetupError) as ei, \
                sandbox(block_network=True, target=tgt, output=out) as run:
            run(["/bin/echo", "x"], capture_output=True, text=True)
        assert "Landlock" in str(ei.value)

    def test_drain_status_pipe_keeps_bytes_and_warns_on_read_error(
            self, caplog):
        # An unreadable status pipe is not EOF: the drain must keep any
        # bytes it read before the error (the category byte comes
        # first, so a truncated payload still names the failed step)
        # and warn — silently mapping the error to None made a
        # reported setup failure indistinguishable from a clean exec.
        import logging
        import os
        from unittest import mock

        from core.sandbox._spawn import _drain_status_pipe

        r, w = os.pipe()
        os.set_blocking(r, False)
        os.write(w, b"X:exec: permission denied")
        os.close(w)
        real_read = os.read
        calls = {"n": 0}

        def flaky_read(fd, size):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_read(fd, 4)  # partial: category + "exe"
            raise OSError(5, "Input/output error")

        parent_fds = {r}
        with mock.patch.object(os, "read", side_effect=flaky_read), \
                caplog.at_level(logging.WARNING,
                                logger="core.sandbox._spawn"):
            status = _drain_status_pipe(r, parent_fds)
        assert status is not None
        assert status[0] == "X"
        assert r not in parent_fds
        assert any("exec-status pipe drain failed" in rec.message
                   for rec in caplog.records)

    def test_drain_status_pipe_read_error_with_no_bytes_warns_unknown(
            self, caplog):
        # Nothing read at all before the error: the status is unknown,
        # which now maps to the same '!' refusal as a missing exec
        # confirmation — an unreadable pipe must not masquerade as a
        # confirmed exec — and the condition is named out loud.
        import logging
        import os
        from unittest import mock

        from core.sandbox._spawn import _drain_status_pipe

        r, w = os.pipe()
        os.set_blocking(r, False)
        os.close(w)
        with mock.patch.object(
                os, "read",
                side_effect=OSError(9, "Bad file descriptor")), \
                caplog.at_level(logging.WARNING,
                                logger="core.sandbox._spawn"):
            status = _drain_status_pipe(r, {r})
        assert status is not None and status[0] == "!"
        assert any("status unknown" in rec.message
                   for rec in caplog.records)

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


def test_demotion_refusal_names_the_actual_unmet_condition_source_pin():
    """The per-call demotion refusal must not claim "Landlock ABI v4+
    is missing" on ABI-v4+ hosts where the deny-all lane was excluded
    by allowed_tcp_ports — that wording sent an operator chasing a
    Landlock upgrade the host already had (live case: a GitHub runner
    probing ABI 7 refused every block_network+allowlist call with the
    ABI message). Source pin, same style as the cgroup pin below: the
    arm computes the condition instead of hardcoding the ABI claim."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "context.py").read_text(
        encoding="utf-8")
    start = src.index("_demoted_net_deny = False")
    block = src[start:src.index("ENGAGE_FAIL_INSTRUCTIONS + \" Alternatively \"",
                                start)]
    assert "_no_deny_why" in block, (
        "the per-call demotion refusal no longer computes the actual "
        "unmet network-deny condition")
    assert "allowed_tcp_ports is the" in block, (
        "the allowlist-excluded branch of the refusal wording is gone")
    assert "{_no_deny_why}" in block, (
        "the refusal message no longer interpolates the computed "
        "condition")


def test_engage_probe_covers_the_cgroup_flag_source_pin():
    """The real unshare command appends --cgroup when the CLI supports
    it — the engagement gate must probe the SAME flag-set, or a kernel
    or policy that refuses CLONE_NEWCGROUP slips past the gate and the
    wrapper exits pre-exec: the exact silent-empty-output failure this
    file guards against."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "context.py").read_text(
        encoding="utf-8")
    start = src.index('_engage_flags = ["--user"')
    block = src[start:src.index("check_unshare_engages(_engage_flags)",
                                start)]
    assert "unshare_supports_cgroup()" in block, (
        "the engagement probe no longer covers the conditional "
        "--cgroup the real command appends")
    assert '_engage_flags.append("--cgroup")' in block
