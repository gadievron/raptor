"""Pytest fixtures for the sandbox test module.

The sandbox module has several pieces of process-level global state that
can leak between tests if a setUp/tearDown is forgotten or fails. We
snapshot them before every test and restore afterwards as a safety net
— individual tests are still free to mutate them deliberately.
"""

import os
import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def short_sock_dir():
    """A directory short enough that AF_UNIX socket paths fit sun_path.

    The kernel caps unix-socket paths at sizeof(sun_path) — ~104 bytes
    on macOS/BSD, 108 on Linux. pytest's ``tmp_path`` on CI runners
    routinely exceeds that once a socket name is appended (macOS:
    ``/private/var/folders/.../pytest-of-runner/pytest-N/<test>N/``),
    so ``bind()`` fails with "AF_UNIX path too long". Tests that bind
    unix sockets must derive their socket paths from this fixture
    instead of ``tmp_path``. Production has the equivalent guard:
    core.sandbox.context falls back to the system tempdir when the
    output-derived proxy socket path exceeds 104 bytes.
    """
    d = tempfile.mkdtemp(prefix="raptor-sk-", dir="/tmp")
    try:
        yield Path(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def hermetic_invalid_dns(monkeypatch):
    """Deterministic NXDOMAIN for RFC 2606 ``.invalid`` CONNECT targets.

    Several proxy tests use ``.invalid`` hostnames as guaranteed-failing
    resolve targets. The GUARANTEE is only about the outcome — the
    latency and exception detail come from the host's live resolver,
    and platform resolvers differ wildly: glibc fails an NXDOMAIN
    immediately, while macOS (search-domain retries through
    mDNSResponder) has been observed taking longer than a test client's
    5s read budget, so the proxy's 502 arrived after the client gave
    up. Stub the proxy's resolve seam for ``.invalid`` names — instant
    gaierror, no resolver in the loop — and delegate every other name
    (e.g. ``localhost``, literal IPs) to the real lookup.

    The patch MUST go through the shared ``monkeypatch`` fixture, not a
    manual save/restore: tests layer their own ``monkeypatch.setattr``
    on the same class attribute, and a manual ``finally`` restore runs
    BEFORE that monkeypatch's undo — which then re-installs the value
    it saved at setattr time (this fixture's stub), leaking the stub
    onto the class for the rest of the process. One shared undo stack
    unwinds LIFO and always lands back on the pristine method (the
    session-end seam guard below trips if that ever regresses).
    """
    import socket as _socket

    from core.sandbox import proxy as _proxy_mod

    real = _proxy_mod.EgressProxy._cached_getaddrinfo

    async def _stubbed(self, host, port):
        if host.endswith(".invalid"):
            raise _socket.gaierror(
                _socket.EAI_NONAME, "Name or service not known")
        return await real(self, host, port)

    monkeypatch.setattr(_proxy_mod.EgressProxy, "_cached_getaddrinfo",
                        _stubbed)
    yield


@pytest.fixture
def confined_parser_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the parser-jail floor to confined (``landlocked`` -> True).

    Buffer-semantics tests (lane fan-out, caps, record/unregister
    serialisation) pin the EXACT contents of registration event
    buffers. On a host without Landlock (macOS; Linux < 5.13) the
    parser-jail worker comes up on the degraded floor, and
    ``register_sandbox`` then injects the documented per-registration
    ``parser_jail_degraded`` control-plane marker into every buffer —
    shifting every count, segregation set, and index-0 assumption by
    one. That marker contract is pinned hermetically BOTH ways in
    test_parser_jail.py (TestDegradedFloor); pinning the floor here
    keeps the buffer pins running identically on every host instead
    of skipping them off-platform. Patches the class property so
    proxies constructed later inside the test observe it, and only
    the floor REPORT is pinned — the real worker still parses.
    """
    from core.sandbox import parser_jail as _parser_jail_mod

    def _confined(self: "_parser_jail_mod.ParserJail") -> bool:
        return True

    monkeypatch.setattr(_parser_jail_mod.ParserJail, "landlocked",
                        property(_confined))


@pytest.fixture(scope="session", autouse=True)
def _resolver_seam_leak_guard():
    """Leak tripwire for the proxy resolve seam.

    Session-scoped so its teardown runs after every function-scoped
    fixture (including ``monkeypatch``, which instantiates early — it
    is requested by root-conftest autouse fixtures — and therefore
    finalizes after any function-scoped guard could). If any test or
    fixture leaves a stub on ``EgressProxy._cached_getaddrinfo``, the
    whole session fails loudly here instead of silently running every
    later module against the stub.
    """
    from core.sandbox import proxy as _proxy_mod

    pristine = _proxy_mod.EgressProxy._cached_getaddrinfo
    yield
    current = _proxy_mod.EgressProxy._cached_getaddrinfo
    assert current is pristine, (
        f"EgressProxy._cached_getaddrinfo leaked a test stub past its "
        f"test: {current!r} (pristine: {pristine!r})"
    )


@pytest.fixture(autouse=True)
def _consent_env_guard(monkeypatch):
    """Strip the consent variables around every test.

    RAPTOR_ALLOW_DEGRADED_UNTRUSTED steers untrusted-run refusal
    behaviour, so a shell or CI job exporting it flips fail-closed
    expectations across this directory (four refusal tests turn red
    under an exported consent). RAPTOR_NO_SANDBOX_NONCE gets the same
    treatment: an ambient nonce exported by an operator's shell would
    let in-process disable-gate tests resolve a consent the test never
    granted. Tests that exercise the opt-ins set them explicitly via
    monkeypatch.setenv (or the ``no_sandbox_consent`` fixture), which
    composes with this guard: the guard strips first, the test sets,
    both restore in LIFO order.
    """
    _vars = ("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "RAPTOR_NO_SANDBOX_NONCE")
    # Share the test's undo stack. A separate manual restore runs before
    # monkeypatch teardown, whose undo would then erase the restored ambient
    # consent when a test temporarily set its own nonce.
    for v in _vars:
        monkeypatch.delenv(v, raising=False)


@pytest.fixture
def no_sandbox_consent(monkeypatch, tmp_path):
    """Mint a real, test-scoped consent for the CLI sandbox disable.

    THE migration path for tests that legitimately drive
    ``set_cli_profile("none")`` / ``disable_from_cli()`` /
    ``--no-sandbox`` in-process: the gate's only consent source is a
    minted nonce backed by a uid-owned consent file — terminal
    presence grants nothing — so without one the disable refuses
    regardless of the test process's fd shape. This fixture goes through
    the REAL validation path — a digest-content consent file, mode
    0600, in a consents directory redirected to tmp_path — rather
    than stubbing the gate, so migrated tests still exercise the
    production consent logic. This conftest is also the designated
    OUT-OF-RUNTIME mint surface for the test suite (the runtime
    module only ever re-exports an already-accepted consent).

    Returns the nonce string (already exported via monkeypatch.setenv).
    """
    import secrets

    from core.sandbox import disable_consent as dc

    d = tmp_path / "consents.d"
    d.mkdir(mode=0o700)
    monkeypatch.setattr(dc, "_consents_dir", lambda: d)
    nonce = secrets.token_hex(dc.NONCE_HEX_LEN // 2)
    path = d / dc._nonce_filename(nonce)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (dc._nonce_digest(nonce) + "\n").encode("ascii"))
    finally:
        os.close(fd)
    monkeypatch.setenv(dc.NONCE_ENV_VAR, nonce)
    return nonce


@pytest.fixture
def no_sandbox_consent_subprocess(tmp_path):
    """Mint a disable consent a SUBPROCESS can validate.

    Yield the nonce and its scratch directory. The test's child harness
    redirects ONLY the storage lookup to that directory; the real nonce
    format, ownership, permissions, digest and expiry checks still run.
    Tests must never mint real sandbox-disable authority in the operator's
    passwd-derived home, including when a child cannot inherit monkeypatch.
    """
    import secrets

    from core.sandbox import disable_consent as dc

    d = tmp_path / "consents.d"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    nonce = secrets.token_hex(dc.NONCE_HEX_LEN // 2)
    path = d / dc._nonce_filename(nonce)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (dc._nonce_digest(nonce) + "\n").encode("ascii"))
    finally:
        os.close(fd)
    try:
        yield nonce, d
    finally:
        try:
            path.unlink()
        except OSError:
            pass


@pytest.fixture
def monkeypatch(_sandbox_state_guard):
    # Keep body fault injection inside the owner that closes evidence handles.
    with pytest.MonkeyPatch.context() as patch:
        yield patch


@pytest.fixture(autouse=True)
def _sandbox_state_guard(_process_pin_state):
    """Isolate process state and held evidence without mutating borrowed owners.

    Keep kernel-capability observations, but give mutable cache containers
    private copies. The functional Landlock probe remains process-scoped.
    Root process defaults are installed first; body patches unwind before
    evidence finalization and restoration of the caller's state.
    """
    from core.testing.sandbox_state_scope import isolated_sandbox_state

    state_names = [
        # CLI overrides
        "_cli_sandbox_disabled", "_cli_sandbox_profile",
        "_cli_sandbox_disable_consent",
        "_cli_sandbox_audit", "_cli_sandbox_audit_verbose",
        "_cli_sandbox_audit_budget",
        "_cli_sandbox_readable_paths", "_cli_sandbox_tool_paths",
        "_cli_sandbox_floor", "_project_sandbox_floor",
        # Once-per-process warnings
        "_landlock_warned_unavailable", "_landlock_warned_abi_v4",
        "_landlock_warned_abi_v3", "_landlock_warned_abi_v2",
        "_sandbox_unavailable_warned", "_sandbox_landlock_only_warned",
        "_mountless_backend_warned",
        "_nproc_pressure_degrade_warned",
        "_floor_lowered_banner_warned",
        "_floor_flag_banner_warned",
        "_floor_project_banner_warned",
        "_floor_host_banner_warned",
        "_floor_host_degrade_notice_warned",
        "_floor_surface_disagreement_warned",
        "_inherit_netns_block_warned",
        "_mountless_unachievable_warned",
        "_bare_run_posture_warned",
        "_net_and_tcp_allowlist_warned",
        "_degraded_tcp_deny_warned",
        "_degraded_net_open_override_warned",
        "_degraded_landlock_override_warned",
        "_demoted_tcp_deny_warned",
        "_demoted_net_open_override_warned",
        "_tolerated_policy_unenforced_warned",
        "_proxy_tier2_port_pin_warned",
        "_seccomp_filter_lost_warned",
        "_seccomp_arch_missing_warned", "_mount_unavailable_warned",
        "_ptrace_unavailable_warned", "_audit_warned_no_spawn",
        "_engage_probe_indeterminate_warned",
        # Availability caches — deliberately EXCLUDING _landlock_cache:
        # check_landlock_available() does a functional self-test that
        # forks a child. Forking after other threads have started (e.g.
        # the egress proxy's daemon thread) triggers Python 3.12's
        # multi-threaded-fork DeprecationWarning. Kernel capability is
        # deterministic across a single test session, so we let the
        # cache persist process-wide rather than re-running the self-
        # test (and re-forking) for every test.
        "_net_available_cache", "_mount_available_cache",
        # _mount_ns_available_cache: test_spawn_mount_ns.py deliberately
        # flips this cache via `state._mount_ns_available_cache = ...` to
        # verify the cache-honouring behaviour. Without snapshotting it,
        # the flipped value would leak into subsequent tests and make
        # mount_ns_available() return the poisoned value (e.g. True on a
        # sysctl=1 box where it should be False).
        "_mount_ns_available_cache",
        "_libseccomp_cache", "_user_limits_cache",
        # `_user_limits_cache_decided_at` carries the wall-clock
        # at which the negative-cache decision was made (see
        # core/sandbox/preexec.py:_FAIL_TTL_S). Snapshotted alongside
        # the cache itself so a test that pokes the cache also rolls
        # the timestamp back — otherwise the next test sees a
        # cached `{}` whose timestamp is in the future relative to
        # the test's assumed "fresh process" baseline.
        "_user_limits_cache_decided_at",
        "_ptrace_available_cache",
        # macOS sandbox-exec smoke-test result. Tests that mock
        # check_seatbelt_available() without snapshotting would
        # leak the mocked value into sibling tests on Linux hosts
        # (where the cache otherwise stays at None and the function
        # short-circuits to False on platform check).
        "_seatbelt_available_cache",
        # raptor-gidmap-allow helper probe result + warn-once flag.
        # test_spawn_mount_ns.py::TestGidmapAllowProbe resets the cache
        # to exercise the probe; without snapshot the poisoned value
        # leaks into subsequent tests.
        "_gidmap_allow_cache", "_gidmap_allow_warned_missing",
        "_unshare_path_cache",
        "_mount_path_cache", "_mkdir_path_cache",
        "_newuidmap_path_cache", "_newgidmap_path_cache",
        "_getcap_path_cache", "_sandbox_exec_path_cache",
        # AF_UNIX connect-scoping probe result + warn-once flag —
        # test_unix_connect_scope.py patches probe_unix_scope and must
        # not leak a poisoned availability verdict into sibling tests.
        "_unix_scope_cache", "_unix_scope_unavailable_warned",
        # Fresh-procfs (pid-ns remount) probe cache + warn-once flag —
        # test_pidns_proc_mount.py seeds the cache to exercise the
        # once-per-process WARNING and the per-run posture stamp.
        "_pidns_fresh_proc_cache", "_pidns_proc_mount_unavailable_warned",
        # Supervised pid-ns tier probe cache — test_supervised.py seeds
        # and flips it (probe-count assertions, runtime-refusal flip);
        # a leaked False would silently reroute every later
        # spawn_supervised test onto the group tier.
        "_pidns_supervision_cache",
    ]
    with isolated_sandbox_state(state_names):
        yield

@pytest.fixture
def private_triage_readers(monkeypatch, tmp_path):
    """Keep reader fault injection off process-wide os/json modules."""
    from types import ModuleType

    from core.sandbox import triage
    from core.testing.state_isolation import pin_user_state_dirs

    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
    for name in ('os', 'json'):
        original = getattr(triage, name)
        private = ModuleType(original.__name__)
        vars(private).update(vars(original))
        monkeypatch.setattr(triage, name, private)


@pytest.fixture
def owned_audit_source(tmp_path, monkeypatch, request):
    """Feed the real audit reader from an owned process, without native tracing."""
    import subprocess
    import sys
    from types import ModuleType
    from core.sandbox import seatbelt_audit as audit
    from core.sandbox import observe_profile as observe

    owners, children = [], []

    def cleanup():
        errors = []
        for proc in children:
            try:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=5)
            except BaseException as error:
                errors.append(error)
        for owner in owners:
            try:
                owner.stop()
            except BaseException as error:
                errors.append(error)
            reader = owner._reader
            if reader is not None:
                reader.join(timeout=5)
                if reader.is_alive():
                    errors.append(AssertionError('owned audit reader survived cleanup'))
        for proc in children:
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError as error:
                        errors.append(error)
        if errors:
            raise errors[0]

    request.addfinalizer(cleanup)

    def run(data, *, decode_failure=False, observe_mode=True):
        run_dir = tmp_path / f'capture-{len(owners)}'
        owner = audit.LogStreamer(run_dir, observe_mode=observe_mode,
                                  observe_nonce='trusted' if observe_mode else None)
        owners.append(owner)
        private = ModuleType('owned_audit_subprocess')
        vars(private).update(vars(subprocess))

        def popen(argv, **kwargs):
            kwargs['cwd'] = str(tmp_path)
            kwargs['stderr'] = subprocess.PIPE
            proc = subprocess.Popen([
                sys.executable, '-c',
                'import sys;sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]));sys.stdout.buffer.flush()',
                data.hex(),
            ], **kwargs)
            children.append(proc)
            return proc

        private.Popen = popen
        monkeypatch.setattr(audit, 'subprocess', private)
        monkeypatch.setattr(owner, '_warm_up_until_attached', lambda: True)
        if decode_failure:
            original = audit._decode_log_entry
            calls = 0

            def fail_after_one(line):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise RuntimeError('injected producer decode failure')
                return original(line)

            monkeypatch.setattr(audit, '_decode_log_entry', fail_after_one)
        owner.start()
        owner._reader.join(timeout=5)
        assert not owner._reader.is_alive(), 'owned producer did not reach reader EOF'
        owner._proc.wait(timeout=5)
        error = owner._proc.stderr.read(4096)
        assert owner._proc.returncode == 0, f'owned producer exited {owner._proc.returncode}: {error}'
        owner.stop()
        profile = (observe.parse_observe_log(run_dir, expected_nonce='trusted', current_run=True)
                   if observe_mode else None)
        return owner, profile

    return run


@pytest.fixture
def private_egress_readers(monkeypatch, tmp_path):
    """Isolate egress reader fault injection from shared module APIs."""
    from types import ModuleType
    from core.sandbox import egress_summary
    from core.security import capped_read
    from core.testing.state_isolation import pin_user_state_dirs

    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    for owner, name in ((egress_summary, 'json'), (capped_read, 'os')):
        original = getattr(owner, name)
        private = ModuleType(original.__name__)
        vars(private).update(vars(original))
        monkeypatch.setattr(owner, name, private)
