"""Pytest fixtures for the sandbox test module.

The sandbox module has several pieces of process-level global state that
can leak between tests if a setUp/tearDown is forgotten or fails. We
snapshot them before every test and restore afterwards as a safety net
— individual tests are still free to mutate them deliberately.
"""

import pytest


@pytest.fixture(autouse=True)
def _sandbox_state_guard():
    """Snapshot and restore all mutable module state around each test, so a
    test that sets any global can't poison others.

    Covers:
    - CLI-override flags (_cli_sandbox_*)
    - Once-per-process warning flags (_landlock_warned_*, _sandbox_unavailable_warned)
    - Availability caches (_net_available_cache, _mount_available_cache,
      _user_limits_cache) — tests that mock check_net_available or
      override _CONFIG_PATH would otherwise leave a stale False/{}
      value that subsequent tests see as real state. NOTE:
      _landlock_cache is INTENTIONALLY EXCLUDED — see the comment
      next to its slot in state_names below for why.
    - summary._active_run_dir — the per-run sandbox-summary recording
      target. Test files have their own per-test fixtures that set/clear
      this, but a forgotten cleanup would leak the run dir into
      subsequent tests' record_denial calls (silently writing into a
      stale dir). Snapshotting in the conftest is a backstop.

    Runs automatically for every test in this directory (autouse=True).
    """
    from core.sandbox import state as mod
    from core.sandbox import summary as summary_mod
    state_names = [
        # CLI overrides
        "_cli_sandbox_disabled", "_cli_sandbox_profile",
        "_cli_sandbox_audit", "_cli_sandbox_audit_verbose",
        "_cli_sandbox_audit_budget",
        # Once-per-process warnings
        "_landlock_warned_unavailable", "_landlock_warned_abi_v4",
        "_landlock_warned_abi_v3", "_landlock_warned_abi_v2",
        "_sandbox_unavailable_warned", "_sandbox_landlock_only_warned",
        "_net_and_tcp_allowlist_warned",
        "_seccomp_arch_missing_warned", "_mount_unavailable_warned",
        "_ptrace_unavailable_warned", "_audit_warned_no_spawn",
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
        "_unshare_path_cache", "_prlimit_path_cache",
        "_mount_path_cache", "_mkdir_path_cache",
    ]
    saved = {name: getattr(mod, name) for name in state_names}
    # Snapshot+restore the speculative-failure cache as a deep copy
    # — it's a dict, so a shallow alias would let test mutations
    # bleed across tests via the shared dict object. A test that
    # populates it (or expects it empty) must not see entries left
    # over from a sibling test.
    saved_spec_cache = dict(mod._speculative_failure_cache)
    saved_active_run = summary_mod._active_run_dir
    try:
        yield
    finally:
        for name, value in saved.items():
            setattr(mod, name, value)
        mod._speculative_failure_cache.clear()
        mod._speculative_failure_cache.update(saved_spec_cache)
        # Restore via the public setter so the module's threading.Lock
        # is honoured (set_active_run_dir also resets _denial_count,
        # which is harmless — a per-test counter reset is appropriate).
        summary_mod.set_active_run_dir(saved_active_run)
