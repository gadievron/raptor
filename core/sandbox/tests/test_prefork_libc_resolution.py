"""libc is resolved in the parent, never in a forked child.

``ctypes.util.find_library("c")`` can shell out to /sbin/ldconfig;
spawning a subprocess from the forked child of a multi-threaded
parent is the banned fork-storm pattern (allocator/import locks held
at fork can wedge the child pre-exec). Every sandbox fork site must
therefore resolve libc PRE-FORK and hand the child a ready handle —
and every lazy cache the child reads must also cache FAILURE, so a
parent-side miss never triggers a child-side re-probe.
"""

from __future__ import annotations

import ast
import inspect
import sys as _sys
import textwrap

import pytest

from core.sandbox import _landlock_audit, fingerprint, landlock, preexec

pytestmark = pytest.mark.skipif(
    _sys.platform != "linux",
    reason="libc pre-fork contract is Linux fork-site plumbing",
)


def _called_names(fn) -> set[str]:
    """Names of everything CALLED in *fn*'s body (docstrings,
    comments, and annotations don't count)."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute):
                names.add(f.attr)
            elif isinstance(f, ast.Name):
                names.add(f.id)
    return names


class TestLandlockAuditPtracer:

    def test_child_body_never_resolves_libc(self):
        called = _called_names(_landlock_audit._set_ptracer_any_in_child)
        assert "find_library" not in called
        assert "CDLL" not in called

    def test_none_handle_degrades_silently(self):
        _landlock_audit._set_ptracer_any_in_child(None)  # must not raise

    def test_prctl_called_on_parent_handle(self):
        calls: list[tuple] = []

        class _FakePrctl:
            argtypes = None
            restype = None

            def __call__(self, *args):
                calls.append(args)
                return 0

        class _FakeLibc:
            prctl = _FakePrctl()

        _landlock_audit._set_ptracer_any_in_child(_FakeLibc())
        assert calls == [(
            _landlock_audit._PR_SET_PTRACER,
            _landlock_audit._PR_SET_PTRACER_ANY,
            0, 0, 0,
        )]


class TestLandlockSelftestChild:

    def test_child_body_never_resolves_libc(self):
        called = _called_names(landlock._run_selftest_in_child)
        assert "find_library" not in called
        assert "CDLL" not in called

    def test_none_handle_reports_broken_and_cleans_up(self):
        import glob
        before = set(glob.glob("/tmp/.raptor_landlock_selftest_*"))
        assert landlock._run_selftest_in_child(None) == 0
        # The mkstemp stub must not survive the early-out. Compare
        # against the pre-call snapshot: concurrent self-tests in
        # other processes may own stubs of their own.
        after = set(glob.glob("/tmp/.raptor_landlock_selftest_*"))
        assert after - before == set()

    def test_parent_resolved_handle_reaches_forked_child(self, monkeypatch):
        # The verdict byte is the only channel out of the forked
        # child: report enforcement iff the pre-fork handle arrived.
        monkeypatch.setattr(
            landlock, "_run_selftest_in_child",
            lambda libc: 1 if libc is not None else 0,
        )
        assert landlock._landlock_functional_self_test() is True


class TestPreexecLibcCache:

    def test_pdeathsig_factory_primes_cache_parent_side(self):
        preexec.set_pdeathsig()
        # Resolution (success OR cached failure) happened in the
        # factory — post-fork _get_libc is a pure cache read.
        assert preexec._libc is not None

    def test_musl_shape_falls_back_to_dlopen_null(self, monkeypatch):
        # find_library("c") returns None on hosts without ldconfig
        # (musl-shaped) even though libc is loaded and working —
        # dlopen(NULL) must rescue the lane instead of silently
        # disabling pdeathsig and the reaper/subreaper split.
        monkeypatch.setattr(preexec, "_libc", None)
        monkeypatch.setattr(
            preexec.ctypes.util, "find_library", lambda name: None,
        )
        libc = preexec._get_libc()
        assert libc is not None
        assert hasattr(libc, "prctl")

    def test_failure_is_cached_never_reprobed(self, monkeypatch):
        monkeypatch.setattr(preexec, "_libc", None)
        monkeypatch.setattr(
            preexec.ctypes.util, "find_library", lambda name: None,
        )

        def _no_dlopen(*a, **kw):
            raise OSError("dlopen unavailable")

        monkeypatch.setattr(preexec.ctypes, "CDLL", _no_dlopen)
        assert preexec._get_libc() is None
        assert preexec._libc is preexec._LIBC_UNAVAILABLE

        def _boom(name):
            raise AssertionError("post-failure re-probe: find_library "
                                 "ran again (would be post-fork in prod)")

        monkeypatch.setattr(preexec.ctypes.util, "find_library", _boom)
        assert preexec._get_libc() is None

    def test_success_is_cached_never_reprobed(self, monkeypatch):
        monkeypatch.setattr(preexec, "_libc", None)
        assert preexec._get_libc() is not None

        def _boom(name):
            raise AssertionError("re-probe after successful resolve")

        monkeypatch.setattr(preexec.ctypes.util, "find_library", _boom)
        assert preexec._get_libc() is not None

    def test_total_failure_warns_parent_side(self, monkeypatch, caplog):
        # When resolution truly fails, the disable must be LOUD: a
        # silent None turns off pdeathsig + the reaper split for every
        # subsequent spawn in the process.
        monkeypatch.setattr(preexec, "_libc", None)
        monkeypatch.setattr(
            preexec.ctypes.util, "find_library", lambda name: None,
        )

        def _no_dlopen(*a, **kw):
            raise OSError("dlopen unavailable")

        monkeypatch.setattr(preexec.ctypes, "CDLL", _no_dlopen)
        with caplog.at_level("WARNING", logger=preexec.__name__):
            assert preexec._get_libc() is None
        assert any("pdeathsig" in r.message for r in caplog.records)


class TestFingerprintLibcCache:

    def test_success_cached_lock_free_for_child(self, monkeypatch):
        monkeypatch.setattr(fingerprint, "_libc", None)
        monkeypatch.setattr(fingerprint, "_libc_error", None)
        assert fingerprint._get_libc() is not None

        def _boom(name):
            raise AssertionError("re-probe after successful resolve")

        monkeypatch.setattr(fingerprint._ctypes_util, "find_library", _boom)
        assert fingerprint._get_libc() is not None

    def test_failure_cached_raises_without_reprobe(self, monkeypatch):
        monkeypatch.setattr(fingerprint, "_libc", None)
        monkeypatch.setattr(fingerprint, "_libc_error", None)

        def _raise(name, use_errno=False):
            raise OSError("simulated missing libc")

        monkeypatch.setattr(fingerprint.ctypes, "CDLL", _raise)
        with pytest.raises(OSError):
            fingerprint._get_libc()
        assert fingerprint._libc_error is not None

        def _boom(name):
            raise AssertionError("post-failure re-probe: find_library "
                                 "ran again (would be post-fork in prod)")

        monkeypatch.setattr(fingerprint._ctypes_util, "find_library", _boom)
        with pytest.raises(OSError):
            fingerprint._get_libc()

    def test_spawn_prefork_prime_exists(self):
        # The persona lane's set_uts runs in _spawn's forked child;
        # the pre-fork section must prime fingerprint's cache.
        from core.sandbox import _spawn
        src = inspect.getsource(_spawn.run_sandboxed)
        assert "_fp_get_libc" in src
