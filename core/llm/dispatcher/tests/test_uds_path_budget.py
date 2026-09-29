"""Regression tests: AF_UNIX sun_path budgets measure BYTES, not chars.

The kernel compares the FSENCODED socket path against the sun_path cap
(108 bytes on Linux, including the trailing NUL), so every budget check
must measure ``len(os.fsencode(...))``:

* ``len(str)`` undercounts a multibyte root (fewer characters than
  bytes), admitting roots whose socket paths later fail ``bind()``;
* bare ``str.encode()`` crashes (``UnicodeEncodeError``) on a root
  carrying undecodable bytes, which reach Python as surrogate-escaped
  ``str``.

This module covers the ``_af_unix_safe_tmp`` re-rooting fixture in
this directory's conftest plus the exact-value boundary of the
runtime budget (``test_sun_path_budget_exact_value``); the rest of
the runtime side (``LLMDispatcher``'s own /tmp fallback) is pinned in
``test_lifecycle.py::TestSocketPathBudget``.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from core.llm.dispatcher.tests import conftest as dispatcher_conftest

_SAFE = dispatcher_conftest._SAFE_TMP_LEN


def _drive(monkeypatch: pytest.MonkeyPatch, root: str) -> Iterator[None]:
    """Point ``gettempdir()`` at ``root`` and start the fixture body.

    The fixture is autouse, so the real instance already ran for this
    test with the session TMPDIR; driving the unwrapped generator with
    the test's own monkeypatch exercises the re-root decision against
    a controlled root. Callers ``next()`` it and ``close()`` it.
    """
    monkeypatch.setenv("TMPDIR", root)
    monkeypatch.setattr(tempfile, "tempdir", root)
    fixture = dispatcher_conftest._af_unix_safe_tmp
    fn = getattr(fixture, "__wrapped__", fixture)
    return fn(monkeypatch)


def test_multibyte_root_counted_in_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A root that is chars-under but bytes-over the budget MUST be
    re-rooted — a char-counting check no-ops and leaves an over-budget
    TMPDIR in place, so every dispatcher socket path built under it
    can blow sun_path at bind()."""
    k = _SAFE // 2 + 1
    root = "/" + "é" * k  # 2 UTF-8 bytes per char
    assert len(root) <= _SAFE                  # chars: looks in-budget
    assert len(os.fsencode(root)) > _SAFE      # bytes: over budget
    gen = _drive(monkeypatch, root)
    next(gen)
    try:
        got = len(os.fsencode(tempfile.gettempdir()))
        assert got <= _SAFE, (
            f"fixture left a {got}-byte TMPDIR in place (budget "
            f"{_SAFE} bytes): sun_path is a BYTE budget, and this "
            f"root is only {len(root)} chars but "
            f"{len(os.fsencode(root))} bytes"
        )
    finally:
        gen.close()


def test_surrogate_root_measured_not_crashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Undecodable TMPDIR bytes surface as surrogate escapes; the
    budget check must neither raise nor miscount them (one byte per
    escaped byte), on both sides of the cap."""
    under = "/" + "\udcff" * (_SAFE - 1)
    assert len(os.fsencode(under)) == _SAFE
    gen = _drive(monkeypatch, under)
    next(gen)
    try:
        # Within budget: used as-is, no re-root.
        assert tempfile.gettempdir() == under
    finally:
        gen.close()

    over = "/" + "\udcff" * _SAFE
    assert len(os.fsencode(over)) == _SAFE + 1
    gen = _drive(monkeypatch, over)
    next(gen)
    try:
        got = tempfile.gettempdir()
        assert got != over
        assert len(os.fsencode(got)) <= _SAFE
    finally:
        gen.close()


def test_boundary_both_directions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pin ``_SAFE_TMP_LEN`` in both directions with an ASCII root
    (chars == bytes): exactly at the budget stays, one byte over
    re-roots. Looser admits roots whose socket paths can exceed
    sun_path; tighter forces needless /tmp re-roots that abandon the
    session TMPDIR containment."""
    at = "/" + "a" * (_SAFE - 1)
    gen = _drive(monkeypatch, at)
    next(gen)
    try:
        assert tempfile.gettempdir() == at
    finally:
        gen.close()

    over = "/" + "a" * _SAFE
    gen = _drive(monkeypatch, over)
    next(gen)
    try:
        assert tempfile.gettempdir() != over
    finally:
        gen.close()


def _padded_tmpdir(host: str, run_id: str, target_bytes: int) -> str:
    """Make a dir under ``host`` sized so the dispatcher's minted
    child-socket path is exactly ``target_bytes`` fsencoded bytes.

    The minted path is deterministic given TMPDIR:
    ``<TMPDIR>/raptor-llm-<run_id[:40]>-<suffix>/llm-child.sock``
    (mirrors ``_sock_prefix`` in ``LLMDispatcher.__init__``), with the
    mkdtemp random-suffix width measured via a probe, not assumed.
    """
    prefix = f"raptor-llm-{run_id[:40]}-"
    probe = tempfile.mkdtemp(prefix=prefix, dir=host)
    suffix_len = len(os.fsencode(os.path.basename(probe))) - len(
        os.fsencode(prefix)
    )
    os.rmdir(probe)
    # "/" + prefix + suffix + "/" + "llm-child.sock"
    fixed = 1 + len(os.fsencode(prefix)) + suffix_len + 1 + len(
        os.fsencode("llm-child.sock")
    )
    pad = target_bytes - len(os.fsencode(host)) - 1 - fixed
    assert pad > 0, "host dir too deep to land the boundary"
    root = os.path.join(host, "p" * pad)
    os.mkdir(root)
    assert len(os.fsencode(root)) + fixed == target_bytes
    return root


# The LITERAL budget value, restated independently of the constant in
# server.py — importing it would make the pin self-referential (the
# padding would track a drifted constant and the boundary test would
# still pass). 100 is load-bearing for existing deep-TMPDIR
# deployments, so both directions matter: raising it silently admits
# paths the kernel truncates on smaller-sun_path platforms, lowering
# it silently diverts working deployments to the system-global /tmp,
# abandoning their TMPDIR containment. Changing _SUN_PATH_BUDGET means
# consciously changing this pin with it.
_PINNED_SUN_PATH_BUDGET = 100


def test_sun_path_budget_exact_value(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Boundary pin for the EXACT value of ``_SUN_PATH_BUDGET``: a
    worst-case socket path of exactly 100 fsencoded bytes stays in the
    caller's TMPDIR (no /tmp diversion) and binds; exactly one byte
    over diverts to the /tmp fallback. Rationale for pinning the
    value: see ``_PINNED_SUN_PATH_BUDGET`` above and the constant's
    own comment in server.py."""
    import shutil
    import tempfile as _tempfile

    from core.llm.dispatcher.auth import CredentialStore
    from core.llm.dispatcher.server import LLMDispatcher

    creds = CredentialStore.__new__(CredentialStore)
    creds._keys = {}

    # Anchor at /tmp (not tmp_path): the padding math needs positive
    # headroom under the budget even on deep-scratch hosts.
    host = _tempfile.mkdtemp(prefix="rl-pin-", dir="/tmp")
    try:
        for overshoot, must_stay in ((0, True), (1, False)):
            root = _padded_tmpdir(
                host, "pin", _PINNED_SUN_PATH_BUDGET + overshoot
            )
            monkeypatch.setenv("TMPDIR", root)
            monkeypatch.setattr(_tempfile, "tempdir", None)
            d = LLMDispatcher(
                run_id="pin",
                creds=creds,
                audit_path=tmp_path / "audit.jsonl",
            )
            try:
                assert d.socket_path.exists()
                stayed = str(d._sock_dir).startswith(root + os.sep)
                assert stayed == must_stay, (
                    f"worst-case socket path at pinned budget"
                    f"{'+1' if overshoot else ''} "
                    f"({_PINNED_SUN_PATH_BUDGET + overshoot} bytes) "
                    f"{'diverted to /tmp' if must_stay else 'stayed'}"
                )
                if must_stay:
                    # Landed exactly AT the boundary, not merely under
                    # it — this also self-validates the padding math
                    # against the real minted path.
                    assert (
                        len(os.fsencode(d.child_socket_path))
                        == _PINNED_SUN_PATH_BUDGET
                    )
            finally:
                d.shutdown()
    finally:
        monkeypatch.setattr(_tempfile, "tempdir", None)
        shutil.rmtree(host, ignore_errors=True)
