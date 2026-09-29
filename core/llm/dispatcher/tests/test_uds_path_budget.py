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
this directory's conftest; the runtime side (``LLMDispatcher``'s own
/tmp fallback) is pinned in
``test_lifecycle.py::TestSocketPathBudget``.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator

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
