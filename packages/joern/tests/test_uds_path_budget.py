"""AF_UNIX sun_path budget arithmetic for the shared ``uds_dir`` fixture.

The kernel compares the fsencoded byte string against sun_path's
107-usable-byte cap, so the budget helper must count BYTES: a
TMPDIR root with multibyte UTF-8 characters is shorter in ``str``
characters than in encoded bytes, and a character count lets an
over-budget root through to a confusing ``bind()`` failure inside
whichever test touches the socket first. A root carrying undecodable
bytes (surrogate-escaped ``str``) must not crash the check either —
``os.fsencode`` round-trips those where ``str.encode("utf-8")``
raises.
"""

from __future__ import annotations

import os
import shutil
import tempfile

import pytest

from packages.joern.tests.conftest import (
    _SUN_PATH_MAX,
    _UDS_SOCK_NAME_MAX,
    _uds_budget_ok,
)

# Bytes ``_uds_budget_ok`` appends to the root it is given:
# "/" + "j" + 8 mkdtemp chars + "/" + the longest socket filename.
_WORST_SUFFIX_BYTES: int = 1 + 9 + 1 + _UDS_SOCK_NAME_MAX


class TestUdsBudgetOk:
    def test_multibyte_root_counted_in_bytes(self) -> None:
        # 54 characters but 107 bytes: a char count sees a worst-case
        # path of 75 <= 107 and admits it; the encoded form is
        # 107 + 21 = 128 bytes and must be refused.
        root = "/" + "é" * 53
        assert len(root) + _WORST_SUFFIX_BYTES <= _SUN_PATH_MAX  # chars fit
        assert len(os.fsencode(root)) + _WORST_SUFFIX_BYTES > _SUN_PATH_MAX
        assert not _uds_budget_ok(root)

    def test_surrogate_escaped_root_does_not_raise(self) -> None:
        # os.fsdecode of an undecodable TMPDIR yields surrogate escapes;
        # str.encode("utf-8") raises on those, os.fsencode round-trips
        # them (one byte each). The check must survive and stay exact.
        under = "/" + "\udc80" * 60  # 61 bytes -> worst 82, fits
        over = "/" + "\udc80" * 90  # 91 bytes -> worst 112, refused
        assert _uds_budget_ok(under)
        assert not _uds_budget_ok(over)

    def test_boundary_both_directions(self) -> None:
        # Exactly 107 bytes passes; 108 is refused. sun_path is 108
        # bytes including the trailing NUL, so 107 is the last usable
        # length — off-by-one in either direction is a real bug
        # (106 wastes budget, 108 binds EINVAL/ENAMETOOLONG).
        root_at_cap = "/" + "a" * (_SUN_PATH_MAX - _WORST_SUFFIX_BYTES - 1)
        root_over = root_at_cap + "a"
        assert _uds_budget_ok(root_at_cap)
        assert not _uds_budget_ok(root_over)


class TestUdsDirFixtureByteBudget:
    def test_multibyte_tmpdir_falls_back_within_byte_budget(
        self,
        request: pytest.FixtureRequest,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A REAL tmp root that fits the budget in characters but not
        # in bytes: the fixture must reject it and fall back to /tmp,
        # never yield a directory whose socket path overflows sun_path.
        base = tempfile.mkdtemp(prefix="ju", dir="/tmp")
        request.addfinalizer(lambda: shutil.rmtree(base, ignore_errors=True))
        fake_root = os.path.join(base, "é" * 45)
        os.mkdir(fake_root)
        assert len(fake_root) + _WORST_SUFFIX_BYTES <= _SUN_PATH_MAX
        assert len(os.fsencode(fake_root)) + _WORST_SUFFIX_BYTES > _SUN_PATH_MAX

        monkeypatch.setattr(tempfile, "gettempdir", lambda: fake_root)
        d = request.getfixturevalue("uds_dir")
        sock = os.path.join(d, "n" * _UDS_SOCK_NAME_MAX)
        assert len(os.fsencode(sock)) <= _SUN_PATH_MAX
        assert not d.startswith(fake_root)
