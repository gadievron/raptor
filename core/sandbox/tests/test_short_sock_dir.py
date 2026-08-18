"""Regression guard for the ``short_sock_dir`` conftest fixture.

Unix-socket tests derive their bind paths from this fixture because
pytest's ``tmp_path`` on CI runners can exceed the kernel's sun_path
buffer. The budget asserted here is the strictest platform's (macOS/
BSD: 104 bytes including the NUL terminator; Linux allows 108) so a
fixture regression is caught on Linux CI before it breaks macOS.
"""

from __future__ import annotations

import socket

# sizeof(sun_path) on macOS/BSD — the strictest platform. The bind
# path plus NUL terminator must fit inside it.
_SUN_PATH_MACOS = 104


def test_socket_paths_fit_macos_sun_path(short_sock_dir):
    # Longest socket name currently used by the unix-lane tests, plus
    # generous headroom for future names.
    p = short_sock_dir / "raptor-proxy-lane-never-bound.sock"
    assert len(str(p).encode()) < _SUN_PATH_MACOS


def test_bind_succeeds_under_short_base(short_sock_dir):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.bind(str(short_sock_dir / "probe.sock"))
    finally:
        s.close()
