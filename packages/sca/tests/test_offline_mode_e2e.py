"""Tier-6 E2E: ``--offline`` truly blocks network.

Tiers 1-5 USE ``--offline`` for hermeticity but don't assert that
no network call HAPPENS. This tier enforces it at the syscall
layer: spawn the CLI in a subprocess whose Python interpreter is
preloaded with a monkeypatch that fails any ``socket.connect``
attempt to a non-loopback address.

Catches the regression class where a code path silently bypasses
the offline flag — e.g. a new client is added that doesn't
respect ``offline=options.offline`` and unconditionally hits
PyPI/npm/etc.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parents[3]


# ``sitecustomize.py`` is auto-imported by Python at startup. By
# pointing ``PYTHONPATH`` at a dir containing our sitecustomize,
# the subprocess gets the monkeypatch BEFORE any user code runs.
# The monkeypatch raises ``RuntimeError`` on any non-loopback
# ``socket.connect`` so a stray network call becomes a visible
# crash, not a silent timeout.
_SITECUSTOMIZE = '''
"""Network-block sitecustomize for the offline E2E test."""
import socket

_real_connect = socket.socket.connect


def _blocked_connect(self, address):
    if isinstance(address, tuple) and address[:1]:
        host = address[0]
        if host in ("127.0.0.1", "::1", "localhost"):
            return _real_connect(self, address)
        # Sentinel marker on stderr the test can find — no
        # raise because some best-effort code may swallow it
        # silently, but we'd still see the marker.
        import sys
        sys.stderr.write(
            f"OFFLINE_VIOLATION: socket.connect to {address}\\n"
        )
        raise RuntimeError(
            f"offline-mode test: refusing socket.connect to {address}"
        )
    return _real_connect(self, address)


socket.socket.connect = _blocked_connect
'''


def _run_with_network_blocked(
    args: List[str], tmp_path: Path, *, timeout: int = 90,
) -> subprocess.CompletedProcess:
    """Spawn the CLI with the network-block sitecustomize loaded."""
    sc_dir = tmp_path / "sc"
    sc_dir.mkdir(exist_ok=True)
    (sc_dir / "sitecustomize.py").write_text(_SITECUSTOMIZE)
    env = {**os.environ}
    # Prepend so our sitecustomize.py wins
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(sc_dir) + (
        os.pathsep + existing if existing else ""
    )
    cmd = [sys.executable, "-m", "packages.sca.cli"] + args
    return subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), env=env, timeout=timeout,
    )


def _build_simple_fixture(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "requirements.txt").write_text(
        "requests==2.31.0\n", encoding="utf-8",
    )
    (repo / "package.json").write_text(
        '{"name": "f", "version": "1.0.0", '
        '"dependencies": {"lodash": "4.17.21"}}',
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# The actual gate
# ---------------------------------------------------------------------------



def test_offline_scan_makes_no_network_connections(tmp_path: Path) -> None:
    """``raptor-sca <target> --offline`` must complete without
    any ``socket.connect`` to a non-loopback address.

    If the test fails: a code path doesn't respect ``--offline``.
    The stderr carries ``OFFLINE_VIOLATION:`` lines pointing to
    the host(s) the violating client tried to reach."""
    repo = tmp_path / "repo"
    _build_simple_fixture(repo)
    out = tmp_path / "out"

    proc = _run_with_network_blocked(
        [str(repo), "--offline", "--out", str(out)],
        tmp_path,
    )
    # Must complete (no crash). Note: even with offline, scan
    # may return exit 1 if any hygiene findings warrant it.
    assert proc.returncode in (0, 1), (
        f"offline scan crashed: exit={proc.returncode}\n"
        f"stderr (last 2k):\n{proc.stderr[-2000:]}"
    )
    # No OFFLINE_VIOLATION marker — the gate
    assert "OFFLINE_VIOLATION" not in proc.stderr, (
        "offline mode leaked network calls; stderr contained:\n"
        + "\n".join(
            line for line in proc.stderr.split("\n")
            if "OFFLINE_VIOLATION" in line
        )
    )


def test_offline_scan_still_emits_canonical_outputs(tmp_path: Path) -> None:
    """Offline with empty cache must still emit findings.json /
    report.md / sbom.cdx.json. Local-only analysis (hygiene,
    supply-chain heuristics) doesn't need network."""
    repo = tmp_path / "repo"
    _build_simple_fixture(repo)
    out = tmp_path / "out"

    proc = _run_with_network_blocked(
        [str(repo), "--offline", "--out", str(out)],
        tmp_path,
    )
    assert proc.returncode in (0, 1)
    for name in ("findings.json", "report.md", "sbom.cdx.json"):
        assert (out / name).is_file(), (
            f"offline mode failed to emit {name}"
        )


def test_offline_review_subcommand_blocks_network(tmp_path: Path) -> None:
    """``raptor-sca review <eco> <pkg> <ver> --offline`` is a
    one-shot lookup; verify it doesn't reach for the registry."""
    proc = _run_with_network_blocked(
        ["review", "PyPI", "requests", "2.31.0", "--offline"],
        tmp_path,
    )
    # Review may exit 0 (clean), 1 (review-needed), or 2 (block);
    # all are acceptable. Crash codes are not.
    assert proc.returncode in (0, 1, 2), (
        f"review crashed: exit={proc.returncode}\n"
        f"stderr (last 2k):\n{proc.stderr[-2000:]}"
    )
    assert "OFFLINE_VIOLATION" not in proc.stderr, (
        f"review --offline leaked network: {proc.stderr[-500:]}"
    )


def test_offline_with_explicit_cache_root(tmp_path: Path) -> None:
    """Passing an explicit empty cache root → offline mode still
    works (no fall-through to live network when cache is cold)."""
    repo = tmp_path / "repo"
    _build_simple_fixture(repo)
    out = tmp_path / "out"
    cache = tmp_path / "empty-cache"
    cache.mkdir()

    proc = _run_with_network_blocked(
        [str(repo), "--offline", "--out", str(out),
         "--cache-root", str(cache)],
        tmp_path,
    )
    assert proc.returncode in (0, 1)
    assert "OFFLINE_VIOLATION" not in proc.stderr
