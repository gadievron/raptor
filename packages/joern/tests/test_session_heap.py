"""joern_session must pass the operator's heap tunable to the CPG
build — the joern-parse JVM on a large target is exactly where
joern_heap_mb matters, not just the query server."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import packages.joern as joern_pkg
from packages.joern.tunables import JoernTunables


def _run_session(tmp_path: Path, tunables: JoernTunables, use_cache: bool):
    captured: dict = {}

    def fake_build(*args, **kwargs):
        captured.update(kwargs)
        cpg = MagicMock()
        cpg.exists.return_value = False
        return cpg

    server = MagicMock()
    with patch.object(joern_pkg, "is_available", return_value=True), \
            patch.object(joern_pkg.JoernServer, "from_tunables",
                         return_value=server), \
            patch.object(joern_pkg, "build_cpg_cached",
                         side_effect=fake_build), \
            patch.object(joern_pkg, "build_cpg", side_effect=fake_build):
        with joern_pkg.joern_session(
            tmp_path,
            cache_dir=(tmp_path if use_cache else None),
            tunables=tunables,
            register_reach_audit=False,
        ) as srv:
            assert srv is server
    return captured


def test_cached_build_receives_heap_mb(tmp_path):
    captured = _run_session(
        tmp_path, JoernTunables(heap_mb=8192), use_cache=True)
    assert captured.get("heap_mb") == 8192


def test_uncached_build_receives_heap_mb(tmp_path):
    captured = _run_session(
        tmp_path, JoernTunables(heap_mb=4096), use_cache=False)
    assert captured.get("heap_mb") == 4096


def test_builds_receive_heap_is_derived():
    # The ledger clamps only DERIVED heaps — the flag must survive
    # the trip from tunables to both build paths, or a derived heap
    # would ride as an operator assertion and never clamp.
    import tempfile

    tunables = JoernTunables(heap_mb=8192, heap_is_derived=True)
    with tempfile.TemporaryDirectory() as tmp:
        for use_cache in (True, False):
            captured = _run_session(Path(tmp), tunables, use_cache=use_cache)
            assert captured.get("heap_is_derived") is True


def test_from_tunables_carries_heap_is_derived():
    from packages.joern.server import JoernServer

    srv = JoernServer.from_tunables(
        JoernTunables(heap_mb=1024, heap_is_derived=True))
    assert srv._heap_is_derived is True
    srv = JoernServer.from_tunables(JoernTunables(heap_mb=1024))
    assert srv._heap_is_derived is False
