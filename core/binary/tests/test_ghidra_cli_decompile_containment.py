"""Containment of the cached binary_path in raptor-ghidra decompile.

The cached re-database.json's binary_path is derived (hostile) data:
the disassembly fallback may only follow it into the Ghidra project's
own directory or the RAPTOR checkout's out/ dir. The out/ anchor must
be the repo root, NOT the process cwd — a cwd-relative anchor would
admit <scanned-repo>/out when the CLI is invoked from inside a hostile
repo, and refuse legitimate binaries when invoked from elsewhere.

Hermetic: packages.ghidra engine modules are stubbed so no Ghidra, JVM,
r2, or objdump is needed.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-ghidra"


def _load_script(monkeypatch):
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    loader = importlib.machinery.SourceFileLoader(
        "raptor_ghidra_under_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _stub_ghidra_packages(monkeypatch, binary_path: str):
    """Stub the engine modules so decompile falls through to the
    objdump-disassembly branch with a cached db pointing at binary_path."""

    class GhidraSessionError(Exception):
        pass

    class GhidraSession:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def open(self, *a, **k):
            raise GhidraSessionError("no engine in tests")

    session_mod = types.ModuleType("packages.ghidra.session")
    session_mod.GhidraSession = GhidraSession
    session_mod.GhidraSessionError = GhidraSessionError

    db = SimpleNamespace(
        binary_path=binary_path,
        functions=[SimpleNamespace(
            name="fn", address=0x100, size=16, decompilation=None)],
    )
    inject_mod = types.ModuleType("packages.ghidra.context_inject")
    inject_mod._load_cached_redb = lambda gpr: db

    detect_mod = types.ModuleType("packages.ghidra.detect")
    detect_mod.pyghidra_available = lambda: False
    detect_mod.prefer_in_process = lambda: False

    objdump_mod = types.ModuleType("packages.ghidra.objdump_import")
    objdump_mod.disassemble_function = lambda binary, addr, size: "DISASM-OK"

    for name, mod in (
        ("packages.ghidra.session", session_mod),
        ("packages.ghidra.context_inject", inject_mod),
        ("packages.ghidra.detect", detect_mod),
        ("packages.ghidra.objdump_import", objdump_mod),
    ):
        monkeypatch.setitem(sys.modules, name, mod)


def _decompile(mod, gpr: Path) -> int:
    args = SimpleNamespace(gpr=gpr, function="fn", program=None, timeout=1)
    return mod._cmd_decompile(args)


@pytest.fixture
def proj(tmp_path):
    d = tmp_path / "proj"
    d.mkdir()
    gpr = d / "target.gpr"
    gpr.write_text("")
    return gpr


def test_cwd_relative_out_is_not_an_allowed_root(
        monkeypatch, tmp_path, proj, capsys):
    # A hostile repo could carry its own out/ dir; running the CLI from
    # inside it must not admit a planted binary there.
    hostile = tmp_path / "hostile-repo"
    planted = hostile / "out" / "planted.bin"
    planted.parent.mkdir(parents=True)
    planted.write_bytes(b"\x7fELF")
    monkeypatch.chdir(hostile)

    mod = _load_script(monkeypatch)
    _stub_ghidra_packages(monkeypatch, str(planted))
    rc = _decompile(mod, proj)
    captured = capsys.readouterr()
    assert rc == 1
    assert "outside the project and out/ directories" in captured.err
    assert "DISASM-OK" not in captured.out


def test_binary_inside_project_dir_is_allowed(
        monkeypatch, tmp_path, proj, capsys):
    binary = proj.parent / "target.bin"
    binary.write_bytes(b"\x7fELF")
    # cwd elsewhere — containment must not depend on where the CLI runs.
    monkeypatch.chdir(tmp_path)

    mod = _load_script(monkeypatch)
    _stub_ghidra_packages(monkeypatch, str(binary))
    rc = _decompile(mod, proj)
    captured = capsys.readouterr()
    assert rc == 0
    assert "DISASM-OK" in captured.out


def _stub_bridge(monkeypatch, calls: list):
    class FakeBridge:
        def __init__(self, gpr, program_name=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def import_project(self, out_dir, decompile=False):
            calls.append("import_project")
            return "db"

        def import_and_enrich(self, out_dir, binary_path=None):
            calls.append("import_and_enrich")
            return "db"

    bridge_mod = types.ModuleType("packages.ghidra.bridge")
    bridge_mod.GhidraBridge = FakeBridge
    monkeypatch.setitem(sys.modules, "packages.ghidra.bridge", bridge_mod)


def test_binary_without_enrich_warns(monkeypatch, tmp_path, proj, capsys):
    mod = _load_script(monkeypatch)
    calls: list = []
    _stub_bridge(monkeypatch, calls)
    args = SimpleNamespace(binary=tmp_path / "b.elf", enrich=False,
                           program=None, decompile_all=False)
    mod._do_import(proj, args, tmp_path / "out")
    captured = capsys.readouterr()
    # The operator asked for r2 enrichment data; dropping --binary
    # silently would leave the cache missing what they requested.
    assert "--binary is only used with --enrich" in captured.err
    assert calls == ["import_project"]


def test_binary_with_enrich_does_not_warn(monkeypatch, tmp_path, proj, capsys):
    mod = _load_script(monkeypatch)
    calls: list = []
    _stub_bridge(monkeypatch, calls)
    binary = tmp_path / "b.elf"
    binary.write_bytes(b"\x7fELF")
    args = SimpleNamespace(binary=binary, enrich=True,
                           program=None, decompile_all=False)
    mod._do_import(proj, args, tmp_path / "out")
    captured = capsys.readouterr()
    assert "--binary is only used with --enrich" not in captured.err
    assert calls == ["import_and_enrich"]
