"""raptor-ghidra exception relays render inert on the operator TTY.

r2 / Ghidra exception messages quote binary-derived strings (section
names, embedded paths) which a hostile binary controls — the CLI's
other display sites scrub via ``_safe_name``/``_safe_line``, and the
degradation notices that echo exception text must too.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-ghidra"

_ESC_PAYLOAD = "boom\x1b]0;pwned\x07\x1b[2J"


def _load_cli():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    loader = SourceFileLoader("raptor_ghidra_cli_relays", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _assert_inert(text: str) -> None:
    assert "\x1b" not in text
    assert "\x07" not in text


def test_r2_import_failure_notice_is_inert(tmp_path, monkeypatch, capsys):
    import packages.ghidra.objdump_import as objdump_import
    import packages.ghidra.r2_import as r2_import
    from packages.ghidra.model import REDatabase, REFunction

    mod = _load_cli()
    binary = tmp_path / "app.bin"
    binary.write_bytes(b"\x7fELF")

    def _raise(_b):
        raise RuntimeError(_ESC_PAYLOAD)

    db = REDatabase(
        source_tool="objdump", binary_path=str(binary),
        architecture="x86:64",
        functions=[REFunction(name="main", address=0x1000, size=16)],
    )
    monkeypatch.setattr(r2_import, "r2_available", lambda: True)
    monkeypatch.setattr(r2_import, "import_binary_r2", _raise)
    monkeypatch.setattr(
        objdump_import, "import_binary_objdump", lambda b: db)

    rc = mod._import_binary_fallback(binary, tmp_path / "out")
    assert rc == 0
    err = capsys.readouterr().err
    assert "r2 import failed" in err
    _assert_inert(err)


def _decompile_args(tmp_path: Path) -> argparse.Namespace:
    gpr = tmp_path / "proj.gpr"
    gpr.write_text("")
    return argparse.Namespace(
        gpr=gpr, function="main", program=None, timeout=5)


def test_decompile_server_failure_notice_is_inert(
        tmp_path, monkeypatch, capsys):
    import packages.ghidra.context_inject as context_inject
    import packages.ghidra.detect as detect
    import packages.ghidra.server as server

    mod = _load_cli()

    class _BoomServer:
        def __init__(self, *a, **kw):
            raise RuntimeError(_ESC_PAYLOAD)

    monkeypatch.setattr(context_inject, "_load_cached_redb",
                        lambda gpr: None)
    monkeypatch.setattr(detect, "pyghidra_available", lambda: True)
    monkeypatch.setattr(detect, "prefer_in_process", lambda: False)
    monkeypatch.setattr(server, "GhidraServer", _BoomServer)

    rc = mod._cmd_decompile(_decompile_args(tmp_path))
    assert rc == 1
    err = capsys.readouterr().err
    assert "decompile server failed" in err
    _assert_inert(err)


def test_decompile_inprocess_failure_notice_is_inert(
        tmp_path, monkeypatch, capsys):
    import packages.ghidra.context_inject as context_inject
    import packages.ghidra.detect as detect
    import packages.ghidra.session as session

    mod = _load_cli()

    class _BoomSession:
        def __init__(self, *a, **kw):
            raise session.GhidraSessionError(_ESC_PAYLOAD)

    monkeypatch.setattr(context_inject, "_load_cached_redb",
                        lambda gpr: None)
    monkeypatch.setattr(detect, "pyghidra_available", lambda: False)
    monkeypatch.setattr(detect, "prefer_in_process", lambda: False)
    monkeypatch.setattr(session, "GhidraSession", _BoomSession)

    rc = mod._cmd_decompile(_decompile_args(tmp_path))
    assert rc == 1
    err = capsys.readouterr().err
    assert "in-process decompiler unavailable" in err
    _assert_inert(err)
