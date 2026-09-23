"""raptor-ghidra engine-fallback import writes its artifact atomically.

The fallback lane wrote re-database.json via bare json.dump while
raptor-build-checklist routes the same artifact through the atomic
save_json chokepoint — a crash mid-dump left a torn database every
later reader rejects.
"""

from __future__ import annotations

import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-ghidra"


def _load_cli():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    loader = SourceFileLoader("raptor_ghidra_cli_fallback", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_fallback_import_writes_via_atomic_chokepoint(
        tmp_path, monkeypatch):
    import core.json as core_json
    import packages.ghidra.objdump_import as objdump_import
    import packages.ghidra.r2_import as r2_import
    from packages.ghidra.model import REDatabase, REFunction

    mod = _load_cli()
    binary = tmp_path / "app.bin"
    binary.write_bytes(b"\x7fELF")
    out_dir = tmp_path / "out"

    db = REDatabase(
        source_tool="objdump", binary_path=str(binary),
        architecture="x86:64",
        functions=[REFunction(name="main", address=0x1000, size=16)],
    )
    monkeypatch.setattr(r2_import, "r2_available", lambda: False)
    monkeypatch.setattr(
        objdump_import, "import_binary_objdump", lambda b: db)

    atomic_writes: list[Path] = []
    real_save = core_json.save_json

    def spy_save(path, data, *a, **k):
        atomic_writes.append(Path(path))
        return real_save(path, data, *a, **k)

    monkeypatch.setattr(core_json, "save_json", spy_save)

    rc = mod._import_binary_fallback(binary, out_dir)
    assert rc == 0
    out_path = out_dir / "re-database.json"
    assert out_path in atomic_writes
    written = json.loads(out_path.read_text())
    assert written["binary_path"] == str(binary)
    assert written["functions"][0]["name"] == "main"
