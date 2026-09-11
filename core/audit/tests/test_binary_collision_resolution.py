"""Collision-suffixed binary function names resolve by address.

Checklist names carry an ``@0xADDR`` suffix precisely when several
binary functions share a name. Every sweep branch that maps a checklist
item back to the RE database must resolve those by address — stripping
the suffix and taking the first namesake can silently analyse (and
receipt) a different function than the one the item denotes.
"""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_bincol", str(_SCRIPT))
    spec = importlib.util.spec_from_loader("raptor_audit_cli_bincol", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _fake_db():
    return SimpleNamespace(functions=[
        SimpleNamespace(
            name="parse", address=0x401000,
            decompilation="int parse(void) { return 1; }",
        ),
        SimpleNamespace(
            name="parse", address=0x402000,
            decompilation="int parse(void) { return 2; }",
        ),
    ])


class TestResolveBinaryFunction:
    def test_suffixed_name_resolves_by_address(self):
        mod = _load_cli()
        f = mod._resolve_binary_function(_fake_db(), "parse@0x402000")
        assert f is not None
        assert f.address == 0x402000

    def test_bare_name_resolves_by_name(self):
        mod = _load_cli()
        f = mod._resolve_binary_function(_fake_db(), "parse")
        assert f is not None
        assert f.address == 0x401000

    def test_unknown_address_returns_none_not_a_namesake(self):
        mod = _load_cli()
        assert mod._resolve_binary_function(_fake_db(), "parse@0x999999") is None

    def test_malformed_suffix_falls_back_to_full_name(self):
        db = _fake_db()
        db.functions.append(SimpleNamespace(
            name="odd@0xzz", address=0x403000, decompilation="x",
        ))
        mod = _load_cli()
        f = mod._resolve_binary_function(db, "odd@0xzz")
        assert f is not None
        assert f.address == 0x403000


def _sweep_args(out_dir: Path, target: Path, function: str,
                file_path: str) -> SimpleNamespace:
    return SimpleNamespace(
        out=str(out_dir),
        target=str(target),
        file=file_path,
        function=function,
        tool="heap-copy",
        rule=None,
        rule_file=None,
        query=None,
        result_file=None,
        outcome=None,
        cwe="CWE-787",
        line_start=None,
        line_end=None,
        smt_verb=None,
        smt_args=None,
        codeql_db=None,
    )


def test_heap_copy_sweep_uses_address_resolution(tmp_path, monkeypatch):
    """End-to-end through cmd_sweep: a suffixed name must feed the
    decompilation of the function at that address to the checker."""
    mod = _load_cli()
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    target = tmp_path / "bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 12)

    import core.audit.binary_context as binary_context
    monkeypatch.setattr(binary_context, "find_redb",
                        lambda out, tgt: tmp_path / "re-database.json")
    monkeypatch.setattr(binary_context, "load_redb", lambda p: _fake_db())

    seen: dict[str, str] = {}

    def fake_heap_copy(*, file_path, function_name, source, cwe):
        seen["source"] = source
        return SimpleNamespace(
            outcome="refuted", matches=[], errors=[],
            to_log_entry=lambda: {
                "action": "sweep", "key": f"{file_path}:{function_name}",
                "file": file_path, "function": function_name,
                "tool": "heap-copy", "outcome": "refuted",
            },
        )

    import core.audit.sweep as sweep_mod
    monkeypatch.setattr(sweep_mod, "run_heap_copy_sweep", fake_heap_copy)

    from core.inventory.binary_builder import BINARY_PATH_PREFIX
    args = _sweep_args(
        out_dir, target, "parse@0x402000", f"{BINARY_PATH_PREFIX}parse",
    )
    rc = mod.cmd_sweep(args)
    assert rc == 0
    assert "return 2" in seen["source"]
    assert "return 1" not in seen["source"]
