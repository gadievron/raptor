"""Binary-item sweeps error when no decompilation is available.

The heap-copy / integer-truncation-family branches used to fall
through with source="" when the RE database (or the function's
decompilation) was missing — the detector then logged a vacuous
outcome for code that exists in the binary. The rule-file branch
already errored; all three now share one extraction helper and the
same contract.
"""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_bindecomp", str(_SCRIPT))
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_bindecomp", loader,
    )
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _sweep_args(out_dir: Path, target: Path, tool: str) -> SimpleNamespace:
    return SimpleNamespace(
        out=str(out_dir), target=str(target),
        file="binary:app", function="parse_hdr",
        tool=tool, rule=None, rule_file=None,
        query=None, result_file=None, outcome=None, cwe=None,
        line_start=None, line_end=None,
    )


def _setup(tmp_path: Path, *, with_redb: bool):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    target = tmp_path / "app.bin"
    target.write_bytes(b"\x7fELF")
    if with_redb:
        from packages.ghidra.model import REDatabase, REFunction
        db = REDatabase(
            source_tool="test", binary_path=str(target),
            architecture="x86:64",
            functions=[REFunction(
                name="parse_hdr", address=0x1000, size=16,
                decompilation=(
                    "int parse_hdr(char *p) {\n"
                    "  char buf[8];\n"
                    "  memcpy(buf, p, 64);\n"
                    "  return buf[0];\n"
                    "}\n"
                ),
            )],
        )
        (out_dir / "re-database.json").write_text(json.dumps(db.to_dict()))
    return out_dir, target


def test_heap_copy_errors_without_decompilation(tmp_path, capsys):
    mod = _load_cli()
    out_dir, target = _setup(tmp_path, with_redb=False)
    rc = mod.cmd_sweep(_sweep_args(out_dir, target, "heap-copy"))
    captured = capsys.readouterr()
    assert rc == 1
    assert "no decompilation available" in captured.err
    # No vacuous sweep receipt reached the audit log.
    from core.audit.record import load_audit_log
    assert not [e for e in load_audit_log(out_dir)
                if e.get("action") == "sweep"]


def test_integer_truncation_errors_without_decompilation(tmp_path, capsys):
    mod = _load_cli()
    out_dir, target = _setup(tmp_path, with_redb=False)
    rc = mod.cmd_sweep(_sweep_args(out_dir, target, "integer-truncation"))
    captured = capsys.readouterr()
    assert rc == 1
    assert "no decompilation available" in captured.err


def test_heap_copy_sweeps_available_decompilation(tmp_path, capsys):
    # Two-direction: with a decompilation present the sweep runs and
    # logs a receipt as before.
    mod = _load_cli()
    out_dir, target = _setup(tmp_path, with_redb=True)
    rc = mod.cmd_sweep(_sweep_args(out_dir, target, "heap-copy"))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    from core.audit.record import load_audit_log
    sweeps = [e for e in load_audit_log(out_dir)
              if e.get("action") == "sweep"]
    assert len(sweeps) == 1
    assert sweeps[0]["tool"].startswith("heap-copy")


def test_sanitiser_failure_is_fail_closed(tmp_path, capsys, monkeypatch):
    """A decompilation crafted to crash the sanitiser must not re-open
    the raw channel — the item is skipped (None), matching the file's
    refusal contracts."""
    import core.audit.decompiler_sanitise as ds

    mod = _load_cli()
    out_dir, target = _setup(tmp_path, with_redb=True)

    def boom(source):
        raise RuntimeError("hostile decompilation broke the sanitiser")

    monkeypatch.setattr(ds, "sanitise", boom)
    result = mod._binary_decompilation(out_dir, target, "parse_hdr")
    assert result is None
    err = capsys.readouterr().err
    assert "sanitisation failed" in err
    assert "refusing the raw decompilation" in err


def test_sanitised_decompilation_still_returned(tmp_path):
    mod = _load_cli()
    out_dir, target = _setup(tmp_path, with_redb=True)
    result = mod._binary_decompilation(out_dir, target, "parse_hdr")
    assert result is not None
    assert "memcpy" in result
