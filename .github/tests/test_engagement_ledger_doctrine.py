"""Doctrine fence for the engagement artifact ledger.

The ledger is a privilege-adjacent store: its rows steer which
artifacts later engagement stages spend on, its checklist slots are
coverage denominators, and most of its bytes originate in a hostile
target. Four doctrine rows are pinned here, independent of the unit
battery's placement:

  1. **No LLM anywhere near classification** — the ledger module must
     never import an LLM/dispatch/prompt seam, and must not spawn
     processes or open sockets itself (its only subprocess exposure
     is the sealed identity front door it calls).
  2. **derived_from_target coverage (M1)** — every row leaves the
     builder through the one ``_finish_row`` seam that stamps
     ``derived_from_target``; writes go through ``save_json``
     (atomic) under ``core.fs_lock.artifact_lock``, never a hand
     ``open(..., "w")``.
  3. **Identity-collision demotion (M2)** — two artifacts sharing a
     producer-authored identity value with different content demote
     to content-hash identity, both flagged elevated interest.
  4. **Caps in both directions (S14)** — a compliant archive is NOT
     truncated; an over-cap archive IS, with an explicit
     "truncated at N of M" residual and a remainder row.

Rows 1–2 are mechanical AST/source proofs; rows 3–4 are compact
behavioral proofs over crafted files (stdlib-only fixtures; the
sandboxed build-id probe is stubbed, so no toolchain is required —
runs on any CI runner with the repo checkout alone).
"""

from __future__ import annotations

import ast
import io
import sys
import zipfile
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

LEDGER_PATH = REPO_ROOT / "core" / "engagement" / "ledger.py"

#: Import prefixes that would put the LLM (or any dispatch seam that
#: reaches one) inside classification. Substring "llm" additionally
#: catches renamed homes.
_FORBIDDEN_IMPORT_PREFIXES = (
    "core.llm", "core.dispatch", "packages.llm",
    "core.security.prompt", "core.recall",
)
#: The ledger classifies; it never executes or talks to a network
#: itself. (Subprocess use lives behind the sealed identity front
#: door / sandboxed helpers it calls, which carry their own gates.)
_FORBIDDEN_MODULES = ("subprocess", "socket", "urllib", "requests",
                      "http")


def _module_ast() -> ast.Module:
    return ast.parse(LEDGER_PATH.read_text(encoding="utf-8"))


def _all_imports(tree: ast.Module) -> list[str]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def test_no_llm_or_dispatch_import() -> None:
    imports = _all_imports(_module_ast())
    for name in imports:
        assert not any(
            name == p or name.startswith(p + ".")
            for p in _FORBIDDEN_IMPORT_PREFIXES
        ), f"ledger imports a classification-forbidden seam: {name}"
        assert "llm" not in name.lower(), (
            f"ledger imports an LLM-adjacent module: {name}")


def test_no_process_or_network_module() -> None:
    imports = _all_imports(_module_ast())
    for name in imports:
        top = name.split(".")[0]
        assert top not in _FORBIDDEN_MODULES, (
            f"ledger must stay pure-mechanical; imports {name}")


#: Bare-name calls that evade the import fences (dynamic import, code
#: execution) — none has a legitimate use in a mechanical classifier.
_FORBIDDEN_NAME_CALLS = {"__import__", "eval", "exec", "compile"}
#: Attribute calls that evade them: ``importlib.import_module`` (a
#: plain ``import importlib`` passes the module fence), ``os.system``
#: / ``os.popen`` / ``os.exec*`` / ``os.spawn*`` (``os`` is a
#: legitimately imported module), and ``Path.write_text`` /
#: ``write_bytes`` (a store write that would bypass the atomic
#: ``save_json`` seam).
_FORBIDDEN_ATTR_CALLS = {"import_module", "system", "popen",
                         "write_text", "write_bytes"}
_FORBIDDEN_ATTR_PREFIXES = ("exec", "spawn")


def test_no_dynamic_import_exec_or_raw_write_call() -> None:
    for node in ast.walk(_module_ast()):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            assert node.func.id not in _FORBIDDEN_NAME_CALLS, (
                f"ledger calls a fence-evading builtin: {node.func.id}")
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            assert attr not in _FORBIDDEN_ATTR_CALLS, (
                f"ledger calls a fence-evading attribute: .{attr}(...)")
            assert not attr.startswith(_FORBIDDEN_ATTR_PREFIXES), (
                f"ledger calls a process-spawning attribute: .{attr}(...)")


def test_every_row_leaves_through_the_stamping_seam() -> None:
    """Every mutation that can put a row into ``self.rows`` — append,
    extend, insert, ``+=``, slice/index assignment — lives inside
    ``_finish_row`` (construction aside: ``__init__`` creates the empty
    list), and ``_finish_row`` stamps ``derived_from_target`` first —
    so no row can reach the store unstamped."""
    tree = _module_ast()
    builder = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "_Builder")
    sites: list[tuple[str, str]] = []

    def _is_rows_attr(node: ast.AST) -> bool:
        return (isinstance(node, ast.Attribute)
                and node.attr == "rows")

    for method in builder.body:
        if not isinstance(method, ast.FunctionDef):
            continue
        for node in ast.walk(method):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("append", "extend", "insert",
                                           "__iadd__")
                    and _is_rows_attr(node.func.value)):
                sites.append((f".{node.func.attr}", method.name))
            if (isinstance(node, ast.AugAssign)
                    and (_is_rows_attr(node.target)
                         or (isinstance(node.target, ast.Subscript)
                             and _is_rows_attr(node.target.value)))):
                sites.append(("+=", method.name))
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (_is_rows_attr(target)
                            and method.name != "__init__"):
                        sites.append(("=", method.name))
                    if (isinstance(target, ast.Subscript)
                            and _is_rows_attr(target.value)):
                        sites.append(("[...]=", method.name))
    assert sites and all(
        kind == ".append" and owner == "_finish_row"
        for kind, owner in sites
    ), f"rows mutation escaped the stamping seam: {sites}"
    finish = next(m for m in builder.body
                  if isinstance(m, ast.FunctionDef)
                  and m.name == "_finish_row")
    called = {
        node.func.id
        for node in ast.walk(finish)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "_stamp_derived" in called


def test_store_writes_are_atomic_and_locked() -> None:
    """No hand-rolled text writes; the store writers hold the sibling
    flock around every save."""
    tree = _module_ast()
    source = LEDGER_PATH.read_text(encoding="utf-8")
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "open"):
            for arg in node.args[1:]:
                if isinstance(arg, ast.Constant) and "w" in str(arg.value):
                    raise AssertionError(
                        "ledger writes must go through save_json "
                        "(atomic), not open(..., 'w')")
    assert "artifact_lock(" in source
    assert "save_json(" in source


def _write_minimal_elf(path: Path) -> None:
    import struct
    path.write_bytes(
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        + struct.pack("<HHIQQQIHHHHHH",
                      3, 0x3E, 1, 0, 0, 0, 0, 64, 0, 0, 64, 0, 0)
        + path.name.encode())          # distinct content per file


def test_identity_collision_demotes_to_content_hash(tmp_path) -> None:
    import core.binary.elf as elf_mod
    from core.binary.identity import ContentIdentity
    from core.engagement import ledger as ledger_mod

    target = tmp_path / "install"
    target.mkdir()
    _write_minimal_elf(target / "one")
    _write_minimal_elf(target / "two")
    forged = "cd" * 20
    with mock.patch.object(
        ledger_mod, "content_identity",
        lambda path, **kw: ContentIdentity(
            "elf_build_id", forged, forged[:16]),
    ), mock.patch.object(elf_mod, "_read_build_id",
                         lambda p: (None, None)):
        doc = ledger_mod.build_ledger(target, tmp_path / "out")
    rows = [r for r in doc["rows"] if r["class"].startswith("elf")]
    assert len(rows) == 2
    for row in rows:
        assert row["identity"]["kind"] == "sha256"
        assert row["elevated_interest"] is True
    assert len({r["artifact_id"] for r in rows}) == 2
    assert doc["collisions"] and (
        doc["collisions"][0]["identity_kind"] == "elf_build_id")


def _zip_with(n: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(n):
            zf.writestr(f"member_{i}.txt", b"x" * 16)
    return buf.getvalue()


def test_archive_caps_cut_both_ways(tmp_path) -> None:
    import core.binary.elf as elf_mod
    from core.engagement import ledger as ledger_mod

    with mock.patch.object(elf_mod, "_read_build_id",
                           lambda p: (None, None)):
        ok_target = tmp_path / "ok"
        ok_target.mkdir()
        (ok_target / "small.zip").write_bytes(_zip_with(3))
        ok_doc = ledger_mod.build_ledger(
            ok_target, tmp_path / "ok-out",
            caps=ledger_mod.LedgerCaps(max_archive_children=10))
        assert not any(r["kind"] == "archive_truncated"
                       for r in ok_doc["residuals"])
        assert not any(r["class"] == "archive-remainder"
                       for r in ok_doc["rows"])
        assert any(r["path"] == "member_0.txt"
                   or (r.get("family") or {}).get("member_count")
                   for r in ok_doc["rows"])

        big_target = tmp_path / "big"
        big_target.mkdir()
        (big_target / "big.zip").write_bytes(_zip_with(6))
        big_doc = ledger_mod.build_ledger(
            big_target, tmp_path / "big-out",
            caps=ledger_mod.LedgerCaps(max_archive_children=2))
        residual = next(r for r in big_doc["residuals"]
                        if r["kind"] == "archive_truncated")
        assert "of 6 members" in residual["message"]
        assert any(r["class"] == "archive-remainder"
                   for r in big_doc["rows"])


def test_render_paths_escape_target_bytes(tmp_path) -> None:
    import core.binary.elf as elf_mod
    from core.engagement import ledger as ledger_mod

    target = tmp_path / "install"
    target.mkdir()
    (target / "evil\x1b[31m.dat").write_bytes(b"data")
    out = tmp_path / "out"
    with mock.patch.object(elf_mod, "_read_build_id",
                           lambda p: (None, None)):
        doc = ledger_mod.build_ledger(target, out)
    for line in ledger_mod.render_status_lines(doc, out):
        assert all(c.isprintable() for c in line), repr(line)
    for row in doc["rows"]:
        for line in ledger_mod.render_artifact_lines(row):
            assert all(c.isprintable() for c in line), repr(line)
