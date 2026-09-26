"""Doctrine fence for the ELF engagement chain.

The chain sequences LLM-calling children (study, audit, seed
re-review) but must never classify with one itself: its verdicts come
from journal VERDICT rows and file existence alone. Five doctrine
rows are pinned here, independent of the unit battery's placement:

  1. **No LLM anywhere near classification** — the chain module never
     imports an LLM/dispatch/prompt seam (the LLM work happens in
     children behind their own gates).
  2. **One subprocess seam** — every ``subprocess`` touch and every
     env selection (``get_safe_env`` / ``get_llm_env``) lives inside
     ``_run_child``; no ``shell=True``, no ``os.system``/``popen``/
     ``exec*``/``spawn*`` anywhere. ``from subprocess import ...``
     and ``from os import system/exec*/spawn*/popen`` are banned too
     — bare names would evade the attribute census.
  3. **No fence-evading calls** — no dynamic import or code
     execution.
  4. **Store writes stay atomic** — JSON artifacts leave through
     ``save_json``; no hand ``open(..., "w")`` / ``write_text``
     (``write_bytes`` never on a JSON store).
  5. **Launcher preamble** — ``libexec/raptor-engage-chain`` carries
     the trust-marker gate and the ``process_init`` import like every
     other dispatch script.

All rows are mechanical AST/source proofs — no repo imports, no
toolchain; they run on any CI runner with the checkout alone.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

CHAIN_PATH = REPO_ROOT / "core" / "engagement" / "chain_elf.py"
LAUNCHER_PATH = REPO_ROOT / "libexec" / "raptor-engage-chain"

#: Import prefixes that would put the LLM (or any dispatch seam that
#: reaches one) inside the sequencing/verdict layer. Substring "llm"
#: additionally catches renamed homes.
_FORBIDDEN_IMPORT_PREFIXES = (
    "core.llm", "core.dispatch", "packages.llm",
    "core.security.prompt", "core.recall",
)


def _module_ast() -> ast.Module:
    return ast.parse(CHAIN_PATH.read_text(encoding="utf-8"))


def _all_imports(tree: ast.Module) -> list[str]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def test_no_llm_or_dispatch_import() -> None:
    for name in _all_imports(_module_ast()):
        assert not any(
            name == p or name.startswith(p + ".")
            for p in _FORBIDDEN_IMPORT_PREFIXES
        ), f"chain imports a classification-forbidden seam: {name}"
        assert "llm" not in name.lower(), (
            f"chain imports an LLM-adjacent module: {name}")


def _functions(tree: ast.Module) -> list[ast.FunctionDef]:
    out: list[ast.FunctionDef] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            out.append(node)
    return out


def _owner_of(tree: ast.Module, target: ast.AST) -> str:
    """Name of the innermost function containing ``target``."""
    owner = "<module>"
    for fn in _functions(tree):
        for sub in ast.walk(fn):
            if sub is target:
                owner = fn.name  # innermost wins on later matches
    return owner


def test_subprocess_confined_to_the_single_seam() -> None:
    """Every ``subprocess.*`` attribute use and every env selection
    lives inside ``_run_child`` — the one place argv lists meet a
    sanitised environment. ``shell=True`` is banned outright.
    ``from subprocess import ...`` is banned too: a bare-name
    ``Popen`` would evade the ``subprocess.<attr>`` census below, so
    the module must import the module and dot into it."""
    tree = _module_ast()
    for node in ast.walk(tree):
        if (isinstance(node, ast.ImportFrom) and node.module
                and (node.module == "subprocess"
                     or node.module.startswith("subprocess."))):
            raise AssertionError(
                "'from subprocess import ...' evades the seam census "
                "— import the module and use subprocess.<attr> inside "
                "_run_child")
        if (isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "subprocess"):
            owner = _owner_of(tree, node)
            assert owner == "_run_child", (
                f"subprocess.{node.attr} escaped the seam "
                f"(in {owner})")
        if (isinstance(node, ast.Attribute)
                and node.attr in ("get_safe_env", "get_llm_env")):
            owner = _owner_of(tree, node)
            assert owner == "_run_child", (
                f".{node.attr} escaped the seam (in {owner})")
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "shell":
                    raise AssertionError(
                        "chain must never pass shell= to a spawn")


_FORBIDDEN_NAME_CALLS = {"__import__", "eval", "exec", "compile"}
_FORBIDDEN_ATTR_CALLS = {"import_module", "system", "popen"}
_FORBIDDEN_ATTR_PREFIXES = ("spawn",)


def test_no_dynamic_import_exec_or_shell_call() -> None:
    for node in ast.walk(_module_ast()):
        if isinstance(node, ast.ImportFrom) and node.module == "os":
            # ``from os import system/exec*/spawn*/popen`` would give
            # the banned calls bare names the attribute census below
            # cannot see.
            for alias in node.names:
                assert not (alias.name in ("system", "popen")
                            or alias.name.startswith(
                                ("exec", "spawn"))), (
                    f"chain imports a process-spawning os name: "
                    f"{alias.name}")
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            assert node.func.id not in _FORBIDDEN_NAME_CALLS, (
                f"chain calls a fence-evading builtin: {node.func.id}")
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            assert attr not in _FORBIDDEN_ATTR_CALLS, (
                f"chain calls a fence-evading attribute: .{attr}(...)")
            # ``os.exec*`` is banned; ``proc.wait``/``os.killpg`` are
            # the seam's legitimate process management.
            if (isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"):
                assert not attr.startswith(
                    ("exec",) + _FORBIDDEN_ATTR_PREFIXES), (
                    f"chain calls a process-spawning os.{attr}(...)")


def test_json_store_writes_are_atomic() -> None:
    """Artifacts leave through ``save_json`` (atomic tempfile+rename);
    never a hand text write. (``os.link``/``copy2`` move an EXISTING
    completed artifact — they create no partially-written JSON.)"""
    tree = _module_ast()
    source = CHAIN_PATH.read_text(encoding="utf-8")
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "open"):
            for arg in node.args[1:]:
                if (isinstance(arg, ast.Constant)
                        and "w" in str(arg.value)):
                    raise AssertionError(
                        "chain writes must go through save_json")
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("write_text", "write_bytes")):
            raise AssertionError(
                f"chain calls .{node.func.attr}(...) — store writes "
                "go through save_json")
    assert "save_json(" in source
    assert "artifact_lock(" in source  # chain-state writes hold it


def test_ledger_writes_go_through_the_public_api() -> None:
    """The chain touches the ledger only via its public write verbs —
    never a private seam, never a direct rewrite of ledger.json."""
    tree = _module_ast()
    allowed = {"STATUS_STATES", "checklist_slot_path", "load_ledger",
               "set_artifact_status", "write_artifact_checklist"}
    for node in ast.walk(tree):
        if (isinstance(node, ast.ImportFrom) and node.module
                and node.module.startswith("core.engagement")):
            for alias in node.names:
                assert alias.name in allowed, (
                    f"chain imports a non-public ledger seam: "
                    f"{alias.name}")


def test_launcher_preamble_present() -> None:
    source = LAUNCHER_PATH.read_text(encoding="utf-8")
    assert "CLAUDECODE" in source and "_RAPTOR_TRUSTED" in source, (
        "launcher lost the trust-marker gate")
    assert "import core.startup.process_init" in source, (
        "launcher lost the process_init import")
    assert LAUNCHER_PATH.stat().st_mode & 0o111, (
        "launcher must be executable")
