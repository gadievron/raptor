"""Doctrine fence for the engagement supervisor.

The supervisor is unattended sequencing machinery: it reserves,
reconciles, parks, and reports — it never analyses, never spawns,
never asks. Six doctrine rows are pinned here, independent of the
unit battery's placement:

  1. **No LLM anywhere** — the supervisor module never imports an
     LLM/dispatch/prompt seam. One named exception:
     ``core.llm.detection`` for the models-config PATH helper alone
     (the M6 code pin hashes the config bytes; nothing is sent
     anywhere), and only that name may be imported from it. The bare
     parent package (``import core`` / ``from core import x``) is
     banned outright — it reaches every seam as attributes.
  2. **No process spawning at all** — unlike the chain (which owns
     one audited seam), the supervisor has NO subprocess story:
     every child ride goes through ``chain_elf``. ``subprocess`` in
     any import spelling is banned, as is any ``os`` name or
     attribute call that spawns (``system``/``popen``/``fdopen``
     plus anything containing ``exec``/``spawn``/``fork`` —
     substring, so ``posix_spawn`` counts).
  3. **No fence-evading calls** — no dynamic import (``importlib``
     in any spelling, ``__import__``), no code execution, and no
     attribute laundering (``getattr``/``setattr``/``delattr``/
     ``vars``/``globals``/``locals`` are banned names: a
     concatenated-string ``getattr(os, 'sys' + 'tem')`` walks around
     any name gate).
  4. **Parks, never prompts** — the supervisor is cron-schedulable
     unattended machinery; ``input()`` (or any tty prompt) is banned.
     A decision it cannot make alone becomes a park.
  5. **Store writes stay atomic** — JSON leaves through
     ``save_json``, the interim report through
     ``write_text_atomically``. The supervisor performs NO direct
     ``open()`` at all (read or write, name or attribute form —
     ``Path.open`` and ``os.open`` included), and no
     ``write_text``/``write_bytes``. Ledger writes go through the
     ledger's public verbs only.
  6. **Launcher preamble** — ``libexec/raptor-engage-supervise``
     carries the trust-marker gate and the ``process_init`` import
     like every other dispatch script.

All rows are mechanical AST/source proofs — no repo imports, no
toolchain; they run on any CI runner with the checkout alone. The
evasion self-test below feeds known fence-walking payloads through
the same checkers to prove each is caught.

ACCEPTED STATIC GAPS (named, not silently open): a syntactic fence
does not chase dataflow. Laundering a callable through a container
(``[getattr][0]`` is caught, ``{'g': some_alias}`` rebinding is
not), ``operator.attrgetter``, reaching builtins via
``__builtins__``-style dunder walks, or an ALLOWED import
(``chain_elf``, ``governor``, the ledger verbs) re-exporting a
banned seam are out of AST reach. Those are owned by review of the
allowed modules' own fences and the unit battery's behavioral
checks, not by this file.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

MODULE_PATH = REPO_ROOT / "core" / "engagement" / "supervise.py"
LAUNCHER_PATH = REPO_ROOT / "libexec" / "raptor-engage-supervise"

#: Import prefixes that would put the LLM (or any dispatch seam that
#: reaches one) inside the supervisor. Substring "llm" additionally
#: catches renamed homes, with the one named path-helper exception.
_FORBIDDEN_IMPORT_PREFIXES = (
    "core.llm", "core.dispatch", "packages.llm",
    "core.security.prompt", "core.recall",
)

#: The single LLM-adjacent exception: the models-config path helper
#: feeding the M6 pin hash. Only this module, only this name.
_PIN_HASH_MODULE = "core.llm.detection"
_PIN_HASH_NAMES = {"_models_config_path"}

#: Module roots banned in the ``import X`` form. ``core`` is here
#: because a bare ``import core`` reaches every seam as attribute
#: access — the supervisor imports specific names from specific
#: submodules only.
_FORBIDDEN_IMPORT_ROOTS = {"subprocess", "importlib", "pkgutil", "core"}

#: Module roots banned in the ``from X import ...`` form (``core``
#: is handled separately: ``from core import x`` is banned, deeper
#: ``from core.engagement import ...`` is the audited path).
_FORBIDDEN_FROM_ROOTS = {"subprocess", "importlib", "pkgutil"}

#: ``os`` names that spawn or hand-write, in from-import or
#: attribute-call form. Substrings so ``posix_spawn``/``execvpe``/
#: ``register_at_fork`` all count.
_SPAWNY_SUBSTRINGS = ("exec", "spawn", "fork")
_SPAWNY_EXACT = {"system", "popen", "fdopen"}

#: Builtins whose CALL evades a syntactic fence: dynamic import,
#: code execution, attribute laundering, and the prompt ban (rule 4).
_FORBIDDEN_NAME_CALLS = {
    "__import__", "eval", "exec", "compile",
    "getattr", "setattr", "delattr", "vars", "globals", "locals",
    "input", "breakpoint",
}

#: Attribute calls banned outright wherever the receiver came from —
#: alias tracking is exactly what an evader defeats, so the ban is
#: unconditional. ``open`` covers ``Path(p).open('w')`` and
#: ``os.open(p, O_WRONLY)`` in one stroke; the supervisor performs
#: no direct file opens at all by design.
_FORBIDDEN_ATTR_CALLS = {"open", "write_text", "write_bytes",
                         "import_module", "system", "popen",
                         "fdopen"}


def _is_spawny(name: str) -> bool:
    low = name.lower()
    return (low in _SPAWNY_EXACT
            or any(s in low for s in _SPAWNY_SUBSTRINGS))


def _import_violations(tree: ast.Module) -> list[str]:
    """Rule 1 + the import half of rules 2/3."""
    bad: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _FORBIDDEN_IMPORT_ROOTS:
                    bad.append(f"import {alias.name} (banned root "
                               f"{root!r})")
                if "llm" in alias.name.lower():
                    bad.append(f"import {alias.name} (LLM-adjacent)")
                if any(alias.name == p
                       or alias.name.startswith(p + ".")
                       for p in _FORBIDDEN_IMPORT_PREFIXES):
                    bad.append(f"import {alias.name} (forbidden "
                               f"seam)")
        elif isinstance(node, ast.ImportFrom) and node.module:
            name = node.module
            if name == _PIN_HASH_MODULE:
                bad.extend(
                    f"from {name} import {alias.name} (only the "
                    f"models-config path helper is allowed)"
                    for alias in node.names
                    if alias.name not in _PIN_HASH_NAMES)
                continue
            if name == "core":
                bad.append(f"from core import "
                           f"{', '.join(a.name for a in node.names)}"
                           " (bare parent package)")
            if name.split(".")[0] in _FORBIDDEN_FROM_ROOTS:
                bad.append(f"from {name} import ... (banned root)")
            if any(name == p or name.startswith(p + ".")
                   for p in _FORBIDDEN_IMPORT_PREFIXES):
                bad.append(f"from {name} import ... (forbidden seam)")
            if "llm" in name.lower():
                bad.append(f"from {name} import ... (LLM-adjacent)")
            if name == "os":
                bad.extend(
                    f"from os import {alias.name} (spawning/"
                    f"hand-writing os name)"
                    for alias in node.names
                    if _is_spawny(alias.name) or alias.name == "open")
    return bad


def _call_violations(tree: ast.Module) -> list[str]:
    """Rules 2/3/4/5, call half: spawning attributes, fence-evading
    builtins, prompts, and hand file writes."""
    bad: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            if node.func.id in _FORBIDDEN_NAME_CALLS:
                bad.append(f"{node.func.id}(...) (fence-evading "
                           f"builtin / prompt)")
            if node.func.id == "open":
                bad.append("open(...) (supervisor performs no "
                           "direct file opens)")
        elif isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr in _FORBIDDEN_ATTR_CALLS:
                bad.append(f".{attr}(...) (banned attribute call)")
            elif _is_spawny(attr):
                bad.append(f".{attr}(...) (spawning attribute)")
    return bad


def _all_violations(tree: ast.Module) -> list[str]:
    return _import_violations(tree) + _call_violations(tree)


def _module_ast() -> ast.Module:
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"))


def test_no_llm_dispatch_or_banned_import() -> None:
    assert _import_violations(_module_ast()) == []


def test_no_spawn_dynamic_import_prompt_or_hand_write_call() -> None:
    assert _call_violations(_module_ast()) == []


def test_store_writes_are_atomic() -> None:
    """The write seams the call fence enforces negatively, positively:
    JSON via ``save_json``, the interim report via
    ``write_text_atomically``, mutation under the artifact lock."""
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert "save_json(" in source
    assert "write_text_atomically(" in source
    assert "artifact_lock(" in source  # state/registry writes hold it


def test_ledger_writes_go_through_the_public_api() -> None:
    """The supervisor touches the ledger only via its public verbs —
    never a private seam, never a direct rewrite of ledger.json."""
    allowed_ledger = {
        "append_policy_amendment", "append_residual", "is_artifact_id",
        "load_ledger", "render_status_lines", "set_artifact_policy",
        "set_artifact_status", "update_engagement_policy",
    }
    allowed_siblings = {"chain_elf", "governor"}
    for node in ast.walk(_module_ast()):
        if not (isinstance(node, ast.ImportFrom) and node.module):
            continue
        if node.module == "core.engagement":
            for alias in node.names:
                assert alias.name in allowed_siblings, (
                    f"supervisor imports an unexpected engagement "
                    f"module: {alias.name}")
        elif node.module.startswith("core.engagement."):
            assert node.module == "core.engagement.ledger", (
                f"supervisor deep-imports {node.module} — sibling "
                "modules come in whole")
            for alias in node.names:
                assert alias.name in allowed_ledger, (
                    f"supervisor imports a non-public ledger seam: "
                    f"{alias.name}")


def test_launcher_preamble_present() -> None:
    source = LAUNCHER_PATH.read_text(encoding="utf-8")
    assert "CLAUDECODE" in source and "_RAPTOR_TRUSTED" in source, (
        "launcher lost the trust-marker gate")
    assert "import core.startup.process_init" in source, (
        "launcher lost the process_init import")
    assert LAUNCHER_PATH.stat().st_mode & 0o111, (
        "launcher must be executable")


#: Known fence-walking payloads. Each is appended to the REAL module
#: source and must trip at least one checker — the same experiment a
#: by-hand evasion probe runs, pinned so a fence loosening fails CI.
_EVASION_PAYLOADS = {
    "parent_package_attribute": (
        "\n\nimport core\ndef _evade():\n"
        "    return core.llm.detection.detect_models()\n"),
    "from_core_import_llm": (
        "\n\nfrom core import llm as _l\ndef _evade():\n"
        "    return _l.detection\n"),
    "aliased_import_module": (
        "\n\nfrom importlib import import_module as _im\n"
        "def _evade():\n"
        "    return _im('subp' + 'rocess').run(['id'])\n"),
    "getattr_concatenated": (
        "\n\nimport os as _o\ndef _evade():\n"
        "    return getattr(_o, 'sys' + 'tem')('id')\n"),
    "open_keyword_mode": (
        "\n\ndef _evade(p):\n    with open(p, mode='w') as f:\n"
        "        f.write('x')\n"),
    "path_open_write": (
        "\n\ndef _evade(p):\n    with Path(p).open('w') as f:\n"
        "        f.write('x')\n"),
    "os_open_write_flags": (
        "\n\nimport os as _o7\ndef _evade(p):\n"
        "    fd = _o7.open(p, _o7.O_WRONLY | _o7.O_CREAT)\n"
        "    _o7.write(fd, b'x')\n    _o7.close(fd)\n"),
    "from_os_import_posix_spawn": (
        "\n\nfrom os import posix_spawn as _ps\ndef _evade():\n"
        "    return _ps('/usr/bin/id', ['id'], {})\n"),
    "pkgutil_resolve_name": (
        "\n\nimport pkgutil as _pk\ndef _evade():\n"
        "    return _pk.resolve_name('subprocess:run')(['true'])\n"),
}


@pytest.mark.parametrize("shape", sorted(_EVASION_PAYLOADS))
def test_fence_catches_known_evasion_shapes(shape: str) -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source + _EVASION_PAYLOADS[shape])
    assert _all_violations(tree), (
        f"evasion shape {shape!r} walked through the fence — a rule "
        "was loosened")
