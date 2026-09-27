"""Doctrine fence for the engagement report + coverage synthesis.

The report module is PURE SYNTHESIS over artifacts the other layers
wrote — it renders verdicts, it never produces them. Six doctrine
rows are pinned here, independent of the unit battery's placement:

  1. **No LLM anywhere** — the report module never imports an LLM /
     dispatch / prompt seam. A report layer that could reach a model
     could reword an attestation; this one provably cannot.
  2. **No process spawning at all** — unlike the chain (which has one
     audited subprocess seam), the report has ZERO: no ``subprocess``
     import, no ``os.system``/``popen``/``exec*``/``spawn*``, no
     sockets. Synthesis reads files and writes two artifacts.
  3. **No fence-evading calls** — no dynamic import, no dynamic
     attribute fetch (``getattr``), no code execution, and no plain
     ``import X`` at all (every import is a from-import against an
     explicit name, so the census sees the full surface).
  4. **Writes stay atomic and are the report's own** — the JSON
     leaves through ``save_json`` and the markdown through
     ``write_text_atomically``, both under ``artifact_lock``; no hand
     ``open(...)`` in a write mode (positional OR keyword), no
     ``.open(...)`` at all, no ``.write_text`` / ``.write_bytes``,
     no ``os.open`` / ``os.write``.
  5. **Read-only over every substrate** — the import census pins the
     ledger / chain / journal / overlay seams to their READ verbs
     (``load_*`` / ``read_*`` / view functions / vocabulary
     constants), and imports from a seam's PARENT package are banned
     outright (``from core.coverage import journal`` would hand the
     whole module — including ``append_entry`` — to the report). A
     report that could reach ``append_entry`` or
     ``set_artifact_status`` could manufacture the coverage it then
     attests.
  6. **Escaping-closure registration** — the module is listed in
     ``core.security.report_writer_audit._REPORT_WRITER_FILES`` so
     the escaping-closure gate audits its LLM-derived free-text
     seams. That audit is vocabulary-driven and does NOT cover
     foreign-dict count/label values (a documented limitation in the
     audit module); those render seams are pinned by the report's
     own unit battery instead. The ``libexec/raptor-engage-report``
     launcher carries the standard trust-marker preamble.

All rows are mechanical AST/source proofs — no repo imports, no
toolchain; they run on any CI runner with the checkout alone. Each
census is also SELF-TESTED: the known evasion shapes (module-alias
imports, parent-package aliases, ``getattr`` fetches, keyword-mode /
``Path.open`` / ``os.open`` writes, ``pkgutil.resolve_name``) are
appended to the real module source and must each trip at least one
check — a census that stops catching its own corpus fails loudly.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

REPORT_PATH = REPO_ROOT / "core" / "engagement" / "report.py"
LAUNCHER_PATH = REPO_ROOT / "libexec" / "raptor-engage-report"
AUDIT_PATH = (REPO_ROOT / "core" / "security"
              / "report_writer_audit.py")

_FORBIDDEN_IMPORT_PREFIXES = (
    "core.llm", "core.dispatch", "packages.llm",
    "core.security.prompt", "core.recall",
)

#: Zero-spawn / zero-dynamic-load doctrine: modules the report must
#: never import at all (``pkgutil.resolve_name`` is a dynamic import
#: in a trenchcoat).
_FORBIDDEN_MODULES = ("subprocess", "socket", "importlib", "ctypes",
                      "pkgutil", "runpy")

#: ``getattr`` is banned alongside eval/exec: a dynamic attribute
#: fetch through an allowed seam module reaches its write verbs
#: without any import the census could see.
_FORBIDDEN_NAME_CALLS = {"eval", "exec", "compile", "__import__",
                         "getattr"}
_FORBIDDEN_ATTR_CALLS = {"system", "popen", "import_module",
                         "resolve_name"}

#: Substrate seams pinned to their read-only verbs (row 5). A module
#: listed here may import ONLY the named verbs from that seam, and
#: only via the seam's FULL module path.
_READ_ONLY_SEAMS = {
    "core.engagement.ledger": {
        "TIER_FULL", "is_artifact_id", "load_engagement_policy",
        "load_ledger", "load_policy_amendments",
        "read_artifact_checklist",
    },
    "core.engagement.chain_elf": {
        "SURVIVORS_FILENAME", "VERDICT_SCHEMA", "chain_dir_for",
        "load_chain_state",
    },
    "core.coverage.journal": {"VALID_VERDICTS",
                              "load_entries_checked"},
    "core.coverage.store_summary": {"coverage_view",
                                    "no_lane_residual"},
    "core.labeled_attempts.view": {"collect_outcomes"},
}

#: Write-mode characters for the open()/. open() mode-string checks.
_WRITE_MODE_CHARS = ("w", "a", "x", "+")


def _module_ast() -> ast.Module:
    return ast.parse(REPORT_PATH.read_text(encoding="utf-8"))


def _all_import_froms(tree: ast.Module) -> list[ast.ImportFrom]:
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.ImportFrom) and n.module]


# ── Census bodies (callable on any tree — the self-tests below run
#    them against known evasion payloads) ────────────────────────────

def _check_no_plain_imports(tree: ast.Module) -> None:
    """Row 3: every import must be a from-import of an explicit name.
    A plain ``import core.engagement.ledger`` (or ``import os as _x``)
    hands the report a whole module object whose write verbs no name
    census can see."""
    for node in ast.walk(tree):
        assert not isinstance(node, ast.Import), (
            "report uses a plain 'import X' — only explicit "
            "from-imports are allowed: "
            f"{', '.join(a.name for a in node.names)}")


def _check_forbidden_modules(tree: ast.Module) -> None:
    for node in _all_import_froms(tree):
        root = node.module.split(".")[0]
        assert root not in _FORBIDDEN_MODULES, (
            f"report imports a spawn/dynamic-load module: "
            f"{node.module}")
        assert root != "os", (
            "report imports names from os — synthesis needs no "
            "os-level primitives")


def _check_llm_import_ban(tree: ast.Module) -> None:
    for node in _all_import_froms(tree):
        name = node.module
        assert not any(
            name == p or name.startswith(p + ".")
            for p in _FORBIDDEN_IMPORT_PREFIXES
        ), f"report imports a classification-forbidden seam: {name}"
        assert "llm" not in name.lower(), (
            f"report imports an LLM-adjacent module: {name}")


def _check_no_os_calls(tree: ast.Module) -> None:
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"):
            assert not node.func.attr.startswith(
                ("exec", "spawn", "system", "popen", "open",
                 "write", "fdopen")), (
                f"report calls os.{node.func.attr}(...)")


def _check_no_dynamic_calls(tree: ast.Module) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            assert node.func.id not in _FORBIDDEN_NAME_CALLS, (
                f"report calls a fence-evading builtin: "
                f"{node.func.id}")
        if isinstance(node.func, ast.Attribute):
            assert node.func.attr not in _FORBIDDEN_ATTR_CALLS, (
                f"report calls a fence-evading attribute: "
                f".{node.func.attr}(...)")


def _mode_is_write(node: ast.Call) -> bool:
    """True when an open-shaped call carries a write-capable mode
    string — positional (args[1] for ``open``, args[0] for
    ``.open``) or the ``mode=`` keyword."""
    candidates: list[ast.expr] = list(node.args)
    candidates.extend(kw.value for kw in node.keywords
                      if kw.arg == "mode")
    for arg in candidates:
        if (isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and any(c in arg.value for c in _WRITE_MODE_CHARS)):
            return True
    return False


def _check_writes_are_atomic(tree: ast.Module) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if (isinstance(node.func, ast.Name)
                and node.func.id == "open"
                and _mode_is_write(node)):
            raise AssertionError(
                "report opens a file in a write mode — writes go "
                "through save_json / write_text_atomically")
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "open":
                # No `.open(...)` at all: reads go through load_json,
                # writes through the atomic writers; a hand
                # Path.open('w') is exactly the forgery seam.
                raise AssertionError(
                    "report calls .open(...) — reads go through "
                    "load_json; writes through save_json / "
                    "write_text_atomically")
            if node.func.attr in ("write_text", "write_bytes"):
                raise AssertionError(
                    f"report calls .{node.func.attr}(...) — writes "
                    "go through save_json / write_text_atomically")


def _check_read_only_seams(tree: ast.Module) -> None:
    """Row 5, both directions: every seam must be consumed (import
    present), never past its allowlist, and never reached through a
    parent package (``from core.coverage import journal`` hands the
    whole seam module over, write verbs included)."""
    seen: set[str] = set()
    for node in _all_import_froms(tree):
        allowed = _READ_ONLY_SEAMS.get(node.module)
        if allowed is not None:
            seen.add(node.module)
            for alias in node.names:
                assert alias.name in allowed, (
                    f"report imports a non-read seam from "
                    f"{node.module}: {alias.name}")
            continue
        # Parent-package ban: importing ANY name from a strict
        # ancestor package of a seam is forbidden — the name may BE
        # the seam module (aliased or not).
        for seam in _READ_ONLY_SEAMS:
            if seam.startswith(node.module + "."):
                raise AssertionError(
                    f"report imports from {node.module} — a parent "
                    f"package of the read-only seam {seam}; import "
                    "the seam's allowed names via its full path")
    assert seen == set(_READ_ONLY_SEAMS), (
        f"report no longer consumes: "
        f"{sorted(set(_READ_ONLY_SEAMS) - seen)}")


_ALL_CHECKS = (
    _check_no_plain_imports,
    _check_forbidden_modules,
    _check_llm_import_ban,
    _check_no_os_calls,
    _check_no_dynamic_calls,
    _check_writes_are_atomic,
    _check_read_only_seams,
)


# ── The fence over the real module ───────────────────────────────────

def test_no_llm_or_dispatch_import() -> None:
    _check_llm_import_ban(_module_ast())


def test_no_plain_imports() -> None:
    _check_no_plain_imports(_module_ast())


def test_zero_process_spawn_surface() -> None:
    tree = _module_ast()
    _check_forbidden_modules(tree)
    _check_no_os_calls(tree)


def test_no_dynamic_import_or_exec_call() -> None:
    _check_no_dynamic_calls(_module_ast())


def test_writes_are_atomic_and_locked() -> None:
    _check_writes_are_atomic(_module_ast())
    source = REPORT_PATH.read_text(encoding="utf-8")
    assert "save_json(" in source
    assert "write_text_atomically(" in source
    assert "artifact_lock(" in source


def test_substrate_imports_are_read_only() -> None:
    _check_read_only_seams(_module_ast())


def test_registered_in_escaping_closure_baseline() -> None:
    source = AUDIT_PATH.read_text(encoding="utf-8")
    assert '"core/engagement/report.py"' in source, (
        "core/engagement/report.py must stay registered in "
        "_REPORT_WRITER_FILES (escaping-closure baseline)")


def test_launcher_preamble_present() -> None:
    source = LAUNCHER_PATH.read_text(encoding="utf-8")
    assert "CLAUDECODE" in source and "_RAPTOR_TRUSTED" in source, (
        "launcher lost the trust-marker gate")
    assert "import core.startup.process_init" in source, (
        "launcher lost the process_init import")
    assert LAUNCHER_PATH.stat().st_mode & 0o111, (
        "launcher must be executable")


# ── Census self-tests: the evasion corpus must stay caught ───────────
#
# Each payload is a write-capable / spawn-capable construct appended
# to the REAL module source; at least one census must reject the
# mutant. These are the exact shapes that evaded the first cut of
# this fence — they are pinned so the census can never regress to
# missing them again.

_EVASION_PAYLOADS = {
    "module_import_writer":
        "import core.engagement.ledger\n"
        "def _evil(out):\n"
        "    core.engagement.ledger.set_artifact_status("
        "out, 'x', 'verdicted')\n",
    "from_package_alias":
        "from core.engagement import ledger as _l\n"
        "def _evil2(out, e):\n"
        "    _l.append_row(out, e)\n",
    "journal_module_alias":
        "from core.coverage import journal as _j\n"
        "def _evil3(rd, e):\n"
        "    _j.append_entry(rd, e)\n",
    "getattr_writer":
        "import core.engagement.chain_elf as _c\n"
        "def _evil4(cd, s):\n"
        "    getattr(_c, '_save_chain_state')(cd, s)\n",
    "open_kw_mode":
        "def _evil5(p):\n"
        "    with open(p, mode='w') as fh:\n"
        "        fh.write('forged')\n",
    "path_open_write":
        "def _evil6(p):\n"
        "    from pathlib import Path as _P\n"
        "    with _P(p).open('w') as fh:\n"
        "        fh.write('forged')\n",
    "pkgutil_resolve":
        "from pkgutil import resolve_name as _rn\n"
        "def _evil7(n):\n"
        "    return _rn(n)\n",
    "pkgutil_attr_call":
        "import pkgutil\n"
        "def _evil7b(n):\n"
        "    return pkgutil.resolve_name(n)\n",
    "os_open_write":
        "import os as _os\n"
        "def _evil8(p):\n"
        "    fd = _os.open(p, _os.O_WRONLY | _os.O_CREAT)\n"
        "    _os.write(fd, b'forged')\n"
        "    _os.close(fd)\n",
    "os_from_import_write":
        "from os import open as _oo, write as _ow, O_WRONLY\n"
        "def _evil9(p):\n"
        "    _ow(_oo(p, O_WRONLY), b'forged')\n",
}


@pytest.mark.parametrize("shape", sorted(_EVASION_PAYLOADS))
def test_census_catches_evasion_shape(shape: str) -> None:
    source = (REPORT_PATH.read_text(encoding="utf-8")
              + "\n\n" + _EVASION_PAYLOADS[shape])
    tree = ast.parse(source)
    caught = False
    for check in _ALL_CHECKS:
        try:
            check(tree)
        except AssertionError:
            caught = True
            break
    assert caught, (
        f"evasion shape '{shape}' passes every census — the fence "
        "regressed against its own corpus")


def test_census_passes_clean_module() -> None:
    """The self-test harness is not vacuous: the real module passes
    every check it feeds the mutants through."""
    tree = _module_ast()
    for check in _ALL_CHECKS:
        check(tree)
