"""Doctrine fence for the cross-artifact hypothesis router.

The router mints hypothesis seed files that steer later audit spend,
and most of its input bytes originate in a hostile target or sibling
run directories. Doctrine rows pinned here, independent of the unit
battery's placement:

  1. **No LLM anywhere near routing** — the router must never import
     an LLM/dispatch/prompt seam, and must not spawn processes or
     open sockets itself (its only subprocess exposure is the sealed
     ELF/identity helpers it calls, which carry their own gates).
  2. **No fence-evading calls** — no dynamic import, code execution,
     or raw file writes; every artifact leaves through the atomic
     ``save_json`` seam.
  3. **One cap, the consumer's** — the routing quota is the intake's
     own ``MAX_SEED_RECORDS``, imported, never a shadow constant that
     could drift from what the consumer actually accepts.
  4. **Saturation escalates** — overflow beyond the quota reaches the
     engagement governor as ``routing_saturated``; it is never only a
     silent drop.
  5. **Quota shares are total and rank-ordered** — every producer
     class has a floor share, the shares never oversubscribe the cap,
     and the strongest class ranks first.
  6. **No unregistered producer class** — the allocator refuses a
     candidate whose class carries no floor share instead of dropping
     it from every counter.

Rows 1–4 are mechanical AST/source proofs (including the ImportFrom
alias, call-of-call, ``os.write``, and ``pkgutil.resolve_name``
evasion shapes); rows 5–6 import the module (stdlib + repo checkout
only — no toolchain, no network).
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

ROUTER_PATH = REPO_ROOT / "core" / "engagement" / "router.py"

_FORBIDDEN_IMPORT_PREFIXES = (
    "core.llm", "core.dispatch", "packages.llm",
    "core.security.prompt", "core.recall",
)
_FORBIDDEN_MODULES = ("subprocess", "socket", "urllib", "requests",
                      "http")


def _module_ast() -> ast.Module:
    return ast.parse(ROUTER_PATH.read_text(encoding="utf-8"))


def _all_imports(tree: ast.Module) -> list[str]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def _importfrom_joined_names(tree: ast.Module) -> list[str]:
    """``from core import llm`` binds ``core.llm`` while
    ``node.module`` only says ``core`` — the alias-joined names close
    that evasion for every ImportFrom."""
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.extend(
                f"{node.module}.{alias.name}" for alias in node.names
            )
    return names


def test_no_llm_or_dispatch_import() -> None:
    tree = _module_ast()
    for name in _all_imports(tree) + _importfrom_joined_names(tree):
        assert not any(
            name == p or name.startswith(p + ".")
            for p in _FORBIDDEN_IMPORT_PREFIXES
        ), f"router imports a routing-forbidden seam: {name}"
        assert "llm" not in name.lower(), (
            f"router imports an LLM-adjacent module: {name}")


def test_no_process_or_network_module() -> None:
    tree = _module_ast()
    for name in _all_imports(tree) + _importfrom_joined_names(tree):
        top = name.split(".")[0]
        assert top not in _FORBIDDEN_MODULES, (
            f"router must stay pure-mechanical; imports {name}")


_FORBIDDEN_NAME_CALLS = {"__import__", "eval", "exec", "compile",
                         "open", "resolve_name"}
_FORBIDDEN_ATTR_CALLS = {"import_module", "resolve_name", "system",
                         "popen", "write", "write_text",
                         "write_bytes", "open"}
_FORBIDDEN_ATTR_PREFIXES = ("exec", "spawn")


def test_no_dynamic_import_exec_or_raw_write_call() -> None:
    for node in ast.walk(_module_ast()):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            assert node.func.id not in _FORBIDDEN_NAME_CALLS, (
                f"router calls a fence-evading builtin: {node.func.id}")
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            assert attr not in _FORBIDDEN_ATTR_CALLS, (
                f"router calls a fence-evading attribute: .{attr}(...)")
            assert not attr.startswith(_FORBIDDEN_ATTR_PREFIXES), (
                f"router calls a process-spawning attribute: "
                f".{attr}(...)")
        if isinstance(node.func, ast.Call):
            # Call-of-Call is the getattr(importlib,
            # 'import_module')(...) evasion: the callee is minted at
            # runtime, so no static name gate above can see it. The
            # router has no legitimate call-of-call shape.
            raise AssertionError(
                "router calls the result of a call — runtime-minted "
                f"callees evade the static fence (line {node.lineno})")


def test_quota_cap_is_the_intakes_never_a_shadow() -> None:
    """The allocation cap is imported from the consumer
    (``core.audit.hypothesis_intake.MAX_SEED_RECORDS``); the router
    never assigns its own — a shadow constant would silently drift
    from what the intake actually accepts, and seed #cap+1 would be
    minted only to be dropped at load."""
    tree = _module_ast()
    imported = [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module == "core.audit.hypothesis_intake"
        for alias in node.names
    ]
    assert "MAX_SEED_RECORDS" in imported, (
        "router must import the intake's record cap")
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        for target in targets:
            assert not (
                isinstance(target, ast.Name)
                and target.id == "MAX_SEED_RECORDS"
            ), "router redefines the intake's record cap"


def test_saturation_escalates_to_the_governor() -> None:
    """Exactly the routing_saturated escalation kind, called on the
    governor's recorded seam — overflow is a policy event, not a
    silent drop."""
    found = False
    for node in ast.walk(_module_ast()):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        name = (
            callee.id if isinstance(callee, ast.Name)
            else callee.attr if isinstance(callee, ast.Attribute)
            else ""
        )
        if name != "record_escalation":
            continue
        kinds = [
            kw.value.value for kw in node.keywords
            if kw.arg == "kind" and isinstance(kw.value, ast.Constant)
        ]
        assert kinds == ["routing_saturated"], (
            "escalation kind must be the constant routing_saturated")
        found = True
    assert found, "router never escalates saturation to the governor"


def test_artifact_writes_go_through_save_json() -> None:
    imports = _all_imports(_module_ast())
    assert "core.json" in imports, (
        "router must write artifacts through the atomic save_json seam")
    for node in ast.walk(_module_ast()):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ("dump", "dumps")
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "json"):
            raise AssertionError(
                "router serialises via json.dump* — artifact writes "
                "must ride save_json (atomic tempfile + rename)")


def test_quota_shares_total_and_rank_ordered() -> None:
    from core.engagement.router import PRODUCER_CLASSES, QUOTA_SHARES
    assert set(QUOTA_SHARES) == set(PRODUCER_CLASSES), (
        "every producer class needs a floor share — a shareless class "
        "would starve entirely under contention")
    assert sum(QUOTA_SHARES.values()) <= 1.0 + 1e-9, (
        "floor shares must never oversubscribe the intake cap")
    assert all(share > 0 for share in QUOTA_SHARES.values())
    assert PRODUCER_CLASSES[0] == "sibling_hypotheses", (
        "externally-validated sibling leads redistribute first — "
        "reordering hands leftover budget to weaker producers")


def test_allocator_refuses_unregistered_producer_classes() -> None:
    """A candidate whose producer class is not in PRODUCER_CLASSES
    must refuse loudly — an unregistered class has no floor share and
    would otherwise vanish from every allocation counter. A series
    adding a producer class (the q4 carved-anomaly flip) must extend
    PRODUCER_CLASSES and QUOTA_SHARES consciously, and then this pin,
    to route it."""
    import pytest

    from core.engagement.router import _Candidate, _allocate
    ghost = _Candidate(
        artifact_id="elf_build_id-" + "aa" * 8,
        producer="not_a_registered_class",
        rank=1.0,
        seed={"file": "binary:t", "claim": "c"},
        join="identity",
    )
    with pytest.raises(ValueError, match="producer class"):
        _allocate([ghost], 10)
