"""Doctrine fence for the engagement depth-policy + budget governor.

The governor decides how deep every artifact is engaged and how much
of the operator's envelope a segment may charge — a steering surface
one rung above the ledger. The doctrine rows pinned here, independent
of the unit battery's placement:

  1. **Depth assignment is mechanical (M3a)** — the governor module
     must never import an LLM / dispatch / prompt seam, spawn
     processes, open sockets, or reach any of those dynamically. Its
     only cost input is the scorecard estimator (recorded call
     history — mechanical facts, not judgment).
  2. **Determinism** — assignment (stratified sample included) is a
     pure function of (document, persisted launch nonce): the only
     randomness is a ``random.Random`` instance seeded from that
     pair, and the module's ONLY unseeded entropy is the single
     ``os.urandom`` call minting the nonce (persisted at first
     ensure, loaded ever after); module-level ``random.*`` draws and
     any second entropy source are fenced out.
  3. **Store discipline** — the governor persists ONLY through the
     ledger's validated writers; no raw file writes.
  4. **S16 pre-spend park** — an unattended feasibility conflict
     parks the engagement before any reservation exists.
  5. **Soft dependency** — the coverage journal's governor contact is
     import-guarded (nested in a try), never a top-level dependency.

Rows 1-3 and 5 are mechanical AST/source proofs; rows 2 and 4 also
carry compact behavioral proofs (stdlib-only fixtures; the sandboxed
build-id probe is stubbed, so no toolchain is required).
"""

from __future__ import annotations

import ast
import struct
import sys
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

GOVERNOR_PATH = REPO_ROOT / "core" / "engagement" / "governor.py"
JOURNAL_PATH = REPO_ROOT / "core" / "coverage" / "journal.py"

_FORBIDDEN_IMPORT_PREFIXES = (
    "core.llm", "core.dispatch", "packages.llm",
    "core.security.prompt", "core.recall",
)
_FORBIDDEN_MODULES = ("subprocess", "socket", "urllib", "requests",
                      "http")


def _module_ast(path: Path = GOVERNOR_PATH) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


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
        ), f"governor imports a depth-steering-forbidden seam: {name}"
        assert "llm" not in name.lower(), (
            f"governor imports an LLM-adjacent module: {name}")


def test_no_process_or_network_module() -> None:
    for name in _all_imports(_module_ast()):
        top = name.split(".")[0]
        assert top not in _FORBIDDEN_MODULES, (
            f"governor must stay pure-mechanical; imports {name}")


_FORBIDDEN_NAME_CALLS = {"__import__", "eval", "exec", "compile"}
_FORBIDDEN_ATTR_CALLS = {"import_module", "system", "popen",
                         "write_text", "write_bytes"}
_FORBIDDEN_ATTR_PREFIXES = ("exec", "spawn")


def test_no_dynamic_import_exec_or_raw_write_call() -> None:
    for node in ast.walk(_module_ast()):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            assert node.func.id not in _FORBIDDEN_NAME_CALLS, (
                f"governor calls a fence-evading builtin: "
                f"{node.func.id}")
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            assert attr not in _FORBIDDEN_ATTR_CALLS, (
                f"governor calls a fence-evading attribute: "
                f".{attr}(...)")
            assert not attr.startswith(_FORBIDDEN_ATTR_PREFIXES), (
                f"governor calls a process-spawning attribute: "
                f".{attr}(...)")


def test_no_raw_open_write() -> None:
    """The governor persists only through the ledger's validated
    writers — a raw ``open(..., "w")`` would bypass validation,
    locking and atomicity at once."""
    def _writing_mode(value: ast.expr) -> bool:
        return (isinstance(value, ast.Constant)
                and any(c in str(value.value) for c in "wax+"))

    for node in ast.walk(_module_ast()):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "open"):
            # positional mode AND the keyword spelling — a bare
            # positional check waves open(path, mode="w") through
            writing = [arg for arg in node.args[1:]
                       if _writing_mode(arg)]
            writing += [kw.value for kw in node.keywords
                        if kw.arg == "mode"
                        and _writing_mode(kw.value)]
            if writing:
                raise AssertionError(
                    "governor writes must go through the ledger's "
                    "writers, not open(..., 'w')")


def test_randomness_is_seeded_only() -> None:
    """The stratified sample must be reproducible from the persisted
    ledger alone: the only randomness allowed is a seeded
    ``random.Random`` instance — module-level ``random.*`` draws
    (process-seeded) are fenced out — and the module's ONLY unseeded
    entropy is the single ``os.urandom`` call inside
    ``_mint_sample_nonce`` (minted once, persisted; every other read
    LOADS the stored nonce). A second entropy site would fork
    resume determinism."""
    tree = _module_ast()
    seeded = 0
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "random"):
            continue
        assert node.func.attr == "Random", (
            f"unseeded module-level randomness: "
            f"random.{node.func.attr}(...)")
        assert node.args, "random.Random() must be explicitly seeded"
        seeded += 1
    assert seeded >= 1, "expected the seeded sampling RNG"

    # the one sanctioned entropy site: os.urandom in the nonce mint
    mint_calls: set[int] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.FunctionDef)
                and node.name == "_mint_sample_nonce"):
            mint_calls = {
                id(n) for n in ast.walk(node)
                if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "urandom"
            }
    urandom_calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "urandom"
    ]
    assert len(urandom_calls) == 1, (
        f"expected exactly ONE os.urandom site (the nonce mint), "
        f"found {len(urandom_calls)}")
    assert {id(n) for n in urandom_calls} == mint_calls, (
        "os.urandom outside _mint_sample_nonce")
    # and no second entropy module rides in
    for name in _all_imports(tree):
        assert name.split(".")[0] not in ("secrets", "uuid"), (
            f"governor imports a second entropy source: {name}")


def test_journal_contact_is_import_guarded() -> None:
    """The coverage journal must never grow a hard engagement
    dependency: its only import of the governor sits inside a
    ``try`` (lazy, best-effort), never at module top level."""
    tree = _module_ast(JOURNAL_PATH)

    def _is_contact(node: ast.AST) -> bool:
        return (isinstance(node, ast.ImportFrom)
                and node.module is not None
                and node.module.startswith("core.engagement"))

    contacts = {id(n) for n in ast.walk(tree) if _is_contact(n)}
    assert contacts, "expected the journal's governor contact"
    guarded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            guarded |= {id(n) for n in ast.walk(node)
                        if _is_contact(n)}
    assert contacts == guarded, (
        "core.engagement import in journal.py outside a try guard")


# ── behavioral proofs ────────────────────────────────────────────────

def _write_elf(path: Path) -> None:
    path.write_bytes(
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        + struct.pack("<HHIQQQIHHHHHH",
                      3, 0x3E, 1, 0, 0, 0, 0, 64, 0, 0, 64, 0, 0)
        + path.name.encode())


def test_assignment_is_deterministic_and_resume_stable(
        tmp_path) -> None:
    import core.binary.elf as elf_mod
    from core.engagement import governor as gov
    from core.engagement import ledger as ledger_mod

    target = tmp_path / "install"
    target.mkdir()
    for i in range(30):
        _write_elf(target / f"bin{i:02d}")
    out = tmp_path / "out"
    with mock.patch.object(elf_mod, "_read_build_id",
                           lambda p: (None, None)):
        doc = ledger_mod.build_ledger(target, out)
    p1 = gov.assign_depth(doc)
    p2 = gov.assign_depth(doc)
    assert p1 == p2
    assert p1.sampled_ids  # the sample exists and is reproducible
    slots, fresh = gov.ensure_policy(out, doc)
    assert fresh
    # the launch nonce persisted — resume determinism rides on it
    assert ledger_mod.load_engagement_policy(out).get("sample_nonce")
    doc2 = ledger_mod.load_ledger(out)
    assert doc2 is not None
    slots2, fresh2 = gov.ensure_policy(out, doc2)
    assert not fresh2 and slots2 == slots


def test_unattended_conflict_parks_before_any_spend(tmp_path) -> None:
    import core.binary.elf as elf_mod
    from core.engagement import governor as gov
    from core.engagement import ledger as ledger_mod

    target = tmp_path / "install"
    target.mkdir()
    for i in range(3):
        _write_elf(target / f"bin{i}")
    out = tmp_path / "out"
    with mock.patch.object(elf_mod, "_read_build_id",
                           lambda p: (None, None)):
        doc = ledger_mod.build_ledger(target, out)
    slots, _fresh = gov.ensure_policy(out, doc)
    for aid, slot in slots.items():
        ledger_mod.set_artifact_policy(
            out, aid, policy={**slot, "tier": "T3",
                              "bucket": "deep_dive"})
    doc2 = ledger_mod.load_ledger(out)
    assert doc2 is not None
    verdict = gov.enforce_feasibility(out, doc2, 1.0, attended=False)
    assert verdict.verdict == gov.VERDICT_CONFLICT
    doc3 = ledger_mod.load_ledger(out)
    assert doc3 is not None
    assert gov.is_engagement_parked(doc3)
    # BEFORE spend: no reservation exists anywhere, nothing committed
    assert gov.committed_usd(doc3) == 0.0
    assert all("reservation" not in row for row in doc3["rows"])
