"""Closure gate: the /audit surface stays transcript-adopted.

Transcript record/replay (``RAPTOR_LLM_TRANSCRIPT``) intercepts LLM
traffic at ONE construction seam — ``core.llm.transcript.
build_llm_client`` (and ``core.llm.factory.get_client``, which routes
through it). A bare ``LLMClient(...)`` construction bypasses the seam:
record mode silently records nothing from that call site (an operator
freezing a corpus-baseline believes the run recorded when it did not),
and replay mode dispatches live. Every live run still works, so
nothing else in CI notices the regression.

This census closes that structurally for the audit surface: no
runtime module under ``core/audit/`` may construct ``LLMClient``
directly. New sites either construct through ``build_llm_client`` or
carry an adjudicated entry in ``_ALLOWLIST`` below. Both directions
are enforced: an unlisted site fails (the silent-under-recording class
regrew), and a stale allowlist entry fails (the site changed or moved
— re-adjudicate it). Tests, fixtures, conftest and subsystem
``scripts/`` dirs are outside the runtime universe and exempt by
construction.

The runtime honesty fence for the same defect class lives in
``LLMClient.__init__`` (``fence_bare_client_construction``: loud
under-recording warning under record, hard refusal under replay).
This census is the CI-time fence — it fails without a transcript
session ever being active.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from runtime_universe import repo_root, runtime_file_universe  # noqa: E402

_SURFACE_PREFIX = "core/audit/"

# (relpath, exact stripped first source line of the call) -> reason
# the bare construction is safe as written. Keep entries tight: every
# one is an adjudication record, not an exemption of convenience.
_ALLOWLIST: dict[tuple[str, str], str] = {}


def _client_name_bindings(tree: ast.Module) -> set[str]:
    """Local names bound to ``core.llm.client.LLMClient`` by import
    (``from core.llm.client import LLMClient [as X]``), module- or
    function-scoped."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and (
            node.module.endswith("client") and "llm" in node.module
        ):
            for alias in node.names:
                if alias.name == "LLMClient":
                    names.add(alias.asname or alias.name)
    return names


def _bare_constructions(
    source: str,
) -> list[tuple[int, str]]:
    """(lineno, stripped first source line) for every direct
    ``LLMClient`` construction in *source*.

    Detects calls through the imported name (any ``as`` alias) and
    through any attribute access ending in ``.LLMClient`` (module
    aliases). ``TranscriptLLMClient`` and other names are not
    LLMClient constructions and are ignored.
    """
    tree = ast.parse(source)
    bound = _client_name_bindings(tree)
    lines = source.splitlines()
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        direct = isinstance(func, ast.Name) and func.id in bound
        attr = isinstance(func, ast.Attribute) and func.attr == "LLMClient"
        if direct or attr:
            hits.append((node.lineno, lines[node.lineno - 1].strip()))
    return hits


def _audit_surface_files() -> list[Path]:
    root = repo_root()
    return [
        p for p in runtime_file_universe(root)
        if p.relative_to(root).as_posix().startswith(_SURFACE_PREFIX)
    ]


def test_detector_sees_both_construction_shapes():
    """Vacuousness pin: the detector must flag the direct-name and the
    module-attribute construction shapes (a parser regression would
    otherwise turn the census silently green)."""
    snippet = (
        "from core.llm.client import LLMClient as _C\n"
        "import core.llm.client as m\n"
        "a = _C()\n"
        "b = m.LLMClient(cfg)\n"
    )
    hits = _bare_constructions(snippet)
    assert len(hits) == 2, hits


def test_detector_ignores_the_seam_and_unrelated_names():
    snippet = (
        "from core.llm.transcript import build_llm_client\n"
        "a = build_llm_client()\n"
        "b = TranscriptLLMClient(cfg)\n"
    )
    assert _bare_constructions(snippet) == []


def test_audit_surface_universe_is_populated():
    """Vacuousness pin: a rename of the surface prefix (or a universe
    regression) must fail loudly, not empty the census."""
    files = _audit_surface_files()
    assert len(files) >= 30, (
        f"only {len(files)} runtime files under {_SURFACE_PREFIX} — "
        "surface prefix or runtime universe regressed"
    )
    names = {p.name for p in files}
    # The corpus baseline runner is the census's reason for existing.
    assert "run_corpus.py" in names


def test_audit_surface_constructs_through_the_seam():
    """The adopted surface actually uses the seam — the census must
    not be green because LLM dispatch vanished from the surface."""
    root = repo_root()
    seam_users = [
        p.relative_to(root).as_posix()
        for p in _audit_surface_files()
        if "build_llm_client(" in p.read_text(encoding="utf-8")
    ]
    assert "core/audit/corpus/run_corpus.py" in seam_users
    assert len(seam_users) >= 5, seam_users


def test_no_bare_llm_client_constructions_on_the_audit_surface():
    root = repo_root()
    found: dict[tuple[str, str], int] = {}
    for path in _audit_surface_files():
        rel = path.relative_to(root).as_posix()
        for lineno, line in _bare_constructions(
            path.read_text(encoding="utf-8"),
        ):
            found[(rel, line)] = lineno

    unlisted = {k: v for k, v in found.items() if k not in _ALLOWLIST}
    stale = [k for k in _ALLOWLIST if k not in found]

    msgs = []
    if unlisted:
        listing = "\n".join(
            f"  {rel}:{lineno}: {line}"
            for (rel, line), lineno in sorted(unlisted.items())
        )
        msgs.append(
            "bare LLMClient construction(s) on the audit surface — "
            "these bypass transcript record/replay (record mode "
            "silently records NOTHING for their calls; replay would "
            "dispatch live). Construct through "
            "core.llm.transcript.build_llm_client, or adjudicate an "
            f"_ALLOWLIST entry with a reason:\n{listing}"
        )
    if stale:
        listing = "\n".join(f"  {rel}: {line}" for rel, line in sorted(stale))
        msgs.append(
            "stale _ALLOWLIST entr(ies) — the adjudicated site changed "
            f"or moved; re-adjudicate:\n{listing}"
        )
    assert not msgs, "\n\n".join(msgs)
