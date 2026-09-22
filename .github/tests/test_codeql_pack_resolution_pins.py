"""CodeQL pack resolution must never be steered by the target repo.

Why this test exists
--------------------
The codeql trust gate (core/security/codeql_trust.py) is
defense-in-depth: verified against CLI 2.26.3, ``database create``
under RAPTOR's invocation does not consume repo-tree pack config at
all, and the analyze-side pack sources are RAPTOR-controlled (the
``~/.codeql`` vendored cache, run-out_dir-staged packs, operator dev
CLI values). That safety is structural — it holds because no
target-repo-derived path ever reaches ``--search-path``,
``--additional-packs``, or ``--codescanning-config``.

This pin freezes the dispatch surface: every QUOTED occurrence of
those flag spellings (string literals — the lines that can actually
put the flag on a command) in runtime Python under core/ and
packages/ is enumerated below with its value provenance. Prose and
docstring mentions are deliberately not pinned. A new or moved quoted
site fails the test, forcing the author to confirm the value cannot
be target-repo-derived before extending the registry — the moment one
is, the trust gate's accepted walk boundaries (symlinked dirs, dotted
dirs) stop being moot and need a matching lane first.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_SCAN_ROOTS = (_REPO / "core", _REPO / "packages")

_FLAGS = ("--additional-packs", "--search-path", "--codescanning-config")
# A quoted occurrence: the flag spelling immediately preceded by a
# quote character (plain or f-string literal) — the dispatch surface.
_QUOTED = tuple(q + f for f in _FLAGS for q in ('"', "'"))

# (path relative to repo, exact stripped line) — the complete allowed
# set, each with verified value provenance:
#   - query_runner search_dir: agent-staged model packs under the
#     run's out_dir (agent.py additional_model_packs staging)
#   - query_runner / iris vendored roots: ~/.codeql package cache
#     (vendored_stdlib_roots)
#   - codeql_augmented_run extension_pack: write_extension_pack output
#     staged under the run's out_dir, _require_data_only_pack-validated
#   - barrier_synth / cvefix_bridge: operator dev-lane CLI arguments
#     (argparse definitions and their pass-through), never target-tree
_PINNED = {
    ("packages/codeql/query_runner.py",
     '"--additional-packs", str(search_dir),'),
    ("packages/codeql/query_runner.py",
     'f"--additional-packs={root}" for root in vendored'),
    ("core/iris/codeql_runner.py",
     'f"--additional-packs={root}" for root in vendored'),
    ("core/dataflow/codeql_augmented_run.py",
     '"--additional-packs", str(extension_pack),'),
    ("core/dataflow/barrier_synth.py",
     'extra = ["--additional-packs", search_path] if search_path else []'),
    ("core/dataflow/barrier_synth.py",
     'p.add_argument("--search-path", help="codeql query-pack search path'
     ' (--additional-packs)")'),
    ("core/dataflow/cvefix_bridge.py",
     'ap.add_argument("--search-path", default=None,'),
}


def _runtime_sources() -> list[Path]:
    out: list[Path] = []
    for root in _SCAN_ROOTS:
        out.extend(
            p for p in sorted(root.rglob("*.py"))
            if "tests" not in p.parts and "__pycache__" not in p.parts
        )
    return out


def test_quoted_pack_resolution_flag_sites_are_pinned():
    found = set()
    for path in _runtime_sources():
        rel = str(path.relative_to(_REPO))
        for ln in path.read_text(encoding="utf-8",
                                 errors="replace").splitlines():
            if any(q in ln for q in _QUOTED):
                found.add((rel, ln.strip()))
    new = found - _PINNED
    gone = _PINNED - found
    assert not new and not gone, (
        "codeql pack-resolution dispatch surface drifted. New sites "
        "must prove their value is NOT target-repo-derived (then "
        "extend the registry with the provenance note); repo-derived "
        "values reopen the trust gate's accepted walk boundaries as "
        "real bypasses. A moved/reworded pinned line just needs "
        "re-pinning.\n"
        + (f"new/moved: {sorted(new)}\n" if new else "")
        + (f"missing:   {sorted(gone)}\n" if gone else "")
    )
