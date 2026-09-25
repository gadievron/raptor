#!/usr/bin/env python3
"""Transcript-seam census: LLM dispatch stays replay-coverable.

The frozen-transcript record/replay machinery (``core/llm/transcript``)
intercepts LLM traffic at ONE seam: ``LLMClient`` construction through
``build_llm_client`` (adopted surfaces) or an explicit
``fence_unadopted_dispatch`` call (surfaces that honestly refuse
replay). A dispatch path that constructs a client or provider outside
that seam silently dispatches LIVE under replay mode — the exact
failure the replay evals exist to prevent — and nothing else in CI
notices, because the surface still works on every live run.

This census closes that hole structurally. It AST-walks the runtime
source universe (shared derivation: ``runtime_universe.py``, dev
``scripts/`` dirs included — measurement harnesses dispatch LLMs too;
the local replay-case corpus ``core/audit/corpus/replay-cases`` is
excluded by REL-PATH PREFIX, never by bare directory name, so a
runtime dir that happens to share the name cannot shrink the
universe) and records every construction-shaped dispatch site:

* ``llm_client`` arm — every ``LLMClient(...)`` call (including calls
  through an ``import … as`` alias of the symbol) and every class
  DEFINITION deriving from ``LLMClient`` / ``TranscriptLLMClient`` (a
  subclass is a constructible dispatch surface; censusing the
  ``ClassDef`` catches it at the definition, before any construction
  site exists). Allowed without adjudication only inside the seam
  itself (``core/llm/transcript.py``, ``core/llm/factory.py``);
  everywhere else the site must either sit inside a FENCED SCOPE
  (below) or carry a baseline row with a note.
* ``provider`` arm — every ``create_provider(...)`` call, every
  direct construction of a provider class, calls through ``import …
  as`` aliases of either, and every class definition deriving from a
  provider class, all outside ``core/llm/``. Provider class names are
  DERIVED from ``core/llm/providers.py`` (top-level classes named
  ``*Provider``), never hand-typed.

Fence scoping: a ``fence_unadopted_dispatch`` call exempts
constructions in the SAME enclosing scope (function/method qualname,
nested scopes included) — the shape both adopted fence sites use. A
fence at module level exempts the whole module: it executes at import
time, so under replay the module is unusable before any construction
runs. A fence in one function never exempts a construction in a
sibling function.

Baseline semantics follow the miswiring gate: a finding not recorded
in ``transcript_seam_baseline.json`` fails; a recorded key whose
observed count GREW fails (a second unfenced construction in the same
function is a new site, not the old one); a recorded key that no
longer fires warns as stale, and a recorded count above the observed
one warns as unused headroom (it would let a new construction at that
site pass silently — tighten it). Every baseline row must carry a
``note`` and an integer ``count`` — a noteless row, or a boolean
masquerading as a count, is a usage error, not an accepted site.

Two vacuousness pins keep the census honest against refactors of the
things it greps for: the walk must still see the factory seam's own
``LLMClient`` construction, and the provider-class derivation must
yield at least :data:`PROVIDER_NAME_FLOOR` names. Either going quiet
is exit 2, never a silent green.

Declared boundaries (literal-shape census, matching the sibling
censuses): an assignment alias (``cls = LLMClient; cls()``),
``getattr``/``functools.partial`` indirection, a provider name built
at runtime, and cross-file construction of a censused subclass are
outside the AST census. All are un-idiomatic for this tree today; the
subclass's own ``ClassDef`` row is the tripwire for the last one.

Usage:
    python3 .github/scripts/check_transcript_seam.py
    python3 .github/scripts/check_transcript_seam.py --root <tree>
    python3 .github/scripts/check_transcript_seam.py --list

``--list`` prints the observed census as JSON (key -> count) — the
adoption/refresh surface: copy the keys you accept into the baseline
and write the note by hand.

Exit codes: 0 clean (stale/headroom warnings only), 1 unbaselined or
grown sites, 2 usage error (unparseable runtime file, corrupt or
noteless baseline, vacuous census).
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runtime_universe import runtime_file_universe  # noqa: E402

DEFAULT_BASELINE = (
    Path(__file__).resolve().parent / "transcript_seam_baseline.json"
)

#: Files that ARE the seam: they construct ``LLMClient`` /
#: ``TranscriptLLMClient`` as the adoption chokepoint every other
#: surface is measured against.
SEAM_FILES: frozenset[str] = frozenset({
    "core/llm/transcript.py",
    "core/llm/factory.py",
})

#: The module whose top-level ``*Provider`` classes define the
#: provider-construction vocabulary for the ``provider`` arm.
PROVIDERS_MODULE = "core/llm/providers.py"

#: Provider constructions inside core/llm are the seam's own plumbing
#: (client dispatch, adapters, preflight probes) — the census polices
#: construction OUTSIDE this prefix only.
PROVIDER_ALLOWED_PREFIX = "core/llm/"

#: Vacuousness floor on the derived provider-class vocabulary
#: (currently 5 concrete classes + the ABC; a derivation that finds
#: fewer than this has gone quiet).
PROVIDER_NAME_FLOOR = 3

#: The factory seam file must contribute at least one ``LLMClient``
#: construction to the walk — the non-vacuousness pin for the
#: ``llm_client`` arm.
FACTORY_PIN_FILE = "core/llm/factory.py"

#: Gate-specific legitimate home excluded from the walk, by REL-PATH
#: PREFIX (a bare directory-name exclusion would drop ANY dir of the
#: same name anywhere in the runtime roots): the local replay-case
#: corpus (never committed) may carry target-source snapshots under
#: ``repo/`` whose code is eval CONTENT, not runtime source — without
#: this a maintainer machine censuses its own case material.
EXCLUDED_PATH_PREFIXES: tuple[str, ...] = (
    "core/audit/corpus/replay-cases/",
)

#: The names whose call sites the fence classification looks for.
FENCE_NAME = "fence_unadopted_dispatch"
CLIENT_NAME = "LLMClient"
#: Base-class tails that mark a ClassDef as a client subclass.
CLIENT_BASE_NAMES: frozenset[str] = frozenset({
    "LLMClient", "TranscriptLLMClient",
})
PROVIDER_FACTORY_NAME = "create_provider"


def _tail_name(node: ast.expr) -> str | None:
    """The bare name an expression targets (``Name`` or ``Attribute``
    tail)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _symbol_aliases(tree: ast.AST, targets: frozenset[str]) -> set[str]:
    """``import … as`` / ``from … import … as`` aliases of *targets*.

    Only symbol renames matter: a module alias (``import x.y as z``)
    still constructs via ``z.LLMClient()``, whose Attribute tail the
    census already matches.
    """
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                base = alias.name.rsplit(".", 1)[-1]
                if alias.asname and base in targets:
                    aliases.add(alias.asname)
    return aliases


class _SiteVisitor(ast.NodeVisitor):
    """Collect dispatch-construction sites with their enclosing
    qualname (class/function nesting; ``<module>`` at top level).

    Sites: client/provider construction CALLS (through the canonical
    names or their in-file ``import … as`` aliases) and client/
    provider SUBCLASS definitions. Fence calls are collected with
    their scope for same-scope correlation.
    """

    def __init__(
        self,
        client_names: frozenset[str],
        client_base_names: frozenset[str],
        provider_call_names: frozenset[str],
        provider_base_names: frozenset[str],
    ) -> None:
        self._client_names = client_names
        self._client_base_names = client_base_names
        self._provider_call_names = provider_call_names
        self._provider_base_names = provider_base_names
        self._scopes: list[str] = []
        self.client_sites: list[str] = []
        self.provider_sites: list[str] = []
        self.fence_scopes: set[str] = set()

    def _qualname(self, extra: str | None = None) -> str:
        parts = self._scopes + ([extra] if extra else [])
        return ".".join(parts) if parts else "<module>"

    def _visit_scope(self, node: ast.AST, name: str) -> None:
        self._scopes.append(name)
        self.generic_visit(node)
        self._scopes.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        base_tails = {_tail_name(b) for b in node.bases}
        if base_tails & self._client_base_names:
            self.client_sites.append(self._qualname(node.name))
        if base_tails & self._provider_base_names:
            self.provider_sites.append(self._qualname(node.name))
        self._visit_scope(node, node.name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_scope(node, node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_scope(node, node.name)

    def visit_Call(self, node: ast.Call) -> None:
        name = _tail_name(node.func)
        if name in self._client_names:
            self.client_sites.append(self._qualname())
        elif name in self._provider_call_names:
            self.provider_sites.append(self._qualname())
        elif name == FENCE_NAME:
            self.fence_scopes.add(self._qualname())
        self.generic_visit(node)


def derive_provider_names(root: Path) -> frozenset[str]:
    """Top-level ``*Provider`` class names in the providers module."""
    module = root / PROVIDERS_MODULE
    tree = ast.parse(module.read_text(encoding="utf-8"))
    names = frozenset(
        node.name for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name.endswith("Provider")
    )
    if len(names) < PROVIDER_NAME_FLOOR:
        msg = (
            f"provider-class derivation from {PROVIDERS_MODULE} went "
            f"vacuous ({sorted(names)}) — the census's provider arm "
            f"would silently stop seeing direct constructions"
        )
        raise ValueError(msg)
    return names


def _in_fenced_scope(qual: str, fence_scopes: set[str]) -> bool:
    """Same-scope fence correlation (module docstring): a fence at
    ``<module>`` exempts everything in the module (import-time
    refusal); a fence in a function exempts that function and its
    nested scopes only."""
    if "<module>" in fence_scopes:
        return True
    return any(
        qual == fence or qual.startswith(fence + ".")
        for fence in fence_scopes
    )


def census(root: Path) -> dict[str, int]:
    """Observed dispatch-construction sites, keyed
    ``<arm>:<relpath>::<qualname>`` -> count.

    Seam-internal ``llm_client`` sites (:data:`SEAM_FILES`) and
    fence-scoped sites (see :func:`_in_fenced_scope`) are excluded —
    a fenced scope's constructions consult the active transcript
    session and refuse replay loudly, which is the honesty contract.
    Provider sites under :data:`PROVIDER_ALLOWED_PREFIX` are the
    seam's own plumbing and likewise excluded.
    """
    provider_names = derive_provider_names(root)
    observed: dict[str, int] = {}
    factory_pin_seen = False
    for path in runtime_file_universe(root, include_dev_scripts=True):
        rel = path.relative_to(root).as_posix()
        if rel.startswith(EXCLUDED_PATH_PREFIXES):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as exc:
            msg = f"cannot parse runtime file {rel}: {exc}"
            raise ValueError(msg) from exc
        client_names = frozenset(
            {CLIENT_NAME} | _symbol_aliases(tree, frozenset({CLIENT_NAME})),
        )
        provider_targets = frozenset(
            {PROVIDER_FACTORY_NAME} | provider_names,
        )
        provider_call_names = frozenset(
            provider_targets | _symbol_aliases(tree, provider_targets),
        )
        visitor = _SiteVisitor(
            client_names=client_names,
            client_base_names=frozenset(CLIENT_BASE_NAMES | client_names),
            provider_call_names=provider_call_names,
            provider_base_names=frozenset(
                n for n in provider_call_names
                if n != PROVIDER_FACTORY_NAME
            ),
        )
        visitor.visit(tree)
        if rel == FACTORY_PIN_FILE and visitor.client_sites:
            factory_pin_seen = True
        if rel not in SEAM_FILES:
            for qual in visitor.client_sites:
                if _in_fenced_scope(qual, visitor.fence_scopes):
                    continue
                key = f"llm_client:{rel}::{qual}"
                observed[key] = observed.get(key, 0) + 1
        if not rel.startswith(PROVIDER_ALLOWED_PREFIX):
            for qual in visitor.provider_sites:
                if _in_fenced_scope(qual, visitor.fence_scopes):
                    continue
                key = f"provider:{rel}::{qual}"
                observed[key] = observed.get(key, 0) + 1
    if not factory_pin_seen:
        msg = (
            f"census no longer sees the {CLIENT_NAME} construction inside "
            f"{FACTORY_PIN_FILE} — the llm_client arm has gone vacuous "
            f"(renamed class? changed walk?); refusing a silent green"
        )
        raise ValueError(msg)
    return observed


def load_baseline(path: Path) -> dict[str, dict]:
    """Baseline rows keyed like the census. Absent file = empty
    (pre-adoption); present but corrupt, misshapen, or carrying a
    noteless / countless row raises — falling open would demote every
    recorded site to unenforced behind one bad commit."""
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        msg = f"cannot read baseline at {path}: {exc}"
        raise ValueError(msg) from exc
    entries = loaded.get("entries") if isinstance(loaded, dict) else None
    if not isinstance(entries, dict):
        msg = (
            f"baseline at {path} must be a JSON object with an "
            f"'entries' object — fix or remove it"
        )
        raise ValueError(msg)
    for key, row in entries.items():
        if not isinstance(row, dict) or not str(row.get("note", "")).strip():
            msg = (
                f"baseline row {key!r} has no note — every accepted "
                f"dispatch site must say why it is accepted"
            )
            raise ValueError(msg)
        count = row.get("count")
        # bool is an int subclass; a `true` count would slip through a
        # bare isinstance(int) check and read as headroom 1.
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            msg = (
                f"baseline row {key!r} needs an integer 'count' >= 1 "
                f"(the number of accepted constructions at that site)"
            )
            raise ValueError(msg)
    return entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument(
        "--list", action="store_true",
        help="print the observed census as JSON and exit 0",
    )
    args = parser.parse_args(argv)

    try:
        observed = census(args.root.resolve())
    except (OSError, ValueError) as exc:
        print(f"[transcript-seam] {exc}", file=sys.stderr)
        return 2

    if args.list:
        print(json.dumps(observed, indent=2, sort_keys=True))
        return 0

    try:
        baseline = load_baseline(args.baseline)
    except ValueError as exc:
        print(f"[transcript-seam] {exc}", file=sys.stderr)
        return 2

    failures: list[str] = []
    for key in sorted(observed):
        row = baseline.get(key)
        if row is None:
            failures.append(
                f"NEW dispatch site outside the transcript seam: {key} "
                f"(x{observed[key]})"
            )
        elif observed[key] > row["count"]:
            failures.append(
                f"dispatch site grew: {key} (observed {observed[key]} > "
                f"recorded {row['count']})"
            )

    for key in sorted(baseline):
        seen = observed.get(key, 0)
        if seen == 0:
            print(
                f"[transcript-seam] WARN stale baseline row: {key} "
                f"(recorded {baseline[key]['count']}, observed 0) — the "
                f"site no longer fires; prune the row. A stale row is a "
                f"silent re-entry ticket: a construction reintroduced at "
                f"this exact key would trip nothing"
            )
        elif seen < baseline[key]["count"]:
            print(
                f"[transcript-seam] WARN unused headroom: {key} "
                f"(recorded {baseline[key]['count']}, observed {seen}) — "
                f"a NEW construction at this site would pass silently "
                f"inside the recorded count; tighten the row"
            )
    if failures:
        print(
            "[transcript-seam] LLM dispatch construction outside the "
            "record/replay seam — under RAPTOR_LLM_TRANSCRIPT=replay:… "
            "these sites dispatch live instead of replaying. Route the "
            "construction through core.llm.transcript.build_llm_client "
            "(or core.llm.factory.get_client), or declare the surface "
            "with core.llm.transcript.fence_unadopted_dispatch in the "
            "same scope, or — only with a reviewed note — add the key "
            f"to {args.baseline.name}:"
        )
        for line in failures:
            print(f"  {line}")
        return 1

    print(
        f"[transcript-seam] census clean: {len(observed)} adjudicated "
        f"site(s), no new dispatch construction outside the seam"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
