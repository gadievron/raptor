"""Go function-level reachability tier.

Sibling of the PyPI / npm tiers, covering Go modules now that the
Go call-graph extractor in ``core.inventory.call_graph`` emits the
same ``FileCallGraph`` shape the resolver consumes.

The Go module-level reachability already harvests
``ecosystem_specific.imports[].symbols`` from OSV advisories (in
``_build_go_symbol_map``) and uses them for module-level matching.
This tier consumes the same symbol set but matches against actual
call sites in the project's Go source — distinguishing "your code
imports the affected module AND calls the vulnerable function"
from "your code only imports the module".

Of all the ecosystems wired in SCA today, Go has the most reliable
OSV symbol data. Go's `vulncheck` ecosystem standard ships
``imports[].symbols`` with practically every advisory, so this
tier produces meaningful noise reduction on virtually every CVE
match against Go projects.

## Verdict transitions (mirror the PyPI + npm tiers)

  * Any affected function CALLED → ``likely_called``.
  * EVERY advisory-listed symbol evaluated and NOT_CALLED, none
    UNCERTAIN → ``not_function_reachable``.
  * Any UNCERTAIN, mixed, or unevaluable entry → leave at
    ``imported``.

## Qualified-name shape

OSV's Go symbols come in two shapes per advisory:

  * Plain function: ``HandlerFunc`` — top-level package function.
  * Method: ``Server.ServeHTTP`` — method on a type, where ``Server``
    is the type name.

For both, the resolver's chain matching uses the dotted path
``<module_path>.<symbol>`` — e.g. ``net/http.HandlerFunc`` or
``net/http.Server.ServeHTTP``. The Go extractor's import map
preserves slashes in the value (``imports["http"] = "net/http"``)
so the chain ``["http", "HandlerFunc"]`` resolves to
``"net/http" + "." + "HandlerFunc" = "net/http.HandlerFunc"``,
matching the OSV symbol shape.

For method symbols (``Type.Method``), the chain is
``["http", "Server", "ServeHTTP"]`` — still resolves correctly
because the resolver concatenates middle parts.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from ..models import Confidence, Dependency, Reachability
from ._shared import UNRESOLVED_ENTRY

# The Go extractor's convention authority for what binding names a
# bare ``import "<path>"`` makes available: last path segment PLUS
# the /vN pre-version segment (path-versioned modules declare the
# pre-version package name) and go-/hyphen aliases (go-multierror →
# package multierror). Shared so the advisory-entry rebinds below
# can never drift from what the call-graph pass actually binds.
from core.inventory.call_graph import _go_bare_binding_names

logger = logging.getLogger(__name__)


_VERSION_SUFFIX_RE = re.compile(r"/v\d+$")


def _unversioned_root(module_path: str) -> str:
    """The module path without its ``/vN`` major-version suffix
    (``github.com/foo/bar/v2`` → ``github.com/foo/bar``), or ``""``
    when the path carries no version suffix. A ``/vN`` module is the
    SAME dependency spelled for a different major — advisory entries
    routinely use the unversioned spelling."""
    stripped = _VERSION_SUFFIX_RE.sub("", module_path)
    return stripped if stripped != module_path else ""


def build_go_symbol_map(
    osv_results: Iterable[Any] | None,
) -> dict[str, list[str]]:
    """Extract per-dep qualified-name targets from Go OSV results.

    Returns ``{dep_key: [qualified_name, ...]}``. Each qualified
    name is ``<advisory_import_path>.<symbol>`` — Go OSV records
    pair each symbol with the specific sub-package it lives in
    (``imports[].path``), which is often a sub-module of the dep
    (``golang.org/x/crypto/ssh.ParsePrivateKey`` lives under
    ``golang.org/x/crypto`` but the actual import path in
    project source is the sub-module).

    The resolver matches against this qualified name as-is —
    chain comparison handles slashes in the head and dots in the
    tail, so ``imports[].path = "golang.org/x/crypto/ssh"`` plus
    a project chain ``["ssh", "ParsePrivateKey"]`` (where
    ``imports["ssh"] = "golang.org/x/crypto/ssh"``) resolves to a
    match against ``"golang.org/x/crypto/ssh.ParsePrivateKey"``.

    Empty when no Go advisories carry symbol info.
    """
    if not osv_results:
        return {}
    out: dict[str, list[str]] = {}
    for r in osv_results:
        if not hasattr(r, "advisories"):
            continue
        dep_key = getattr(r, "dep_key", None)
        if not dep_key or not dep_key.startswith("Go:"):
            continue
        # Default fallback path = the dep's name (used for the
        # rare ``affected_functions`` flat shape that doesn't
        # carry a separate path).
        dep_name = dep_key.split(":", 1)[1].split("@", 1)[0]
        qualified: list[str] = []
        for adv in r.advisories:
            qualified.extend(_extract_qualified(adv, dep_name))
        if qualified:
            out.setdefault(dep_key, []).extend(qualified)
    return {k: list(dict.fromkeys(v)) for k, v in out.items()}


def _extract_qualified(advisory: Any, dep_name: str) -> list[str]:
    """Pull ``<path>.<symbol>`` qualified names out of an Advisory.

    Go advisories canonically use ``ecosystem_specific.imports[]
    .symbols`` paired with ``imports[].path`` (the affected
    sub-package). For each ``(path, symbol)`` pair we emit
    ``"<path>.<symbol>"``.

    Flat fallback shapes (``affected_symbols`` /
    ``affected_functions``) lack a per-symbol path. An entry that
    already carries the ``<dep_name>.`` or ``<dep_name>/`` prefix is
    emitted verbatim; an entry spelled with the package TAIL
    (``lib.Parse`` under ``example.com/lib``) is rebound onto the
    module path; every dotted entry additionally emits the
    slash-joined direct-sub-package twin
    (``<dep_name>/<seg0>.<rest>``) and keeps the blindly-prefixed
    twin; anything else is emitted as ``"<dep_name>.<symbol>"`` —
    operator gets module-level matching for that case.
    """
    out: list[str] = []
    es = getattr(advisory, "ecosystem_specific", None) or {}
    ds = getattr(advisory, "database_specific", None) or {}
    for source in (es, ds):
        if not isinstance(source, dict):
            continue
        for imp in source.get("imports") or []:
            if not isinstance(imp, dict):
                continue
            path = imp.get("path")
            junk_path = path is not None and not isinstance(path, str)
            symbols = imp.get("symbols") or []
            if not isinstance(symbols, list):
                # Junk-shaped container (a bare string iterates
                # char-by-char into garbage queries): one counted
                # marker instead.
                out.append(UNRESOLVED_ENTRY)
                continue
            for s in symbols:
                if not (isinstance(s, str) and s):
                    continue
                if junk_path:
                    # A junk (non-string) path admits no honest
                    # composition — dep-qualifying its symbols is a
                    # guess whose wrong readings pair NOT_CALLED and
                    # satisfy the coverage gate. Count the entry
                    # unresolved so the tier abstains instead.
                    out.append(UNRESOLVED_ENTRY)
                    continue
                head = path if isinstance(path, str) and path else dep_name
                if not head:
                    continue
                out.append(f"{head}.{s}")
    # Flat-list fallback — no per-symbol path. Blindly composing ONE
    # reading of an entry minted well-formed garbage queries the
    # resolver answers NOT_CALLED, manufacturing a false
    # high-confidence ``not_function_reachable`` on a symbol the
    # project genuinely calls. Per entry, emit the honest query for
    # EVERY plausible reading — all twins are counted and queried, so
    # whichever reading the advisory meant, the honest query is
    # present and a flat entry can never pair vacuously and mint the
    # suppression:
    #   * already fully qualified, dot-joined (``<dep_name>.<sym>``)
    #     or slash-joined sub-package path
    #     (``example.com/lib/sub.Parse`` — the canonical OSV symbol
    #     shape appearing in a flat list) → verbatim;
    #   * package-TAIL spelling (``lib.Parse`` under
    #     ``example.com/lib`` — the source-level spelling
    #     human-written advisory function lists use, since Go call
    #     sites read ``lib.Parse``) → rebind onto the module path
    #     (``example.com/lib.Parse``);
    #   * dotted head that may name a direct SUB-PACKAGE
    #     (``sub.Parse`` meaning ``example.com/lib/sub.Parse`` —
    #     realistically ``ssh.ParsePublicKey`` under
    #     ``golang.org/x/crypto``) → slash-joined twin;
    #   * every dotted entry keeps the blindly-prefixed twin
    #     (``example.com/lib.lib.Parse``) for the rare type genuinely
    #     named after its package, and bare entries get the plain
    #     module-path prefix.
    # A NESTED sub-package tail (``b.Parse`` meaning
    # ``example.com/lib/a/b.Parse``) has no statically-composable
    # honest spelling here — the refine pass closes it by deriving
    # twins from the project's own imports of this module (a project
    # can only call the function after importing its package, so the
    # import-derived twin always exists for a called function).
    #
    # Tail candidates come from the Go extractor's binding-name
    # conventions, NOT the literal last path segment alone: a
    # path-versioned module (``github.com/foo/bar/v2``) declares
    # package ``bar``, and a ``go-<name>`` repo declares its package
    # without the prefix — the literal-tail-only rebind composed
    # garbage for both classes and re-minted the suppression on
    # their source-level spellings.
    tails: list[str] = (
        [t for t in _go_bare_binding_names(dep_name) if t]
        if dep_name else []
    )
    root: str = _unversioned_root(dep_name) if dep_name else ""
    for key in ("affected_symbols", "affected_functions"):
        for source in (es, ds):
            if not isinstance(source, dict):
                continue
            v = source.get(key)
            if not (isinstance(v, list) and dep_name):
                continue
            for s in v:
                if not (isinstance(s, str) and s):
                    continue
                if s.startswith(dep_name + ".") or s.startswith(dep_name + "/"):
                    out.append(s)
                    continue
                if root and (s.startswith(root + ".")
                             or s.startswith(root + "/")):
                    spelled_rest = s[len(root):]
                    # The unversioned-root spelling names the SAME
                    # module (advisories routinely omit the /vN
                    # suffix) — respell it onto the dep's module
                    # path so the honest query exists. A remainder
                    # opening with ANOTHER version segment is a
                    # different major, not a respell target.
                    if not re.match(r"/v\d+[./]", spelled_rest):
                        out.append(s)
                        out.append(f"{dep_name}{spelled_rest}")
                        continue
                for t in tails:
                    if len(s) > len(t) + 1 and s.startswith(t + "."):
                        out.append(f"{dep_name}.{s[len(t) + 1:]}")
                seg0, _, rest = s.partition(".")
                if seg0 and rest:
                    out.append(f"{dep_name}/{seg0}.{rest}")
                out.append(f"{dep_name}.{s}")
    return out


def refine_go_verdicts(
    deps: list[Dependency],
    out: dict[str, Reachability],
    *,
    target: Path,
    go_symbol_map: dict[str, list[str]],
    inventory: dict[str, Any] | None = None,
) -> None:
    """For Go deps in ``go_symbol_map`` whose current verdict is
    ``imported``, run the function-level resolver and update
    ``out`` in-place.

    Note: Go's existing module-level path can produce
    ``likely_called`` when ``advisory_symbols`` matches via the
    regex sweep. This tier consumes the same symbols but with
    chain-resolved matching from the inventory; results are
    typically consistent. When the existing module-level path
    produced ``likely_called``, this tier doesn't fire (gated on
    ``imported`` only) so its verdict isn't overwritten.
    """
    candidates: list[Dependency] = []
    for d in deps:
        if d.ecosystem != "Go":
            continue
        current = out.get(d.key())
        if current is None or current.verdict != "imported":
            continue
        symbols = go_symbol_map.get(d.key())
        if not symbols:
            continue
        candidates.append(d)

    if not candidates:
        return

    if inventory is None:
        try:
            from core.inventory.builder import build_inventory
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                inventory = build_inventory(str(target), td)
        except Exception:                           # noqa: BLE001
            logger.warning(
                "sca.reachability.go_function_level: inventory "
                "build failed; skipping function-level tier",
                exc_info=True,
            )
            return

    from core.analysis.reachability import (
        ReachabilityResult,
        Verdict,
        function_called,
    )

    # The project's import universe — every import path the
    # call-graph pass recorded. Used to derive per-entry twins for
    # advisory spellings that name a sub-package by tail or by
    # relative dotted path: a project can only CALL a function after
    # IMPORTING its package, so for any spelling of a genuinely
    # called function the import-derived twin exists and binds — the
    # statically-composed reading can never pair vacuously alone.
    universe: set[str] = {
        v
        for f in (inventory.get("files") or [])
        for v in ((f.get("call_graph") or {}).get("imports") or {}).values()
        if isinstance(v, str) and v
    }

    # Prefer-stronger ordering for combining one entry's verdicts
    # across its reading twins: any CALLED wins outright, else any
    # UNCERTAIN, and NOT_CALLED only when every reading came back
    # not-called.
    strength = {Verdict.NOT_CALLED: 0, Verdict.UNCERTAIN: 1, Verdict.CALLED: 2}

    # Binding-name conventions per imported path (versioned modules
    # bind the pre-version segment, go-/hyphen repos bind the
    # collapsed forms) — memoised, the universe is shared across deps.
    _bare_names_cache: dict[str, list[str]] = {}

    def _bare_names(pth: str) -> list[str]:
        names = _bare_names_cache.get(pth)
        if names is None:
            names = _go_bare_binding_names(pth)
            _bare_names_cache[pth] = names
        return names

    for d in candidates:
        dep_module = d.name
        dep_root = _unversioned_root(dep_module)
        qualified_names = go_symbol_map[d.key()]
        paired = []
        for qualified in qualified_names:
            if not qualified or "." not in qualified:
                continue
            queries: list[str] = [qualified]
            # Import-derived sub-package twins (restricted to imports
            # under THIS dep's module path — a crafted entry can never
            # borrow another module's packages): for a reading
            # ``<module>.<head>.<rest>``, every imported
            # ``<module>/...`` path whose binding names contain the
            # head, or whose slash-relative path dot-spells a prefix
            # of the remainder, yields a ``<import_path>.<suffix>``
            # twin; the module-ROOT import contributes the honest
            # reading of ``<module>.<binding>.<rest>`` (the middle
            # segment being one of the module's own binding names —
            # the advisory-literal blind spelling of a /vN or go-
            # module); a BARE remainder (``<module>.<sym>``) twins
            # onto every imported sub-package, since a flat advisory
            # entry names a function that may live in any package of
            # the module. A ``<unversioned-root>.``-spelled reading
            # is the SAME dep (/vN is version selection) and is
            # respelled onto the module path first.
            rem = ""
            if dep_module and qualified.startswith(dep_module + "."):
                rem = qualified[len(dep_module) + 1:]
            elif dep_root and qualified.startswith(dep_root + "."):
                rem = qualified[len(dep_root) + 1:]
                respelled = f"{dep_module}.{rem}"
                if respelled not in queries:
                    queries.append(respelled)
            if rem:
                head, _, rest = rem.partition(".")
                for pth in universe:
                    twin: str | None = None
                    if pth == dep_module:
                        if rest and head and head in _bare_names(pth):
                            twin = f"{pth}.{rest}"
                    elif pth.startswith(dep_module + "/"):
                        rel_dot = pth[len(dep_module) + 1:].replace("/", ".")
                        if rem.startswith(rel_dot + "."):
                            suffix = rem[len(rel_dot) + 1:]
                            if suffix:
                                twin = f"{pth}.{suffix}"
                        elif rest and head and head in _bare_names(pth):
                            twin = f"{pth}.{rest}"
                        elif not rest and head:
                            twin = f"{pth}.{head}"
                    if twin and twin not in queries:
                        queries.append(twin)
            best: ReachabilityResult | None = None
            for q in queries:
                try:
                    r = function_called(inventory, q)
                except ValueError:
                    continue
                if best is None or strength[r.verdict] > strength[best.verdict]:
                    best = r
                if best.verdict == Verdict.CALLED:
                    break
            if best is None:
                continue
            paired.append((qualified, best))

        if not paired:
            continue

        verdicts = {r.verdict for _, r in paired}
        covered = len(paired) == len(qualified_names)
        if Verdict.CALLED in verdicts:
            evidence_lines: list[str] = []
            called_qns: list[str] = []
            for qn, r in paired:
                if r.verdict == Verdict.CALLED:
                    called_qns.append(qn)
                    evidence_lines.extend(
                        f"{path}:{line}" for path, line in r.evidence
                    )
            from ._host_reachability import classify_called_or_dead
            affected = ", ".join(sorted(set(called_qns)))
            out[d.key()] = classify_called_or_dead(
                inventory, evidence_lines,
                likely_called_reason=(
                    "OSV-listed affected symbol called from "
                    f"project Go source: {affected}"
                ),
                affected_summary=affected,
            )
        elif Verdict.UNCERTAIN in verdicts or not covered:
            # ``not covered``: at least one advisory entry was never
            # evaluated (unresolvable spelling / resolver refusal) —
            # claiming "all listed symbols unreached" from the
            # bindable remainder would be a false suppression. Same
            # epistemic state as UNCERTAIN → preserve the verdict.
            continue
        else:
            out[d.key()] = Reachability(
                verdict="not_function_reachable",
                confidence=Confidence(
                    "high",
                    reason=(
                        f"Go module imported but the "
                        f"{len(paired)} OSV-listed "
                        f"affected symbol(s) are not called from "
                        f"non-test Go source"
                    ),
                ),
                evidence=[],
            )


__all__ = [
    "build_go_symbol_map",
    "refine_go_verdicts",
]

