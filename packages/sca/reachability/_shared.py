"""Shared helpers for the per-ecosystem reachability tiers.

Small, pure functions that recur byte-for-byte across the
per-ecosystem modules (``cargo_function_level``,
``rubygems_function_level``, ``python.py``, ``nuget.py``, ...).
Consolidated here so the copies can't drift. (``python.py`` and
``nodejs.py`` still carry local ``_format_evidence`` variants with a
different overflow-marker text — not yet migrated.)

Deliberately NOT here: the per-ecosystem variants that look similar
but differ behaviourally — e.g. ``go_function_level`` /
``java_function_level`` / ``nuget_function_level`` each carry their
own qualified-symbol extraction with ecosystem-specific separator
and fallback rules. Those stay local until someone does the semantic
unification.
"""

from __future__ import annotations

import re
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

# A name the cross-language resolver can actually bind as a
# namespace-chain prefix: dotted identifier segments. Composer
# ``vendor/pkg`` names (slash), Maven ``group:artifact`` coordinates
# (colon), and hyphenated crate spellings all fail this shape — the
# resolver splits on "." and binds the head against imports, so a
# prefix in any of those spellings guarantees NOT_CALLED.
_NAMESPACE_HEAD_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
)

# Placeholder emitted for an advisory function entry that has NO
# resolver-bindable spelling (a bare symbol under a non-namespace dep
# name, a symbol under a malformed imports path, Java flat-list
# entries, ...). The refine passes never query it — it is dot-less by
# construction, so the existing "not dotted → skip" guard drops it
# from pairing — but its PRESENCE keeps the entry counted: a tier may
# only downgrade to ``not_function_reachable`` when EVERY advisory
# entry was actually evaluated, and silently discarding unbindable
# entries manufactured exactly the false high-confidence suppression
# the shape-parametrised tests pin. The NUL prefix keeps any
# legitimate advisory string from colliding; a hostile advisory that
# ships the literal marker only BLOCKS a downgrade (fail-safe).
UNRESOLVED_ENTRY = "\x00unresolved-advisory-entry"


def _normalise_qualified(name: str) -> str:
    r"""Map Rust ``::``, Ruby ``#``, and PHP ``\`` qualifier
    separators to dots.

    The cross-language resolver (``core.analysis.reachability
    .function_called``) splits qualified names on ``.`` only, so a
    ``SmallVec::insert_many``, ``Mapper#draw``, or
    ``Symfony\Component\HttpFoundation\Request::create`` symbol left
    verbatim could never match any call chain — it would read as a
    single opaque segment (or a segment carrying embedded
    backslashes) and silently guarantee NOT_CALLED, minting a false
    high-confidence ``not_function_reachable`` downgrade.
    """
    return (
        name.replace("::", ".").replace("#", ".").replace("\\", ".")
    )


def extract_qualified_symbols(
    advisory: Any, dep_name: str, *, dep_is_namespace_head: bool = True,
    head_fold: Callable[[str], list[str]] | None = None,
    fold_is_exact: bool = False,
) -> list[str]:
    """Pull qualified affected-symbol names out of an OSV advisory.

    Handles the three shapes seen in real OSV records:

      * ``imports[].symbols`` (mirrors the Go convention) — each
        symbol is qualified with the import's ``path`` when the
        normalised path has the dotted-identifier shape the resolver
        can bind; a path that fails that grammar (hyphenated /
        slashed / coordinate spellings) yields the counted
        :data:`UNRESOLVED_ENTRY` marker per symbol instead — a
        composed unbindable prefix would pair NOT_CALLED and satisfy
        the coverage gate, minting the exact false suppression the
        marker exists to block. When the record omits the path the
        flat-list policy below applies.
      * ``affects.functions`` — the RustSec convention (the dominant
        Rust advisory producer): fully-qualified
        ``crate::Type::method`` strings (live OSV export shape, e.g.
        RUSTSEC-2021-0003). Same emit policy as the flat lists after
        separator normalisation.
      * Flat ``affected_symbols`` / ``affected_functions`` lists —
        emitted so that every name the resolver receives is BINDABLE:
        an already-qualified symbol is emitted verbatim (normalised),
        with a ``dep_name.``-prefixed variant added only when the dep
        name can head a namespace chain; a bare symbol is emitted
        under such a prefix, or as :data:`UNRESOLVED_ENTRY` when no
        bindable spelling exists (so the entry stays COUNTED — the
        refine passes refuse the ``not_function_reachable`` downgrade
        while any advisory entry went unevaluated). Unconditional
        ``dep_name.symbol`` minting produced names like
        ``symfony/http-foundation.Symfony.Component...`` and
        ``actionpack.ActionDispatch...`` that the resolver's
        dot-split import binding can never match — every one paired
        as NOT_CALLED and manufactured a false high-confidence
        ``not_function_reachable`` suppression.

    ``dep_is_namespace_head`` is the per-ecosystem contract: True
    where the package name heads real code namespaces (Rust crates,
    NuGet root namespaces, Python distributions ≈ modules), False
    where it never does (RubyGems gem names, Composer vendor/pkg) —
    mirrors java_function_level's documented flat-arm refusal for
    Maven coordinates. Even when True, a prefix is added only if the
    dep name has the dotted-identifier shape and would not
    double-prefix an already-qualified symbol.

    ``head_fold`` supplies per-ecosystem respellings tried when the
    raw head fails the grammar (consulted for the dep head under
    ``dep_is_namespace_head`` and for ``imports[].path`` values):
    grammar-passing fold candidates are composed as queries.
    ``fold_is_exact`` declares whether the fold is a LANGUAGE RULE
    (Cargo's ``-``→``_``: crate ``foo-bar`` is imported as
    ``foo_bar``, deterministically) or a naming CONVENTION (NuGet's
    dash collapse). An exact fold replaces the unresolved marker
    outright — both the upgrade and the honest-downgrade arms work
    through it. A convention fold emits its readings as
    UPGRADE-ONLY twins and keeps the marker: a called function binds
    through the guessed spelling, but a wrong guess pairing
    NOT_CALLED can never satisfy the coverage gate into the
    high-confidence downgrade.

    Both ``ecosystem_specific`` and ``database_specific`` are
    consulted. Non-dict sources and non-string / empty symbols are
    skipped. Rust ``::``, Ruby ``#``, and PHP ``\\`` separators are
    normalised to ``.`` so the resolver's dot-split chain matching
    can see the individual segments.
    """
    dep_head = _normalise_qualified(dep_name) if dep_name else ""
    prefix_ok = bool(
        dep_is_namespace_head
        and dep_head
        and _NAMESPACE_HEAD_RE.fullmatch(dep_head)
    )

    def _folds(head: str) -> list[str]:
        """Grammar-passing fold candidates for a head that failed
        the grammar raw (deduped, order preserved)."""
        if not (head_fold and head):
            return []
        return list(dict.fromkeys(
            h for h in head_fold(head)
            if h and _NAMESPACE_HEAD_RE.fullmatch(h)
        ))

    dep_folds = (
        _folds(dep_head)
        if dep_is_namespace_head and not prefix_ok else []
    )

    def _emit(sym: str, out: list[str]) -> None:
        ns = _normalise_qualified(sym)
        if "." in ns:
            out.append(ns)
            if prefix_ok and not ns.startswith(dep_head + "."):
                out.append(f"{dep_head}.{ns}")
            else:
                out.extend(
                    f"{h}.{ns}" for h in dep_folds
                    if not ns.startswith(h + ".")
                )
        elif prefix_ok:
            out.append(f"{dep_head}.{ns}")
        elif dep_folds:
            # Folded head(s): compose the respelled queries; a
            # convention fold additionally keeps the marker so a
            # wrong guess can only block the downgrade, never
            # enable it.
            out.extend(f"{h}.{ns}" for h in dep_folds)
            if not fold_is_exact:
                out.append(UNRESOLVED_ENTRY)
        else:
            # A bare symbol under a non-namespace dep name has no
            # bindable spelling — minting an unbindable prefix here
            # would only manufacture NOT_CALLED pairs. Emit the
            # unresolved marker instead of dropping the entry: the
            # advisory DID name this function, so the tier must not
            # claim "every listed function is unreached" from the
            # bindable remainder alone.
            out.append(UNRESOLVED_ENTRY)

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
            if path is not None and not isinstance(path, str):
                # Malformed entry — never dep-qualify junk, but its
                # string symbols still name advisory functions this
                # tier cannot evaluate: mark them unresolved so the
                # downgrade arm abstains instead of suppressing.
                for s in imp.get("symbols") or []:
                    if isinstance(s, str) and s:
                        out.append(UNRESOLVED_ENTRY)
                continue
            symbols = imp.get("symbols") or []
            path_head = _normalise_qualified(path) if path else ""
            path_ok = bool(
                path_head and _NAMESPACE_HEAD_RE.fullmatch(path_head)
            )
            path_folds = _folds(path_head) if not path_ok else []
            for s in symbols:
                if not (isinstance(s, str) and s):
                    continue
                if path_ok:
                    out.append(f"{path_head}.{_normalise_qualified(s)}")
                elif path_folds:
                    # The path names the package in its ecosystem
                    # spelling — the same fold applies, with the same
                    # exact/convention split as the dep head.
                    ns = _normalise_qualified(s)
                    out.extend(f"{h}.{ns}" for h in path_folds)
                    if not fold_is_exact:
                        out.append(UNRESOLVED_ENTRY)
                elif path:
                    # A string path that fails the resolver's
                    # dotted-identifier grammar even after separator
                    # normalisation (hyphenated / slashed / coordinate
                    # spellings) composes a guaranteed-NOT_CALLED
                    # query — the same silent-suppression mechanism
                    # as unconditional dep-name minting, one arm
                    # over. Count the entry unresolved instead.
                    out.append(UNRESOLVED_ENTRY)
                else:
                    _emit(s, out)
        for key in ("affected_symbols", "affected_functions"):
            v = source.get(key)
            if isinstance(v, list) and dep_name:
                for s in v:
                    if isinstance(s, str) and s:
                        _emit(s, out)
        # RustSec convention: ``affects.functions``.
        affects = source.get("affects")
        if isinstance(affects, dict) and dep_name:
            v = affects.get("functions")
            if isinstance(v, list):
                for s in v:
                    if isinstance(s, str) and s:
                        _emit(s, out)
    return out


def extract_function_names(advisory: Any) -> list[str]:
    """Pull bare (unqualified) function names out of an OSV advisory.

    Tries every shape seen in real OSV PyPI / npm records — schema
    variation is high: some GHSAs use
    ``database_specific.affected_functions``, others
    ``ecosystem_specific.imports[].symbols`` mirroring Go's
    convention, others inline structured data. Both
    ``ecosystem_specific`` and ``database_specific`` are consulted;
    callers dedupe.
    """
    out: list[str] = []
    es = getattr(advisory, "ecosystem_specific", None) or {}
    ds = getattr(advisory, "database_specific", None) or {}
    # ``imports[].symbols`` shape (mirrors Go convention).
    for source in (es, ds):
        if not isinstance(source, dict):
            continue
        for imp in source.get("imports") or []:
            if not isinstance(imp, dict):
                continue
            syms = imp.get("symbols") or []
            out.extend(s for s in syms if isinstance(s, str) and s)
    # Flat-list variants. Empty strings are schema junk that names no
    # function — excluded so they can neither pair as NOT_CALLED nor
    # block a downgrade under the full-coverage gate.
    for key in ("affected_symbols", "affected_functions"):
        for source in (es, ds):
            if not isinstance(source, dict):
                continue
            v = source.get(key)
            if isinstance(v, list):
                out.extend(s for s in v if isinstance(s, str) and s)
    return out


def format_evidence(
    hits: list[tuple[Path, int, bool]],
    *,
    target: Path | None,
    cap: int = 5,
) -> list[str]:
    """Format scan hits as compact ``file:line`` evidence strings.

    Paths under ``target`` are shown relative to it; the list is
    capped at ``cap`` entries with a ``... (+N more)`` marker when
    hits overflow.
    """
    out: list[str] = []
    for f, line, _ in hits[:cap]:
        rel = (f.relative_to(target) if target and target in f.parents
                else f)
        out.append(f"{rel}:{line}")
    if len(hits) > cap:
        out.append(f"... (+{len(hits) - cap} more)")
    return out
