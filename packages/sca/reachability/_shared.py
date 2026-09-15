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
) -> list[str]:
    """Pull qualified affected-symbol names out of an OSV advisory.

    Handles the two shapes seen in real OSV records:

      * ``imports[].symbols`` (mirrors the Go convention) — each
        symbol is qualified with the import's ``path``; when the
        record omits it the flat-list policy below applies.
      * Flat ``affected_symbols`` / ``affected_functions`` lists —
        emitted so that every name the resolver receives is BINDABLE:
        an already-qualified symbol is emitted verbatim (normalised),
        with a ``dep_name.``-prefixed variant added only when the dep
        name can head a namespace chain; a bare symbol is emitted
        only under such a prefix. Unconditional ``dep_name.symbol``
        minting produced names like
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

    def _emit(sym: str, out: list[str]) -> None:
        ns = _normalise_qualified(sym)
        if "." in ns:
            out.append(ns)
            if prefix_ok and not ns.startswith(dep_head + "."):
                out.append(f"{dep_head}.{ns}")
        elif prefix_ok:
            out.append(f"{dep_head}.{ns}")
        # A bare symbol under a non-namespace dep name has no
        # bindable spelling — the bare-name lane
        # (extract_function_names) covers it; minting an unbindable
        # prefix here would only manufacture NOT_CALLED pairs.

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
                continue  # malformed entry — never dep-qualify junk
            symbols = imp.get("symbols") or []
            for s in symbols:
                if not (isinstance(s, str) and s):
                    continue
                if path:
                    out.append(_normalise_qualified(f"{path}.{s}"))
                else:
                    _emit(s, out)
        for key in ("affected_symbols", "affected_functions"):
            v = source.get(key)
            if isinstance(v, list) and dep_name:
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
            out.extend(s for s in syms if isinstance(s, str))
    # Flat-list variants.
    for key in ("affected_symbols", "affected_functions"):
        for source in (es, ds):
            if not isinstance(source, dict):
                continue
            v = source.get(key)
            if isinstance(v, list):
                out.extend(s for s in v if isinstance(s, str))
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
