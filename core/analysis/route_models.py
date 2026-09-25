"""Framework route models — mechanical route/handler extraction.

Maps Python web-framework route registrations (Flask, Django,
FastAPI) to entry-point records that downstream consumers — the
cross-file taint engine, the authorization peer-census lane, and
``/understand --map``'s ``entry_points`` (type ``http_route``) — can
read mechanically. No parsing happens here: the raw material is the
per-file registration facts the inventory already extracts
(:mod:`core.inventory.call_graph` — ``decorated_functions`` with
``decorator_args``, ``constructed_objects``, ``string_ref_calls``,
import maps, class defs) joined with the package call graph
(:mod:`core.analysis.package_callgraph`) for handler node identity
and middleware resolution tiers.

## Why the inventory join, not callgraph decorator edges

Instance-bound decorator registrars (``@app.route(...)`` where
``app`` is an object) land in the package call graph as
``dynamic_attribute`` UNRESOLVED markers, not ``decorator`` edges —
the graph cannot type the receiver. Route extraction therefore joins
the inventory's ``decorated_functions`` facts against
``constructed_objects`` (which binds ``app`` to ``Flask(...)``) and
the import maps, and uses the graph only where it is authoritative:
handler node ids and the resolution tier of NON-registration
decorators (the middleware chain).

## Recognition is structural, never a project-name list

A registration is recognised by HOW the object was built and WHERE
the callable came from, never by variable naming conventions:

  * **Flask / FastAPI (decorator + method-call styles):** the
    receiver object's module-scope constructor chain must join,
    through the defining file's import map, to the framework's app
    factory (``flask.Flask`` / ``flask.Blueprint`` /
    ``fastapi.FastAPI`` / ``fastapi.APIRouter``). Cross-file
    receivers (``from myapp.app import app``) resolve through the
    package-scope constructed-object registry. ``add_url_rule`` /
    ``add_api_route`` method calls on such objects are the
    method-call style.
  * **Django (urlconf style):** ``path(...)`` / ``re_path(...)`` /
    legacy ``url(...)`` call sites whose callee joins through the
    import map to ``django.urls`` / ``django.conf.urls``. The
    ``urlpatterns`` variable name is never consulted — the call is
    the registration.

The only fixed vocabulary is the framework model itself (the small
structural seeds above) plus the HTTP method names — a protocol
constant, not project API.

## The middleware chain is the contract

Every route record carries ``middleware_chain``: the handler's
NON-registration decorators in source order (top → bottom — see the
position caveat below), each with a resolution tier taken
from the package call graph's decorator edges (``resolved_static`` /
``resolved_convention`` / ``heuristic_dynamic``), ``external`` for
decorators that resolve out of the analysed tree
(``login_required`` from an installed package), or ``unresolved``.
The authorization peer-census lane consumes exactly this: routes
whose peers carry an auth decorator and this one does not are
candidate findings. ``middleware_truncated`` marks chains cut by the
depth cap — a truncated chain must never be read as "no auth
decorator present".

Two consumer caveats:

  * **Decorator-style chain entries are decorator-PRESENCE facts,
    not wrapping proofs.** For a DECORATOR-style registration, an
    entry ABOVE the registration decorator in source
    (``@login_required`` above ``@app.route``) rebinds the module
    name but does NOT wrap the callable the framework registered —
    Flask captured the function produced by the decorators BELOW
    ``@app.route`` only. The chain does not record position
    relative to the registration decorator (a later series should —
    see the known-gaps note), so identical chains can differ in
    runtime protection. urlconf / method-call styles are unaffected:
    the handler reference resolves AFTER decoration, so every
    recorded entry wraps the registered callable.
  * **Class-based-view records always carry an EMPTY
    middleware_chain** (CBV method decorators are not walked) —
    peer-census consumers must exclude or special-case CBV handlers,
    never count them as unprotected peers. CBV records are marked
    ``handler_kind: "class"`` (their fallback ``handler`` ids are
    byte-shaped like function ids, so the field — not the id shape —
    is the mechanical exclusion hook).

## Consuming doctrine — originate and prioritize, never refute

Same contract as the package call graph, enforced in the API shape:
the read surface is positive-evidence only (:meth:`RouteModels.
all_routes` / :meth:`RouteModels.routes_for_file` /
:meth:`RouteModels.unresolved_routes`). There is deliberately NO
``no_routes`` / "file has no endpoints" surface: registrations this
module cannot see (dynamically composed registrars, framework
plugins, ``include()`` trees, conditional registration) mean absence
of a record is never absence of a route. Registrations it can see
but not resolve become explicit :class:`UnresolvedRoute` markers
with reasons, never silent drops.

## Attacker-controlled text

``route_pattern``, ``params[].name``, ``middleware_chain[].name``,
``handler``, and ``registration.file`` are copied from the scanned
repository — attacker-chosen bytes. Every record carries
``derived_from_target: true``; any consumer RENDERING these fields
(reports, prompts, terminal output) must escape non-printables first
(the ``core.security.log_sanitisation`` contract). This module only
ever writes them into the JSON artifact.

## Known silent gaps (no marker possible)

  * Blueprint / router MOUNT composition: a Flask blueprint's
    ``register_blueprint(bp, url_prefix=...)`` and FastAPI's
    ``app.include_router(router, prefix=...)`` prefixes are not
    joined — records carry the constructor-declared prefix
    (``Blueprint(..., url_prefix=...)`` / ``APIRouter(prefix=...)``)
    plus the local pattern only. Django ``include()`` mounts get an
    explicit marker; the included module's own routes still appear,
    un-prefixed.
  * ``methods=`` computed at runtime defaults to ``GET`` — the
    inventory records no fact for a dynamic keyword, so the default
    may understate. ``http_methods`` is a prioritization hint, never
    a verdict input.
  * FastAPI query/body parameters injected from the handler
    signature are not modelled — ``params`` lists PATH parameters
    parsed from the pattern (all three frameworks). Django
    function-based views registered without method constraints carry
    ``http_methods: []`` — meaning "not constrained at
    registration", never "no methods".
  * Class-based-view method decorators (Django CBV
    ``@method_decorator`` stacks) are not walked — CBV records
    carry an empty ``middleware_chain``.
  * Decorator-style ``middleware_chain`` entries do not record
    their position relative to the registration decorator (see the
    consumer caveats above) — position-relative recording is a
    later-series fix.
  * An in-file ``class Flask`` shadowing the framework import lets
    ``app = Flask(…)`` mint a confident record for the local class
    (hostile / broken-code shape; a wrong record here can only
    over-originate, never suppress).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.analysis.package_callgraph import (
    KIND_DECORATOR,
    CallGraphEdge,
    CallGraphNode,
    PackageCallGraph,
    build_package_callgraph,
    # Shared dotted-form conventions: module-path derivation and
    # layout-prefix aliasing must agree byte-for-byte with the graph
    # this module joins against, so the helpers are imported rather
    # than twinned.
    _module_aliases,
    _module_for_path,
    _resolve_relative_target,
)
from core.inventory.call_graph import (
    CallArgumentFacts,
    ClassDef,
    ConstructedObject,
    DecoratedFunction,
    FileCallGraph,
    StringRefCall,
)
from core.json import load_json, save_json

SCHEMA_VERSION = 1

# Default artifact filename (written next to the other run artifacts).
ROUTE_MODELS_FILENAME = "route-models.json"

# Same doctrine marker as the package call graph — serialised so
# downstream readers that never import this module see the contract.
DOCTRINE = "originate_and_prioritize_only"

# --- frameworks / registration styles ---------------------------------------

FRAMEWORK_FLASK = "flask"
FRAMEWORK_DJANGO = "django"
FRAMEWORK_FASTAPI = "fastapi"

STYLE_DECORATOR = "decorator"
STYLE_METHOD_CALL = "method_call"
STYLE_URLCONF = "urlconf"

# --- handler kinds -----------------------------------------------------------
# What the ``handler`` id points at. ``class`` marks class-based-view
# registrations (``Class.as_view()``) — their fallback handler ids are
# byte-shaped like function ids, so without this field a consumer
# cannot mechanically apply the CBV special-case the middleware-chain
# contract requires (CBV chains are always empty because the method
# decorator stacks are unwalked; counting one as an unprotected peer
# would be a false signal).

HANDLER_KIND_FUNCTION = "function"
HANDLER_KIND_CLASS = "class"

# --- param sources -----------------------------------------------------------
# The enum a consumer may see: path | query | body | header. Only
# ``path`` is emitted today (parsed from the route pattern — see the
# module docstring's known-gaps note on query/body inference).

SOURCE_PATH = "path"

# --- middleware resolution tiers ---------------------------------------------
# resolved_static / resolved_convention / heuristic_dynamic come from
# the package call graph's decorator edges; these two are route-model
# specific.

TIER_EXTERNAL = "external"
TIER_UNRESOLVED = "unresolved"

# --- unresolved-route reasons ------------------------------------------------

REASON_DYNAMIC_PATTERN = "dynamic_route_pattern"
REASON_HANDLER_UNRESOLVED = "handler_unresolved"
REASON_RECEIVER_UNRESOLVED = "receiver_unresolved"
REASON_INCLUDE_NOT_FOLLOWED = "include_not_followed"

# --- structural seeds --------------------------------------------------------
# The framework model: constructor dotted names an object must have
# been built from, and the framework registration API surface. These
# are the frameworks' OWN documented names (the thing a per-framework
# route model exists to encode), not learned project vocabulary.

# HTTP method names — protocol constants (RFC 9110 + PATCH), the one
# fixed vocabulary besides the framework APIs themselves.
_HTTP_VERBS = frozenset(
    {"get", "post", "put", "delete", "patch", "options", "head", "trace"},
)

# Constructor dotted name → (framework, prefix-kwarg name or None).
# The prefix kwarg is the constructor argument the framework
# composes into every route registered on the object
# (``Blueprint(..., url_prefix="/admin")`` / ``APIRouter(
# prefix="/v1")``).
_APP_CONSTRUCTORS: dict[str, tuple[str, str | None]] = {
    "flask.Flask": (FRAMEWORK_FLASK, None),
    "flask.Blueprint": (FRAMEWORK_FLASK, "url_prefix"),
    "fastapi.FastAPI": (FRAMEWORK_FASTAPI, None),
    "fastapi.APIRouter": (FRAMEWORK_FASTAPI, "prefix"),
}

# Django urlconf callables → pattern syntax of their first argument.
_DJANGO_URLCONF_CALLS: dict[str, str] = {
    "django.urls.path": "angle",
    "django.urls.re_path": "regex",
    "django.conf.urls.url": "regex",     # pre-2.0 legacy alias
}


@dataclass(frozen=True)
class _FrameworkModel:
    """Registration surface of one decorator-style framework."""
    framework: str
    # Decorator method names that register a route when called on a
    # framework object (verb shortcuts + the generic form).
    decorator_methods: frozenset[str]
    # Method-call registration names (``obj.<name>(pattern, ...)``).
    call_methods: frozenset[str]
    # Keyword argument carrying the handler in the method-call style.
    handler_kwarg: str
    # Route-pattern syntax: "angle" (<conv:name>) or "brace" ({name}).
    pattern_syntax: str


_FLASK_MODEL = _FrameworkModel(
    framework=FRAMEWORK_FLASK,
    # ``route`` plus the Flask ≥2.0 verb shortcuts (Flask defines
    # get/post/put/delete/patch only).
    decorator_methods=frozenset(
        {"route", "get", "post", "put", "delete", "patch"},
    ),
    call_methods=frozenset({"add_url_rule"}),
    handler_kwarg="view_func",
    pattern_syntax="angle",
)

_FASTAPI_MODEL = _FrameworkModel(
    framework=FRAMEWORK_FASTAPI,
    decorator_methods=frozenset(_HTTP_VERBS | {"api_route"}),
    call_methods=frozenset({"add_api_route"}),
    handler_kwarg="endpoint",
    pattern_syntax="brace",
)

_MODELS: dict[str, _FrameworkModel] = {
    FRAMEWORK_FLASK: _FLASK_MODEL,
    FRAMEWORK_FASTAPI: _FASTAPI_MODEL,
}

# --- bounds ------------------------------------------------------------------
# Hostile / generated repos are the norm; every accumulation is
# capped and hitting a cap degrades with an explicit ``caps_hit``
# marker plus a stat, never a failure. A capped artifact remains
# valid for origination — it covers less.

# Route records kept. Higher keeps a generated mega-API whole in one
# artifact; lower bounds the artifact and every consumer's load. Real
# hand-written services sit well under 10k registrations.
_MAX_ROUTES = 10_000

# Unresolved-route markers, total and per file. Higher keeps every
# blind spot addressable; lower stops a hostile file (thousands of
# dynamic registrations) from drowning the artifact — the full count
# survives in ``stats.unresolved_total``.
_MAX_UNRESOLVED_TOTAL = 10_000
_MAX_UNRESOLVED_PER_FILE = 200

# Middleware entries recorded per route. Higher preserves crafted
# mega-stacks exactly; lower bounds the record. Real decorator
# stacks are < 10 deep. Truncation sets ``middleware_truncated`` on
# the record — the chain is the authz contract, so a silent cut
# would read as "no auth decorator".
_MAX_MIDDLEWARE_CHAIN = 32

# Longest composed route pattern accepted. Higher admits generated
# regex monsters as routes; lower turns them into explicit
# dynamic-pattern markers (a pattern this long is either generated
# or hostile, and a marker is more honest than a truncated pattern
# that no longer matches the real URL space).
_MAX_PATTERN_LENGTH = 1024

# Path parameters parsed per route (first N kept, drop counted).
# Real routes carry < 10; the cap only bounds crafted patterns.
_MAX_PARAMS = 32

# Longest recorded param / detail strings — display-bound fields.
_MAX_PARAM_NAME = 128
_MAX_DETAIL = 200


# ---------------------------------------------------------------------------
# Artifact dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RouteParam:
    """One route parameter. ``name`` is target-derived text.
    ``source`` is one of path | query | body | header (only ``path``
    is emitted today). ``attacker_controlled`` is always True for
    emitted params — a URL path segment is caller-chosen."""
    name: str
    source: str = SOURCE_PATH
    attacker_controlled: bool = True


@dataclass(frozen=True)
class MiddlewareEntry:
    """One non-registration decorator on a handler, in source order.
    ``name`` is the decorator chain as written (target-derived).
    ``tier`` is the resolution tier — see the module docstring."""
    name: str
    tier: str


@dataclass(frozen=True)
class RouteRecord:
    """One recognised route registration.

    ``handler`` is a package-callgraph node id where resolvable,
    else the ``<file_path>::<name>@<line>`` fallback form (class-
    based views always use the fallback form — classes are not graph
    nodes). ``handler_kind`` says what the id points at:
    ``function`` (default) or ``class`` for class-based views — the
    mechanical hook for the CBV special-case (empty chains, see the
    module docstring's consumer caveats). ``http_methods`` empty
    means "not constrained at registration" (Django function views),
    never "no methods". ``derived_from_target`` covers
    ``route_pattern``, ``handler``, ``params[].name``,
    ``middleware_chain[].name`` and the registration file path —
    escape before rendering.
    """
    framework: str
    route_pattern: str
    http_methods: tuple[str, ...]
    handler: str
    params: tuple[RouteParam, ...]
    middleware_chain: tuple[MiddlewareEntry, ...]
    file_path: str
    line: int
    style: str
    middleware_truncated: bool = False
    handler_kind: str = HANDLER_KIND_FUNCTION
    derived_from_target: bool = True


@dataclass(frozen=True)
class UnresolvedRoute:
    """One registration the extractor recognised but could not turn
    into a full route record — the explicit marker that replaces a
    silent drop. ``detail`` carries a short target-derived excerpt
    (bounded; escape before rendering)."""
    file_path: str
    line: int
    reason: str
    framework: str | None = None
    detail: str = ""


@dataclass
class RouteModels:
    """Assembled route models + extraction diagnostics.

    Read surface is positive-evidence only (see the module
    docstring): there is deliberately no ``no_routes`` / per-file
    absence surface.
    """
    routes: tuple[RouteRecord, ...] = ()
    unresolved: tuple[UnresolvedRoute, ...] = ()
    caps_hit: tuple[str, ...] = ()
    stats: dict[str, int] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    # -- queries -----------------------------------------------------------

    def all_routes(self) -> tuple[RouteRecord, ...]:
        """Every recognised route. An empty result is not absence
        evidence — see the doctrine note."""
        return self.routes

    def routes_for_file(self, file_path: str) -> tuple[RouteRecord, ...]:
        """Routes REGISTERED in ``file_path`` (the registration
        site, not necessarily the handler's file). Empty for unknown
        paths; never absence evidence."""
        return tuple(r for r in self.routes if r.file_path == file_path)

    def unresolved_routes(self) -> tuple[UnresolvedRoute, ...]:
        """The explicit blind-spot markers. Read
        ``stats["unresolved_total"]`` before treating this list as
        the census — it is capped."""
        return self.unresolved

    # -- serialisation -------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "doctrine": DOCTRINE,
            "routes": [
                {
                    "framework": r.framework,
                    "route_pattern": r.route_pattern,
                    "http_methods": list(r.http_methods),
                    "handler": r.handler,
                    "params": [
                        {"name": p.name, "source": p.source,
                         "attacker_controlled": p.attacker_controlled}
                        for p in r.params
                    ],
                    "middleware_chain": [
                        {"name": m.name, "tier": m.tier}
                        for m in r.middleware_chain
                    ],
                    "registration": {
                        "file": r.file_path, "line": r.line,
                        "style": r.style,
                    },
                    **({"middleware_truncated": True}
                       if r.middleware_truncated else {}),
                    **({"handler_kind": r.handler_kind}
                       if r.handler_kind != HANDLER_KIND_FUNCTION
                       else {}),
                    "derived_from_target": r.derived_from_target,
                }
                for r in self.routes
            ],
            "unresolved_routes": [
                {
                    "file": u.file_path, "line": u.line,
                    "reason": u.reason, "framework": u.framework,
                    "detail": u.detail,
                }
                for u in self.unresolved
            ],
            "caps_hit": list(self.caps_hit),
            "stats": dict(self.stats),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RouteModels:
        def _params(raw: Any) -> tuple[RouteParam, ...]:
            return tuple(
                RouteParam(
                    name=str(p.get("name", "")),
                    source=str(p.get("source", SOURCE_PATH)),
                    attacker_controlled=bool(
                        p.get("attacker_controlled", True)),
                )
                for p in (raw if isinstance(raw, list) else [])
                if isinstance(p, dict)
            )

        def _chain(raw: Any) -> tuple[MiddlewareEntry, ...]:
            return tuple(
                MiddlewareEntry(name=str(m.get("name", "")),
                                tier=str(m.get("tier", TIER_UNRESOLVED)))
                for m in (raw if isinstance(raw, list) else [])
                if isinstance(m, dict)
            )

        stats_raw = d.get("stats")
        stats: dict[str, int] = {
            str(k): int(v)
            for k, v in (stats_raw.items()
                         if isinstance(stats_raw, dict) else ())
            if isinstance(v, (int, float)) and not isinstance(v, bool)
        }
        routes = []
        for r in (d.get("routes") or []):
            if not isinstance(r, dict):
                continue
            reg = r.get("registration")
            reg = reg if isinstance(reg, dict) else {}
            routes.append(RouteRecord(
                framework=str(r.get("framework", "")),
                route_pattern=str(r.get("route_pattern", "")),
                http_methods=_str_tuple(r.get("http_methods")),
                handler=str(r.get("handler", "")),
                params=_params(r.get("params")),
                middleware_chain=_chain(r.get("middleware_chain")),
                file_path=str(reg.get("file", "")),
                line=_as_int(reg.get("line")),
                style=str(reg.get("style", "")),
                middleware_truncated=bool(
                    r.get("middleware_truncated", False)),
                # Garbage degrades to the default — only the one
                # value consumers key their special-case on survives
                # the load (same tolerance as the other scalars).
                handler_kind=(
                    HANDLER_KIND_CLASS
                    if r.get("handler_kind") == HANDLER_KIND_CLASS
                    else HANDLER_KIND_FUNCTION
                ),
            ))
        return cls(
            routes=tuple(routes),
            unresolved=tuple(
                UnresolvedRoute(
                    file_path=str(u.get("file", "")),
                    line=_as_int(u.get("line")),
                    reason=str(u.get("reason", "")),
                    framework=(str(u["framework"])
                               if u.get("framework") is not None else None),
                    detail=str(u.get("detail", "")),
                )
                for u in (d.get("unresolved_routes") or [])
                if isinstance(u, dict)
            ),
            caps_hit=_str_tuple(d.get("caps_hit")),
            stats=stats,
            schema_version=_as_int(d.get("schema_version"),
                                   SCHEMA_VERSION),
        )

    def save(self, path: str | Path) -> None:
        """Atomic JSON write via the shared artifact primitive."""
        save_json(path, self.to_dict())


def _as_int(value: Any, default: int = 0) -> int:
    """Coerce a disk-loaded scalar; garbage degrades to the default.
    ``from_dict`` promises to tolerate hand-edited artifacts — a
    ``"line": "nope"`` must not crash every loader."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _str_tuple(value: Any) -> tuple[str, ...]:
    """String tuple from a disk-loaded value; only real sequences
    qualify — a bare string must not explode into characters."""
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return ()


def load_route_models(path: str | Path) -> RouteModels:
    """Load a saved artifact. Raises like :func:`core.json.load_json`
    on missing / unparseable files — callers decide their
    degradation."""
    data = load_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"route models artifact is not an object: {path}")
    return RouteModels.from_dict(data)


# ---------------------------------------------------------------------------
# Pattern → params
# ---------------------------------------------------------------------------

# Flask / Django ``path()`` converter syntax: ``<int:pk>`` / ``<pk>``.
_ANGLE_PARAM_RE = re.compile(r"<(?:[^<>:]*:)?([^<>]+)>")
# FastAPI brace syntax: ``{item_id}`` / ``{rest:path}``.
_BRACE_PARAM_RE = re.compile(r"\{([^{}:]+)(?::[^{}]*)?\}")
# Regex-pattern named groups: ``(?P<name>...)`` (Django re_path/url).
# The name repeat is BOUNDED at the param-name cap: an unbounded
# ``[^>]+`` before the required ``>`` is the unanchored scan-restart
# ReDoS shape (every finditer position re-scans a hostile no-``>``
# run), and a name longer than _MAX_PARAM_NAME would be truncated
# anyway — an over-long group name now yields no param at all, the
# same degradation as the extractor's over-cap literals. Group names
# are Python identifiers in real patterns (< 40 chars).
_NAMED_GROUP_RE = re.compile(r"\(\?P<([^>]{1,128})>")

_PARAM_RES = {
    "angle": _ANGLE_PARAM_RE,
    "brace": _BRACE_PARAM_RE,
    "regex": _NAMED_GROUP_RE,
}


def _params_from_pattern(
    pattern: str, syntax: str, stats: dict[str, int],
) -> tuple[RouteParam, ...]:
    """Parse the PATH parameters out of one route pattern. Names are
    target-derived text, bounded; over-cap params are dropped with a
    stat (never a partial name)."""
    rx = _PARAM_RES.get(syntax)
    if rx is None:
        return ()
    out: list[RouteParam] = []
    for m in rx.finditer(pattern):
        if len(out) >= _MAX_PARAMS:
            stats["params_dropped_cap"] = (
                stats.get("params_dropped_cap", 0) + 1)
            continue
        name = m.group(1)[:_MAX_PARAM_NAME]
        out.append(RouteParam(name=name))
    return tuple(out)


# ---------------------------------------------------------------------------
# Assembly — internal state
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FwObject:
    """One framework object binding (``app`` / ``bp`` / ``router``)."""
    framework: str
    # Constructor-declared route prefix ("" when none) — composed
    # into every pattern registered on the object, matching the
    # framework's own semantics (straight concatenation).
    prefix: str


@dataclass
class _FileFacts:
    """Per-file joined facts, typed through
    :class:`~core.inventory.call_graph.FileCallGraph`."""
    path: str
    module: str
    import_table: dict[str, str]
    decorated: list[DecoratedFunction]
    string_ref_calls: list[StringRefCall]
    constructed: dict[str, ConstructedObject]
    classes: list[ClassDef]
    # Local framework objects (same-file receivers).
    local_objects: dict[str, _FwObject] = field(default_factory=dict)
    imports_framework: bool = False


class _GraphIndex:
    """Lookup structures over the package call graph."""

    def __init__(self, graph: PackageCallGraph) -> None:
        self.nodes_by_file: dict[str, list[CallGraphNode]] = {}
        self.node_by_qual: dict[str, CallGraphNode] = {}
        self.qual_collisions = 0
        for n in graph.nodes:
            if n.kind != "function":
                continue
            self.nodes_by_file.setdefault(n.file_path, []).append(n)
            for alias in _module_aliases(n.module) if n.module else [""]:
                q = f"{alias}.{n.name}" if alias else n.name
                if q in self.node_by_qual:
                    if self.node_by_qual[q].node_id != n.node_id:
                        self.qual_collisions += 1
                    continue
                self.node_by_qual[q] = n
        # Decorator edges by (file, line): the tier source for
        # middleware entries. src of a decorator edge is the module
        # node (import-time executor).
        self.deco_edges: dict[
            tuple[str, int], list[tuple[CallGraphEdge, CallGraphNode]],
        ] = {}
        node_ids = {n.node_id: n for n in graph.nodes}
        for e in graph.edges:
            if e.kind != KIND_DECORATOR:
                continue
            src = node_ids.get(e.src)
            dst = node_ids.get(e.dst)
            if src is None or dst is None:
                continue
            for line in e.lines:
                self.deco_edges.setdefault(
                    (src.file_path, line), []).append((e, dst))
        # External-call targets by (file, line): decorators that
        # resolve out of the analysed tree.
        self.externals: dict[tuple[str, int], list[str]] = {}
        for x in graph.external_calls:
            self.externals.setdefault(
                (x.file_path, x.line), []).append(x.target)

    def node_for_def(
        self, file_path: str, bare_name: str, line: int,
    ) -> CallGraphNode | None:
        """Find the graph node for a def by file + bare name,
        preferring the exact line (method names match without their
        class prefix)."""
        candidates = [
            n for n in self.nodes_by_file.get(file_path, [])
            if n.name.rsplit(".", 1)[-1] == bare_name
        ]
        if not candidates:
            return None
        exact = [n for n in candidates if n.line == line]
        if exact:
            return exact[0]
        return min(candidates, key=lambda n: abs(n.line - line))


class _Assembler:
    """Build-time state. One instance per :func:`build_route_models`
    call; never reused."""

    def __init__(self, *, max_routes: int, max_unresolved: int) -> None:
        self.max_routes = max_routes
        self.max_unresolved = max_unresolved
        self.routes: list[RouteRecord] = []
        self.unresolved: list[UnresolvedRoute] = []
        self.caps_hit: list[str] = []
        self.stats: dict[str, int] = {}
        self.files: list[_FileFacts] = []
        self.facts_by_path: dict[str, _FileFacts] = {}
        # Package-scope registries.
        self.objects_q: dict[str, _FwObject] = {}      # dotted obj name
        self.classes_q: dict[str, tuple[str, ClassDef]] = {}  # dotted class
        self.decorated_by_file: dict[str, list[DecoratedFunction]] = {}
        # Any analysed file imports flask/fastapi. Gates the
        # receiver-unresolved markers: a views module typically
        # imports its app object, not the framework, so the per-file
        # flag alone would silence exactly the interesting case.
        self.package_imports_framework = False
        # Dotted roots of the analysed tree (incl. layout-stripped
        # aliases) — distinguishes an in-package receiver the
        # extraction failed to type (marker-worthy) from a KNOWN
        # external non-framework binding (``@mock.patch("…")`` —
        # registration-shaped by accident, exempt).
        self.module_roots: set[str] = set()
        self._per_file_unresolved = 0

    def bump(self, key: str, n: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + n

    def mark_cap(self, name: str) -> None:
        if name not in self.caps_hit:
            self.caps_hit.append(name)

    def new_file(self) -> None:
        self._per_file_unresolved = 0

    def add_route(self, record: RouteRecord) -> None:
        self.bump("routes_total")
        if len(self.routes) >= self.max_routes:
            self.mark_cap("routes")
            self.bump("routes_dropped_cap")
            return
        self.routes.append(record)

    def add_unresolved(
        self, file_path: str, line: int, reason: str,
        framework: str | None = None, detail: str = "",
    ) -> None:
        self.bump("unresolved_total")
        if (self._per_file_unresolved >= _MAX_UNRESOLVED_PER_FILE
                or len(self.unresolved) >= self.max_unresolved):
            self.mark_cap("unresolved")
            self.bump("unresolved_dropped_cap")
            return
        self._per_file_unresolved += 1
        self.unresolved.append(UnresolvedRoute(
            file_path=file_path, line=line, reason=reason,
            framework=framework, detail=detail[:_MAX_DETAIL],
        ))


def _dotted_for_chain(
    chain: list[str], import_table: dict[str, str],
) -> str | None:
    """Join a name/attribute chain through the file's import map.
    ``["views", "detail"]`` + ``{"views": "pkg.views"}`` →
    ``"pkg.views.detail"``. None when the root is not an import."""
    if not chain:
        return None
    root = chain[0]
    target = import_table.get(root)
    if target is None:
        return None
    return ".".join([target, *chain[1:]])


def _classify_constructor(
    co: ConstructedObject, import_table: dict[str, str],
) -> _FwObject | None:
    """Type one module-scope constructor binding: does its chain
    join, through the defining file's imports, to a framework app
    factory?"""
    dotted = _dotted_for_chain(co.chain, import_table)
    if dotted is None:
        return None
    entry = _APP_CONSTRUCTORS.get(dotted)
    if entry is None:
        return None
    framework, prefix_kwarg = entry
    prefix = ""
    if prefix_kwarg is not None:
        prefix = co.args.kw_strings.get(prefix_kwarg, "")
    return _FwObject(framework=framework, prefix=prefix)


def _collect_file(
    asm: _Assembler, record: dict[str, Any],
) -> None:
    """Phase 1 per file: typed facts + local framework objects.

    A record whose ``call_graph`` cannot be rebuilt (hand-corrupted
    artifact) contributes nothing — counted, never raised (the
    never-raises contract of the entry point)."""
    path = str(record.get("path") or "")
    module, is_init = _module_for_path(path)
    cg_raw = record.get("call_graph")
    if not isinstance(cg_raw, dict):
        asm.bump("files_without_facts")
        return
    try:
        cg = FileCallGraph.from_dict(cg_raw)
    except Exception:
        asm.bump("malformed_files")
        return

    # Import table: absolute entries as written, relative quads
    # resolved against this file's package (same rules as the
    # package call graph's assembler).
    import_table = {
        str(k): str(v) for k, v in cg.imports.items() if k and v
    }
    pkg_parts = module.split(".") if module else []
    if not is_init and pkg_parts:
        pkg_parts = pkg_parts[:-1]
    for level, rel_module, name, asname in cg.relative_imports:
        if level <= 0 or not name:
            continue
        target = _resolve_relative_target(
            pkg_parts, level, rel_module, name)
        if target:
            import_table[str(asname or name)] = target

    facts = _FileFacts(
        path=path, module=module, import_table=import_table,
        decorated=cg.decorated_functions,
        string_ref_calls=cg.string_ref_calls,
        constructed=cg.constructed_objects,
        classes=cg.classes,
    )
    facts.imports_framework = any(
        v.split(".", 1)[0] in (FRAMEWORK_FLASK, FRAMEWORK_FASTAPI)
        for v in import_table.values()
    )
    if facts.imports_framework:
        asm.package_imports_framework = True
    for alias in (_module_aliases(module) if module else []):
        root = alias.split(".", 1)[0]
        if root:
            asm.module_roots.add(root)

    for name, co in cg.constructed_objects.items():
        obj = _classify_constructor(co, import_table)
        if obj is not None:
            facts.local_objects[name] = obj
            for alias in _module_aliases(module) if module else [""]:
                q = f"{alias}.{name}" if alias else name
                asm.objects_q.setdefault(q, obj)

    for cdef in cg.classes:
        if "." in cdef.name:
            continue
        for alias in _module_aliases(module) if module else [""]:
            q = f"{alias}.{cdef.name}" if alias else cdef.name
            asm.classes_q.setdefault(q, (path, cdef))

    asm.decorated_by_file.setdefault(path, []).extend(
        cg.decorated_functions)
    asm.files.append(facts)
    asm.facts_by_path[path] = facts


def _receiver_known_external(
    asm: _Assembler, facts: _FileFacts, chain_prefix: list[str],
) -> bool:
    """True when a receiver chain import-joins to a binding whose
    dotted root is neither the analysed tree nor flask/fastapi — a
    KNOWN external non-framework object (``mock`` from
    ``unittest``). Such receivers are exempt from the
    receiver-unresolved markers: the binding is understood, it just
    isn't a route registrar (``@mock.patch("…")`` matches the
    registration shape by accident, hundreds of times per test
    suite). In-package receivers the extraction failed to type keep
    their marker — those ARE the blind spots."""
    dotted = _dotted_for_chain(chain_prefix, facts.import_table)
    if dotted is None:
        return False
    root = dotted.split(".", 1)[0]
    return (root not in asm.module_roots
            and root not in (FRAMEWORK_FLASK, FRAMEWORK_FASTAPI))


def _resolve_receiver(
    asm: _Assembler, facts: _FileFacts, chain_prefix: list[str],
) -> _FwObject | None:
    """Bind a decorator/method-call receiver chain to a framework
    object: same-file constructed name first, then the import join
    into the package-scope registry."""
    if not chain_prefix:
        return None
    if len(chain_prefix) == 1:
        obj = facts.local_objects.get(chain_prefix[0])
        if obj is not None:
            return obj
    dotted = _dotted_for_chain(chain_prefix, facts.import_table)
    if dotted is not None:
        return asm.objects_q.get(dotted)
    return None


# ---------------------------------------------------------------------------
# Middleware chains
# ---------------------------------------------------------------------------


def _middleware_entry(
    idx: _GraphIndex, facts: _FileFacts, line: int, chain: list[str],
) -> MiddlewareEntry:
    """Tier one non-registration decorator via the graph join at the
    def's line: a decorator EDGE gives its resolution tier; an
    external-call record whose target equals the import-joined
    dotted name gives ``external``; everything else is honest
    ``unresolved``."""
    name = ".".join(chain)
    tail = chain[-1]
    for edge, dst in idx.deco_edges.get((facts.path, line), ()):
        if dst.name.rsplit(".", 1)[-1] == tail:
            return MiddlewareEntry(name=name, tier=edge.tier)
    dotted = _dotted_for_chain(chain, facts.import_table)
    if dotted is not None:
        for target in idx.externals.get((facts.path, line), ()):
            if target == dotted:
                return MiddlewareEntry(name=name, tier=TIER_EXTERNAL)
    return MiddlewareEntry(name=name, tier=TIER_UNRESOLVED)


def _middleware_chain(
    asm: _Assembler, idx: _GraphIndex, facts: _FileFacts,
    df: DecoratedFunction, registration_indices: set[int],
) -> tuple[tuple[MiddlewareEntry, ...], bool]:
    """The handler's non-registration decorators in source order,
    tiered. Presence facts — see the module docstring's position
    caveat. Returns (chain, truncated)."""
    entries: list[MiddlewareEntry] = []
    truncated = False
    for i, chain in enumerate(df.decorators):
        if i in registration_indices or not chain:
            continue
        if len(entries) >= _MAX_MIDDLEWARE_CHAIN:
            truncated = True
            asm.bump("middleware_truncated")
            break
        entries.append(_middleware_entry(idx, facts, df.line, chain))
    asm.bump("middleware_entries", len(entries))
    return tuple(entries), truncated


def _middleware_for_handler(
    asm: _Assembler, idx: _GraphIndex, handler_file: str,
    bare_name: str, line: int,
) -> tuple[tuple[MiddlewareEntry, ...], bool]:
    """Middleware for a handler referenced by a urlconf/method-call
    registration: the decorators on the handler's own def (in ITS
    file). Registration-shaped decorators there are excluded by the
    caller's route pass already having claimed them — here every
    decorator that does not itself register on a framework object
    counts as middleware."""
    hfacts = asm.facts_by_path.get(handler_file)
    if hfacts is None:
        return (), False
    for df in asm.decorated_by_file.get(handler_file, []):
        if df.name != bare_name or df.line != line:
            continue
        reg: set[int] = set()
        for i, ch in enumerate(df.decorators):
            if len(ch) < 2:
                continue
            obj = _resolve_receiver(asm, hfacts, ch[:-1])
            # Same registration test as the decorator pass: a
            # framework-object decorator that is NOT a registration
            # method (e.g. an errorhandler) stays in the middleware
            # chain.
            if (obj is not None
                    and ch[-1] in _MODELS[obj.framework].decorator_methods):
                reg.add(i)
        return _middleware_chain(asm, idx, hfacts, df, reg)
    return (), False


# ---------------------------------------------------------------------------
# Registration strategies
# ---------------------------------------------------------------------------


def _http_methods_for(
    model: _FrameworkModel, method: str, args: CallArgumentFacts | None,
) -> tuple[str, ...]:
    """HTTP methods of one registration. Verb shortcut → that verb;
    generic form → the literal ``methods=`` list when recorded, else
    the framework default GET (see the known-gaps note on dynamic
    ``methods=``)."""
    if method in _HTTP_VERBS:
        return (method.upper(),)
    if args is not None:
        listed = args.kw_string_lists.get("methods")
        if listed:
            return tuple(m.upper() for m in listed)
    return ("GET",)


def _compose_pattern(prefix: str, pattern: str) -> str:
    """Constructor-declared prefix + local pattern — straight
    concatenation, matching Flask blueprint and FastAPI router
    semantics."""
    return f"{prefix}{pattern}" if prefix else pattern


def _emit_route(
    asm: _Assembler, *, framework: str, pattern: str, syntax: str,
    http_methods: tuple[str, ...], handler: str,
    middleware: tuple[MiddlewareEntry, ...], truncated: bool,
    file_path: str, line: int, style: str,
    handler_kind: str = HANDLER_KIND_FUNCTION,
) -> None:
    if len(pattern) > _MAX_PATTERN_LENGTH:
        # A pattern this long is generated or hostile; a truncated
        # pattern would misstate the URL space, the marker is honest.
        asm.add_unresolved(file_path, line, REASON_DYNAMIC_PATTERN,
                           framework, detail="pattern_over_length_cap")
        return
    asm.add_route(RouteRecord(
        framework=framework,
        route_pattern=pattern,
        http_methods=http_methods,
        handler=handler,
        params=_params_from_pattern(pattern, syntax, asm.stats),
        middleware_chain=middleware,
        middleware_truncated=truncated,
        file_path=file_path,
        line=line,
        style=style,
        handler_kind=handler_kind,
    ))


def _decorator_routes(
    asm: _Assembler, idx: _GraphIndex, facts: _FileFacts,
) -> None:
    """Flask / FastAPI decorator-style registrations."""
    for df in asm.decorated_by_file.get(facts.path, []):
        # Index-aligned args; records from pre-fact inventories have
        # an empty args list — zip fills None (bare-decorator shape).
        args_list: list[CallArgumentFacts | None] = list(df.decorator_args)
        if len(args_list) != len(df.decorators):
            args_list = [None] * len(df.decorators)
        registrations: list[tuple[int, _FwObject, str,
                                  CallArgumentFacts | None]] = []
        for i, chain in enumerate(df.decorators):
            if len(chain) < 2:
                continue
            obj = _resolve_receiver(asm, facts, chain[:-1])
            method = chain[-1]
            deco_args = args_list[i]
            if obj is not None:
                model = _MODELS[obj.framework]
                if method in model.decorator_methods:
                    registrations.append((i, obj, method, deco_args))
                continue
            # Registration-SHAPED decorator on an unresolvable
            # receiver in a framework-using package: the honest
            # outcome is a marker, not a guessed route and not
            # silence (this is exactly the shape the package
            # callgraph records as a dynamic_attribute marker).
            if (asm.package_imports_framework
                    and deco_args is not None
                    and deco_args.arg_count >= 1
                    and any(method in m.decorator_methods
                            for m in _MODELS.values())
                    and not _receiver_known_external(
                        asm, facts, chain[:-1])):
                asm.add_unresolved(
                    facts.path, df.line, REASON_RECEIVER_UNRESOLVED,
                    detail=".".join(chain))
        if not registrations:
            continue
        reg_indices = {i for i, _obj, _m, _a in registrations}
        middleware, truncated = _middleware_chain(
            asm, idx, facts, df, reg_indices)
        node = idx.node_for_def(facts.path, df.name, df.line)
        handler = (node.node_id if node is not None
                   else f"{facts.path}::{df.name}@{df.line}")
        asm.bump("handler_resolved_node" if node is not None
                 else "handler_fallback_id")
        for _i, obj, method, args in registrations:
            model = _MODELS[obj.framework]
            if args is None or not args.string_args \
                    or args.string_args[0][0] != 0:
                # Bare decorator, computed pattern, or over-cap
                # literal — registration seen, pattern unknowable.
                asm.add_unresolved(
                    facts.path, df.line, REASON_DYNAMIC_PATTERN,
                    obj.framework, detail=df.name)
                continue
            pattern = _compose_pattern(obj.prefix, args.string_args[0][1])
            _emit_route(
                asm, framework=obj.framework, pattern=pattern,
                syntax=model.pattern_syntax,
                http_methods=_http_methods_for(model, method, args),
                handler=handler, middleware=middleware,
                truncated=truncated, file_path=facts.path,
                line=df.line, style=STYLE_DECORATOR,
            )


def _resolve_handler_ref(
    asm: _Assembler, idx: _GraphIndex, facts: _FileFacts,
    chain: list[str],
) -> tuple[str, str, int] | None:
    """Resolve a function-reference chain (``views.detail`` /
    same-file ``handler``) to (handler_id, file, line). None when
    nothing binds."""
    if len(chain) == 1:
        for n in idx.nodes_by_file.get(facts.path, []):
            if n.name == chain[0]:
                asm.bump("handler_resolved_node")
                return n.node_id, n.file_path, n.line
    dotted = _dotted_for_chain(chain, facts.import_table)
    if dotted is not None:
        node = idx.node_by_qual.get(dotted)
        if node is not None:
            asm.bump("handler_resolved_node")
            return node.node_id, node.file_path, node.line
    return None


def _resolve_class_view(
    asm: _Assembler, facts: _FileFacts, chain: list[str],
) -> tuple[str, tuple[str, ...]] | None:
    """Resolve a ``Class.as_view()`` reference (chain WITHOUT the
    trailing ``as_view``) to (fallback handler id, verb methods
    defined on the class). Classes are not graph nodes, so the
    handler uses the ``file::Name@line`` fallback form."""
    entry: tuple[str, ClassDef] | None = None
    if len(chain) == 1:
        for cdef in facts.classes:
            if cdef.name == chain[0]:
                entry = (facts.path, cdef)
                break
    if entry is None:
        dotted = _dotted_for_chain(chain, facts.import_table)
        if dotted is not None:
            entry = asm.classes_q.get(dotted)
    if entry is None:
        return None
    path, cdef = entry
    verbs = tuple(
        m.upper() for m, _line in cdef.methods if m in _HTTP_VERBS
    )
    asm.bump("handler_class_view")
    return f"{path}::{cdef.name}@{cdef.line}", verbs


def _call_routes(
    asm: _Assembler, idx: _GraphIndex, facts: _FileFacts,
) -> None:
    """Method-call registrations (Flask ``add_url_rule`` / FastAPI
    ``add_api_route``) and Django urlconf calls."""
    for site in facts.string_ref_calls:
        chain = [str(p) for p in site.chain]
        if not chain:
            continue
        args = site.args
        pattern_lit = (args.string_args[0][1]
                       if args.string_args and args.string_args[0][0] == 0
                       else None)

        # --- Django urlconf style ------------------------------------
        dotted_callee = _dotted_for_chain(chain, facts.import_table)
        syntax = (_DJANGO_URLCONF_CALLS.get(dotted_callee)
                  if dotted_callee is not None else None)
        if syntax is not None:
            _urlconf_route(asm, idx, facts, site, pattern_lit, syntax)
            continue

        # --- Flask / FastAPI method-call style ------------------------
        if len(chain) < 2:
            continue
        method = chain[-1]
        obj = _resolve_receiver(asm, facts, chain[:-1])
        if obj is None:
            if (asm.package_imports_framework
                    and any(method in m.call_methods
                            for m in _MODELS.values())
                    and not _receiver_known_external(
                        asm, facts, chain[:-1])):
                asm.add_unresolved(
                    facts.path, site.line, REASON_RECEIVER_UNRESOLVED,
                    detail=".".join(chain))
            continue
        model = _MODELS[obj.framework]
        if method not in model.call_methods:
            continue
        if pattern_lit is None:
            asm.add_unresolved(
                facts.path, site.line, REASON_DYNAMIC_PATTERN,
                obj.framework, detail=".".join(chain))
            continue
        handler_chain = (args.kw_refs.get(model.handler_kwarg)
                         or _first_positional_ref(args))
        middleware: tuple[MiddlewareEntry, ...] = ()
        truncated = False
        resolved: tuple[str, str, int] | None = None
        bare = ""
        if handler_chain is not None:
            resolved = _resolve_handler_ref(asm, idx, facts,
                                            list(handler_chain))
            bare = handler_chain[-1]
        if resolved is None:
            # Also accept the class-view form
            # (``view_func=V.as_view(...)`` / positional call ref).
            cls_chain = (args.kw_call_refs.get(model.handler_kwarg)
                         or _first_positional_call_ref(args))
            if cls_chain is not None and cls_chain[-1] == "as_view":
                cls = _resolve_class_view(asm, facts, cls_chain[:-1])
                if cls is not None:
                    handler_id, verbs = cls
                    _emit_route(
                        asm, framework=obj.framework,
                        pattern=_compose_pattern(obj.prefix, pattern_lit),
                        syntax=model.pattern_syntax,
                        http_methods=verbs or ("GET",),
                        handler=handler_id, middleware=(),
                        truncated=False, file_path=facts.path,
                        line=site.line, style=STYLE_METHOD_CALL,
                        handler_kind=HANDLER_KIND_CLASS,
                    )
                    continue
            asm.add_unresolved(
                facts.path, site.line, REASON_HANDLER_UNRESOLVED,
                obj.framework, detail=".".join(chain))
            continue
        handler_id, hfile, hline = resolved
        middleware, truncated = _middleware_for_handler(
            asm, idx, hfile, bare, hline)
        _emit_route(
            asm, framework=obj.framework,
            pattern=_compose_pattern(obj.prefix, pattern_lit),
            syntax=model.pattern_syntax,
            http_methods=_http_methods_for(model, "", args),
            handler=handler_id, middleware=middleware,
            truncated=truncated, file_path=facts.path,
            line=site.line, style=STYLE_METHOD_CALL,
        )


def _first_positional_ref(
    args: CallArgumentFacts,
) -> list[str] | None:
    """First name/attribute-chain argument past the pattern slot."""
    for pos, chain in args.ref_args:
        if pos >= 1:
            return chain
    return None


def _first_positional_call_ref(
    args: CallArgumentFacts,
) -> list[str] | None:
    for pos, chain in args.call_ref_args:
        if pos >= 1:
            return chain
    return None


def _urlconf_route(
    asm: _Assembler, idx: _GraphIndex, facts: _FileFacts,
    site: StringRefCall, pattern_lit: str | None, syntax: str,
) -> None:
    """One Django ``path()`` / ``re_path()`` / legacy ``url()``
    registration."""
    args = site.args
    if pattern_lit is None:
        asm.add_unresolved(
            facts.path, site.line, REASON_DYNAMIC_PATTERN,
            FRAMEWORK_DJANGO, detail=".".join(site.chain))
        return

    # ``include(...)`` mounts a sub-urlconf — an explicit marker;
    # the included module's own registrations are extracted
    # separately (un-prefixed, see the known-gaps note).
    call_ref = _first_positional_call_ref(args)
    if call_ref is not None and call_ref[-1] == "include":
        asm.add_unresolved(
            facts.path, site.line, REASON_INCLUDE_NOT_FOLLOWED,
            FRAMEWORK_DJANGO, detail=pattern_lit)
        return

    # Class-based view: ``Views.ItemView.as_view()``.
    if call_ref is not None and call_ref[-1] == "as_view":
        cls = _resolve_class_view(asm, facts, call_ref[:-1])
        if cls is None:
            asm.add_unresolved(
                facts.path, site.line, REASON_HANDLER_UNRESOLVED,
                FRAMEWORK_DJANGO, detail=".".join(call_ref))
            return
        handler_id, verbs = cls
        _emit_route(
            asm, framework=FRAMEWORK_DJANGO, pattern=pattern_lit,
            syntax=syntax,
            # Empty = not constrained at registration (the CBV
            # defines no verb methods this extractor can see) —
            # never "no methods".
            http_methods=verbs,
            handler=handler_id, middleware=(), truncated=False,
            file_path=facts.path, line=site.line, style=STYLE_URLCONF,
            handler_kind=HANDLER_KIND_CLASS,
        )
        return

    handler_chain = _first_positional_ref(args)
    if handler_chain is None:
        asm.add_unresolved(
            facts.path, site.line, REASON_HANDLER_UNRESOLVED,
            FRAMEWORK_DJANGO, detail=".".join(site.chain))
        return
    resolved = _resolve_handler_ref(asm, idx, facts, list(handler_chain))
    if resolved is None:
        asm.add_unresolved(
            facts.path, site.line, REASON_HANDLER_UNRESOLVED,
            FRAMEWORK_DJANGO, detail=".".join(handler_chain))
        return
    handler_id, hfile, hline = resolved
    middleware, truncated = _middleware_for_handler(
        asm, idx, hfile, handler_chain[-1], hline)
    _emit_route(
        asm, framework=FRAMEWORK_DJANGO, pattern=pattern_lit,
        syntax=syntax,
        # Function-based views: no method constraint at registration.
        http_methods=(),
        handler=handler_id, middleware=middleware, truncated=truncated,
        file_path=facts.path, line=site.line, style=STYLE_URLCONF,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _is_python_record(record: dict[str, Any]) -> bool:
    if record.get("language") == "python":
        return True
    path = str(record.get("path") or "")
    return path.endswith((".py", ".pyi"))


def build_route_models(
    inventory: dict[str, Any],
    callgraph: PackageCallGraph | None = None,
    *,
    max_routes: int = _MAX_ROUTES,
    max_unresolved: int = _MAX_UNRESOLVED_TOTAL,
) -> RouteModels:
    """Assemble the framework route models from an inventory
    artifact (the :func:`core.inventory.build_inventory` dict shape).

    ``callgraph`` is the package call graph over the SAME inventory;
    when omitted it is built here (handler node ids and middleware
    tiers come from it, so the two artifacts must agree).

    Never raises on malformed records — a file whose facts are
    missing or misshapen contributes nothing (counted in ``stats``),
    and every bound hit is reported through ``caps_hit`` + ``stats``.
    See the module docstring for the consuming doctrine.
    """
    if callgraph is None:
        callgraph = build_package_callgraph(inventory)
    idx = _GraphIndex(callgraph)

    asm = _Assembler(max_routes=max_routes, max_unresolved=max_unresolved)
    records = [r for r in (inventory.get("files") or [])
               if isinstance(r, dict)]
    asm.stats["files_seen"] = len(records)
    for record in sorted(records, key=lambda r: str(r.get("path") or "")):
        if not _is_python_record(record):
            continue
        asm.bump("files_python")
        _collect_file(asm, record)

    for facts in asm.files:
        asm.new_file()
        if facts.imports_framework or facts.string_ref_calls:
            asm.bump("files_candidate")
        _decorator_routes(asm, idx, facts)
        _call_routes(asm, idx, facts)

    if idx.qual_collisions:
        asm.stats["qual_collisions"] = idx.qual_collisions
    asm.stats["routes"] = len(asm.routes)

    return RouteModels(
        routes=tuple(sorted(
            asm.routes,
            key=lambda r: (r.file_path, r.line, r.route_pattern,
                           r.framework),
        )),
        unresolved=tuple(sorted(
            asm.unresolved,
            key=lambda u: (u.file_path, u.line, u.reason),
        )),
        caps_hit=tuple(asm.caps_hit),
        stats=asm.stats,
    )


__all__ = [
    "DOCTRINE",
    "FRAMEWORK_DJANGO",
    "FRAMEWORK_FASTAPI",
    "FRAMEWORK_FLASK",
    "HANDLER_KIND_CLASS",
    "HANDLER_KIND_FUNCTION",
    "REASON_DYNAMIC_PATTERN",
    "REASON_HANDLER_UNRESOLVED",
    "REASON_INCLUDE_NOT_FOLLOWED",
    "REASON_RECEIVER_UNRESOLVED",
    "ROUTE_MODELS_FILENAME",
    "SCHEMA_VERSION",
    "SOURCE_PATH",
    "STYLE_DECORATOR",
    "STYLE_METHOD_CALL",
    "STYLE_URLCONF",
    "TIER_EXTERNAL",
    "TIER_UNRESOLVED",
    "MiddlewareEntry",
    "RouteModels",
    "RouteParam",
    "RouteRecord",
    "UnresolvedRoute",
    "build_route_models",
    "load_route_models",
]
