"""Tests for :mod:`core.analysis.route_models`.

The fixture packages (``fixtures/route_models/``) carry one
registration per recognition class for each framework; the inventory
records are built with the REAL inventory extractors
(``PythonExtractor`` + ``extract_call_graph_python``) so the tests
pin the whole facts → recognition → record chain. The frameworks
themselves are never imported — extraction is purely static.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.analysis.package_callgraph import (
    TIER_RESOLVED_STATIC,
    build_package_callgraph,
)
from core.analysis.route_models import (
    DOCTRINE,
    FRAMEWORK_DJANGO,
    FRAMEWORK_FASTAPI,
    FRAMEWORK_FLASK,
    REASON_DYNAMIC_PATTERN,
    REASON_HANDLER_UNRESOLVED,
    REASON_INCLUDE_NOT_FOLLOWED,
    REASON_RECEIVER_UNRESOLVED,
    STYLE_DECORATOR,
    STYLE_METHOD_CALL,
    STYLE_URLCONF,
    TIER_EXTERNAL,
    TIER_UNRESOLVED,
    RouteModels,
    build_route_models,
    load_route_models,
)
from core.inventory.call_graph import extract_call_graph_python
from core.inventory.extractors import PythonExtractor

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "route_models"


def _record_for(rel_path: str, content: str) -> dict:
    """One inventory file record, built with the real extractors —
    the same shape the inventory builder writes."""
    items = [i.to_dict() for i in PythonExtractor().extract(rel_path, content)]
    return {
        "path": rel_path,
        "language": "python",
        "items": items,
        "call_graph": extract_call_graph_python(content).to_dict(),
    }


def _build_inventory(root: Path) -> dict:
    files = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        files.append(_record_for(rel, path.read_text(encoding="utf-8")))
    return {"files": files}


def _inventory_from_sources(sources: dict[str, str]) -> dict:
    return {"files": [_record_for(p, s) for p, s in sorted(sources.items())]}


@pytest.fixture(scope="module")
def models() -> RouteModels:
    return build_route_models(_build_inventory(FIXTURE_ROOT))


def _route(models: RouteModels, pattern: str):
    matches = [r for r in models.routes if r.route_pattern == pattern]
    assert len(matches) == 1, (
        f"expected exactly one route {pattern!r}, got {matches}"
    )
    return matches[0]


def _markers(models: RouteModels, reason: str):
    return [u for u in models.unresolved if u.reason == reason]


# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------


class TestFlask:
    def test_decorator_route_full_record(self, models):
        r = _route(models, "/users/<int:uid>")
        assert r.framework == FRAMEWORK_FLASK
        assert r.http_methods == ("GET", "POST")
        assert r.style == STYLE_DECORATOR
        assert r.file_path == "miniflask/app.py"
        assert r.handler.startswith("miniflask/app.py::user@")
        assert r.derived_from_target is True

    def test_path_params_attacker_controlled(self, models):
        r = _route(models, "/users/<int:uid>")
        assert [(p.name, p.source, p.attacker_controlled)
                for p in r.params] == [("uid", "path", True)]

    def test_middleware_chain_with_graph_tier(self, models):
        """The non-registration decorator rides the record with the
        package callgraph's resolution tier."""
        r = _route(models, "/users/<int:uid>")
        assert [(m.name, m.tier) for m in r.middleware_chain] == [
            ("require_auth", TIER_RESOLVED_STATIC),
        ]
        assert r.middleware_truncated is False

    def test_verb_shortcut(self, models):
        r = _route(models, "/health")
        assert r.http_methods == ("GET",)
        assert r.style == STYLE_DECORATOR

    def test_blueprint_prefix_composed(self, models):
        """``Blueprint(..., url_prefix="/admin")`` composes into the
        registered pattern."""
        r = _route(models, "/admin/panel")
        assert r.framework == FRAMEWORK_FLASK
        assert r.handler.startswith("miniflask/app.py::panel@")

    def test_add_url_rule_method_call_style(self, models):
        r = _route(models, "/legacy")
        assert r.style == STYLE_METHOD_CALL
        assert r.handler.startswith("miniflask/app.py::legacy_view@")

    def test_cross_file_receiver(self, models):
        """``from miniflask.app import app`` — the receiver resolves
        through the package-scope constructed-object registry."""
        r = _route(models, "/cross")
        assert r.framework == FRAMEWORK_FLASK
        assert r.file_path == "miniflask/views.py"
        assert r.handler.startswith("miniflask/views.py::cross@")

    def test_dynamic_pattern_marker(self, models):
        """``@app.route(BASE + "/dyn")`` — registration recognised,
        pattern unknowable → explicit marker, never a guessed
        route."""
        marks = [u for u in _markers(models, REASON_DYNAMIC_PATTERN)
                 if u.file_path == "miniflask/app.py"]
        assert len(marks) == 1
        assert marks[0].framework == FRAMEWORK_FLASK
        assert not any("/dyn" in r.route_pattern for r in models.routes)


# ---------------------------------------------------------------------------
# Django
# ---------------------------------------------------------------------------


class TestDjango:
    def test_path_route(self, models):
        r = _route(models, "items/<int:pk>/")
        assert r.framework == FRAMEWORK_DJANGO
        assert r.style == STYLE_URLCONF
        assert r.file_path == "minidjango/urls.py"
        assert r.handler.startswith("minidjango/views.py::detail@")
        # Function views carry no method constraint at registration —
        # empty means "not constrained", never "no methods".
        assert r.http_methods == ()
        assert [p.name for p in r.params] == ["pk"]

    def test_referenced_handler_middleware(self, models):
        """The handler's own decorators (in its OWN file) are the
        middleware chain for urlconf registrations."""
        r = _route(models, "items/<int:pk>/")
        assert [(m.name, m.tier) for m in r.middleware_chain] == [
            ("login_required", TIER_RESOLVED_STATIC),
        ]

    def test_re_path_named_groups(self, models):
        r = _route(models, "^archive/(?P<year>[0-9]{4})/$")
        assert [p.name for p in r.params] == ["year"]
        assert r.handler.startswith("minidjango/views.py::archive@")

    def test_class_view_fallback_handler_and_verbs(self, models):
        """CBVs are not graph nodes — the handler uses the
        ``file::Name@line`` fallback form; methods come from the
        verb-named methods the class defines."""
        r = _route(models, "cls/")
        assert r.handler.startswith("minidjango/views.py::ItemView@")
        assert r.http_methods == ("GET", "POST")

    def test_include_marker(self, models):
        marks = _markers(models, REASON_INCLUDE_NOT_FOLLOWED)
        assert len(marks) == 1
        assert marks[0].file_path == "minidjango/urls.py"
        assert marks[0].detail == "nested/"


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------


class TestFastAPI:
    def test_verb_decorator_with_brace_param(self, models):
        r = _route(models, "/items/{item_id}")
        assert r.framework == FRAMEWORK_FASTAPI
        assert r.http_methods == ("GET",)
        assert [p.name for p in r.params] == ["item_id"]

    def test_router_prefix_composed(self, models):
        r = _route(models, "/v1/orders")
        assert r.http_methods == ("POST",)
        assert r.handler.startswith("minifastapi/app.py::create_order@")

    def test_api_route_methods_list(self, models):
        r = _route(models, "/multi")
        assert r.http_methods == ("GET", "PUT")


# ---------------------------------------------------------------------------
# Doctrine / read API
# ---------------------------------------------------------------------------


class TestDoctrine:
    def test_artifact_carries_doctrine_marker(self, models):
        assert models.to_dict()["doctrine"] == DOCTRINE

    def test_no_absence_surface(self, models):
        """The read API is positive-evidence only: there is
        deliberately no no-routes / dead-endpoint verdict surface."""
        for forbidden in ("no_routes", "files_without_routes",
                          "has_no_routes", "routes_absent"):
            assert not hasattr(models, forbidden)

    def test_routes_for_file_is_registration_site(self, models):
        files = {r.file_path
                 for r in models.routes_for_file("minidjango/urls.py")}
        assert files == {"minidjango/urls.py"}
        assert models.routes_for_file("nonexistent.py") == ()

    def test_all_routes_and_unresolved_accessors(self, models):
        assert models.all_routes() == models.routes
        assert models.unresolved_routes() == models.unresolved
        assert models.stats["unresolved_total"] == len(models.unresolved)

    def test_explicit_callgraph_matches_implicit(self, models):
        inv = _build_inventory(FIXTURE_ROOT)
        g = build_package_callgraph(inv)
        assert build_route_models(inv, g).to_dict() == models.to_dict()

    def test_deterministic(self, models):
        again = build_route_models(_build_inventory(FIXTURE_ROOT))
        assert again.to_dict() == models.to_dict()


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


class TestSerialisation:
    def test_round_trip(self, models):
        assert RouteModels.from_dict(models.to_dict()).to_dict() \
            == models.to_dict()

    def test_save_load(self, models, tmp_path):
        path = tmp_path / "route-models.json"
        models.save(path)
        assert load_route_models(path).to_dict() == models.to_dict()

    def test_registration_block_shape(self, models):
        d = models.to_dict()
        for r in d["routes"]:
            assert set(r["registration"]) == {"file", "line", "style"}
            assert r["derived_from_target"] is True

    def test_from_dict_tolerates_garbage(self):
        rm = RouteModels.from_dict({
            "routes": [None, 42, {"registration": "nope",
                                  "params": "x",
                                  "middleware_chain": 7}],
            "unresolved_routes": ["x", {}],
            "stats": {"a": "NaNish", "b": 3, "c": True},
            "caps_hit": None,
        })
        assert len(rm.routes) == 1
        assert rm.routes[0].file_path == ""
        assert len(rm.unresolved) == 1
        assert rm.stats == {"b": 3}

    def test_from_dict_tolerates_garbage_scalars(self):
        """A hand-edited artifact with string scalars where numbers
        or lists belong must load, not crash every consumer."""
        rm = RouteModels.from_dict({
            "schema_version": "two",
            "caps_hit": "routes",         # bare string, not a list —
            "routes": [{                  # must not become chars
                "registration": {"file": "a.py", "line": "nope"},
                "http_methods": "GET",
            }],
            "unresolved_routes": [{"file": "b.py", "line": "?"}],
            "stats": "not-a-dict",
        })
        assert rm.schema_version == 1
        assert rm.caps_hit == ()
        assert rm.routes[0].line == 0
        assert rm.routes[0].http_methods == ()
        assert rm.unresolved[0].line == 0
        assert rm.stats == {}


# ---------------------------------------------------------------------------
# Hostile shapes / caps
# ---------------------------------------------------------------------------


_FLOOD_HEADER = "from flask import Flask\napp = Flask(__name__)\n"


def _flask_flood(n: int) -> str:
    parts = [_FLOOD_HEADER]
    for i in range(n):
        parts.append(f"@app.route('/r{i}')\ndef h{i}():\n    return {i}\n")
    return "".join(parts)


class TestHostileShapes:
    def test_route_flood_caps(self):
        inv = _inventory_from_sources({"pkg/app.py": _flask_flood(30)})
        rm = build_route_models(inv, max_routes=10)
        assert len(rm.routes) == 10
        assert "routes" in rm.caps_hit
        assert rm.stats["routes_total"] == 30
        assert rm.stats["routes_dropped_cap"] == 20

    def test_unresolved_flood_caps(self):
        src = [_FLOOD_HEADER]
        for i in range(30):
            src.append(f"@app.route(B + '/d{i}')\ndef d{i}():\n    pass\n")
        inv = _inventory_from_sources({"pkg/app.py": "".join(src)})
        rm = build_route_models(inv, max_unresolved=10)
        assert len(rm.unresolved) == 10
        assert "unresolved" in rm.caps_hit
        # The true blind-spot count survives the cap.
        assert rm.stats["unresolved_total"] == 30

    def test_middleware_depth_cap_sets_truncated_flag(self):
        decos = "".join(f"@w{i}\n" for i in range(40))
        defs = "".join(f"def w{i}(f):\n    return f\n" for i in range(40))
        src = (_FLOOD_HEADER + defs
               + f"@app.route('/deep')\n{decos}def deep():\n    pass\n")
        rm = build_route_models(
            _inventory_from_sources({"pkg/app.py": src}))
        r = rm.routes[0]
        assert len(r.middleware_chain) == 32
        assert r.middleware_truncated is True
        assert rm.to_dict()["routes"][0]["middleware_truncated"] is True

    def test_pattern_length_cap_becomes_marker(self):
        # Composed pattern (constructor prefix + literal) exceeds the
        # cap even though each half passes the extractor's own bound.
        long_prefix = "/p" * 300     # 600 chars — under the extractor cap
        long_tail = "/t" * 300       # composed: 1200 > _MAX_PATTERN_LENGTH
        src = (
            "from flask import Blueprint\n"
            f"bp = Blueprint('b', __name__, url_prefix='{long_prefix}')\n"
            f"@bp.route('{long_tail}')\ndef t():\n    pass\n"
        )
        rm = build_route_models(
            _inventory_from_sources({"pkg/app.py": src}))
        assert rm.routes == ()
        marks = [u for u in rm.unresolved
                 if u.reason == REASON_DYNAMIC_PATTERN]
        assert marks and marks[0].detail == "pattern_over_length_cap"

    def test_params_cap(self):
        pattern = "/" + "/".join(f"<p{i}>" for i in range(40))
        src = (_FLOOD_HEADER
               + f"@app.route('{pattern}')\ndef many():\n    pass\n")
        rm = build_route_models(
            _inventory_from_sources({"pkg/app.py": src}))
        assert len(rm.routes[0].params) == 32
        assert rm.stats["params_dropped_cap"] == 8

    def test_receiver_unresolved_marker(self):
        """A registration-shaped decorator whose receiver never
        resolves, in a package that does import the framework — an
        explicit marker, never a guessed route."""
        inv = _inventory_from_sources({
            "pkg/uses_framework.py": _FLOOD_HEADER,
            "pkg/mystery.py": (
                "from pkg.somewhere_unanalysed import app\n"
                "@app.route('/ghost')\ndef ghost():\n    pass\n"
            ),
        })
        rm = build_route_models(inv)
        marks = [u for u in rm.unresolved
                 if u.reason == REASON_RECEIVER_UNRESOLVED]
        assert len(marks) == 1
        assert marks[0].detail == "app.route"
        assert not any(r.route_pattern == "/ghost" for r in rm.routes)

    def test_named_group_name_bound(self):
        """The named-group parser is bounded (scan-restart ReDoS
        shape otherwise): names within the param cap parse, an
        over-long group name yields NO param — same degradation as
        the extractor's over-cap literals."""
        long_name = "n" * 200
        src = (
            "from django.urls import re_path\n"
            "from pkg import views\n"
            "urlpatterns = [\n"
            "    re_path(r'^a/(?P<ok>[0-9]+)/(?P<" + long_name
            + ">.*)$', views.v),\n"
            "]\n"
        )
        rm = build_route_models(_inventory_from_sources({
            "pkg/urls.py": src,
            "pkg/views.py": "def v(**kw):\n    return kw\n",
        }))
        assert [p.name for p in rm.routes[0].params] == ["ok"]

    def test_known_external_receiver_exempt_from_marker(self):
        """``@mock.patch("module.attr")`` matches the registration
        shape (``patch`` is an HTTP verb, literal first argument)
        but its receiver import-joins to a KNOWN external
        non-framework binding — exempt, no marker. In-package
        unresolvable receivers keep theirs (previous test)."""
        rm = build_route_models(_inventory_from_sources({
            "pkg/uses_framework.py": _FLOOD_HEADER,
            "pkg/test_thing.py": (
                "from unittest import mock\n"
                "@mock.patch('pkg.thing.attr')\n"
                "def test_attr(m):\n    pass\n"
            ),
        }))
        assert rm.routes == ()
        assert rm.unresolved == ()

    def test_no_framework_no_shape_markers(self):
        """Without any framework import in the package, decorator
        shapes that merely LOOK like registrations stay silent —
        ``@cache.get("key")`` in a non-web repo is not a blind
        spot."""
        rm = build_route_models(_inventory_from_sources({
            "pkg/plain.py": (
                "@cache.get('key')\ndef cached():\n    pass\n"
            ),
        }))
        assert rm.routes == ()
        assert rm.unresolved == ()

    def test_urlconf_dynamic_pattern_and_missing_handler(self):
        src = (
            "from django.urls import path\n"
            "from pkg import views\n"
            "urlpatterns = [\n"
            "    path(PREFIX + 'x/', views.real),\n"
            "    path('y/', views.missing),\n"
            "]\n"
        )
        views = "def real(r):\n    return r\n"
        rm = build_route_models(_inventory_from_sources({
            "pkg/urls.py": src, "pkg/views.py": views,
        }))
        # PREFIX + 'x/' has no literal FIRST argument → not even a
        # string_ref_call — silent at the inventory layer, which is
        # exactly the documented gap; 'y/' resolves the callee but
        # not the handler → explicit marker.
        marks = [u for u in rm.unresolved
                 if u.reason == REASON_HANDLER_UNRESOLVED]
        assert [m.detail for m in marks] == ["views.missing"]
        assert rm.routes == ()

    def test_malformed_decorators_no_crash_no_routes(self):
        src = (
            "from flask import Flask\napp = Flask(__name__)\n"
            "@(lambda f: f)\n"
            "@make_deco()(1)\n"
            "@app.route\n"          # bare registration decorator
            "def odd():\n    pass\n"
        )
        rm = build_route_models(
            _inventory_from_sources({"pkg/app.py": src}))
        # The bare @app.route has no call arguments — registration
        # recognised, pattern unknowable → dynamic marker.
        assert rm.routes == ()
        assert [u.reason for u in rm.unresolved] == [
            REASON_DYNAMIC_PATTERN,
        ]

    def test_garbage_inventory_records_never_raise(self):
        rm = build_route_models({"files": [
            None,
            42,
            "string",
            {},
            {"path": "a.py"},
            {"path": "b.py", "call_graph": "garbage"},
            {"path": "c.py", "call_graph": {"calls": "nope",
                                            "imports": 7}},
            {"path": "d.py", "call_graph": {
                "decorated_functions": [None, {"decorators": 3}],
                "string_ref_calls": [None, {"args": []}],
                "constructed_objects": {"x": None, "y": {"chain": 5}},
            }},
        ]})
        assert rm.routes == ()
        # Non-dict entries are dropped before counting (same rule as
        # the package callgraph's files_seen).
        assert rm.stats["files_seen"] == 5

    def test_garbage_inventory_top_level(self):
        assert build_route_models({}).routes == ()
        assert build_route_models({"files": None}).routes == ()


# ---------------------------------------------------------------------------
# Middleware tiers beyond static
# ---------------------------------------------------------------------------


class TestMiddlewareTiers:
    def test_external_decorator_tier(self):
        src = (
            "from flask import Flask\n"
            "from flask_login import login_required\n"
            "app = Flask(__name__)\n"
            "@app.route('/secure')\n"
            "@login_required\n"
            "def secure():\n    pass\n"
        )
        rm = build_route_models(
            _inventory_from_sources({"pkg/app.py": src}))
        r = rm.routes[0]
        assert [(m.name, m.tier) for m in r.middleware_chain] == [
            ("login_required", TIER_EXTERNAL),
        ]

    def test_unknown_decorator_tier_unresolved(self):
        src = (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.route('/odd')\n"
            "@mystery_wrapper\n"
            "def odd():\n    pass\n"
        )
        rm = build_route_models(
            _inventory_from_sources({"pkg/app.py": src}))
        r = rm.routes[0]
        assert [(m.name, m.tier) for m in r.middleware_chain] == [
            ("mystery_wrapper", TIER_UNRESOLVED),
        ]

    def test_framework_non_registration_decorator_stays_middleware(self):
        """A framework-object decorator that is NOT a registration
        method (errorhandler) counts as middleware on a
        method-call-registered handler."""
        src = (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.errorhandler(404)\n"
            "def h():\n    pass\n"
            "app.add_url_rule('/h', view_func=h)\n"
        )
        rm = build_route_models(
            _inventory_from_sources({"pkg/app.py": src}))
        r = rm.routes[0]
        assert [m.name for m in r.middleware_chain] == ["app.errorhandler"]

    def test_source_order_preserved(self):
        src = (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "def outer(f):\n    return f\n"
            "def inner(f):\n    return f\n"
            "@app.route('/ordered')\n"
            "@outer\n"
            "@inner\n"
            "def ordered():\n    pass\n"
        )
        rm = build_route_models(
            _inventory_from_sources({"pkg/app.py": src}))
        assert [m.name for m in rm.routes[0].middleware_chain] == [
            "outer", "inner",
        ]
