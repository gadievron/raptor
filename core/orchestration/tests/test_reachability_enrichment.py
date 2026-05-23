"""Tests for ``core.orchestration.reachability_enrichment``."""

from __future__ import annotations

from pathlib import Path

from core.orchestration.reachability_enrichment import (
    _path_to_module,
    mark_unreachable_low_priority,
)


def _project(tmp_path: Path, files: dict) -> Path:
    """Drop ``files`` (path → contents) under tmp_path."""
    for rel, contents in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contents)
    return tmp_path


def _checklist(files_funcs: dict) -> dict:
    """Build a minimal checklist with ``{rel_path: [{name, ...}, ...]}``."""
    return {
        "files": [
            {"path": rel, "items": funcs}
            for rel, funcs in files_funcs.items()
        ],
    }


# ---------------------------------------------------------------------------
# Marking behaviour
# ---------------------------------------------------------------------------


def test_marks_dead_function_low_priority(tmp_path):
    """Function not called from anywhere → priority=low."""
    target = _project(tmp_path, {
        "src/vuln.py": (
            "def dead(): pass\n"
            "def alive(): pass\n"
        ),
        "src/main.py": (
            "from src.vuln import alive\n"
            "alive()\n"
        ),
    })
    checklist = _checklist({
        "src/vuln.py": [
            {"name": "dead", "kind": "function"},
            {"name": "alive", "kind": "function"},
        ],
    })
    marked = mark_unreachable_low_priority(checklist, target)
    assert marked == 1
    funcs = {f["name"]: f for f in checklist["files"][0]["items"]}
    assert funcs["dead"]["priority"] == "low"
    assert funcs["dead"]["priority_reason"] == "reachability:not_called"
    # alive function untouched.
    assert "priority" not in funcs["alive"]


def test_does_not_overwrite_high_priority(tmp_path):
    """Function already marked priority=high (from context-map
    enrichment) is left alone even if NOT_CALLED."""
    target = _project(tmp_path, {
        "src/vuln.py": "def entry_point(): pass\n",
        "src/main.py": "x = 1\n",
    })
    checklist = _checklist({
        "src/vuln.py": [{
            "name": "entry_point",
            "kind": "function",
            "priority": "high",
            "priority_reason": "entry_point",
        }],
    })
    marked = mark_unreachable_low_priority(checklist, target)
    assert marked == 0
    func = checklist["files"][0]["items"][0]
    assert func["priority"] == "high"
    assert func["priority_reason"] == "entry_point"


def test_skips_uncertain_dispatch(tmp_path):
    """File using getattr → UNCERTAIN → no downgrade."""
    target = _project(tmp_path, {
        "src/vuln.py": "def affected(): pass\n",
        "src/main.py": (
            "from src import vuln\n"
            "fn = getattr(vuln, 'affected')\n"
            "fn()\n"
        ),
    })
    checklist = _checklist({
        "src/vuln.py": [{"name": "affected", "kind": "function"}],
    })
    marked = mark_unreachable_low_priority(checklist, target)
    assert marked == 0
    func = checklist["files"][0]["items"][0]
    assert "priority" not in func


def test_skips_globals_and_classes(tmp_path):
    """Items with kind != "function" are skipped (only functions
    have call-graph reachability semantics)."""
    target = _project(tmp_path, {
        "src/vuln.py": (
            "x = 1\n"
            "def f(): pass\n"
        ),
    })
    checklist = _checklist({
        "src/vuln.py": [
            {"name": "x", "kind": "global"},
            {"name": "f", "kind": "function"},
        ],
    })
    marked = mark_unreachable_low_priority(checklist, target)
    # f gets marked, x doesn't.
    assert marked == 1
    items = {it["name"]: it for it in checklist["files"][0]["items"]}
    assert "priority" not in items["x"]
    assert items["f"]["priority"] == "low"


def test_handles_empty_checklist(tmp_path):
    target = _project(tmp_path, {"src/x.py": "pass\n"})
    assert mark_unreachable_low_priority({}, target) == 0
    assert mark_unreachable_low_priority({"files": []}, target) == 0


def test_handles_malformed_inputs(tmp_path):
    """Non-dict / non-list shapes degrade gracefully."""
    assert mark_unreachable_low_priority(
        "not a dict",  # type: ignore[arg-type]
        tmp_path,
    ) == 0
    assert mark_unreachable_low_priority(
        {"files": "not a list"}, tmp_path,
    ) == 0
    # Files entry not a dict.
    assert mark_unreachable_low_priority(
        {"files": ["not a dict"]}, tmp_path,
    ) == 0


def test_function_without_name_skipped(tmp_path):
    target = _project(tmp_path, {"src/vuln.py": "def f(): pass\n"})
    checklist = _checklist({
        "src/vuln.py": [
            {"kind": "function"},                   # no name
            {"name": "", "kind": "function"},      # empty name
            {"name": "f", "kind": "function"},
        ],
    })
    marked = mark_unreachable_low_priority(checklist, target)
    # Only ``f`` gets marked.
    assert marked == 1


def test_path_without_extension_skipped(tmp_path):
    """File entry with a path that has no extension can't be
    converted to a module — skipped."""
    target = _project(tmp_path, {"src/x.py": "pass\n"})
    checklist = {
        "files": [
            {"path": "Makefile", "items": [
                {"name": "build", "kind": "function"},
            ]},
        ],
    }
    marked = mark_unreachable_low_priority(checklist, target)
    assert marked == 0


def test_inventory_passed_through(tmp_path):
    """When the caller passes an inventory, no fresh build."""
    target = _project(tmp_path, {
        "src/vuln.py": "def dead(): pass\n",
    })
    checklist = _checklist({
        "src/vuln.py": [{"name": "dead", "kind": "function"}],
    })
    # Build inventory ourselves.
    from core.inventory.builder import build_inventory
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        inv = build_inventory(str(target), td)
    marked = mark_unreachable_low_priority(
        checklist, target, inventory=inv,
    )
    assert marked == 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_path_to_module():
    assert _path_to_module("packages/foo/bar.py") == "packages.foo.bar"
    assert _path_to_module("Makefile") is None
    assert _path_to_module("") is None


# ---------------------------------------------------------------------------
# Caller-context enrichment
# ---------------------------------------------------------------------------


def test_enrich_caller_context_attaches_counts(tmp_path):
    """A function with two callers gains caller_count_direct=2,
    caller_count_transitive>=2, and direct_caller_names lists
    them."""
    from core.orchestration.reachability_enrichment import (
        enrich_with_caller_context,
    )
    target = _project(tmp_path, {
        "src/vuln.py": (
            "def affected():\n"             # line 1
            "    pass\n"
        ),
        "src/main.py": (
            "from src.vuln import affected\n"
            "def use_a():\n"                 # caller 1
            "    affected()\n"
            "def use_b():\n"                 # caller 2
            "    affected()\n"
        ),
    })
    checklist = _checklist({
        "src/vuln.py": [{
            "name": "affected", "kind": "function",
            "line_start": 1, "line_end": 2,
        }],
    })
    enriched = enrich_with_caller_context(checklist, target)
    assert enriched == 1
    func = checklist["files"][0]["items"][0]
    assert func["caller_count_direct"] == 2
    assert func["caller_count_transitive"] >= 2
    assert func["caller_count_uncertain"] == 0
    assert len(func["direct_caller_names"]) == 2


def test_enrich_caller_context_skips_low_priority(tmp_path):
    """A function already marked priority=low (dead code) doesn't
    need caller context — the LLM is going to deprioritise it
    regardless. Skip to save the lookup."""
    from core.orchestration.reachability_enrichment import (
        enrich_with_caller_context,
    )
    target = _project(tmp_path, {
        "src/vuln.py": "def dead(): pass\n",
    })
    checklist = _checklist({
        "src/vuln.py": [{
            "name": "dead", "kind": "function",
            "line_start": 1, "line_end": 1,
            "priority": "low",
            "priority_reason": "reachability:not_called",
        }],
    })
    enriched = enrich_with_caller_context(checklist, target)
    assert enriched == 0
    func = checklist["files"][0]["items"][0]
    assert "caller_count_direct" not in func


def test_enrich_caller_context_caps_caller_names(tmp_path):
    """``direct_caller_names`` is capped at ``max_direct_caller_names``."""
    from core.orchestration.reachability_enrichment import (
        enrich_with_caller_context,
    )
    target = _project(tmp_path, {
        "src/vuln.py": "def affected(): pass\n",
        "src/main.py": (
            "from src.vuln import affected\n"
            "def c1(): affected()\n"
            "def c2(): affected()\n"
            "def c3(): affected()\n"
            "def c4(): affected()\n"
            "def c5(): affected()\n"
            "def c6(): affected()\n"
            "def c7(): affected()\n"
        ),
    })
    checklist = _checklist({
        "src/vuln.py": [{
            "name": "affected", "kind": "function",
            "line_start": 1, "line_end": 1,
        }],
    })
    enriched = enrich_with_caller_context(
        checklist, target, max_direct_caller_names=3,
    )
    assert enriched == 1
    func = checklist["files"][0]["items"][0]
    assert func["caller_count_direct"] == 7
    assert len(func["direct_caller_names"]) == 3


def test_enrich_caller_context_handles_no_callers(tmp_path):
    """A function with no callers — counts are 0 but the function
    is still enriched (consumer can read 0 to know "lonely")."""
    from core.orchestration.reachability_enrichment import (
        enrich_with_caller_context,
    )
    target = _project(tmp_path, {
        "src/vuln.py": "def lonely(): pass\n",
    })
    checklist = _checklist({
        "src/vuln.py": [{
            "name": "lonely", "kind": "function",
            "line_start": 1, "line_end": 1,
        }],
    })
    enriched = enrich_with_caller_context(checklist, target)
    assert enriched == 1
    func = checklist["files"][0]["items"][0]
    assert func["caller_count_direct"] == 0
    assert func["caller_count_transitive"] == 0
    assert func["direct_caller_names"] == []


def test_enrich_caller_context_skips_non_function_items(tmp_path):
    from core.orchestration.reachability_enrichment import (
        enrich_with_caller_context,
    )
    target = _project(tmp_path, {
        "src/v.py": "x = 1\n",
    })
    checklist = _checklist({
        "src/v.py": [{
            "name": "GLOBAL_VAR", "kind": "global",
            "line_start": 1, "line_end": 1,
        }],
    })
    enriched = enrich_with_caller_context(checklist, target)
    assert enriched == 0
    func = checklist["files"][0]["items"][0]
    assert "caller_count_direct" not in func


def test_enrich_caller_context_handles_missing_line_start(tmp_path):
    """Defensive: a checklist item without line_start can't be
    resolved to an InternalFunction — skip silently."""
    from core.orchestration.reachability_enrichment import (
        enrich_with_caller_context,
    )
    target = _project(tmp_path, {
        "src/v.py": "def f(): pass\n",
    })
    checklist = _checklist({
        "src/v.py": [{
            "name": "f", "kind": "function",
            # line_start missing
        }],
    })
    enriched = enrich_with_caller_context(checklist, target)
    assert enriched == 0


def test_enrich_caller_context_uncertain_caller_counted_separately(
    tmp_path,
):
    """A function called via getattr counts as an UNCERTAIN
    caller — surfaced in caller_count_uncertain."""
    from core.orchestration.reachability_enrichment import (
        enrich_with_caller_context,
    )
    target = _project(tmp_path, {
        "src/v.py": "def affected(q): pass\n",
        "src/dyn.py": (
            "from src import v\n"
            "def dispatch():\n"
            "    fn = getattr(v, 'affected')\n"
            "    fn('x')\n"
        ),
    })
    checklist = _checklist({
        "src/v.py": [{
            "name": "affected", "kind": "function",
            "line_start": 1, "line_end": 1,
        }],
    })
    enriched = enrich_with_caller_context(checklist, target)
    assert enriched == 1
    func = checklist["files"][0]["items"][0]
    assert func["caller_count_uncertain"] >= 1


# ---------------------------------------------------------------------------
# Framework-callable bypass — functions with framework-dispatch
# decorators must NOT be demoted to priority=low even when the static
# call graph shows zero callers.
# ---------------------------------------------------------------------------


class TestFrameworkCallableBypass:
    def test_flask_route_handler_not_demoted(self, tmp_path):
        # A Flask route handler has no in-project callers — only
        # the Flask runtime invokes it via the registered route.
        # Pre-fix this regressed to priority=low; the LLM analysis
        # then deferred on it. With S1, the framework-callable
        # check skips the demotion.
        target = _project(tmp_path, {
            "src/api.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/users')\n"
                "def list_users():\n"
                "    return []\n"
            ),
        })
        checklist = _checklist({
            "src/api.py": [{
                "name": "list_users", "kind": "function",
                "line_start": 5, "line_end": 6,
            }],
        })
        mark_unreachable_low_priority(checklist, target)
        func = checklist["files"][0]["items"][0]
        assert func.get("priority") != "low", (
            "Flask @app.route handler must not be demoted — "
            "framework dispatches to it at runtime"
        )
        # The diagnostic annotation should mark it as
        # framework-callable so operators can see WHY this didn't
        # get a priority downgrade.
        assert func.get("priority_reason") == (
            "reachability:framework_callable"
        )

    def test_django_receiver_naked_decorator_not_demoted(self, tmp_path):
        # Django's @receiver is the bare-name form covered by S1b.
        # Validates that S1b's naked-name set propagates through
        # to the consumer wiring.
        target = _project(tmp_path, {
            "src/signals.py": (
                "from django.dispatch import receiver\n"
                "from django.db.models.signals import post_save\n"
                "\n"
                "@receiver(post_save)\n"
                "def update_profile(sender, instance, **kw):\n"
                "    pass\n"
            ),
        })
        checklist = _checklist({
            "src/signals.py": [{
                "name": "update_profile", "kind": "function",
                "line_start": 5, "line_end": 6,
            }],
        })
        mark_unreachable_low_priority(checklist, target)
        func = checklist["files"][0]["items"][0]
        assert func.get("priority") != "low"

    def test_genuinely_dead_function_still_demoted(self, tmp_path):
        # A function with no callers AND no framework-dispatch
        # decorator IS dead code — the framework-callable bypass
        # must not over-fire on non-decorated functions.
        target = _project(tmp_path, {
            "src/v.py": (
                "def dead(): pass\n"
                "def alive(): pass\n"
            ),
            "src/main.py": (
                "from src.v import alive\n"
                "alive()\n"
            ),
        })
        checklist = _checklist({
            "src/v.py": [
                {"name": "dead", "kind": "function",
                 "line_start": 1, "line_end": 1},
                {"name": "alive", "kind": "function",
                 "line_start": 2, "line_end": 2},
            ],
        })
        mark_unreachable_low_priority(checklist, target)
        funcs = checklist["files"][0]["items"]
        dead = next(f for f in funcs if f["name"] == "dead")
        alive = next(f for f in funcs if f["name"] == "alive")
        assert dead["priority"] == "low"
        assert dead["priority_reason"] == "reachability:not_called"
        assert "priority" not in alive  # called → no demotion at all


class TestRegistrationViaCallBypass:
    """S2: JS / Go function-as-argument registration. A handler
    passed as an identifier argument to a routing call
    (``http.HandleFunc("/x", handler)``, ``app.get("/users",
    handler)``) must NOT be demoted to priority=low even though
    the static graph shows no callers — the framework dispatches
    to it via the registration call.
    """

    def test_allow_unreachable_suppresses_demotion(self, tmp_path):
        # C2: --allow-unreachable opts out of NOT_CALLED demotion.
        # A genuinely-dead function does NOT get priority=low.
        target = _project(tmp_path, {
            "src/v.py": "def dead(): pass\n",
        })
        checklist = _checklist({
            "src/v.py": [{
                "name": "dead", "kind": "function",
                "line_start": 1, "line_end": 1,
            }],
        })
        marked = mark_unreachable_low_priority(
            checklist, target, allow_unreachable=True,
        )
        assert marked == 0
        func = checklist["files"][0]["items"][0]
        assert "priority" not in func, (
            "--allow-unreachable must NOT demote NOT_CALLED functions"
        )
        assert "priority_reason" not in func

    def test_allow_unreachable_still_annotates_framework_callable(
        self, tmp_path,
    ):
        # Framework-callable annotation is affirmative reachability
        # evidence, not a deferral signal — should still apply even
        # under --allow-unreachable (the operator may find it useful
        # to know which functions ARE framework-registered).
        target = _project(tmp_path, {
            "src/api.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/x')\n"
                "def handler():\n"
                "    return 1\n"
            ),
        })
        checklist = _checklist({
            "src/api.py": [{
                "name": "handler", "kind": "function",
                "line_start": 5, "line_end": 6,
            }],
        })
        mark_unreachable_low_priority(
            checklist, target, allow_unreachable=True,
        )
        func = checklist["files"][0]["items"][0]
        # framework_callable annotation still applies
        assert func.get("priority_reason") == (
            "reachability:framework_callable"
        )

    def test_go_handler_registered_via_handlefunc_not_demoted(
        self, tmp_path,
    ):
        try:
            import tree_sitter_go  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("tree_sitter_go not installed")
        target = _project(tmp_path, {
            "src/main.go": (
                'package main\n'
                'import "net/http"\n'
                'func handler(w http.ResponseWriter, r *http.Request) {}\n'
                'func main() {\n'
                '\thttp.HandleFunc("/x", handler)\n'
                '}\n'
            ),
        })
        checklist = _checklist({
            "src/main.go": [{
                "name": "handler", "kind": "function",
                "line_start": 3, "line_end": 3,
            }],
        })
        mark_unreachable_low_priority(checklist, target)
        func = checklist["files"][0]["items"][0]
        assert func.get("priority") != "low", (
            "Go handler registered via http.HandleFunc must not "
            "be demoted — framework dispatches to it at runtime"
        )
        assert func.get("priority_reason") == (
            "reachability:registered_via_call"
        )
