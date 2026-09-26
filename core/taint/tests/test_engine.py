"""Ground-truth battery for the interprocedural propagation engine.

Every expectation below is hand-computed from a small real source
tree: files are written to disk, the REAL inventory extractors build
the REAL package callgraph and route models, the shipped seed packs
load through the real loader, and the engine propagates — the same
chain a production run uses, no mocked substrate.

The rail boundary tests at the bottom shrink one named cap each and
pin the ±1 degradation (marker + partial-but-honest result); each
one goes red if its cap's enforcement is removed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.analysis.package_callgraph import (
    TIER_HEURISTIC_DYNAMIC,
    TIER_RESOLVED_STATIC,
    PackageCallGraph,
    build_package_callgraph,
)
from core.analysis.route_models import (
    HANDLER_KIND_CLASS,
    RouteModels,
    RouteRecord,
    build_route_models,
)
from core.inventory.call_graph import extract_call_graph_python
from core.inventory.extractors import PythonExtractor
from core.taint.engine import (
    DOCTRINE,
    EngineLimits,
    PropagationResult,
    propagate,
)
from core.taint.learned_intake import LearnedIntake, LearnedSpec
from core.taint.packs import (
    TIER_LEARNED,
    PackSet,
    load_packs,
)
from core.taint.tests import HAND_COMPUTED_PACKS

# ── fixture plumbing (real builders end to end) ──────────────────────


@pytest.fixture(scope="module")
def packs() -> PackSet:
    return load_packs(HAND_COMPUTED_PACKS)


def _record(rel: str, content: str) -> dict:
    items = [i.to_dict() for i in PythonExtractor().extract(rel, content)]
    return {
        "path": rel,
        "language": "python",
        "items": items,
        "call_graph": extract_call_graph_python(content).to_dict(),
    }


def _build(root: Path, files: dict[str, str]) -> tuple[
        PackageCallGraph, RouteModels]:
    records = []
    for rel, content in sorted(files.items()):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        records.append(_record(rel, content))
    inventory = {"files": records}
    graph = build_package_callgraph(inventory)
    return graph, build_route_models(inventory, graph)


def _run(
    tmp_path: Path,
    files: dict[str, str],
    packs: PackSet,
    *,
    learned: LearnedIntake | None = None,
    limits: EngineLimits | None = None,
    routes: RouteModels | None = None,
) -> PropagationResult:
    graph, built_routes = _build(tmp_path, files)
    return propagate(
        graph, routes if routes is not None else built_routes, packs,
        learned, target_root=tmp_path, limits=limits,
    )


_PKG_INIT = {"app/__init__.py": ""}

_SINK_MODULE = {
    "app/exec_layer.py": (
        "import subprocess\n"
        "\n"
        "def launch(payload):\n"
        "    subprocess.run(payload, shell=True)\n"
        "    return None\n"
    ),
}


def _flask_app(handler_body: str, helpers: str = "") -> dict[str, str]:
    files = dict(_PKG_INIT)
    files.update(_SINK_MODULE)
    files["app/views.py"] = handler_body
    if helpers:
        files["app/helpers.py"] = helpers
    return files


# ── ground truth: the three-file chain ───────────────────────────────


class TestRouteParamToSinkAcrossFiles:
    """route param → helper chain → sink, one file per hop."""

    FILES = _flask_app(
        handler_body=(
            "from flask import Flask\n"
            "from .helpers import prepare\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/run/<cmd>')\n"
            "def run_cmd(cmd):\n"
            "    return prepare(cmd)\n"
        ),
        helpers=(
            "from .exec_layer import launch\n"
            "\n"
            "def prepare(text):\n"
            "    staged = 'prefix-' + text\n"
            "    return launch(staged)\n"
        ),
    )

    def test_candidate_hand_computed(self, tmp_path, packs) -> None:
        res = _run(tmp_path, self.FILES, packs)
        assert len(res.candidates) == 1
        c = res.candidates[0]
        assert c.taint_class == "user-input"
        source = c.source_dict()
        assert source["kind"] == "route_param"
        assert source["framework"] == "flask"
        assert source["route_pattern"] == "/run/<cmd>"
        assert source["handler"] == "app/views.py::run_cmd@7"
        assert c.sink_function == "app/exec_layer.py::launch@3"
        assert c.sink_line == 4
        assert c.sink_class == "command-injection"
        assert c.sink_cwe == "CWE-78"
        assert c.sink_match == "subprocess.run"
        assert c.spec_tier == "pack"
        assert [h.function for h in c.hops] == [
            "app/views.py::run_cmd@7",
            "app/helpers.py::prepare@3",
            "app/exec_layer.py::launch@3",
        ]
        assert c.hops[0].kind == "seed"
        assert all(h.tier == TIER_RESOLVED_STATIC for h in c.hops)
        assert c.path_tier == TIER_RESOLVED_STATIC
        assert c.killed == ()
        assert res.caps_hit == ()
        # The once-per-node law, pinned deterministically: one
        # extraction per visited function (wall pins alone stay
        # green under a memoization revert — this does not).
        assert res.stat("summaries_computed") == \
            res.stat("functions_visited")
        assert res.stat("plan_rebuilds") == 0

    def test_demand_driven_visits_only_reached_functions(
            self, tmp_path, packs) -> None:
        files = dict(self.FILES)
        files["app/dead.py"] = (
            "def never_reached(x):\n"
            "    return x\n"
        )
        res = _run(tmp_path, files, packs)
        # dead.py's function is neither routed nor called: no summary
        # is ever computed for it (demand-driven), and its absence is
        # NOT a claim about it.
        assert res.stat("summaries_computed") == 3
        assert res.stat("functions_visited") == 3

    def test_deterministic_output(self, tmp_path, packs) -> None:
        first = _run(tmp_path / "a", self.FILES, packs).to_dict()
        second = _run(tmp_path / "b", self.FILES, packs).to_dict()
        assert first == second
        json.dumps(first)  # serialisable, no exotic values


# ── sanitizers across the chain ───────────────────────────────────────


class TestSanitizerComposition:
    def test_kill_mid_chain_suppresses_counted(self, tmp_path,
                                               packs) -> None:
        """shlex.quote in the handler kills command-injection for the
        whole downstream chain — no candidate, counted, and the
        killed class is never silent."""
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "import shlex\n"
                "from .helpers import prepare\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/safe/<cmd>')\n"
                "def safe_cmd(cmd):\n"
                "    quoted = shlex.quote(cmd)\n"
                "    return prepare(quoted)\n"
            ),
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def prepare(text):\n"
                "    return launch(text)\n"
            ),
        )
        res = _run(tmp_path, files, packs)
        assert res.candidates == ()
        assert res.stat("candidates_killed") >= 1

    def test_branch_kill_is_weak_cross_file(self, tmp_path,
                                            packs) -> None:
        """A kill inside a branch never certifies the fall-through:
        the unkilled flow reaches the sink and the candidate emits
        (over-taint direction, the honest one)."""
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "import shlex\n"
                "from .helpers import prepare\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/maybe/<cmd>')\n"
                "def maybe_cmd(cmd):\n"
                "    if len(cmd) < 10:\n"
                "        cmd = shlex.quote(cmd)\n"
                "    return prepare(cmd)\n"
            ),
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def prepare(text):\n"
                "    return launch(text)\n"
            ),
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1
        assert res.candidates[0].sink_class == "command-injection"

    def test_tag_sanitizer_keeps_flow_and_rides_witness(
            self, tmp_path, packs) -> None:
        """A validate-style (tag) sanitizer never kills; its hop is
        visible on the witness chain."""
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "import re\n"
                "from .helpers import prepare\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/tagged/<cmd>')\n"
                "def tagged_cmd(cmd):\n"
                "    checked = re.match('[a-z]+', cmd)\n"
                "    return prepare(cmd)\n"
            ),
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def prepare(text):\n"
                "    return launch(text)\n"
            ),
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1

    def test_kill_then_unsanitized_second_route_still_emits(
            self, tmp_path, packs) -> None:
        """Two routes converge on one sink: one sanitized, one not.
        The killed set joins by INTERSECTION across paths, so the
        live route emits — a kill on one path never silences
        another."""
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "import shlex\n"
                "from .helpers import prepare\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/safe/<cmd>')\n"
                "def safe_cmd(cmd):\n"
                "    return prepare(shlex.quote(cmd))\n"
                "\n"
                "@app.route('/raw/<cmd>')\n"
                "def raw_cmd(cmd):\n"
                "    return prepare(cmd)\n"
            ),
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def prepare(text):\n"
                "    return launch(text)\n"
            ),
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1
        assert res.candidates[0].killed == ()

    def test_killed_field_is_final_state_never_stale(
            self, tmp_path, packs) -> None:
        """A SHORT sanitized arm emits first (killed poisoned); a
        LONGER live arm then shrinks the lattice join, but its
        re-emission loses the witness-priority race. The candidate's
        killed tuple must still report the FINAL joined state — ()
        — not the stale emission-time value: an over-claimed killed
        set is sanitization the run never proved on every path."""
        files = dict(_PKG_INIT)
        files.update(_SINK_MODULE)
        files["app/p1.py"] = (
            "from .exec_layer import launch\n\n"
            "def short_arm(v):\n"
            "    return launch(v)\n"
        )
        files["app/p2.py"] = (
            "from .mid import mid_stage\n\n"
            "def long_arm(v):\n"
            "    return mid_stage(v)\n"
        )
        files["app/mid.py"] = (
            "from .exec_layer import launch\n\n"
            "def mid_stage(v):\n"
            "    return launch(v)\n"
        )
        files["app/views.py"] = (
            "from flask import Flask\n"
            "import html\n"
            "from .p1 import short_arm\n"
            "from .p2 import long_arm\n\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/x/<cmd>')\n"
            "def x(cmd):\n"
            "    short_arm(html.escape(cmd))\n"
            "    long_arm(cmd)\n"
            "    return 'ok'\n"
        )
        res = _run(tmp_path, files, packs)
        cands = [c for c in res.candidates
                 if c.sink_class == "command-injection"]
        assert len(cands) == 1
        # Hand-computed truth: xss is killed on the short arm only —
        # the live long arm kills nothing, so the intersection over
        # ALL discovered paths is empty.
        assert cands[0].killed == ()
        assert res.stat("candidates_killed_refreshed") >= 1


# ── learned specs ────────────────────────────────────────────────────


class TestLearnedSpecs:
    def test_learned_sink_candidate_carries_learned_tier(
            self, tmp_path, packs) -> None:
        learned = LearnedIntake(sinks=(LearnedSpec(
            role="sink", function="app.store.raw_query",
            taint_classes=("sql-injection",),
        ),))
        files = dict(_PKG_INIT)
        files["app/views.py"] = (
            "from flask import Flask\n"
            "from .store import raw_query\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/q/<term>')\n"
            "def q(term):\n"
            "    return raw_query(term)\n"
        )
        files["app/store.py"] = (
            "def raw_query(sql):\n"
            "    return sql\n"
        )
        res = _run(tmp_path, files, packs, learned=learned)
        matches = [c for c in res.candidates
                   if c.sink_match == "app.store.raw_query"]
        assert len(matches) == 1
        assert matches[0].spec_tier == TIER_LEARNED
        assert matches[0].sink_class == "sql-injection"


# ── frontier honesty ─────────────────────────────────────────────────


class TestFrontier:
    FILES = _flask_app(
        handler_body=(
            "from flask import Flask\n"
            "from .helpers import mystery\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/dyn/<x>')\n"
            "def dyn(x):\n"
            "    fn = mystery()\n"
            "    fn(x)\n"
            "    return 'ok'\n"
        ),
        helpers=(
            "def mystery():\n"
            "    return None\n"
        ),
    )

    def test_taint_at_unresolved_is_frontier_never_candidate(
            self, tmp_path, packs) -> None:
        res = _run(tmp_path, self.FILES, packs)
        assert res.candidates == ()
        assert res.stat("taint_at_unresolved") >= 1
        assert len(res.frontier) >= 1
        rec = res.frontier[0]
        assert rec.function == "app/views.py::dyn@7"
        assert rec.taint_class == "user-input"
        assert rec.to_dict()["derived_from_target"] is True

    def test_zero_candidates_never_reads_as_clean(self, tmp_path,
                                                  packs) -> None:
        """The result surface has no refutation vocabulary at all —
        an empty candidate list coexists with frontier markers, and
        no field spells absence-as-evidence."""
        res = _run(tmp_path, self.FILES, packs)
        assert res.candidates == ()
        assert res.frontier  # the honest signal instead
        payload = res.to_dict()
        assert payload["doctrine"] == DOCTRINE
        forbidden = ("refut", "disproven", "suppress", "clean",
                     "no_flow", "not_vulnerable", "is_dead", "ruled_out")
        def walk_keys(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    yield k
                    yield from walk_keys(v)
            elif isinstance(obj, list):
                for v in obj:
                    yield from walk_keys(v)
        for key in walk_keys(payload):
            for bad in forbidden:
                assert bad not in key.lower(), key
        for name in dir(PropagationResult):
            for bad in forbidden:
                assert bad not in name.lower(), name


# ── tiers ────────────────────────────────────────────────────────────


class TestTierPropagation:
    def test_heuristic_hop_pins_path_tier_to_the_min(
            self, tmp_path, packs) -> None:
        """Dispatch-table hop (heuristic) followed by a static call:
        the path tier is the MIN of hops, and the weak hop is
        visible on the chain — low-confidence edges propagate WITH
        their tier, never dropped, never upgraded."""
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "from .helpers import handle_a\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "TABLE = {'a': handle_a}\n"
                "\n"
                "@app.route('/d/<x>')\n"
                "def dispatch(x):\n"
                "    TABLE['a'](x)\n"
                "    return 'ok'\n"
            ),
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def handle_a(v):\n"
                "    return launch(v)\n"
            ),
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1
        c = res.candidates[0]
        assert c.path_tier == TIER_HEURISTIC_DYNAMIC
        tiers = [h.tier for h in c.hops]
        assert TIER_HEURISTIC_DYNAMIC in tiers
        assert tiers[-1] == TIER_RESOLVED_STATIC  # the static tail hop

    def test_later_static_route_improves_the_recorded_tier(
            self, tmp_path, packs) -> None:
        """The STATE-side tier join (a key's rank is min over the
        whole path, joined best across arrivals): a heuristic-headed
        path reaches the sink first; a later all-static route must
        register as an IMPROVEMENT (the heuristic hop pinned the
        recorded rank) and surface the static witness. If the child
        rank took only the entering edge's tier, the first arrival
        would be mis-recorded as static and the improvement — and
        the static-tier candidate — would never happen."""
        files = dict(_PKG_INIT)
        files.update(_SINK_MODULE)
        files["app/m1.py"] = (
            "from .exec_layer import launch\n\n"
            "def m1(v):\n"
            "    return launch(v)\n"
        )
        files["app/s1.py"] = (
            "from .exec_layer import launch\n\n"
            "def s1(v):\n"
            "    return launch(v)\n"
        )
        files["app/views.py"] = (
            "from flask import Flask\n"
            "from .m1 import m1\n"
            "from .s1 import s1\n\n"
            "app = Flask(__name__)\n\n"
            "TABLE = {'m': m1}\n\n"
            "@app.route('/aa/<x>')\n"
            "def aa(x):\n"
            "    TABLE['m'](x)\n"
            "    return 'ok'\n\n"
            "@app.route('/zz/<x>')\n"
            "def zz(x):\n"
            "    s1(x)\n"
            "    return 'ok'\n"
        )
        res = _run(tmp_path, files, packs)
        static = [c for c in res.candidates
                  if c.path_tier == TIER_RESOLVED_STATIC]
        assert static, [c.path_tier for c in res.candidates]
        assert res.stat("fact_improvements") >= 1
        assert all(h.tier == TIER_RESOLVED_STATIC
                   for h in static[0].hops)


# ── the return-taint miss class stays counted ────────────────────────


class TestReturnTaintCounted:
    def test_source_returned_out_of_a_helper_is_counted(
            self, tmp_path, packs) -> None:
        """The canonical shape: a helper fires a source and RETURNS
        it; the caller sinks the result. The parameter-shaped
        lattice cannot carry that flow — the run's account must say
        so, never silence."""
        files = dict(_PKG_INIT)
        files.update(_SINK_MODULE)
        files["app/helpers.py"] = (
            "from flask import request\n\n"
            "def fetch():\n"
            "    c = request.args.get('c')\n"
            "    return c\n"
        )
        files["app/jobs.py"] = (
            "from .helpers import fetch\n"
            "from .exec_layer import launch\n\n"
            "def job():\n"
            "    launch(fetch())\n"
            "    return 'ok'\n"
        )
        res = _run(tmp_path, files, packs)
        assert res.candidates == ()  # the honest miss, not a claim
        assert res.stat("return_taint_unpropagated") >= 1

    def test_param_reaching_return_is_counted(self, tmp_path,
                                              packs) -> None:
        res = _run(tmp_path, _CHAIN, packs)
        # prepare()'s parameter flows into its return value; the
        # pops that observe it count the param-origin sub-case.
        assert res.stat("return_taint_unpropagated") >= 1


# ── cycles ───────────────────────────────────────────────────────────


class TestCycles:
    FILES = _flask_app(
        handler_body=(
            "from flask import Flask\n"
            "from .helpers import ping\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/loop/<x>')\n"
            "def loop(x):\n"
            "    return ping(x)\n"
        ),
        helpers=(
            "from .exec_layer import launch\n"
            "\n"
            "def ping(v):\n"
            "    return pong(v)\n"
            "\n"
            "def pong(v):\n"
            "    launch(v)\n"
            "    return ping(v)\n"
        ),
    )

    def test_mutual_recursion_converges_without_caps(
            self, tmp_path, packs) -> None:
        res = _run(tmp_path, self.FILES, packs)
        assert len(res.candidates) == 1
        assert res.caps_hit == ()
        # Finite lattice: the cycle re-enqueues each key a bounded
        # number of times; hand bound for this shape.
        assert res.stat("worklist_pops") <= 16


# ── seeding rules ────────────────────────────────────────────────────


class TestSeeding:
    def test_whole_parameter_surface_is_seeded(self, tmp_path,
                                               packs) -> None:
        """Route params understate the surface: a handler parameter
        NOT in the route pattern still seeds (FastAPI-style query /
        body params ride the signature)."""
        files = dict(_PKG_INIT)
        files.update(_SINK_MODULE)
        files["app/views.py"] = (
            "from flask import Flask\n"
            "from .exec_layer import launch\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/go/<a>')\n"
            "def go(a, extra=None):\n"
            "    launch(extra)\n"
            "    return 'ok'\n"
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1
        assert res.stat("seed_facts") == 2  # both params, one class

    def test_middleware_chain_never_gates_seeding(self, tmp_path,
                                                  packs) -> None:
        """Middleware entries are presence facts, not wrapping proofs
        and never sanitizers — a decorated handler seeds exactly like
        a bare one."""
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "from .helpers import prepare, require_auth\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/guarded/<cmd>')\n"
                "@require_auth\n"
                "def guarded(cmd):\n"
                "    return prepare(cmd)\n"
            ),
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def require_auth(fn):\n"
                "    return fn\n"
                "\n"
                "def prepare(text):\n"
                "    return launch(text)\n"
            ),
        )
        graph, routes = _build(tmp_path, files)
        route = routes.all_routes()[0]
        assert route.middleware_chain  # the chain IS recorded
        res = propagate(graph, routes, packs, target_root=tmp_path)
        assert len(res.candidates) == 1  # and gates nothing

    def test_cbv_prefix_join_seeds_verb_methods_not_self(
            self, tmp_path, packs) -> None:
        """Class-kind handlers seed via the name-prefix join over
        HTTP-verb methods; the receiver parameter is not seeded."""
        files = dict(_PKG_INIT)
        files.update(_SINK_MODULE)
        files["app/views.py"] = (
            "from .exec_layer import launch\n"
            "\n"
            "class ItemView:\n"
            "    def get(self, item_id):\n"
            "        launch(item_id)\n"
            "        return 'ok'\n"
            "\n"
            "    def helper(self, x):\n"
            "        launch(x)\n"
            "        return 'ok'\n"
        )
        graph, _ = _build(tmp_path, files)
        routes = RouteModels(routes=(RouteRecord(
            framework="django", route_pattern="/items/<int:item_id>",
            http_methods=(), handler="app/views.py::ItemView@3",
            params=(), middleware_chain=(), file_path="app/views.py",
            line=3, style="urlconf", handler_kind=HANDLER_KIND_CLASS,
        ),))
        res = propagate(graph, routes, packs, target_root=tmp_path)
        assert len(res.candidates) == 1
        c = res.candidates[0]
        assert c.hops[0].function == "app/views.py::ItemView.get@4"
        # helper is not an HTTP verb: not seeded, no candidate.
        assert res.stat("seed_facts") == 1  # item_id only, never self

    def test_source_entry_function_seeds_without_a_route(
            self, tmp_path, packs) -> None:
        """A pack source firing in a routeless function still seeds:
        the external-call census names the caller, the visit fires
        the in-body source, and the candidate's source descriptor is
        the source spec — not a route."""
        files = dict(_PKG_INIT)
        files.update(_SINK_MODULE)
        files["app/jobs.py"] = (
            "from flask import request\n"
            "from .exec_layer import launch\n"
            "\n"
            "def job_runner():\n"
            "    cmd = request.args.get('cmd')\n"
            "    launch(cmd)\n"
            "    return 'ok'\n"
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1
        source = res.candidates[0].source_dict()
        assert source["kind"] == "module_attribute"
        assert source["match"] == "flask.request"
        assert source["function"] == "app/jobs.py::job_runner@4"
        assert res.candidates[0].hops[0].kind == "seed"

    def test_same_function_source_to_sink(self, tmp_path,
                                          packs) -> None:
        """Source and sink in one function: a single seed hop, no
        edges crossed, path tier stays at the seed tier."""
        files = dict(_PKG_INIT)
        files["app/views.py"] = (
            "import subprocess\n"
            "from flask import Flask, request\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/one')\n"
            "def one():\n"
            "    subprocess.run(request.args.get('c'), shell=True)\n"
            "    return 'ok'\n"
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1
        c = res.candidates[0]
        assert len(c.hops) == 1
        assert c.path_tier == TIER_RESOLVED_STATIC
        assert c.source_dict()["kind"] == "module_attribute"


# ── argument binding ─────────────────────────────────────────────────


class TestArgumentBinding:
    def test_keyword_argument_binds_by_name(self, tmp_path,
                                            packs) -> None:
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "from .helpers import prepare\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/kw/<cmd>')\n"
                "def kw(cmd):\n"
                "    return prepare(safe='x', text=cmd)\n"
            ),
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def prepare(safe, text):\n"
                "    launch(text)\n"
                "    return safe\n"
            ),
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1

    def test_keyword_binding_is_positionally_precise(
            self, tmp_path, packs) -> None:
        """The tainted kwarg lands on ITS parameter only: a sink fed
        by the untainted sibling parameter stays quiet."""
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "from .helpers import prepare\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/kw/<cmd>')\n"
                "def kw(cmd):\n"
                "    return prepare(safe='x', text=cmd)\n"
            ),
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def prepare(safe, text):\n"
                "    launch(safe)\n"
                "    return text\n"
            ),
        )
        res = _run(tmp_path, files, packs)
        assert res.candidates == ()

    def test_star_args_degrade_to_all_params_tagged(
            self, tmp_path, packs) -> None:
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "from .helpers import prepare\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/star/<cmd>')\n"
                "def star(cmd):\n"
                "    args = [cmd]\n"
                "    return prepare(*args)\n"
            ),
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def prepare(text):\n"
                "    return launch(text)\n"
            ),
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1
        tags = {t for h in res.candidates[0].hops for t in h.tags}
        assert "binding_all_params" in tags


# ── eviction under a candidate flood ─────────────────────────────────


class TestEviction:
    def test_priority_order_curated_survives_learned_evicts_first(
            self, tmp_path, packs) -> None:
        """At the candidate cap: learned-spec candidates evict before
        pack-spec candidates; within a spec tier, longer paths evict
        before shorter. Counts are visible per spec tier."""
        learned = LearnedIntake(sinks=(LearnedSpec(
            role="sink", function="app.store.raw_query",
            taint_classes=("sql-injection",),
        ),))
        files = dict(_PKG_INIT)
        files["app/store.py"] = (
            "def raw_query(sql):\n"
            "    return sql\n"
        )
        files["app/sink_a.py"] = (
            "import subprocess\n"
            "\n"
            "def launch_a(payload):\n"
            "    subprocess.run(payload, shell=True)\n"
            "    return None\n"
        )
        files["app/sink_b.py"] = (
            "import subprocess\n"
            "\n"
            "def launch_b(payload):\n"
            "    subprocess.run(payload, shell=True)\n"
            "    return None\n"
        )
        files["app/views.py"] = (
            "from flask import Flask\n"
            "from .sink_a import launch_a\n"
            "from .store import raw_query\n"
            "from .helpers import step\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/a/<x>')\n"
            "def a(x):\n"
            "    launch_a(x)\n"
            "    return 'ok'\n"
            "\n"
            "@app.route('/b/<x>')\n"
            "def b(x):\n"
            "    raw_query(x)\n"
            "    return 'ok'\n"
            "\n"
            "@app.route('/c/<x>')\n"
            "def c(x):\n"
            "    step(x)\n"
            "    return 'ok'\n"
        )
        files["app/helpers.py"] = (
            "from .sink_b import launch_b\n"
            "\n"
            "def step(v):\n"
            "    launch_b(v)\n"
            "    return 'ok'\n"
        )
        limits = EngineLimits(max_candidates=2)
        res = _run(tmp_path, files, packs, learned=learned,
                   limits=limits)
        assert "candidates" in res.caps_hit
        assert len(res.candidates) == 2
        # The learned-sink candidate lost first; the two pack-sink
        # candidates (short direct + longer chain) survive.
        tiers = [c.spec_tier for c in res.candidates]
        assert TIER_LEARNED not in tiers
        assert res.stat("candidates_evicted") == 1
        assert res.stat("candidates_evicted_spec_learned") == 1
        # Within the surviving spec tier, shorter path sorts first.
        assert len(res.candidates[0].hops) <= len(res.candidates[1].hops)

    def test_within_tier_longer_paths_evict_first(
            self, tmp_path, packs) -> None:
        files = dict(_PKG_INIT)
        files["app/sink_a.py"] = (
            "import subprocess\n"
            "\n"
            "def launch_a(payload):\n"
            "    subprocess.run(payload, shell=True)\n"
            "    return None\n"
        )
        files["app/sink_b.py"] = (
            "import subprocess\n"
            "\n"
            "def launch_b(payload):\n"
            "    subprocess.run(payload, shell=True)\n"
            "    return None\n"
        )
        files["app/views.py"] = (
            "from flask import Flask\n"
            "from .sink_a import launch_a\n"
            "from .helpers import step\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/short/<x>')\n"
            "def short(x):\n"
            "    launch_a(x)\n"
            "    return 'ok'\n"
            "\n"
            "@app.route('/long/<x>')\n"
            "def long_route(x):\n"
            "    step(x)\n"
            "    return 'ok'\n"
        )
        files["app/helpers.py"] = (
            "from .sink_b import launch_b\n"
            "\n"
            "def step(v):\n"
            "    launch_b(v)\n"
            "    return 'ok'\n"
        )
        res = _run(tmp_path, files, packs,
                   limits=EngineLimits(max_candidates=1))
        assert len(res.candidates) == 1
        assert [h.function for h in res.candidates[0].hops] == [
            "app/views.py::short@8",
            "app/sink_a.py::launch_a@3",
        ]
        assert res.stat("candidates_evicted") == 1
        assert res.stat("candidates_evicted_spec_pack") == 1

    def test_converging_routes_collapse_to_the_best_witness(
            self, tmp_path, packs) -> None:
        """Two routes reaching the SAME sink through the same
        parameter share one fact key and yield ONE candidate (the
        witness); alternative paths are the reconstruction phase's
        job. Pinned so the collapse is a documented choice, not an
        accident."""
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "from .helpers import prepare\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/one/<x>')\n"
                "def one(x):\n"
                "    return prepare(x)\n"
                "\n"
                "@app.route('/two/<x>')\n"
                "def two(x):\n"
                "    return prepare(x)\n"
            ),
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def prepare(text):\n"
                "    return launch(text)\n"
            ),
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1
        assert res.caps_hit == ()


# ── rail boundaries (each reds if its enforcement is removed) ─────────


_CHAIN = _flask_app(
    handler_body=(
        "from flask import Flask\n"
        "from .helpers import prepare\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/run/<cmd>')\n"
        "def run_cmd(cmd):\n"
        "    return prepare(cmd)\n"
    ),
    helpers=(
        "from .exec_layer import launch\n"
        "\n"
        "def prepare(text):\n"
        "    return launch(text)\n"
    ),
)


class TestRailBoundaries:
    def test_iteration_cap_binds_with_marker(self, tmp_path,
                                             packs) -> None:
        res = _run(tmp_path, _CHAIN, packs,
                   limits=EngineLimits(max_iterations=1))
        assert "iterations" in res.caps_hit
        assert res.stat("worklist_pops") == 1

    def test_iteration_cap_plus_one_boundary(self, tmp_path,
                                             packs) -> None:
        full = _run(tmp_path / "full", _CHAIN, packs)
        needed = full.stat("worklist_pops")
        exact = _run(tmp_path / "exact", _CHAIN, packs,
                     limits=EngineLimits(max_iterations=needed))
        assert "iterations" not in exact.caps_hit
        assert len(exact.candidates) == 1
        under = _run(tmp_path / "under", _CHAIN, packs,
                     limits=EngineLimits(max_iterations=needed - 1))
        assert "iterations" in under.caps_hit
        assert under.candidates == ()  # the sink pop was the last one

    def test_fact_key_cap_bounds_state(self, tmp_path, packs) -> None:
        res = _run(tmp_path, _CHAIN, packs,
                   limits=EngineLimits(max_fact_keys=1))
        assert "fact_keys" in res.caps_hit
        assert res.stat("fact_keys") <= 1
        assert res.stat("fact_keys_capped") >= 1

    def test_visit_cap_degrades_counted(self, tmp_path, packs) -> None:
        res = _run(tmp_path, _CHAIN, packs,
                   limits=EngineLimits(max_functions_visited=1))
        assert "functions_visited" in res.caps_hit
        assert res.stat("functions_visited") == 1
        assert res.candidates == ()  # the sink function was never planned

    def test_summary_cap_degrades_counted(self, tmp_path,
                                          packs) -> None:
        res = _run(tmp_path, _CHAIN, packs,
                   limits=EngineLimits(max_summaries=1))
        assert "summaries" in res.caps_hit
        assert res.stat("summaries_computed") == 1

    def test_file_index_cap_degrades_counted(self, tmp_path,
                                             packs) -> None:
        res = _run(tmp_path, _CHAIN, packs,
                   limits=EngineLimits(max_files_indexed=0))
        assert "files_indexed" in res.caps_hit
        assert res.candidates == ()
        assert res.stat("files_indexed_capped") >= 1

    def test_seed_cap_binds_with_marker(self, tmp_path, packs) -> None:
        files = dict(_CHAIN)
        files["app/views.py"] = files["app/views.py"].replace(
            "def run_cmd(cmd):", "def run_cmd(cmd, extra=None):")
        res = _run(tmp_path, files, packs,
                   limits=EngineLimits(max_seed_facts=1))
        assert "seeds" in res.caps_hit
        assert res.stat("seed_facts") == 1

    def test_param_cap_drops_wide_signatures_counted(
            self, tmp_path, packs) -> None:
        files = dict(_PKG_INIT)
        files.update(_SINK_MODULE)
        files["app/views.py"] = (
            "from flask import Flask\n"
            "from .exec_layer import launch\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/wide/<a>')\n"
            "def wide(a, b):\n"
            "    launch(b)\n"
            "    return 'ok'\n"
        )
        res = _run(tmp_path, files, packs,
                   limits=EngineLimits(max_params_per_function=1))
        assert "params_per_function" in res.caps_hit
        assert res.stat("params_capped") >= 1
        assert res.candidates == ()  # b was beyond the cap

    def test_path_hop_cap_stops_deep_chains_counted(
            self, tmp_path, packs) -> None:
        res = _run(tmp_path, _CHAIN, packs,
                   limits=EngineLimits(max_path_hops=1))
        assert "path_hops" in res.caps_hit
        assert res.stat("path_hops_capped") >= 1
        assert res.candidates == ()  # sink sits two hops deep

    def test_frontier_record_cap_keeps_full_count(self, tmp_path,
                                                  packs) -> None:
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "from .helpers import mystery\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/d/<x>')\n"
                "def d(x):\n"
                "    fa = mystery()\n"
                "    fa(x)\n"
                "    fb = mystery()\n"
                "    fb(x)\n"
                "    return 'ok'\n"
            ),
            helpers=(
                "def mystery():\n"
                "    return None\n"
            ),
        )
        res = _run(tmp_path, files, packs,
                   limits=EngineLimits(max_frontier_records=1))
        assert "frontier_records" in res.caps_hit
        assert len(res.frontier) == 1
        assert res.stat("taint_at_unresolved") >= 2  # full count survives

    def test_wall_budget_degrades_to_partial_result(
            self, tmp_path, packs) -> None:
        res = _run(tmp_path, _CHAIN, packs,
                   limits=EngineLimits(wall_budget_s=0.0))
        assert "wall_budget" in res.caps_hit
        assert res.candidates == ()
        assert res.to_dict()["doctrine"] == DOCTRINE

    def test_candidate_cap_never_over_admits(self, tmp_path,
                                             packs) -> None:
        res = _run(tmp_path, _CHAIN, packs,
                   limits=EngineLimits(max_candidates=0))
        assert res.candidates == ()
        assert "candidates" in res.caps_hit
        assert res.stat("candidates_evicted") >= 1

    def test_plan_successor_cap_bounds_fan_out_counted(
            self, tmp_path, packs) -> None:
        res = _run(tmp_path, _CHAIN, packs,
                   limits=EngineLimits(max_plan_successors=0))
        assert "plan_successors" in res.caps_hit
        assert res.stat("plan_succ_capped") >= 1
        assert res.candidates == ()  # nothing propagated past hop one

    def test_retained_bytes_floor_refuses_counted(self, tmp_path,
                                                  packs) -> None:
        """A budget below even one index: everything refuses with
        the marker — a partial, honest result instead of unbounded
        RAM (host memory is never the enforcement mechanism)."""
        res = _run(tmp_path, _CHAIN, packs,
                   limits=EngineLimits(max_retained_bytes=1))
        assert "retained_bytes" in res.caps_hit
        assert res.candidates == ()
        assert res.stat("index_refused_bytes") >= 1
        assert res.stat("retained_bytes_estimate") <= 1

    def test_retained_bytes_eviction_preserves_coverage(
            self, tmp_path, packs) -> None:
        """A budget that fits the fact state and one file at a time
        but not the whole memo set, on a chain that RETURNS to its
        first file (so an evicted index is needed again): caches
        evict LRU and reload on demand (counted), and the candidate
        is STILL found — the rail trades wall time for RAM, never
        coverage."""
        files = dict(_PKG_INIT)
        files.update(_SINK_MODULE)
        files["app/views.py"] = (
            "from flask import Flask\n"
            "from .mid import step\n"
            "from .exec_layer import launch\n\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/go/<cmd>')\n"
            "def go(cmd):\n"
            "    return step(cmd)\n\n"
            "def finish(v):\n"
            "    launch(v)\n"
            "    return v\n"
        )
        files["app/mid.py"] = (
            "from .views import finish\n\n"
            "def step(v):\n"
            "    return finish(v)\n"
        )
        res = _run(tmp_path, files, packs,
                   limits=EngineLimits(max_retained_bytes=40_000))
        assert len(res.candidates) == 1  # coverage preserved
        assert "retained_bytes" in res.caps_hit
        assert (res.stat("indexes_evicted")
                + res.stat("plans_evicted")) >= 1
        assert res.stat("index_reloads") >= 1
        assert res.stat("retained_bytes_estimate") <= 40_000
        # Rebuild spend is accounted: extractions exceed distinct
        # visits exactly when plan rebuilds happened.
        assert res.stat("summaries_computed") == (
            res.stat("functions_visited") + res.stat("plan_rebuilds"))

    def test_opaque_summary_dead_end_is_counted(self, tmp_path,
                                                packs) -> None:
        """Taint reaching a function whose summary degraded opaque
        (over a summary-layer cap) dead-ends visibly, never as a
        silent no-flow."""
        from core.taint.summaries import Limits
        res = _run(tmp_path, _CHAIN, packs,
                   limits=EngineLimits(
                       summary_limits=Limits(max_statements=0)))
        assert res.stat("taint_at_opaque_summary") >= 1
        assert res.stat("summaries_opaque") >= 1
        assert res.candidates == ()
