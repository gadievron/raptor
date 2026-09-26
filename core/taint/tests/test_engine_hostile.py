"""Hostile-shape, flood, fuzz and growth batteries for the
propagation engine.

The generators below build SYNTHETIC packages: module texts (indexed
by the real summary layer through the engine's indexer seam) plus a
callgraph and route records constructed to match — the shapes a
hostile repo can force (dependency cycles at the iteration boundary,
entry-point floods, pathological fan-in/fan-out, dangling edges,
mutated bytes) without paying the inventory builder's cost per
iteration. Ground truth against the REAL builder chain lives in
``test_engine.py``; this file attacks the engine's own rails.
"""

from __future__ import annotations

import json
import random
import time
from pathlib import Path

import pytest

from core.analysis.package_callgraph import (
    TIER_HEURISTIC_DYNAMIC,
    TIER_RESOLVED_STATIC,
    CallGraphEdge,
    CallGraphNode,
    PackageCallGraph,
)
from core.analysis.route_models import RouteModels, RouteRecord
from core.taint.engine import (
    EngineLimits,
    PropagationResult,
    propagate,
)
from core.taint.packs import PackSet, load_packs
from core.taint.tests import HAND_COMPUTED_PACKS
from core.taint.summaries import ModuleIndex, index_module_text

#: Virtual root: the indexer below never touches the filesystem.
_ROOT = Path("/raptor-synthetic-taint-root")


@pytest.fixture(scope="module")
def packs() -> PackSet:
    return load_packs(HAND_COMPUTED_PACKS)


def _mem_indexer(texts: dict[str, str]):
    """In-memory indexer keyed by the node file paths. The indexer
    seam is trusted plumbing (it must not raise); a missing file
    degrades exactly like an unreadable one."""

    def indexer(path: Path, module_name: str) -> ModuleIndex:
        rel = (path.relative_to(_ROOT).as_posix()
               if path.is_absolute() else path.as_posix())
        text = texts.get(rel)
        if text is None:
            idx = ModuleIndex(path=rel, module_name=module_name)
            idx.ok = False
            idx.degrade_reason = "file_unreadable_or_over_cap"
            return idx
        return index_module_text(text, rel, module_name=module_name)

    return indexer


class _FileBuf:
    """One synthetic module under construction, with line accounting
    so graph nodes/edges match the text exactly."""

    def __init__(self, path: str, module: str) -> None:
        self.path = path
        self.module = module
        self.lines: list[str] = ["import subprocess", "import shlex"]

    def func(self, name: str, body: list[str]) -> int:
        """Append ``def name(v):`` + body; return the def line."""
        def_line = len(self.lines) + 1
        self.lines.append(f"def {name}(v):")
        self.lines.extend(body)
        self.lines.append("")
        return def_line

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def _node(path: str, module: str, name: str, line: int) -> CallGraphNode:
    return CallGraphNode(
        node_id=f"{path}::{name}@{line}", kind="function",
        file_path=path, name=name, module=module, line=line,
    )


def _route(handler: str, pattern: str, file_path: str,
           line: int) -> RouteRecord:
    return RouteRecord(
        framework="flask", route_pattern=pattern, http_methods=("GET",),
        handler=handler, params=(), middleware_chain=(),
        file_path=file_path, line=line, style="decorator",
    )


def _chain_body(stmts: int, tails: list[str]) -> list[str]:
    body = []
    var = "v"
    for s in range(stmts):
        body.append(f"    x{s} = {var} + 'k'")
        var = f"x{s}"
    for tail in tails:
        body.append(tail.format(var=var))
    body.append(f"    return {var}")
    return body


def _chain_package(
    n_chains: int, depth: int, stmts: int = 4,
) -> tuple[dict[str, str], PackageCallGraph, RouteModels]:
    """``n_chains`` independent route → helper chain → sink shapes,
    one file per chain (same-file static calls)."""
    texts: dict[str, str] = {}
    nodes: list[CallGraphNode] = []
    edges: list[CallGraphEdge] = []
    routes: list[RouteRecord] = []
    for c in range(n_chains):
        path = f"pkg/chain_{c}.py"
        module = f"pkg.chain_{c}"
        buf = _FileBuf(path, module)
        ids: list[str] = []
        call_lines: list[int] = []
        for d in range(depth):
            last = d == depth - 1
            tail = ("    subprocess.run({var}, shell=True)" if last
                    else f"    f_{d + 1}({{var}})")
            body = _chain_body(stmts, [tail])
            def_line = buf.func(f"f_{d}", body)
            ids.append(f"{path}::f_{d}@{def_line}")
            nodes.append(_node(path, module, f"f_{d}", def_line))
            call_lines.append(def_line + len(body) - 1)
        for d in range(depth - 1):
            edges.append(CallGraphEdge(
                src=ids[d], dst=ids[d + 1], tier=TIER_RESOLVED_STATIC,
                kind="call", lines=(call_lines[d],),
            ))
        texts[path] = buf.text()
        routes.append(_route(ids[0], f"/c{c}/<v>", path, 1))
    graph = PackageCallGraph(nodes=tuple(nodes), edges=tuple(edges))
    return texts, graph, RouteModels(routes=tuple(routes))


def _run(texts, graph, routes, packs, limits=None) -> PropagationResult:
    return propagate(graph, routes, packs, target_root=_ROOT,
                     limits=limits, indexer=_mem_indexer(texts))


# ── adversarial worst shape at the REAL caps ─────────────────────────


def _ripple_package(
    n_ladders: int, h_depth: int, stmts: int,
) -> tuple[dict[str, str], PackageCallGraph, RouteModels]:
    """The convergence-stretching LADDER: monotone joins coalesce
    improvements that arrive while a key is still queued, so an
    adversary stretches iterations only by landing improvements
    AFTER keys have popped. Per ladder:

    * ``enter_h`` (file sorts first → seeds first) SANITIZES then
      dispatches over a HEURISTIC edge into the ``h_0..h_n`` chain:
      the first wave floods every h-key at the worst tier with a
      poisoned killed set (every in-chain sink suppressed, counted).
    * ``enter_s`` reaches the same rungs through a HALF-SPEED spine
      (``s_i → d_i → h_i`` cross + ``d_i → s_{i+1}``): its clean,
      static arrivals land after the h-wave already popped — every
      rung key improves in BOTH lattice coordinates and re-propagates
      down the rest of the chain.

    Every ``h_i`` also fires a sink, so the improvements re-emit and
    the candidate flood exercises eviction.
    """
    texts: dict[str, str] = {}
    nodes: list[CallGraphNode] = []
    edges: list[CallGraphEdge] = []
    route_list: list[RouteRecord] = []
    rungs = min(h_depth, 8)  # spine arrivals stay under MAX_PATH_HOPS
    for lad in range(n_ladders):
        path = f"pkg/ladder_{lad}.py"
        module = f"pkg.ladder_{lad}"
        buf = _FileBuf(path, module)
        # Function block layout is deterministic: 1 def line + body
        # + 1 blank, so every def line is computable up front.
        h_body_len = stmts + 3  # stmts + sink + chain/cycle call + return
        first_def = len(buf.lines) + 1
        h_def = {d: first_def + d * (h_body_len + 2)
                 for d in range(h_depth)}
        h_ids = [f"{path}::h_{d}@{h_def[d]}" for d in range(h_depth)]
        for d in range(h_depth):
            tails = ["    subprocess.run({var}, shell=True)"]
            nxt = f"h_{d + 1}" if d < h_depth - 1 else "h_0"
            tails.append(f"    {nxt}({{var}})")
            body = _chain_body(stmts, tails)
            line = buf.func(f"h_{d}", body)
            assert line == h_def[d]
            nodes.append(_node(path, module, f"h_{d}", line))
            call_line = line + len(body) - 1  # the chain/cycle call
            dst = h_ids[d + 1] if d < h_depth - 1 else h_ids[0]
            # d == h_depth - 1 is the cycle back-edge (the
            # dependency-cycle dimension; converges by lattice
            # height, not by luck).
            edges.append(CallGraphEdge(
                src=h_ids[d], dst=dst, tier=TIER_RESOLVED_STATIC,
                kind="call", lines=(call_line,)))
        s_def: dict[int, int] = {}
        for i in range(rungs):
            line = buf.func(f"s_{i}", [f"    d_{i}(v)", "    return v"])
            s_def[i] = line
            nodes.append(_node(path, module, f"s_{i}", line))
        for i in range(rungs):
            body = [f"    h_{i}(v)"]
            if i + 1 < rungs:
                body.append(f"    s_{i + 1}(v)")
            body.append("    return v")
            line = buf.func(f"d_{i}", body)
            d_id = f"{path}::d_{i}@{line}"
            nodes.append(_node(path, module, f"d_{i}", line))
            edges.append(CallGraphEdge(
                src=f"{path}::s_{i}@{s_def[i]}", dst=d_id,
                tier=TIER_RESOLVED_STATIC, kind="call",
                lines=(s_def[i] + 1,)))
            edges.append(CallGraphEdge(
                src=d_id, dst=h_ids[i], tier=TIER_RESOLVED_STATIC,
                kind="call", lines=(line + 1,)))
            if i + 1 < rungs:
                edges.append(CallGraphEdge(
                    src=d_id, dst=f"{path}::s_{i + 1}@{s_def[i + 1]}",
                    tier=TIER_RESOLVED_STATIC, kind="call",
                    lines=(line + 2,)))
        texts[path] = buf.text()

        ha_path, ha_mod = f"pkg/aa_enter_{lad}.py", f"pkg.aa_enter_{lad}"
        ha = _FileBuf(ha_path, ha_mod)
        ha.lines.append("TABLE = {}")
        line = ha.func("enter_h", ["    v = shlex.quote(v)",
                                   "    TABLE[v](v)", "    return v"])
        ha_id = f"{ha_path}::enter_h@{line}"
        nodes.append(_node(ha_path, ha_mod, "enter_h", line))
        edges.append(CallGraphEdge(
            src=ha_id, dst=h_ids[0], tier=TIER_HEURISTIC_DYNAMIC,
            kind="dict_dispatch", lines=(line + 2,)))
        texts[ha_path] = ha.text()
        route_list.append(_route(ha_id, f"/h{lad}/<v>", ha_path, 1))

        hb_path, hb_mod = f"pkg/ab_enter_{lad}.py", f"pkg.ab_enter_{lad}"
        hb = _FileBuf(hb_path, hb_mod)
        hb.lines.append(f"from .ladder_{lad} import s_0")
        line = hb.func("enter_s", ["    s_0(v)", "    return v"])
        hb_id = f"{hb_path}::enter_s@{line}"
        nodes.append(_node(hb_path, hb_mod, "enter_s", line))
        edges.append(CallGraphEdge(
            src=hb_id, dst=f"{path}::s_0@{s_def[0]}",
            tier=TIER_RESOLVED_STATIC, kind="call", lines=(line + 1,)))
        texts[hb_path] = hb.text()
        route_list.append(_route(hb_id, f"/s{lad}/<v>", hb_path, 1))

    graph = PackageCallGraph(nodes=tuple(nodes), edges=tuple(edges))
    return texts, graph, RouteModels(routes=tuple(route_list))


def test_worst_shape_wall_at_real_caps(packs) -> None:
    # The committed adversarial worst shape, run at the REAL default
    # caps: 120 chains × 18 deep (inside MAX_PATH_HOPS) × 6
    # statements, each chain reachable through a heuristic dispatch
    # hub, a kill-poisoned wrapper AND its own static route, plus a
    # cycle back-edge per chain — every fact key takes the maximum
    # number of monotone improvements this lattice admits, and every
    # improvement re-propagates through the whole chain.
    #
    # Bound calibration (both directions): the clean run measures
    # 0.80-0.90s across 5 back-to-back runs on the development host
    # (median 0.83s, ~12% spread); 12s keeps >13x slow-host headroom
    # while sitting far below what a super-linear regression
    # produces at this size (the growth pin below reds first on
    # gentle regressions; this absolute pin is the wall against
    # catastrophic ones). Raising it hides blowups; lowering it
    # flakes on slow hosts.
    texts, graph, routes = _ripple_package(120, 18, 6)
    start = time.monotonic()
    res = _run(texts, graph, routes, packs)
    elapsed = time.monotonic() - start
    assert elapsed < 12.0, f"worst shape took {elapsed:.1f}s"
    # The shape converged and produced real adversarial work at the
    # real caps: late improvements re-propagated (pops exceed keys),
    # first-wave kills were counted, the candidate flood hit the cap
    # with visible eviction, and the survivors ride the improved
    # static witnesses.
    assert res.stat("fact_improvements") > 1_000
    assert res.stat("worklist_pops") > res.stat("fact_keys")
    assert res.stat("candidates_killed") > 0
    # The once-per-node law, pinned deterministically at scale: one
    # extraction per visited function under the default budgets (a
    # memoization revert re-extracts per pop and reds this equality
    # long before it moves the wall pin).
    assert res.stat("summaries_computed") == \
        res.stat("functions_visited")
    assert res.stat("plan_rebuilds") == 0
    assert len(res.candidates) == 500  # MAX_CANDIDATES bound
    assert "candidates" in res.caps_hit
    assert res.stat("candidates_evicted") > 0
    assert all(c.path_tier == TIER_RESOLVED_STATIC
               for c in res.candidates)


def test_entry_point_flood_10k_routes(packs) -> None:
    # 10k route registrations (the route-model artifact's own cap)
    # over 10k one-hop handlers: the flood is absorbed within the
    # real caps — 500 kept candidates, visible eviction counts,
    # bounded wall.
    texts, graph, routes = _chain_package(2_500, 4, 1)
    # Re-register every chain head 4× (mega-registration flood).
    route_list = list(routes.routes)
    for r in list(route_list):
        for k in range(3):
            route_list.append(_route(
                r.handler, f"{r.route_pattern}/alt{k}", r.file_path,
                r.line + k + 1))
    routes = RouteModels(routes=tuple(route_list))
    assert len(routes.routes) == 10_000
    start = time.monotonic()
    res = _run(texts, graph, routes, packs)
    elapsed = time.monotonic() - start
    assert elapsed < 30.0, f"flood took {elapsed:.1f}s"
    assert len(res.candidates) == 500
    assert "candidates" in res.caps_hit
    assert res.stat("candidates_evicted") >= 2_000
    assert res.stat("candidates_evicted_spec_pack") == \
        res.stat("candidates_evicted")


def test_cycle_convergence_at_iteration_cap_boundary(packs) -> None:
    # A dependency cycle converges by lattice height, not by luck:
    # measure the pops the fixpoint needs, then pin the boundary —
    # the exact budget converges with no marker, one less degrades
    # WITH the marker and still returns a valid partial result.
    texts, graph, routes = _ripple_package(4, 6, 2)
    full = _run(texts, graph, routes, packs)
    needed = full.stat("worklist_pops")
    assert needed > 0
    assert "iterations" not in full.caps_hit

    exact = _run(texts, graph, routes, packs,
                 limits=EngineLimits(max_iterations=needed))
    assert "iterations" not in exact.caps_hit
    assert exact.to_dict() == full.to_dict()

    under = _run(texts, graph, routes, packs,
                 limits=EngineLimits(max_iterations=needed - 1))
    assert "iterations" in under.caps_hit
    assert under.stat("worklist_pops") == needed - 1
    payload = under.to_dict()  # partial but well-formed and honest
    assert payload["doctrine"] == "originate_and_prioritize_only"
    json.dumps(payload)


def test_fan_in_fan_out_pathology(packs) -> None:
    # One callee with 2000 callers (fan-in) and one caller whose one
    # dispatch line fans out to 2000 callees (fan-out beyond
    # anything the real graph emits — its own getattr fan-out cap is
    # 16). The engine must stay bounded, not smart.
    texts: dict[str, str] = {}
    nodes: list[CallGraphNode] = []
    edges: list[CallGraphEdge] = []
    routes: list[RouteRecord] = []

    sink_path, sink_mod = "pkg/sink.py", "pkg.sink"
    sink = _FileBuf(sink_path, sink_mod)
    sink_line = sink.func("swallow", [
        "    subprocess.run(v, shell=True)", "    return v"])
    sink_id = f"{sink_path}::swallow@{sink_line}"
    nodes.append(_node(sink_path, sink_mod, "swallow", sink_line))
    texts[sink_path] = sink.text()

    callers_path, callers_mod = "pkg/callers.py", "pkg.callers"
    callers = _FileBuf(callers_path, callers_mod)
    callers.lines.append("TABLE = {}")
    for i in range(2000):
        line = callers.func(f"in_{i}", ["    TABLE[v](v)",
                                        "    return v"])
        nid = f"{callers_path}::in_{i}@{line}"
        nodes.append(_node(callers_path, callers_mod, f"in_{i}", line))
        edges.append(CallGraphEdge(
            src=nid, dst=sink_id, tier=TIER_HEURISTIC_DYNAMIC,
            kind="dict_dispatch", lines=(line + 1,)))
        routes.append(_route(nid, f"/in{i}/<v>", callers_path, line))
    # Fan-out: one function whose single line reaches every in_*.
    fan_line = callers.func("fan", ["    TABLE[v](v)", "    return v"])
    fan_id = f"{callers_path}::fan@{fan_line}"
    nodes.append(_node(callers_path, callers_mod, "fan", fan_line))
    for n in list(nodes):
        if n.name.startswith("in_"):
            edges.append(CallGraphEdge(
                src=fan_id, dst=n.node_id,
                tier=TIER_HEURISTIC_DYNAMIC, kind="dict_dispatch",
                lines=(fan_line + 1,)))
    routes.append(_route(fan_id, "/fan/<v>", callers_path, fan_line))
    texts[callers_path] = callers.text()

    graph = PackageCallGraph(nodes=tuple(nodes), edges=tuple(edges))
    start = time.monotonic()
    res = _run(texts, graph, RouteModels(routes=tuple(routes)), packs)
    elapsed = time.monotonic() - start
    assert elapsed < 30.0, f"pathology took {elapsed:.1f}s"
    assert len(res.candidates) <= 500
    assert res.stat("worklist_pops") > 0


def test_dangling_edges_never_fabricate(packs) -> None:
    # Edges whose destinations do not exist (and a route whose
    # handler does not exist) must not crash, must not fabricate
    # hops, and taint reaching them lands on the frontier or in
    # counted stats — never in a candidate naming a phantom node.
    texts, graph, routes = _chain_package(3, 3, 2)
    edges = list(graph.edges) + [
        CallGraphEdge(src=graph.nodes[0].node_id,
                      dst="pkg/ghost.py::phantom@1",
                      tier=TIER_RESOLVED_STATIC, kind="call",
                      lines=(9,)),
    ]
    route_list = list(routes.routes) + [
        _route("pkg/nowhere.py::missing@5", "/gone/<v>",
               "pkg/nowhere.py", 5),
    ]
    graph = PackageCallGraph(nodes=graph.nodes, edges=tuple(edges))
    res = _run(texts, graph, RouteModels(routes=tuple(route_list)),
               packs)
    node_ids = {n.node_id for n in graph.nodes}
    for c in res.candidates:
        for hop in c.hops:
            assert hop.function in node_ids, hop.function
    assert res.stat("seed_handler_unbound") == 1


def test_hostile_route_and_node_text_rides_data_plane(packs) -> None:
    # Route patterns / handler ids / file paths are attacker-chosen
    # bytes. The engine treats them as data: no crash, JSON output
    # round-trips, and the hostile bytes appear only inside record
    # FIELDS (render chokepoints escape at display time).
    texts, graph, routes = _chain_package(1, 2, 1)
    evil = "/x\x1b]0;pwned\x07/<v>‮"
    route_list = [RouteRecord(
        framework="flask", route_pattern=evil, http_methods=(),
        handler=routes.routes[0].handler, params=(),
        middleware_chain=(), file_path="pkg/chain_0.py", line=1,
        style="decorator",
    )]
    res = _run(texts, graph, RouteModels(routes=tuple(route_list)),
               packs)
    assert len(res.candidates) == 1
    payload = json.dumps(res.to_dict())
    assert "pwned" in payload  # carried as data, not interpreted


# ── mutation fuzz over generated package trees ───────────────────────


def _fuzz_mutate(rng: random.Random, texts: dict[str, str],
                 graph: PackageCallGraph,
                 routes: RouteModels) -> tuple[
        dict[str, str], PackageCallGraph, RouteModels]:
    mode = rng.randrange(8)
    texts = dict(texts)
    nodes = list(graph.nodes)
    edges = list(graph.edges)
    route_list = list(routes.routes)
    if mode == 0 and texts:
        # Byte-level text mutation (may stop parsing: opaque path).
        key = rng.choice(sorted(texts))
        text = texts[key]
        if text:
            op = rng.randrange(3)
            pos = rng.randrange(len(text))
            if op == 0:
                texts[key] = text[:pos]
            elif op == 1:
                texts[key] = (text[:pos]
                              + rng.choice("\x00\x1b\r‮(:")
                              + text[pos:])
            else:
                texts[key] = text[:pos] + text[pos + 1:]
    elif mode == 1 and edges:
        # Dangling destination.
        i = rng.randrange(len(edges))
        e = edges[i]
        edges[i] = CallGraphEdge(
            src=e.src, dst=f"ghost_{rng.randrange(99)}.py::g@1",
            tier=e.tier, kind=e.kind, lines=e.lines)
    elif mode == 2 and edges:
        # Line jitter: the edge no longer matches its call site.
        i = rng.randrange(len(edges))
        e = edges[i]
        edges[i] = CallGraphEdge(
            src=e.src, dst=e.dst, tier=e.tier, kind=e.kind,
            lines=(max(1, e.lines[0] + rng.randrange(-3, 4)),))
    elif mode == 3 and route_list:
        # Hostile handler id / pattern bytes.
        r = route_list[rng.randrange(len(route_list))]
        route_list.append(RouteRecord(
            framework=r.framework,
            route_pattern="/\x00\x1b<v>",
            http_methods=(), handler="::@\x1b" * rng.randrange(1, 3),
            params=(), middleware_chain=(), file_path=r.file_path,
            line=r.line, style=r.style))
    elif mode == 4 and route_list:
        # Class-kind route with an arbitrary class prefix.
        r = route_list[rng.randrange(len(route_list))]
        route_list.append(RouteRecord(
            framework=r.framework, route_pattern="/cbv/<v>",
            http_methods=(), handler=f"{r.file_path}::Ghost@3",
            params=(), middleware_chain=(), file_path=r.file_path,
            line=r.line, style="urlconf", handler_kind="class"))
    elif mode == 5 and nodes:
        # Node line jitter: summary join must fall back or fail
        # counted, never bind the wrong body silently... the
        # function_at fallback may still find a body; either way no
        # crash and no phantom hops.
        i = rng.randrange(len(nodes))
        n = nodes[i]
        nodes[i] = CallGraphNode(
            node_id=n.node_id, kind=n.kind, file_path=n.file_path,
            name=n.name, module=n.module,
            line=max(1, n.line + rng.randrange(-4, 5)))
    elif mode == 6 and texts:
        # Whole file vanishes (unreadable path).
        del texts[rng.choice(sorted(texts))]
    elif mode == 7 and edges:
        # Self-edge (1-cycle).
        e = edges[rng.randrange(len(edges))]
        edges.append(CallGraphEdge(
            src=e.src, dst=e.src, tier=e.tier, kind=e.kind,
            lines=e.lines))
    return (texts, PackageCallGraph(nodes=tuple(nodes),
                                    edges=tuple(edges)),
            RouteModels(routes=tuple(route_list)))


def test_fuzz_30k_generated_trees(packs) -> None:
    # 30k mutated runs over generated packages: whatever the graph /
    # route / text mutation, the engine returns a well-formed result
    # (no exception outside the contract — there IS no exception in
    # the contract), never fabricates a hop, and stays inside its
    # wall per iteration.
    rng = random.Random(0x51E3)
    bases = [
        _chain_package(2, 3, 2),
        _chain_package(1, 4, 1),
        _ripple_package(2, 3, 1),
    ]
    iterations = 30_000
    candidates_seen = 0
    for i in range(iterations):
        texts, graph, routes = bases[i % len(bases)]
        texts, graph, routes = _fuzz_mutate(rng, texts, graph, routes)
        if rng.randrange(4) == 0:  # stacked mutations
            texts, graph, routes = _fuzz_mutate(rng, texts, graph,
                                                routes)
        start = time.monotonic()
        res = _run(texts, graph, routes, packs)
        elapsed = time.monotonic() - start
        # Host-speed sensitive in the SAFE direction only: a slow
        # host can false-fail, never false-pass.
        assert elapsed < 2.5, f"iteration {i} took {elapsed:.3f}s"
        node_ids = {n.node_id for n in graph.nodes}
        for c in res.candidates:
            candidates_seen += 1
            for hop in c.hops:
                assert hop.function in node_ids, (i, hop.function)
        assert len(res.candidates) <= EngineLimits().max_candidates
        assert all(v >= 0 for v in res.stats.values())
    # Meaningfulness floor: the mutations must not have starved the
    # battery of real propagation.
    assert candidates_seen >= iterations // 4, (
        f"only {candidates_seen} candidates across {iterations} runs")


def test_fuzz_output_stays_serialisable(packs) -> None:
    # A focused pass with hostile bytes everywhere JSON must still
    # round-trip (control chars ride as escaped data).
    rng = random.Random(0xB0B)
    for _ in range(200):
        texts, graph, routes = _chain_package(1, 3, 1)
        for _ in range(3):
            texts, graph, routes = _fuzz_mutate(rng, texts, graph,
                                                routes)
        res = _run(texts, graph, routes, packs)
        json.loads(json.dumps(res.to_dict()))


# ── growth-ratio pin ─────────────────────────────────────────────────


def _timed_propagate(n_chains: int, packs: PackSet) -> float:
    texts, graph, routes = _chain_package(n_chains, 12, 6)
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        res = _run(texts, graph, routes, packs)
        best = min(best, time.perf_counter() - start)
        assert res.candidates  # real propagation, not a degenerate run
    return best


def test_growth_ratio_pin_n_vs_2n(packs) -> None:
    # Host-speed invariant: a RATIO of two timings taken the same
    # way on the same host. n=600 functions (50 chains × 12 deep):
    # small enough for CI, big enough that per-run constant overhead
    # does not swamp a super-linear term (the summary layer measured
    # exactly this — n=150 waved a real quadratic through; 600-class
    # discriminates). 2.6 keeps linear-with-overhead headroom:
    # raising it hides super-linear blowups, lowering it flakes on
    # interpreter noise. Trend belt; the absolute worst-shape wall
    # above is the load-bearing rail against large regressions.
    t_n = _timed_propagate(50, packs)     # 600 functions
    t_2n = _timed_propagate(100, packs)   # 1200 functions
    assert t_n > 0
    ratio = t_2n / t_n
    assert ratio <= 2.6, f"super-linear growth: ratio {ratio:.2f}"


# ── wall budget under a stalled dependency ───────────────────────────


def test_wall_budget_holds_against_slow_indexing(packs) -> None:
    # The wall is checked at plan builds too: an indexer that stalls
    # (giant files, cold NFS, crafted parse shapes) cannot stretch
    # the run past the budget by more than one file's work.
    texts, graph, routes = _chain_package(20, 3, 2)
    inner = _mem_indexer(texts)

    def slow(path: Path, module_name: str) -> ModuleIndex:
        time.sleep(0.05)
        return inner(path, module_name)

    start = time.monotonic()
    res = propagate(graph, routes, packs, target_root=_ROOT,
                    limits=EngineLimits(wall_budget_s=0.2),
                    indexer=slow)
    elapsed = time.monotonic() - start
    assert "wall_budget" in res.caps_hit
    assert elapsed < 5.0
    json.dumps(res.to_dict())
