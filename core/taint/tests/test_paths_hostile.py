"""Hostile-shape, flood, fuzz and growth batteries for path
reconstruction.

Synthetic packages (module texts through the engine's indexer seam
plus constructed callgraph/routes — the ``test_engine_hostile``
idiom) attack the reconstruction rails: deep chains at the hop cap,
alternative floods at the per-key and per-candidate caps, hostile
bytes through every render egress, mutation fuzz with a
no-fabricated-spans oracle, the growth-ratio pin at a discriminating
size, and the wall under stalled excerpt reloads. Ground truth
against the REAL builder chain lives in ``test_paths.py``.
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
from core.security.log_sanitisation import escape_nonprintable
from core.taint.engine import (
    EngineLimits,
    PropagationResult,
    propagate,
)
from core.taint.packs import PackSet, default_pack_names, load_packs
from core.taint.summaries import ModuleIndex, index_module_text

#: Virtual root: the indexer below never touches the filesystem.
_ROOT = Path("/raptor-synthetic-taint-root")


@pytest.fixture(scope="module")
def packs() -> PackSet:
    return load_packs(default_pack_names())


def _mem_indexer(texts: dict[str, str]):
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
    def __init__(self, path: str, module: str) -> None:
        self.path = path
        self.module = module
        self.lines: list[str] = ["import subprocess", "import shlex"]

    def func(self, name: str, body: list[str]) -> int:
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


def _diamond_package(
    n: int, stmts: int = 2,
) -> tuple[dict[str, str], PackageCallGraph, RouteModels]:
    """``n`` independent route → (via_a | via_b) → sink diamonds:
    every candidate converges two paths at its sink key, so
    reconstruction renders one alternative per candidate — the
    C2-discriminating shape."""
    texts: dict[str, str] = {}
    nodes: list[CallGraphNode] = []
    edges: list[CallGraphEdge] = []
    routes: list[RouteRecord] = []
    for c in range(n):
        path = f"pkg/dia_{c}.py"
        module = f"pkg.dia_{c}"
        buf = _FileBuf(path, module)
        entry_body = _chain_body(stmts, ["    via_a({var})",
                                         "    via_b({var})"])
        entry_line = buf.func("entry", entry_body)
        entry_id = f"{path}::entry@{entry_line}"
        nodes.append(_node(path, module, "entry", entry_line))
        call_a = entry_line + len(entry_body) - 2
        call_b = entry_line + len(entry_body) - 1
        sink_body = _chain_body(
            stmts, ["    subprocess.run({var}, shell=True)"])
        via_ids = {}
        for name in ("via_a", "via_b"):
            line = buf.func(name, ["    sinkf(v)", "    return v"])
            via_ids[name] = f"{path}::{name}@{line}"
            nodes.append(_node(path, module, name, line))
            edges.append(CallGraphEdge(
                src=via_ids[name], dst=f"__sink_{c}__",
                tier=TIER_RESOLVED_STATIC, kind="call",
                lines=(line + 1,)))
        sink_line = buf.func("sinkf", sink_body)
        sink_id = f"{path}::sinkf@{sink_line}"
        nodes.append(_node(path, module, "sinkf", sink_line))
        fixed = []
        for e in edges:
            fixed.append(e if e.dst != f"__sink_{c}__" else
                         CallGraphEdge(src=e.src, dst=sink_id,
                                       tier=e.tier, kind=e.kind,
                                       lines=e.lines))
        edges = fixed
        edges.append(CallGraphEdge(
            src=entry_id, dst=via_ids["via_a"],
            tier=TIER_RESOLVED_STATIC, kind="call", lines=(call_a,)))
        edges.append(CallGraphEdge(
            src=entry_id, dst=via_ids["via_b"],
            tier=TIER_RESOLVED_STATIC, kind="call", lines=(call_b,)))
        texts[path] = buf.text()
        routes.append(_route(entry_id, f"/d{c}/<v>", path, 1))
    graph = PackageCallGraph(nodes=tuple(nodes), edges=tuple(edges))
    return texts, graph, RouteModels(routes=tuple(routes))


def _run(texts, graph, routes, packs, limits=None) -> PropagationResult:
    return propagate(graph, routes, packs, target_root=_ROOT,
                     limits=limits, indexer=_mem_indexer(texts))


def _expected_excerpt(texts: dict[str, str], file_path: str,
                      line: int, cap: int) -> str | None:
    """Recompute the only excerpt the renderer is allowed to emit
    for (file, line) — the no-fabrication oracle."""
    text = texts.get(file_path)
    if text is None:
        return None
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if not (1 <= line <= len(lines)):
        return None
    escaped = escape_nonprintable(lines[line - 1].strip())
    if len(escaped) > cap:
        return f"{escaped[:cap]}...[+{len(escaped) - cap} chars]"
    return escaped


def _assert_no_fabricated_spans(
    res: PropagationResult, texts: dict[str, str],
    graph: PackageCallGraph, limits: EngineLimits,
) -> None:
    """Every rendered span must exist in the real inventory and every
    excerpt must be the escaped/bounded text of the real line —
    reconstruction resolves, it never invents."""
    node_files = {n.file_path for n in graph.nodes}
    for cand in res.candidates:
        all_steps = list(cand.steps)
        for alt in cand.alternatives:
            all_steps.extend(alt.steps)
        for step in all_steps:
            if step.file:
                assert step.file in node_files, step.file
            if step.call_file:
                assert step.call_file in node_files, step.call_file
            if step.excerpt:
                src = step.call_file or step.file
                line = step.call_line or step.function_line
                expected = _expected_excerpt(
                    texts, src, line, limits.max_excerpt_chars)
                assert expected is not None, (src, line)
                assert step.excerpt == expected
                assert "\x1b" not in step.excerpt
                assert "\x00" not in step.excerpt


# ── deep chains at the hop cap ───────────────────────────────────────


def test_64_hop_chain_renders_at_the_cap(packs) -> None:
    """A 64-deep chain with the hop cap raised to match: the witness
    renders one step per hop plus the sink step, every span real,
    in bounded time."""
    texts, graph, routes = _chain_package(1, 64, 1)
    limits = EngineLimits(max_path_hops=64)
    start = time.monotonic()
    res = _run(texts, graph, routes, packs, limits=limits)
    elapsed = time.monotonic() - start
    assert elapsed < 10.0, f"deep chain took {elapsed:.1f}s"
    assert len(res.candidates) == 1
    c = res.candidates[0]
    assert len(c.hops) == 64
    assert len(c.steps) == 65
    assert c.steps[-1].kind == "sink"
    _assert_no_fabricated_spans(res, texts, graph, limits)


def test_hop_capped_chain_stays_honest(packs) -> None:
    """Deeper than the cap: propagation stops counted (C1) and
    whatever DID emit reconstructs within the cap — no partial
    fabrication past the wall."""
    texts, graph, routes = _chain_package(1, 30, 1)
    limits = EngineLimits(max_path_hops=8)
    res = _run(texts, graph, routes, packs, limits=limits)
    assert "path_hops" in res.caps_hit
    for c in res.candidates:  # nothing reaches the depth-30 sink
        assert len(c.steps) <= 8 + 1
    _assert_no_fabricated_spans(res, texts, graph, limits)


# ── alternative floods ───────────────────────────────────────────────


def test_route_flood_convergence_caps_alt_retention(packs) -> None:
    """200 routes converge on one helper key: per-key retention
    stops at the cap counted+marked, the candidate's alternatives
    stay inside the per-candidate cap, and the whole run stays
    bounded."""
    path = "pkg/hub.py"
    module = "pkg.hub"
    buf = _FileBuf(path, module)
    sink_line = buf.func(
        "sinkf", ["    subprocess.run(v, shell=True)", "    return v"])
    sink_id = f"{path}::sinkf@{sink_line}"
    nodes = [_node(path, module, "sinkf", sink_line)]
    edges = []
    routes = []
    for i in range(200):
        line = buf.func(f"h_{i}", ["    sinkf(v)", "    return v"])
        hid = f"{path}::h_{i}@{line}"
        nodes.append(_node(path, module, f"h_{i}", line))
        edges.append(CallGraphEdge(
            src=hid, dst=sink_id, tier=TIER_RESOLVED_STATIC,
            kind="call", lines=(line + 1,)))
        routes.append(_route(hid, f"/f{i}/<v>", path, 1))
    texts = {path: buf.text()}
    graph = PackageCallGraph(nodes=tuple(nodes), edges=tuple(edges))
    limits = EngineLimits()
    start = time.monotonic()
    res = _run(texts, graph, RouteModels(routes=tuple(routes)), packs,
               limits=limits)
    elapsed = time.monotonic() - start
    assert elapsed < 15.0, f"flood took {elapsed:.1f}s"
    assert "alt_arrivals" in res.caps_hit
    assert res.stat("alt_arrivals_capped") > 0
    for c in res.candidates:
        assert len(c.alternatives) <= \
            limits.max_alternatives_per_candidate
    # The retained alternatives still surfaced distinct sources.
    hub_candidates = [c for c in res.candidates
                      if c.sink_function == sink_id]
    assert hub_candidates
    for c in hub_candidates:
        sources = {json.dumps(dict(a.source), sort_keys=True)
                   for a in c.alternatives}
        assert len(sources) == len(c.alternatives)  # deduped
    _assert_no_fabricated_spans(res, texts, graph, limits)


def test_diamond_flood_all_candidates_render_alternatives(
        packs) -> None:
    """120 diamonds: every candidate renders its folded second path;
    reconstruction cost stays linear-ish (the growth pin below is
    the trend belt, this is the absolute wall)."""
    texts, graph, routes = _diamond_package(120)
    start = time.monotonic()
    res = _run(texts, graph, routes, packs)
    elapsed = time.monotonic() - start
    assert elapsed < 20.0, f"diamonds took {elapsed:.1f}s"
    assert len(res.candidates) == 120
    with_alts = [c for c in res.candidates if c.alternatives]
    assert len(with_alts) == 120
    _assert_no_fabricated_spans(res, texts, graph, EngineLimits())


def test_alternative_selection_best_tier_first(packs) -> None:
    """Deterministic selection: with one alternative slot and two
    folded routes — one all-static, one through a heuristic dispatch
    edge — the static alternative survives; the heuristic one is the
    counted overflow."""
    path = "pkg/tiers.py"
    module = "pkg.tiers"
    buf = _FileBuf(path, module)
    sink_line = buf.func(
        "sinkf", ["    subprocess.run(v, shell=True)", "    return v"])
    sink_id = f"{path}::sinkf@{sink_line}"
    nodes = [_node(path, module, "sinkf", sink_line)]
    edges = []
    routes = []
    tiers = {"h_0": TIER_RESOLVED_STATIC, "h_1": TIER_RESOLVED_STATIC,
             "h_2": TIER_HEURISTIC_DYNAMIC}
    for name, tier in tiers.items():
        line = buf.func(name, ["    sinkf(v)", "    return v"])
        hid = f"{path}::{name}@{line}"
        nodes.append(_node(path, module, name, line))
        kind = ("getattr_dispatch" if tier == TIER_HEURISTIC_DYNAMIC
                else "call")
        edges.append(CallGraphEdge(
            src=hid, dst=sink_id, tier=tier, kind=kind,
            lines=(line + 1,)))
        routes.append(_route(hid, f"/{name}/<v>", path, 1))
    texts = {path: buf.text()}
    graph = PackageCallGraph(nodes=tuple(nodes), edges=tuple(edges))
    res = _run(texts, graph, RouteModels(routes=tuple(routes)), packs,
               limits=EngineLimits(max_alternatives_per_candidate=1))
    # The static-tier candidate for the sink key carries the one
    # alternative slot; the surviving alternative must be the OTHER
    # static route, never the heuristic one.
    best = [c for c in res.candidates
            if c.sink_function == sink_id
            and c.path_tier == TIER_RESOLVED_STATIC]
    assert best
    c = best[0]
    assert len(c.alternatives) == 1
    assert c.alternatives[0].path_tier == TIER_RESOLVED_STATIC
    assert "alternatives" in res.caps_hit
    # Two distinct folded paths, one slot — exactly one drop.
    assert res.stat("alternatives_capped") == 1


# ── hostile bytes through every render egress ────────────────────────


def test_hostile_file_names_ride_data_plane_excerpts_escaped(
        packs) -> None:
    """Hostile bytes in file paths / node ids pass through the
    name-shaped step fields BYTE-IDENTICAL (consumers join them
    against the inventory; ``derived_from_target`` marks them for
    display-time escaping) while the excerpt egress — this layer's
    own render product — is escaped here."""
    evil_path = "pkg/\x1b]0;pwned\x07‮.py"
    module = "pkg.evil"
    buf = _FileBuf(evil_path, module)
    entry_line = buf.func(
        "entry", ["    x = v + '\x1b[31mRED'",
                  "    subprocess.run(x + '\x1b[31mRED', shell=True)",
                  "    return x"])
    entry_id = f"{evil_path}::entry@{entry_line}"
    texts = {evil_path: buf.text()}
    graph = PackageCallGraph(
        nodes=(_node(evil_path, module, "entry", entry_line),))
    routes = RouteModels(routes=(
        _route(entry_id, "/e/<v>", evil_path, 1),))
    res = _run(texts, graph, routes, packs)
    assert len(res.candidates) == 1
    c = res.candidates[0]
    assert c.steps
    for step in c.steps:
        assert step.file == evil_path          # verbatim: join integrity
        assert step.function == entry_id
        assert "\x1b" not in step.excerpt      # escaped render egress
        assert "\x07" not in step.excerpt
    sink_step = c.steps[-1]
    # The sink line itself carries the ESC byte: escaped TEXT only.
    assert "\\x1b[31mRED" in sink_step.excerpt
    payload = json.dumps(res.to_dict())
    assert json.loads(payload) == res.to_dict()


def test_megabyte_line_excerpt_costs_a_window_not_the_line(
        packs) -> None:
    """A 1.5 MB single-line sink: the excerpt escapes only a bounded
    window (not the whole crafted line), the elision marker reports
    the elided length in RAW characters, and the run stays fast."""
    pad = "'" + "A" * 1_500_000 + "'"
    path, module = "pkg/fat.py", "pkg.fat"
    buf = _FileBuf(path, module)
    line = buf.func("entry", [
        f"    subprocess.run(v + {pad}, shell=True)", "    return v"])
    entry_id = f"{path}::entry@{line}"
    texts = {path: buf.text()}
    graph = PackageCallGraph(
        nodes=(_node(path, module, "entry", line),))
    routes = RouteModels(routes=(_route(entry_id, "/e/<v>", path, 1),))
    start = time.monotonic()
    res = _run(texts, graph, routes, packs)
    elapsed = time.monotonic() - start
    assert elapsed < 3.0, f"fat line took {elapsed:.2f}s"
    sink_step = res.candidates[0].steps[-1]
    assert sink_step.excerpt_truncated
    marker = sink_step.excerpt[sink_step.excerpt.index("...[+"):]
    elided = int(marker[len("...[+"):-len(" chars]")])
    assert elided > 1_400_000  # raw characters, not escaped length


def test_truncation_never_severs_an_escape_sequence(packs) -> None:
    """When the bound falls inside an escape expansion, the kept
    text ends BEFORE the escape — piece-wise fill, no partial
    ``\\x`` fragments."""
    texts, graph, routes = _chain_package(1, 2, 1)
    key = "pkg/chain_0.py"
    # The sink call line gains a hostile byte positioned so the
    # escape's 4-char expansion straddles the bound.
    texts = dict(texts)
    texts[key] = texts[key].replace(
        "subprocess.run(x0, shell=True)",
        "subprocess.run(x0 + '\x1b', shell=True)")
    cap = len("subprocess.run(x0 + '") + 2  # mid-escape boundary
    res = _run(texts, graph, routes, packs,
               limits=EngineLimits(max_excerpt_chars=cap))
    sink_step = res.candidates[0].steps[-1]
    assert sink_step.excerpt_truncated
    kept = sink_step.excerpt[: sink_step.excerpt.index("...[+")]
    assert len(kept) <= cap
    assert "\\x" not in kept.replace("\\x1b", "")  # no partial escape
    assert not kept.endswith(("\\", "\\x", "\\x1"))


def test_unreadable_file_omits_excerpt_never_invents(packs) -> None:
    """A node whose file cannot be read back gets empty excerpt
    fields — counted, never synthesized."""
    texts, graph, routes = _chain_package(1, 3, 1)
    del texts["pkg/chain_0.py"]
    res = _run(texts, graph, routes, packs)
    # No summaries can be extracted → no candidates at all; the
    # point is no crash and no fabricated render output.
    assert res.candidates == ()
    json.dumps(res.to_dict())


def test_dangling_node_span_left_empty(packs) -> None:
    """A hop entering a node the graph cannot resolve renders with
    empty span fields (file ``""``, line 0) — the honest unknown."""
    texts, graph, routes = _chain_package(1, 3, 1)
    # Point the mid-chain edge at a ghost node id; the summary
    # channel still joins by line, so taint flows into the ghost.
    edges = []
    for e in graph.edges:
        if e.dst.endswith("::f_1@8") or "f_1" in e.dst:
            edges.append(CallGraphEdge(
                src=e.src, dst="ghost.py::g@1", tier=e.tier,
                kind=e.kind, lines=e.lines))
        else:
            edges.append(e)
    hostile = PackageCallGraph(nodes=graph.nodes, edges=tuple(edges))
    res = _run(texts, hostile, routes, packs)
    for c in res.candidates:
        for step in c.steps:
            if step.function == "ghost.py::g@1":
                assert step.file == ""
                assert step.function_line == 0
                assert step.excerpt == ""
    json.dumps(res.to_dict())


# ── mutation fuzz with the no-fabrication oracle ─────────────────────


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
        i = rng.randrange(len(edges))
        e = edges[i]
        edges[i] = CallGraphEdge(
            src=e.src, dst=f"ghost_{rng.randrange(99)}.py::g@1",
            tier=e.tier, kind=e.kind, lines=e.lines)
    elif mode == 2 and edges:
        i = rng.randrange(len(edges))
        e = edges[i]
        edges[i] = CallGraphEdge(
            src=e.src, dst=e.dst, tier=e.tier, kind=e.kind,
            lines=(max(1, e.lines[0] + rng.randrange(-3, 4)),))
    elif mode == 3 and route_list:
        r = route_list[rng.randrange(len(route_list))]
        route_list.append(RouteRecord(
            framework=r.framework,
            route_pattern="/\x00\x1b<v>",
            http_methods=(), handler="::@\x1b" * rng.randrange(1, 3),
            params=(), middleware_chain=(), file_path=r.file_path,
            line=r.line, style=r.style))
    elif mode == 4 and edges:
        # Duplicate an edge at a heuristic tier: alternative arrivals
        # with a different tier at the same key.
        e = edges[rng.randrange(len(edges))]
        edges.append(CallGraphEdge(
            src=e.src, dst=e.dst, tier=TIER_HEURISTIC_DYNAMIC,
            kind="getattr_dispatch", lines=e.lines))
    elif mode == 5 and nodes:
        i = rng.randrange(len(nodes))
        n = nodes[i]
        nodes[i] = CallGraphNode(
            node_id=n.node_id, kind=n.kind, file_path=n.file_path,
            name=n.name, module=n.module,
            line=max(1, n.line + rng.randrange(-4, 5)))
    elif mode == 6 and texts:
        del texts[rng.choice(sorted(texts))]
    elif mode == 7 and edges:
        e = edges[rng.randrange(len(edges))]
        edges.append(CallGraphEdge(
            src=e.src, dst=e.src, tier=e.tier, kind=e.kind,
            lines=e.lines))
    return (texts, PackageCallGraph(nodes=tuple(nodes),
                                    edges=tuple(edges)),
            RouteModels(routes=tuple(route_list)))


def test_fuzz_12k_reconstruction_never_fabricates(packs) -> None:
    """12k mutated runs: whatever the graph / route / text mutation,
    reconstruction returns well-formed step records (no exception —
    there IS none in the contract), every rendered span ⊆ the real
    inventory, every excerpt is the escaped text of the real line,
    and alternatives stay inside their caps."""
    rng = random.Random(0xC2)
    bases = [
        _chain_package(2, 3, 2),
        _chain_package(1, 4, 1),
        _diamond_package(2, 1),
    ]
    limits = EngineLimits()
    iterations = 12_000
    candidates_seen = 0
    alternatives_seen = 0
    for i in range(iterations):
        texts, graph, routes = bases[i % len(bases)]
        texts, graph, routes = _fuzz_mutate(rng, texts, graph, routes)
        if rng.randrange(4) == 0:
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
            assert len(c.steps) in (0, len(c.hops) + 1)
            assert len(c.alternatives) <= \
                limits.max_alternatives_per_candidate
            alternatives_seen += len(c.alternatives)
            for step in c.steps:
                assert step.function in node_ids or \
                    step.function == c.sink_function, (i, step.function)
            for alt in c.alternatives:
                assert alt.steps
                assert alt.steps[-1].kind == "sink"
                assert all(s.excerpt == "" for s in alt.steps)
        _assert_no_fabricated_spans(res, texts, graph, limits)
        assert all(v >= 0 for v in res.stats.values())
    # Meaningfulness floors: the mutations must starve neither
    # candidates nor the alternative machinery.
    assert candidates_seen >= iterations // 4, (
        f"only {candidates_seen} candidates across {iterations} runs")
    assert alternatives_seen >= iterations // 20, (
        f"only {alternatives_seen} alternatives across {iterations}")


def test_fuzz_output_stays_serialisable(packs) -> None:
    rng = random.Random(0xA17)
    for _ in range(200):
        texts, graph, routes = _diamond_package(1, 1)
        for _ in range(3):
            texts, graph, routes = _fuzz_mutate(rng, texts, graph,
                                                routes)
        res = _run(texts, graph, routes, packs)
        assert json.loads(json.dumps(res.to_dict())) == res.to_dict()


# ── growth-ratio pin (reconstruction-heavy shape) ────────────────────


def _timed_diamonds(n: int, packs: PackSet) -> float:
    texts, graph, routes = _diamond_package(n)
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        res = _run(texts, graph, routes, packs)
        best = min(best, time.perf_counter() - start)
        assert res.candidates and res.candidates[0].alternatives
    return best


def test_growth_ratio_pin_n_vs_2n_with_alternatives(packs) -> None:
    # Host-speed invariant: a RATIO of two timings on the same host.
    # n=120 diamonds → 120 candidates each rendering steps +
    # excerpts + one alternative (well under the 500 candidate cap,
    # so reconstruction work genuinely doubles with n — at 250+ the
    # cap would clip the second run and mask growth). 120 is big
    # enough that per-run constant overhead does not swamp a
    # super-linear term in the candidates × hops × alternatives
    # product. 2.6 keeps linear-with-overhead headroom: raising it
    # hides super-linear blowups, lowering it flakes on interpreter
    # noise. Trend belt; the diamond-flood wall above is the
    # absolute rail.
    t_n = _timed_diamonds(120, packs)
    t_2n = _timed_diamonds(240, packs)
    assert t_n > 0
    ratio = t_2n / t_n
    assert ratio <= 2.6, f"super-linear growth: ratio {ratio:.2f}"


# ── wall budget under stalled excerpt reloads ────────────────────────


def test_wall_holds_when_excerpt_reloads_stall(packs) -> None:
    """Excerpt reads ride the LRU index cache; a stalled indexer
    during reconstruction (evicted indexes + cold reload) cannot
    stretch the run unboundedly — the per-candidate wall check
    bounds the excess to one candidate's work."""
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
    # Whatever was skipped is counted, whatever rendered is real.
    skipped = res.stat("reconstruction_skipped_wall")
    detailed = sum(1 for c in res.candidates if c.steps)
    assert skipped + detailed == len(res.candidates)
    json.dumps(res.to_dict())
