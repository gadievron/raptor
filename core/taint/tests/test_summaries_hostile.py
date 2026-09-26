"""Hostile-shape, degradation-boundary, fuzz, and cost-rail battery
for the summary extractor.

The extractor parses ATTACKER BYTES. Contract under hostility:

* nothing raises past the extraction boundary — hostile input yields
  opaque summaries with counted reasons, never exceptions;
* every named cap degrades at its boundary (±1 pins below);
* cost is bounded as a PRODUCT — AST nodes × flows-per-value ×
  summary entries — so a crafted shape can max ONE factor without
  unbounding the walk (the worst-shape and growth pins below);
* no summary field fabricates a name absent from the source.
"""

from __future__ import annotations

import ast
import random
import re
import time

import pytest

from core.taint.packs import PackSet, load_packs
from core.taint.tests import HAND_COMPUTED_PACKS
from core.taint.summaries import (
    MAX_SOURCE_FILE_BYTES,
    FunctionSummary,
    Limits,
    SpecIndex,
    build_spec_index,
    extract_summary,
    index_module,
    index_module_text,
    summarize_module,
)


@pytest.fixture(scope="module")
def packs() -> PackSet:
    return load_packs(HAND_COMPUTED_PACKS)


@pytest.fixture(scope="module")
def specs(packs: PackSet) -> SpecIndex:
    return build_spec_index(packs)


def one_summary(
    source: str, specs: SpecIndex, *, limits: Limits | None = None,
) -> FunctionSummary:
    idx = index_module_text(source, "hostile.py", module_name="hostile")
    assert idx.functions, "fixture must parse to at least one function"
    return extract_summary(idx, idx.functions[0], specs, limits=limits)


def capped_reason(summary: FunctionSummary) -> str:
    for marker in summary.markers:
        if marker.startswith("summary_capped:"):
            return marker.split(":", 1)[1]
    return ""


# ── degradation boundaries (±1 on the named caps) ────────────────────


def test_statement_budget_boundary(specs: SpecIndex) -> None:
    limits = Limits(max_statements=10)
    under = "def f(a):\n" + "    x = a\n" * 9 + "    return x\n"
    over = "def f(a):\n" + "    x = a\n" * 10 + "    return x\n"
    ok = one_summary(under, specs, limits=limits)
    assert not ok.opaque
    capped = one_summary(over, specs, limits=limits)
    assert capped.opaque
    assert capped_reason(capped) == "statement_budget"
    # The opaque degradation is CONSERVATIVE: params -> return.
    assert capped.params_to_return() == (0,)


def test_statement_width_boundary(specs: SpecIndex) -> None:
    limits = Limits(max_expr_nodes_per_statement=64)
    under = "def f(a):\n    x = (" + " + ".join(["a"] * 20) + ")\n"
    over = "def f(a):\n    x = (" + " + ".join(["a"] * 200) + ")\n"
    assert not one_summary(under, specs, limits=limits).opaque
    capped = one_summary(over, specs, limits=limits)
    assert capped.opaque
    assert capped_reason(capped) == "statement_width"


def test_node_budget_boundary(specs: SpecIndex) -> None:
    limits = Limits(max_nodes=200)
    under = "def f(a):\n" + "    x = a\n" * 10
    over = "def f(a):\n" + "    x = a\n" * 100
    assert not one_summary(under, specs, limits=limits).opaque
    capped = one_summary(over, specs, limits=limits)
    assert capped.opaque
    assert capped_reason(capped) == "node_budget"


def test_walk_depth_boundary(specs: SpecIndex) -> None:
    limits = Limits(max_walk_depth=30)
    under = "def f(a):\n    x = " + "[" * 20 + "a" + "]" * 20 + "\n"
    over = "def f(a):\n    x = " + "[" * 40 + "a" + "]" * 40 + "\n"
    assert not one_summary(under, specs, limits=limits).opaque
    capped = one_summary(over, specs, limits=limits)
    assert capped.opaque
    assert capped_reason(capped) == "walk_depth"


def test_locals_tracked_boundary(specs: SpecIndex) -> None:
    limits = Limits(max_locals=8)
    def body(n: int) -> str:
        return "def f(a):\n" + "".join(
            f"    v{i} = a\n" for i in range(n)
        )
    # params occupy one slot; 7 more locals fit, the 8th over-caps.
    assert not one_summary(body(7), specs, limits=limits).opaque
    capped = one_summary(body(8), specs, limits=limits)
    assert capped.opaque
    assert capped_reason(capped) == "locals_tracked"


def test_flows_per_value_boundary(specs: SpecIndex) -> None:
    limits = Limits(max_flows_per_value=4)
    def body(n: int) -> str:
        params = ", ".join(f"p{i}" for i in range(n))
        summed = " + ".join(f"p{i}" for i in range(n))
        return f"def f({params}):\n    x = {summed}\n    return x\n"
    assert not one_summary(body(4), specs, limits=limits).opaque
    capped = one_summary(body(5), specs, limits=limits)
    assert capped.opaque
    assert capped_reason(capped) == "flows_per_value"


def test_call_channel_boundary(specs: SpecIndex) -> None:
    limits = Limits(max_call_channels=4)
    def body(n: int) -> str:
        return "import extlib\n\ndef f(a):\n" + "".join(
            f"    extlib.h{i}(a)\n" for i in range(n)
        )
    assert not one_summary(body(4), specs, limits=limits).opaque
    capped = one_summary(body(5), specs, limits=limits)
    assert capped.opaque
    assert capped_reason(capped) == "call_channels"


def test_sink_event_boundary(specs: SpecIndex) -> None:
    limits = Limits(max_sink_events=3)
    def body(n: int) -> str:
        return "import os\n\ndef f(a):\n" + "".join(
            "    os.system(a)\n" for _ in range(n)
        )
    assert not one_summary(body(3), specs, limits=limits).opaque
    capped = one_summary(body(4), specs, limits=limits)
    assert capped.opaque
    assert capped_reason(capped) == "sink_events"


def test_access_path_depth_degrades_to_unresolved(
    specs: SpecIndex,
) -> None:
    # Over-depth chains degrade toward UNRESOLVED (assumed
    # propagation) — never toward a match, never opaque.
    limits = Limits(max_access_path_depth=4)
    chain = ".".join(["a"] * 8)
    src = f"import extlib\n\ndef f(x):\n    return extlib.{chain}(x)\n"
    s = one_summary(src, specs, limits=limits)
    assert not s.opaque
    assert s.stat("access_path_depth_capped") >= 1
    assert s.params_to_return() == (0,)


def test_wall_budget_degrades_opaque(specs: SpecIndex) -> None:
    limits = Limits(wall_budget_s=0.0)
    src = "def f(a):\n" + "    x = a\n" * 300
    capped = one_summary(src, specs, limits=limits)
    assert capped.opaque
    assert capped_reason(capped) == "wall_budget"


# ── hostile shapes at the DEFAULT caps ───────────────────────────────


def test_ten_thousand_arg_call_degrades_fast(specs: SpecIndex) -> None:
    src = ("import os\n\ndef f(a):\n    os.system("
           + ", ".join(["a"] * 10_000) + ")\n")
    start = time.monotonic()
    s = one_summary(src, specs)
    elapsed = time.monotonic() - start
    assert s.opaque
    assert capped_reason(s) == "statement_width"
    assert elapsed < 5.0
    # Opaque is still conservative: params propagate to the return.
    assert s.params_to_return() == (0,)


def test_megabyte_line_over_read_cap_degrades_all_functions(
    tmp_path, specs: SpecIndex,
) -> None:
    blob = "def f(a):\n    x = '" + "A" * (MAX_SOURCE_FILE_BYTES + 16)
    blob += "'\n    return x\n"
    path = tmp_path / "huge.py"
    path.write_text(blob)
    idx = index_module(path)
    assert not idx.ok
    assert idx.degrade_reason == "file_unreadable_or_over_cap"


def test_megabyte_line_within_cap_still_summarises(
    specs: SpecIndex,
) -> None:
    src = ("import os\n\ndef f(a):\n    x = '" + "A" * 1_000_000
           + "' + a\n    os.system(x)\n")
    s = one_summary(src, specs)
    assert not s.opaque
    assert {f.origin for ev in s.sink_events for f in ev.flows} == {
        "param:0",
    }


def test_fifo_shaped_paths_never_hang(tmp_path, specs: SpecIndex) -> None:
    import os as _os

    fifo = tmp_path / "trap.py"
    _os.mkfifo(fifo)
    idx = index_module(fifo)
    assert not idx.ok


def test_deep_statement_nesting_refused_or_capped(
    specs: SpecIndex,
) -> None:
    # CPython itself refuses >100 indentation levels, so a 200-deep
    # statement nest is closed UPSTREAM: the index degrades to
    # parse_failed (never raises). The walker's own statement-depth
    # guard is pinned separately below with shrunken limits.
    depth = 200
    src = "def f(a):\n"
    for i in range(depth):
        src += "    " * (i + 1) + "if a:\n"
    src += "    " * (depth + 1) + "pass\n"
    idx = index_module_text(src, "deep.py")
    assert not idx.ok
    assert idx.degrade_reason == "parse_failed"


def test_statement_depth_boundary(specs: SpecIndex) -> None:
    limits = Limits(max_walk_depth=10)

    def nested_ifs(depth: int) -> str:
        src = "def f(a):\n"
        for i in range(depth):
            src += "    " * (i + 1) + "if a:\n"
        src += "    " * (depth + 1) + "pass\n"
        return src

    assert not one_summary(nested_ifs(8), specs, limits=limits).opaque
    capped = one_summary(nested_ifs(20), specs, limits=limits)
    assert capped.opaque
    assert capped_reason(capped) == "walk_depth"


def test_pathological_comprehension_is_bounded(specs: SpecIndex) -> None:
    inner = "a"
    for i in range(150):
        inner = f"[{inner} for v{i} in a]"
    src = f"def f(a):\n    return {inner}\n"
    try:
        ast.parse(src)
    except RecursionError:
        pytest.skip("interpreter refuses this nesting before we see it")
    start = time.monotonic()
    s = one_summary(src, specs)
    assert time.monotonic() - start < 5.0
    assert s.opaque
    assert capped_reason(s) == "walk_depth"


def test_wide_comprehension_generator_fanout(specs: SpecIndex) -> None:
    gens = " ".join(f"for v{i} in a" for i in range(60))
    src = f"import os\n\ndef f(a):\n    os.system([v0 {gens}])\n"
    s = one_summary(src, specs)
    # Either summarised (taint reaches the sink through the loop
    # variable) or width-capped opaque — both bounded, neither wrong.
    if not s.opaque:
        assert {f.origin for ev in s.sink_events for f in ev.flows} == {
            "param:0",
        }


def test_unparseable_file_degrades_every_function(
    specs: SpecIndex,
) -> None:
    idx = index_module_text("def f(:\n", "broken.py")
    assert not idx.ok
    assert idx.degrade_reason == "parse_failed"


def test_null_bytes_and_control_chars_never_raise(
    specs: SpecIndex,
) -> None:
    for hostile in ("def f(a):\n    return a\x00\n",
                    "def f(a):\n\x1b[31m    return a\n",
                    "\ufeffdef f(a):\n    return a\n"):
        idx = index_module_text(hostile, "hostile.py")
        for entry in idx.functions:
            extract_summary(idx, entry, specs)  # must not raise


# ── seeded mutation fuzz ─────────────────────────────────────────────

_FUZZ_BASES = [
    """
import os
import shlex
from flask import request

def handler(name, opts):
    q = request.args.get("q")
    cmd = f"run {name} {q}"
    safe = shlex.quote(cmd)
    os.system(safe)
    return cmd
""",
    """
import subprocess

def build(a, b, *rest, **kw):
    parts = [p.strip() for p in (a, b)]
    x, y = parts[0], parts[1]
    subprocess.run(x, shell=False)
    subprocess.run(y, shell=kw.get("shell"))
    return " ".join(parts)
""",
    """
def compute(data):
    try:
        with open("f") as fh:
            out = {k: v for k, v in data.items()}
    except OSError:
        out = None
    match out:
        case {"cmd": c}:
            eval(c)
        case _:
            pass
    return out
""",
]

_MUTATION_CHARS = "()[]{}:=,.*'\"\\\n\t \x00\x1b#@fdeforinifxa0123"

# Identifier pool for token mutations: names from the bases plus
# spec-relevant names, so mutated-but-parsing programs keep hitting
# the matching tables (shadowed builtins, sanitizer roots, sources).
_TOKEN_POOL = [
    "os", "system", "shlex", "quote", "eval", "exec", "open", "int",
    "input", "request", "args", "get", "subprocess", "run", "shell",
    "a", "b", "kw", "name", "cmd", "safe", "x", "y", "parts", "self",
    "compile", "data", "out", "c", "True", "False", "None",
]

_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _mutate(rng: random.Random, text: str) -> str:
    if rng.random() < 0.5:
        # Token mode: swap identifier occurrences for pool names —
        # usually still parses, so the WALKER (not just the parser)
        # sees the mutation.
        for _ in range(rng.randint(1, 4)):
            words = list(_WORD_RE.finditer(text))
            if not words:
                break
            hit = rng.choice(words)
            text = (text[: hit.start()] + rng.choice(_TOKEN_POOL)
                    + text[hit.end():])
        return text
    out = list(text)
    for _ in range(rng.randint(1, 6)):
        op = rng.randrange(3)
        pos = rng.randrange(max(1, len(out)))
        if op == 0 and out:
            out[pos % len(out)] = rng.choice(_MUTATION_CHARS)
        elif op == 1:
            out.insert(pos, rng.choice(_MUTATION_CHARS))
        elif op == 2 and len(out) > 1:
            del out[pos % len(out)]
    return "".join(out)


def test_mutation_fuzz_30k_no_exceptions_outside_contract(
    specs: SpecIndex,
) -> None:
    rng = random.Random(0x7A19)
    iterations = 30_000
    slowest = 0.0
    summarised = 0
    for i in range(iterations):
        base = _FUZZ_BASES[i % len(_FUZZ_BASES)]
        mutated = _mutate(rng, base)
        start = time.monotonic()
        idx = index_module_text(mutated, "fuzz.py", module_name="fuzz")
        for entry in idx.functions:
            extract_summary(
                idx, entry, specs,
                # Tight wall budget: the fuzz also pins per-parse time.
                limits=Limits(wall_budget_s=2.0),
            )
            summarised += 1
        elapsed = time.monotonic() - start
        slowest = max(slowest, elapsed)
        assert elapsed < 2.5, f"iteration {i} took {elapsed:.3f}s"
    assert slowest < 2.5
    # Meaningfulness pin: a fuzz whose mutants all die at the parser
    # exercises nothing — a healthy share must reach the WALKER.
    assert summarised >= iterations // 4, (
        f"only {summarised} mutants reached extraction"
    )


# ── no fabrication ───────────────────────────────────────────────────


def _source_identifiers(source: str) -> set[str]:
    names: set[str] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                               ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.alias):
            names.update(node.name.split("."))
            if node.asname:
                names.add(node.asname)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.update(node.module.split("."))
        elif isinstance(node, ast.keyword) and node.arg:
            names.add(node.arg)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
    return names


def test_no_fabricated_names_in_summaries(specs: SpecIndex) -> None:
    # Every SOURCE-DERIVED name a summary carries must be an
    # identifier the file actually contains (module-name prefixes
    # excepted — the caller supplied that label). Spec-side strings
    # (sink match/class, pack sanitizer names in hops) are
    # operator-authored constants, not source-derived.
    module_name = "pkg.app"
    allowed_extra = set(module_name.split("."))
    for base in _FUZZ_BASES:
        idents = _source_identifiers(base) | allowed_extra
        idx = index_module_text(base, "app.py", module_name=module_name)
        for entry in idx.functions:
            s = extract_summary(idx, entry, specs)
            for part in s.qualname.split("."):
                assert part in idents
            for p in s.params:
                assert p in idents
            for g in s.global_names:
                assert g in idents
            for chan in s.call_channels:
                if chan.callee == "unresolved":
                    continue  # the sentinel constant, not source text
                for segment in chan.callee.split("."):
                    assert segment in idents, (
                        f"fabricated callee segment {segment!r}"
                    )
                if chan.kwarg:
                    assert chan.kwarg in idents
            for f in (*s.returns,
                      *(fl for ev in s.sink_events for fl in ev.flows)):
                if f.origin.startswith("param:"):
                    assert int(f.origin.split(":")[1]) < len(s.params)


# ── cost rails: worst shape + growth-ratio pin ───────────────────────


def _synthetic_module(n_functions: int) -> str:
    # The growth shape: helper chains feeding a sink, plus a
    # dispatch-hub-flavoured wide function — the same shape at N and
    # 2N so the ratio isolates growth behaviour.
    parts = ["import os\nimport extlib\n"]
    for i in range(n_functions):
        parts.append(f"""
def fn_{i}(a, b, c):
    x = a + b
    y = extlib.step(x, c)
    z = " ".join([y, x])
    parts = [p for p in (x, y, z)]
    if c:
        x = extlib.other(z)
    os.system(x)
    extlib.fanout(x, y, z, k0=a, k1=b)
    return x, y, z
""")
    return "".join(parts)


def _timed_summarize(source: str, specs: SpecIndex) -> float:
    best = float("inf")
    for _ in range(3):
        idx = index_module_text(source, "gen.py", module_name="gen")
        start = time.perf_counter()
        results = summarize_module(idx, specs)
        best = min(best, time.perf_counter() - start)
        assert all(not s.opaque for s in results)
    return best


def test_growth_ratio_pin_n_vs_2n(specs: SpecIndex) -> None:
    # Host-speed invariant: the pin is a RATIO of two timings taken
    # the same way on the same host. 2.6 leaves linear-with-overhead
    # headroom; raising it would hide super-linear blowups, lowering
    # it flakes on interpreter noise. n=600: at smaller n the
    # per-function constant overhead swamps a quadratic term and the
    # pin waves real regressions through (measured — n=150 passed a
    # shipped functions-times-bytes quadratic; n=600 reds on it).
    # This is a TREND BELT: a quadratic with a tiny constant slips a
    # ratio pin at any affordable n — the load-bearing cost rail is
    # the max-shape WALL pin below, which reds on both the
    # large-constant and the tiny-constant injection.
    n = 600
    t_n = _timed_summarize(_synthetic_module(n), specs)
    t_2n = _timed_summarize(_synthetic_module(2 * n), specs)
    assert t_n > 0
    ratio = t_2n / t_n
    assert ratio <= 2.6, f"super-linear growth: ratio {ratio:.2f}"


def test_many_tiny_functions_max_shape_wall(tmp_path, specs: SpecIndex) -> None:
    # The cross-function cost dimension, pinned DIRECTLY: a file at
    # the read cap holding 74k one-line functions (the shape that
    # turns any per-function whole-file pass — hashing included —
    # into minutes of work). Bound calibration (both directions):
    # the clean linear pipeline runs ~3s, so 15s keeps ~5x slow-host
    # headroom; the cheapest quadratic injection measured ~30s with
    # real host variance (29.8s-35.0s across two hosts), so 15s
    # keeps ~2x red margin — a 30s bound was host-marginal against
    # exactly the regression this pin exists to catch. The
    # large-constant quadratic it also guards took over three
    # minutes on this shape.
    n = 74_000
    src = "".join(f"def f{i}(a):\n    return a\n" for i in range(n))
    src += "# " + "y" * (MAX_SOURCE_FILE_BYTES - len(src) - 10) + "\n"
    assert len(src) <= MAX_SOURCE_FILE_BYTES
    path = tmp_path / "many.py"
    path.write_text(src)
    start = time.monotonic()
    idx = index_module(path, module_name="m")
    assert idx.ok
    results = summarize_module(idx, specs)
    elapsed = time.monotonic() - start
    assert len(results) == n
    assert not any(s.opaque for s in results)
    assert all(s.content_hash for s in results)
    assert elapsed < 15.0, f"max shape took {elapsed:.1f}s"


def test_adversarial_worst_shape_within_budget(specs: SpecIndex) -> None:
    # Priced product: nodes (statements x width) x flows-per-value x
    # entries. This shape pushes statements AND per-statement width
    # AND fan-in near their defaults simultaneously — the walk must
    # stay linear in the node budget (each node visited once, no
    # per-statement rescans of prior state).
    lines = ["import os\n", "def f(" +
             ", ".join(f"p{i}" for i in range(60)) + "):\n"]
    fanin = " + ".join(f"p{i}" for i in range(60))
    for i in range(2_000):
        lines.append(f"    v{i % 400} = (p{i % 60} + 'x' + v0) if p0 "
                     f"else (p{(i + 1) % 60} + f'{{p{i % 60}}}')\n")
    lines[2] = "    v0 = p0\n"  # seed v0 before its first read
    lines.append(f"    big = {fanin}\n")
    lines.append("    os.system(big)\n")
    lines.append("    return big\n")
    src = "".join(lines)
    start = time.monotonic()
    s = one_summary(src, specs)
    elapsed = time.monotonic() - start
    assert elapsed < 10.0, f"worst shape took {elapsed:.2f}s"
    assert not s.opaque
    assert len(
        {f.origin for ev in s.sink_events for f in ev.flows},
    ) == 60


def test_over_cap_worst_shape_degrades_quickly(specs: SpecIndex) -> None:
    # The same shape pushed OVER the statement budget must degrade
    # opaque fast — a cap that binds slowly is not a cost rail.
    lines = ["def f(a):\n"]
    lines.extend("    x = a\n" for _ in range(6_000))
    start = time.monotonic()
    s = one_summary("".join(lines), specs)
    elapsed = time.monotonic() - start
    assert s.opaque
    assert capped_reason(s) == "statement_budget"
    assert elapsed < 5.0


def test_module_index_node_budget(specs: SpecIndex) -> None:
    idx = index_module_text(
        "x = 1\n" * 2_000, "big.py", max_nodes=500,
    )
    assert not idx.ok
    assert idx.degrade_reason == "module_nodes_capped"
