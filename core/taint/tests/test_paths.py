"""Ground-truth battery for path reconstruction.

Every expectation is hand-computed from a small real source tree
through the REAL builder chain (inventory extractors → package
callgraph → route models → seed packs → engine) — the same plumbing
``test_engine.py`` uses. Pinned here: the step-record rendering of
the witness chain (exact file:line spans, excerpts, tainted
parameter names), the alternative paths/sources the witness collapse
folded away, sanitizer-step visibility, killed-class provenance,
excerpt bounding + escaping, and the ±1 boundaries of the
reconstruction rails.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from core.analysis.package_callgraph import (
    TIER_RESOLVED_STATIC,
    PackageCallGraph,
    build_package_callgraph,
)
from core.analysis.route_models import RouteModels, build_route_models
from core.inventory.call_graph import extract_call_graph_python
from core.inventory.extractors import PythonExtractor
from core.taint import engine as engine_mod
from core.taint.engine import (
    EngineLimits,
    PropagationResult,
    propagate,
)
from core.taint.packs import PackSet, default_pack_names, load_packs
from core.taint.paths import (
    MAX_ALT_ARRIVALS_PER_KEY,
    MAX_ALTERNATIVES_PER_CANDIDATE,
    MAX_EXCERPT_CHARS,
    AlternativePath,
    KilledOrigin,
    Step,
)

# ── fixture plumbing (real builders end to end) ──────────────────────


@pytest.fixture(scope="module")
def packs() -> PackSet:
    return load_packs(default_pack_names())


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
    limits: EngineLimits | None = None,
) -> PropagationResult:
    graph, routes = _build(tmp_path, files)
    return propagate(graph, routes, packs, target_root=tmp_path,
                     limits=limits)


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
        "    staged = 'prefix-' + text\n"
        "    return launch(staged)\n"
    ),
)

_TWO_ROUTES = _flask_app(
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


# ── witness steps: the 3-file chain, every field hand-computed ───────


class TestWitnessSteps:
    def test_three_file_chain_steps_hand_computed(
            self, tmp_path, packs) -> None:
        """route param (views.py) → helper (helpers.py) → sink
        (exec_layer.py): four steps — seed, two calls, terminal sink
        — with exact file:line spans, call sites, tainted parameter
        names and stripped source excerpts."""
        res = _run(tmp_path, _CHAIN, packs)
        assert len(res.candidates) == 1
        steps = [s.to_dict() for s in res.candidates[0].steps]
        assert steps == [
            {
                "function": "app/views.py::run_cmd@7",
                "file": "app/views.py",
                "function_line": 7,
                "tier": TIER_RESOLVED_STATIC,
                "kind": "seed",
                "call_file": "app/views.py",
                "call_line": 7,
                "tainted_param": "cmd",
                "tags": [],
                "sanitizers": [],
                "killed_classes": [],
                "excerpt": "def run_cmd(cmd):",
                "excerpt_truncated": False,
                "derived_from_target": True,
            },
            {
                "function": "app/helpers.py::prepare@3",
                "file": "app/helpers.py",
                "function_line": 3,
                "tier": TIER_RESOLVED_STATIC,
                "kind": "call",
                "call_file": "app/views.py",
                "call_line": 8,
                "tainted_param": "text",
                "tags": [],
                "sanitizers": [],
                "killed_classes": [],
                "excerpt": "return prepare(cmd)",
                "excerpt_truncated": False,
                "derived_from_target": True,
            },
            {
                "function": "app/exec_layer.py::launch@3",
                "file": "app/exec_layer.py",
                "function_line": 3,
                "tier": TIER_RESOLVED_STATIC,
                "kind": "call",
                "call_file": "app/helpers.py",
                "call_line": 5,
                "tainted_param": "payload",
                "tags": [],
                "sanitizers": [],
                "killed_classes": [],
                "excerpt": "return launch(staged)",
                "excerpt_truncated": False,
                "derived_from_target": True,
            },
            {
                "function": "app/exec_layer.py::launch@3",
                "file": "app/exec_layer.py",
                "function_line": 3,
                "tier": TIER_RESOLVED_STATIC,
                "kind": "sink",
                "call_file": "app/exec_layer.py",
                "call_line": 4,
                "tainted_param": "",
                "tags": [],
                "sanitizers": [],
                "killed_classes": [],
                "excerpt": "subprocess.run(payload, shell=True)",
                "excerpt_truncated": False,
                "derived_from_target": True,
            },
        ]

    def test_steps_align_with_hops_plus_sink(self, tmp_path,
                                             packs) -> None:
        """One step per hop plus exactly one terminal sink step; step
        functions mirror the hop chain (the step record RESOLVES the
        chain, it never re-derives a different one)."""
        res = _run(tmp_path, _CHAIN, packs)
        c = res.candidates[0]
        assert len(c.steps) == len(c.hops) + 1
        assert [s.function for s in c.steps[:-1]] == \
            [h.function for h in c.hops]
        assert c.steps[-1].kind == "sink"
        assert c.steps[-1].function == c.sink_function
        assert c.steps[-1].call_line == c.sink_line

    def test_reconstruction_deterministic(self, tmp_path,
                                          packs) -> None:
        a = _run(tmp_path / "a", _CHAIN, packs).to_dict()
        b = _run(tmp_path / "b", _CHAIN, packs).to_dict()
        assert a == b

    def test_payload_json_roundtrips(self, tmp_path, packs) -> None:
        res = _run(tmp_path, _TWO_ROUTES, packs)
        payload = res.to_dict()
        assert json.loads(json.dumps(payload)) == payload
        for cand in payload["candidates"]:
            for step in cand["steps"]:
                assert step["derived_from_target"] is True


# ── alternatives: the collapse, widened ──────────────────────────────


class TestAlternatives:
    def test_hidden_second_source_surfaces(self, tmp_path,
                                           packs) -> None:
        """Two routes converge on the same helper → one candidate
        (the C1 collapse) — reconstruction surfaces the folded
        SECOND SOURCE as an alternative with its own seed step and
        full path."""
        res = _run(tmp_path, _TWO_ROUTES, packs)
        assert len(res.candidates) == 1
        c = res.candidates[0]
        assert c.source_dict()["route_pattern"] == "/one/<x>"
        assert len(c.alternatives) == 1
        alt = c.alternatives[0]
        assert dict(alt.source)["route_pattern"] == "/two/<x>"
        assert alt.steps[0].kind == "seed"
        assert alt.steps[0].function == "app/views.py::two@11"
        assert [s.function for s in alt.steps[1:]] == \
            [s.function for s in c.steps[1:]]
        assert alt.path_tier == TIER_RESOLVED_STATIC
        assert res.stat("alt_sources_surfaced") == 1

    def test_alternative_steps_carry_no_excerpts(self, tmp_path,
                                                 packs) -> None:
        """Documented artifact-size choice: the witness renders the
        excerpts once per candidate; alternative steps keep every
        span/annotation field but no excerpt."""
        res = _run(tmp_path, _TWO_ROUTES, packs)
        alt = res.candidates[0].alternatives[0]
        assert all(s.excerpt == "" and not s.excerpt_truncated
                   for s in alt.steps)
        assert all(s.file for s in alt.steps)

    def test_alternative_path_same_source_diamond(
            self, tmp_path, packs) -> None:
        """One route, two helper paths to the same sink parameter:
        the witness keeps one path, the alternative carries the
        other — same source, different mid-chain function."""
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "from .helpers import via_a, via_b\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/d/<x>')\n"
                "def diamond(x):\n"
                "    via_a(x)\n"
                "    return via_b(x)\n"
            ),
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def via_a(t):\n"
                "    return launch(t)\n"
                "\n"
                "def via_b(t):\n"
                "    return launch(t)\n"
            ),
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1
        c = res.candidates[0]
        assert len(c.alternatives) == 1
        alt = c.alternatives[0]
        assert dict(alt.source) == c.source_dict()
        witness_mid = c.steps[1].function
        alt_mid = alt.steps[1].function
        assert {witness_mid, alt_mid} == {
            "app/helpers.py::via_a@3", "app/helpers.py::via_b@6"}

    def test_distinct_source_admitted_ahead_of_path_variants(
            self, tmp_path, packs) -> None:
        """A flood of same-source path variants must not starve a
        folded DISTINCT source out of the bounded alternative set:
        distinct sources are admitted first, then variants fill, and
        the overflow is counted + marked. The second route reaches
        the sink through an extra wrapper, so its path sorts BEHIND
        every same-source variant — without the distinct-source pass
        it would be truncated away."""
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "from .helpers import via_a, via_b, via_c, via_d, wrap\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/one/<x>')\n"
                "def one(x):\n"
                "    via_a(x)\n"
                "    via_b(x)\n"
                "    via_c(x)\n"
                "    return via_d(x)\n"
                "\n"
                "@app.route('/two/<y>')\n"
                "def two(y):\n"
                "    return wrap(y)\n"
            ),
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def via_a(t):\n"
                "    return launch(t)\n"
                "\n"
                "def via_b(t):\n"
                "    return launch(t)\n"
                "\n"
                "def via_c(t):\n"
                "    return launch(t)\n"
                "\n"
                "def via_d(t):\n"
                "    return launch(t)\n"
                "\n"
                "def wrap(t):\n"
                "    return via_a(t)\n"
            ),
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1
        c = res.candidates[0]
        assert len(c.alternatives) == MAX_ALTERNATIVES_PER_CANDIDATE
        alt_patterns = [dict(a.source).get("route_pattern")
                        for a in c.alternatives]
        assert "/two/<y>" in alt_patterns
        assert "alternatives" in res.caps_hit
        # EXACT truncation count: 4 distinct folded paths, 3 slots —
        # exactly one drop. The audit number must be true (a
        # per-pass skip counter would double-count paths both
        # passes see).
        assert res.stat("alternatives_capped") == 1

    def test_alternatives_cap_boundary(self, tmp_path, packs) -> None:
        """±1 on MAX_ALTERNATIVES_PER_CANDIDATE: at the exact count
        no marker; one below truncates counted."""
        files = _flask_app(
            handler_body=(
                "from flask import Flask\n"
                "from .helpers import via_a, via_b\n"
                "\n"
                "app = Flask(__name__)\n"
                "\n"
                "@app.route('/d/<x>')\n"
                "def diamond(x):\n"
                "    via_a(x)\n"
                "    return via_b(x)\n"
            ),
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def via_a(t):\n"
                "    return launch(t)\n"
                "\n"
                "def via_b(t):\n"
                "    return launch(t)\n"
            ),
        )
        exact = _run(tmp_path / "e", files, packs,
                     limits=EngineLimits(
                         max_alternatives_per_candidate=1))
        assert len(exact.candidates[0].alternatives) == 1
        assert "alternatives" not in exact.caps_hit

        under = _run(tmp_path / "u", files, packs,
                     limits=EngineLimits(
                         max_alternatives_per_candidate=0))
        assert under.candidates[0].alternatives == ()
        assert under.candidates[0].steps  # witness detail unaffected

    def test_alt_arrivals_per_key_cap_boundary(
            self, tmp_path, packs) -> None:
        """±1 on MAX_ALT_ARRIVALS_PER_KEY: four routes converge on
        one helper key (1 witness + 3 alternative arrivals). At cap
        3 all are retained, no marker; at cap 2 the third refuses
        counted + marked and reconstruction surfaces one fewer
        source."""
        handler = (
            "from flask import Flask\n"
            "from .helpers import prepare\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
        )
        for i, name in enumerate(("one", "two", "three", "four")):
            handler += (
                f"@app.route('/{name}/<x>')\n"
                f"def {name}(x):\n"
                f"    return prepare(x)\n"
            )
            handler += "\n" if i < 3 else ""
        files = _flask_app(
            handler_body=handler,
            helpers=(
                "from .exec_layer import launch\n"
                "\n"
                "def prepare(text):\n"
                "    return launch(text)\n"
            ),
        )
        exact = _run(tmp_path / "e", files, packs,
                     limits=EngineLimits(max_alt_arrivals_per_key=3))
        assert "alt_arrivals" not in exact.caps_hit
        assert exact.stat("alt_arrivals_recorded") == 3
        assert len(exact.candidates[0].alternatives) == 3

        under = _run(tmp_path / "u", files, packs,
                     limits=EngineLimits(max_alt_arrivals_per_key=2))
        assert "alt_arrivals" in under.caps_hit
        assert under.stat("alt_arrivals_capped") >= 1
        assert under.stat("alt_arrivals_recorded") == 2
        assert len(under.candidates[0].alternatives) == 2

    def test_alt_retention_joins_byte_accounting(
            self, tmp_path, packs) -> None:
        """The per-key alternative retention is byte-accounted
        against MAX_RETAINED_BYTES — no side channel: the end-of-run
        estimate grows by exactly the estimator constant per
        recorded arrival."""
        with_alts = _run(tmp_path / "a", _TWO_ROUTES, packs)
        without = _run(tmp_path / "b", _TWO_ROUTES, packs,
                       limits=EngineLimits(max_alt_arrivals_per_key=0))
        recorded = with_alts.stat("alt_arrivals_recorded")
        assert recorded == 1
        assert without.stat("alt_arrivals_recorded") == 0
        delta = (with_alts.stat("retained_bytes_estimate")
                 - without.stat("retained_bytes_estimate"))
        assert delta == recorded * engine_mod._ALT_BYTES_EST

    def test_alternatives_deterministic(self, tmp_path,
                                        packs) -> None:
        a = _run(tmp_path / "a", _TWO_ROUTES, packs).to_dict()
        b = _run(tmp_path / "b", _TWO_ROUTES, packs).to_dict()
        assert a == b


# ── sanitizer visibility + killed-class provenance ───────────────────


class TestSanitizerVisibility:
    def test_tag_sanitizer_annotates_step_never_suppresses(
            self, tmp_path, packs) -> None:
        """A TAG sanitizer (validate-style, ``re.match``) on a value
        that flows THROUGH it renders as an annotated step — visible
        on the step's ``sanitizers`` — and the candidate still
        emits."""
        files = _flask_app(
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
                "import re\n"
                "from .exec_layer import launch\n"
                "\n"
                "def prepare(text):\n"
                "    checked = re.match('^[a-z]+$', text)\n"
                "    return launch(checked)\n"
            ),
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1
        c = res.candidates[0]
        launch_step = c.steps[2]
        assert launch_step.function == "app/exec_layer.py::launch@3"
        assert "re.match" in launch_step.sanitizers
        assert launch_step.killed_classes == ()  # tag, not kill

    def test_killed_origin_names_step_and_sanitizer(
            self, tmp_path, packs) -> None:
        """A transform kill for one sink class on a flow reaching a
        DIFFERENT class's sink: the candidate emits with the killed
        class listed, and ``killed_origins`` attributes it to the
        exact step (and sanitizer) whose flow carried the kill."""
        files = dict(_PKG_INIT)
        files["app/views.py"] = (
            "from flask import Flask\n"
            "from .helpers import prepare\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/run/<cmd>')\n"
            "def run_cmd(cmd):\n"
            "    return prepare(cmd)\n"
        )
        files["app/helpers.py"] = (
            "import shlex\n"
            "from .evaluator import use\n"
            "\n"
            "def prepare(text):\n"
            "    safe = shlex.quote(text)\n"
            "    return use(safe)\n"
        )
        files["app/evaluator.py"] = (
            "def use(v):\n"
            "    eval(v)\n"
            "    return None\n"
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1
        c = res.candidates[0]
        assert c.sink_class == "code-injection"
        assert "command-injection" in c.killed
        origin = {k.sink_class: k for k in c.killed_origins}[
            "command-injection"]
        assert origin.step == 2  # the hop entering use()
        assert c.steps[2].function == "app/evaluator.py::use@1"
        assert "command-injection" in c.steps[2].killed_classes
        assert "shlex.quote" in origin.sanitizers

    def test_every_killed_class_has_an_origin_record(
            self, tmp_path, packs) -> None:
        files = dict(_PKG_INIT)
        files["app/views.py"] = (
            "from flask import Flask\n"
            "from .helpers import prepare\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/run/<cmd>')\n"
            "def run_cmd(cmd):\n"
            "    return prepare(cmd)\n"
        )
        files["app/helpers.py"] = (
            "import shlex\n"
            "from .evaluator import use\n"
            "\n"
            "def prepare(text):\n"
            "    safe = shlex.quote(text)\n"
            "    return use(safe)\n"
        )
        files["app/evaluator.py"] = (
            "def use(v):\n"
            "    eval(v)\n"
            "    return None\n"
        )
        res = _run(tmp_path, files, packs)
        c = res.candidates[0]
        assert sorted(k.sink_class for k in c.killed_origins) == \
            sorted(c.killed)


# ── excerpts: bounded, escaped, never fabricated ─────────────────────


class TestExcerpts:
    def test_excerpt_matches_real_source_line(self, tmp_path,
                                              packs) -> None:
        """Every rendered excerpt is the stripped text of the real
        line at the step's span — read back from disk, not
        synthesized."""
        res = _run(tmp_path, _CHAIN, packs)
        for step in res.candidates[0].steps:
            src_file = step.call_file or step.file
            line_no = step.call_line or step.function_line
            raw = (tmp_path / src_file).read_text(
                encoding="utf-8").splitlines()[line_no - 1]
            assert step.excerpt == raw.strip()

    def test_excerpt_bounded_with_elision_marker(
            self, tmp_path, packs) -> None:
        """Over-bound excerpts truncate at the cap with an explicit
        elision marker and the truncated flag — never silently."""
        long_tail = " + 'x'" * 60
        files = _flask_app(
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
                f"    return launch(text{long_tail})\n"
            ),
        )
        cap = 48
        res = _run(tmp_path, files, packs,
                   limits=EngineLimits(max_excerpt_chars=cap))
        step = res.candidates[0].steps[2]
        assert step.excerpt_truncated
        assert step.excerpt.startswith("return launch(text")
        assert "...[+" in step.excerpt
        assert step.excerpt.endswith(" chars]")
        marker = step.excerpt[cap:]
        assert len(step.excerpt) == cap + len(marker)
        assert res.stat("excerpts_truncated") >= 1

    def test_excerpt_exact_cap_is_not_truncated(
            self, tmp_path, packs) -> None:
        """±1 on the excerpt bound: a line whose escaped length is
        exactly the cap renders whole, no marker."""
        res = _run(
            tmp_path, _CHAIN, packs,
            limits=EngineLimits(
                max_excerpt_chars=len("subprocess.run(payload, shell=True)")))
        sink_step = res.candidates[0].steps[-1]
        assert sink_step.excerpt == "subprocess.run(payload, shell=True)"
        assert not sink_step.excerpt_truncated

    def test_hostile_bytes_escaped_in_excerpt(self, tmp_path,
                                              packs) -> None:
        """Control bytes in the source line render as ``\\xHH``
        escape TEXT, never as raw bytes — the excerpt is a render
        egress, escaped at this layer."""
        files = _flask_app(
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
                "    staged = '\x1b]0;pwned\x07' + text\n"
                "    return launch(staged + '\x1b[31m')\n"
            ),
        )
        res = _run(tmp_path, files, packs)
        assert len(res.candidates) == 1
        for cand in res.candidates:
            for step in cand.steps:
                assert "\x1b" not in step.excerpt
                assert "\x07" not in step.excerpt
        launch_step = res.candidates[0].steps[2]
        # The crossing line ITSELF carries the ESC byte: it must
        # arrive as inert \xHH escape TEXT, never as the raw byte.
        assert launch_step.excerpt == \
            "return launch(staged + '\\x1b[31m')"
        seed_of_hostile = res.candidates[0].steps[1]
        assert seed_of_hostile.function == "app/helpers.py::prepare@3"

    def test_step_spans_subset_of_inventory(self, tmp_path,
                                            packs) -> None:
        """No fabricated spans: every step's file is a real inventory
        file and every rendered line is inside that file."""
        graph, routes = _build(tmp_path, _TWO_ROUTES)
        res = propagate(graph, routes, packs, target_root=tmp_path)
        files = {n.file_path for n in graph.nodes}
        line_counts = {
            rel: len((tmp_path / rel).read_text(
                encoding="utf-8").splitlines())
            for rel in _TWO_ROUTES}
        for cand in res.candidates:
            all_steps = list(cand.steps)
            for alt in cand.alternatives:
                all_steps.extend(alt.steps)
            for step in all_steps:
                assert step.file in files
                assert 1 <= step.function_line <= line_counts[step.file]
                if step.call_file:
                    assert step.call_file in files
                    assert 1 <= step.call_line <= \
                        line_counts[step.call_file]


# ── honesty surface ──────────────────────────────────────────────────


class TestHonestySurface:
    def test_no_refutation_vocabulary_in_new_records(
            self, tmp_path, packs) -> None:
        """The C1 pin, extended to the reconstruction vocabulary:
        steps, alternatives and killed_origins spell no refutation —
        and the record classes expose none either."""
        res = _run(tmp_path, _TWO_ROUTES, packs)
        assert res.candidates and res.candidates[0].steps
        assert res.candidates[0].alternatives
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

        for key in walk_keys(res.to_dict()):
            for bad in forbidden:
                assert bad not in key.lower(), key
        for cls in (Step, AlternativePath, KilledOrigin):
            for name in dir(cls):
                for bad in forbidden:
                    assert bad not in name.lower(), (cls, name)

    def test_reconstruction_wall_skip_counted(self, tmp_path,
                                              packs) -> None:
        """Past the wall budget, remaining candidates ship their hop
        chains WITHOUT step detail — counted per candidate, marked,
        never a partial fabrication."""
        graph, routes = _build(tmp_path, _TWO_ROUTES)
        eng = engine_mod._Engine(
            graph, routes, packs, None, target_root=tmp_path,
            limits=EngineLimits(), indexer=None)
        eng.run()
        assert eng.candidates
        eng.deadline = time.monotonic() - 1.0
        res = eng.result()
        assert res.candidates
        for cand in res.candidates:
            assert cand.hops  # the chain survives
            assert cand.steps == ()
            assert cand.alternatives == ()
            assert cand.killed_origins == ()
        assert res.stat("reconstruction_skipped_wall") == \
            len(res.candidates)
        assert "wall_budget" in res.caps_hit

    def test_default_caps_are_the_named_constants(self) -> None:
        limits = EngineLimits()
        assert limits.max_alt_arrivals_per_key == \
            MAX_ALT_ARRIVALS_PER_KEY
        assert limits.max_alternatives_per_candidate == \
            MAX_ALTERNATIVES_PER_CANDIDATE
        assert limits.max_excerpt_chars == MAX_EXCERPT_CHARS
        assert limits.artifact_bytes_marker == \
            engine_mod.MAX_ARTIFACT_BYTES

    def test_artifact_bytes_estimate_tracks_serialized_size(
            self, tmp_path, packs) -> None:
        """The serialized-artifact dimension is MEASURED at result
        assembly: the estimate tracks the real JSON size of the
        candidate records (never badly under — the marker must fire
        early, not late) and shrinks when alternatives are
        withheld."""
        res = _run(tmp_path / "a", _TWO_ROUTES, packs)
        est = res.stat("artifact_bytes_estimate")
        actual = len(json.dumps(
            [c.to_dict() for c in res.candidates]))
        assert est >= actual * 0.9
        assert est <= actual * 3
        bare = _run(tmp_path / "b", _TWO_ROUTES, packs,
                    limits=EngineLimits(max_alt_arrivals_per_key=0))
        assert bare.stat("artifact_bytes_estimate") < est

    def test_artifact_bytes_marker_flags_without_truncating(
            self, tmp_path, packs) -> None:
        """The threshold is a MARKER only: over it the run flags
        ``artifact_bytes`` and ships every candidate fully rendered
        — the enforcing rail belongs at the emission boundary."""
        flagged = _run(tmp_path / "a", _TWO_ROUTES, packs,
                       limits=EngineLimits(artifact_bytes_marker=1))
        assert "artifact_bytes" in flagged.caps_hit
        assert flagged.candidates
        for c in flagged.candidates:
            assert c.steps  # nothing truncated by the marker
        assert flagged.candidates[0].alternatives
        default = _run(tmp_path / "b", _TWO_ROUTES, packs)
        assert "artifact_bytes" not in default.caps_hit
        assert default.to_dict()["candidates"] == \
            flagged.to_dict()["candidates"]
