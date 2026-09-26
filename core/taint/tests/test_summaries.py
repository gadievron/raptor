"""Ground-truth battery for the per-function summary extractor.

Every test carries a HAND-COMPUTED expected summary over a small
fixture: the assertions are the transfer-semantics contract (param to
return, param to call-site argument, param to in-body sink, sanitizer
kill/tag/demote, source firing, builtin shadowing, unless_kwargs
literal matching). Degradation and hostile-shape behaviour live in
the sibling hostile battery."""

from __future__ import annotations

import pytest

from core.staleness import hash_spans_text
from core.taint.learned_intake import intake_learned_specs
from core.taint.packs import PackSet, load_packs
from core.taint.tests import HAND_COMPUTED_PACKS
from core.taint.summaries import (
    MARKER_ASSUMED_PROPAGATION,
    MARKER_BINDING_APPROX,
    MARKER_LEARNED,
    MARKER_SANITIZER_DEMOTED,
    FunctionSummary,
    SpecIndex,
    build_spec_index,
    extract_summary,
    index_module_text,
    kill_census,
)


@pytest.fixture(scope="module")
def packs() -> PackSet:
    return load_packs(HAND_COMPUTED_PACKS)


@pytest.fixture(scope="module")
def specs(packs: PackSet) -> SpecIndex:
    return build_spec_index(packs)


def summarize(
    source: str, specs: SpecIndex, qualname: str,
    *, module_name: str = "app",
) -> FunctionSummary:
    idx = index_module_text(source, "app.py", module_name=module_name)
    entry = idx.function_named(qualname)
    assert entry is not None, f"fixture must define {qualname}"
    return extract_summary(idx, entry, specs)


def sink_origins(summary: FunctionSummary, match: str) -> set[str]:
    return {
        f.origin
        for ev in summary.sink_events if ev.match == match
        for f in ev.flows
    }


# ── param → return ───────────────────────────────────────────────────


def test_param_flows_to_return(specs: SpecIndex) -> None:
    src = """
def f(a, b, c):
    x = a + "suffix"
    return x
"""
    s = summarize(src, specs, "f")
    assert not s.opaque
    assert s.params == ("a", "b", "c")
    assert s.params_to_return() == (0,)


def test_untainted_return_has_no_param_flows(specs: SpecIndex) -> None:
    src = """
def f(a):
    return "constant"
"""
    s = summarize(src, specs, "f")
    assert s.params_to_return() == ()
    assert s.returns == ()


def test_multiple_params_and_fstring_concat(specs: SpecIndex) -> None:
    src = """
def f(a, b, c):
    return f"{a}-" + b.upper()
"""
    s = summarize(src, specs, "f")
    # a via f-string, b via method-call receiver propagation; c stays.
    assert s.params_to_return() == (0, 1)


def test_yield_counts_as_return_channel(specs: SpecIndex) -> None:
    src = """
def gen(a, b):
    yield a
"""
    s = summarize(src, specs, "gen")
    assert s.params_to_return() == (0,)


def test_await_is_transparent(specs: SpecIndex) -> None:
    src = """
async def f(a):
    x = await a
    return x
"""
    s = summarize(src, specs, "f")
    assert s.params_to_return() == (0,)


def test_augmented_assignment_accumulates(specs: SpecIndex) -> None:
    src = """
def f(a):
    out = "x"
    out += a
    return out
"""
    s = summarize(src, specs, "f")
    assert s.params_to_return() == (0,)


# ── param → call-site argument channels ─────────────────────────────


def test_call_channel_positions_and_kwargs(specs: SpecIndex) -> None:
    src = """
import extlib

def f(a, b):
    extlib.helper("const", a, key=b)
"""
    s = summarize(src, specs, "f")
    chans = [c for c in s.call_channels if c.callee == "extlib.helper"]
    by_slot = {(c.arg, c.kwarg): c for c in chans}
    # position 0 is a constant: no channel. Position 1 carries a.
    assert (0, "") not in by_slot
    assert {f.origin for f in by_slot[(1, "")].flows} == {"param:0"}
    assert {f.origin for f in by_slot[(-1, "key")].flows} == {"param:1"}
    assert all(c.resolution == "external" for c in chans)


def test_local_helper_channel_uses_local_resolution(
    specs: SpecIndex,
) -> None:
    src = """
def helper(x):
    return x

def f(a):
    return helper(a)
"""
    s = summarize(src, specs, "f")
    chans = [c for c in s.call_channels if c.arg == 0]
    assert len(chans) == 1
    assert chans[0].callee == "app.helper"
    assert chans[0].resolution == "local"
    assert {f.origin for f in chans[0].flows} == {"param:0"}
    # Unknown-callee return rides the assumed-propagation floor.
    assert s.params_to_return() == (0,)
    assert any(
        MARKER_ASSUMED_PROPAGATION in f.markers for f in s.returns
    )


def test_star_and_kwargs_forwarding_is_binding_approx(
    specs: SpecIndex,
) -> None:
    src = """
import extlib

def f(a, b):
    extlib.helper(*a, **b)
"""
    s = summarize(src, specs, "f")
    stars = {c.star: c for c in s.call_channels}
    assert {f.origin for f in stars["*"].flows} == {"param:0"}
    assert {f.origin for f in stars["**"].flows} == {"param:1"}
    for c in stars.values():
        assert all(MARKER_BINDING_APPROX in f.markers for f in c.flows)


# ── param → sink ─────────────────────────────────────────────────────


def test_param_reaches_sink_directly(specs: SpecIndex) -> None:
    src = """
import os

def f(cmd):
    os.system(cmd)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}
    ev = s.sink_events[0]
    assert ev.sink_class == "command-injection"
    assert ev.cwe == "CWE-78"


def test_param_reaches_sink_via_helper_call(specs: SpecIndex) -> None:
    # Taint rides an UNKNOWN helper's return (assumed propagation)
    # into the sink — the cross-file recall shape, in-body edition.
    src = """
import os
import extlib

def f(user):
    built = extlib.build_command(user)
    os.system(built)
"""
    s = summarize(src, specs, "f")
    origins = sink_origins(s, "os.system")
    assert origins == {"param:0"}
    flows = [f for ev in s.sink_events for f in ev.flows]
    assert all(MARKER_ASSUMED_PROPAGATION in f.markers for f in flows)


def test_untainted_sink_arg_is_no_event(specs: SpecIndex) -> None:
    src = """
import os

def f(cmd):
    os.system("ls -la")
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()


def test_method_name_sink_is_heuristic(specs: SpecIndex) -> None:
    src = """
def f(q, cursor):
    cursor.execute(q)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "execute") == {"param:0"}
    assert all(ev.confidence == "heuristic" for ev in s.sink_events)


def test_sink_kwarg_spelling_matches(specs: SpecIndex) -> None:
    src = """
import subprocess

def f(cmd):
    subprocess.run(args=cmd)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "subprocess.run") == {"param:0"}


# ── unless_kwargs: literal token only ────────────────────────────────


def test_unless_kwargs_literal_suppresses(specs: SpecIndex) -> None:
    src = """
import subprocess

def f(cmd):
    subprocess.run(cmd, shell=False)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()
    assert s.stat("sinks_suppressed_unless_kwargs") == 1


@pytest.mark.parametrize("spelling", [
    "shell=flag",              # variable
    "shell=bool(flag)",        # expression
    "shell=FALSE_CONST",       # module constant spelled like the token
    "**{'shell': False}",      # dict-splat carrying the pair
])
def test_unless_kwargs_non_literal_never_suppresses(
    specs: SpecIndex, spelling: str,
) -> None:
    src = f"""
import subprocess

def f(cmd, flag):
    subprocess.run(cmd, {spelling})
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "subprocess.run") == {"param:0"}
    assert s.stat("sinks_suppressed_unless_kwargs") == 0


def test_unless_kwargs_parenthesised_literal_still_suppresses(
    specs: SpecIndex,
) -> None:
    # ``shell=(False)`` IS the constant False at the AST level — the
    # token comparison sees the constant, not the parentheses.
    src = """
import subprocess

def f(cmd):
    subprocess.run(cmd, shell=(False))
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()


def test_unless_kwargs_true_literal_does_not_suppress(
    specs: SpecIndex,
) -> None:
    src = """
import subprocess

def f(cmd):
    subprocess.run(cmd, shell=True)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "subprocess.run") == {"param:0"}


# ── sanitizers: kill / tag / demote ──────────────────────────────────


def test_kill_mid_path_suppresses_sink_counted(specs: SpecIndex) -> None:
    src = """
import os
import shlex

def f(user):
    safe = shlex.quote(user)
    os.system(safe)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()
    assert s.stat("sinks_suppressed_killed") == 1
    assert s.stat("sanitizer_kills") == 1
    ev = s.sanitizer_events[0]
    assert (ev.match, ev.applied, ev.demoted) == ("shlex.quote", "kill",
                                                  False)


def test_kill_only_covers_its_sink_classes(specs: SpecIndex) -> None:
    # shlex.quote kills command-injection; the SAME value into a
    # template sink still fires — kills are per-class, never global.
    src = """
import shlex
import jinja2

def f(user):
    safe = shlex.quote(user)
    jinja2.Template(safe)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "jinja2.Template") == {"param:0"}
    flows = [f for ev in s.sink_events for f in ev.flows]
    assert any("command-injection" in f.killed for f in flows)
    assert any("shlex.quote" in f.hops for f in flows)


def test_killed_flow_survives_into_return_channel(
    specs: SpecIndex,
) -> None:
    # The kill never deletes the flow: the return channel carries it
    # with the killed set, so cross-function composition can see it.
    src = """
import shlex

def f(user):
    return shlex.quote(user)
"""
    s = summarize(src, specs, "f")
    assert s.params_to_return() == (0,)
    (flow,) = [f for f in s.returns if f.origin == "param:0"]
    assert "command-injection" in flow.killed


def test_tag_sanitizer_keeps_flow_with_hop(specs: SpecIndex) -> None:
    # re.match is a validate-style TAG sanitizer: the flow keeps
    # moving, the hop is recorded, the sink still fires.
    src = """
import os
import re

def f(user):
    checked = re.match(user, "pattern")
    os.system(checked)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}
    flows = [f for ev in s.sink_events for f in ev.flows]
    assert any("re.match" in f.hops for f in flows)
    assert all(f.killed == () for f in flows)
    assert s.stat("sanitizer_kills") == 0


def test_module_rebound_sanitizer_kill_demotes(specs: SpecIndex) -> None:
    # The demote-on-rebind pin: ``import shlex`` then a module-level
    # ``shlex = _noop`` rebind — written-name resolution still says
    # shlex.quote, but the runtime slot may be anything. The kill
    # demotes to a tag (flow alive, marked, counted), never fires.
    src = """
import os
import shlex

def _noop(x):
    return x

shlex = _noop

def f(user):
    safe = shlex.quote(user)
    os.system(safe)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}
    flows = [f for ev in s.sink_events for f in ev.flows]
    assert all(MARKER_SANITIZER_DEMOTED in f.markers for f in flows)
    assert all(f.killed == () for f in flows)
    assert s.stat("sanitizer_kill_demotions") == 1
    assert s.stat("sanitizer_kills") == 0
    ev = s.sanitizer_events[0]
    assert (ev.applied, ev.demoted, ev.demotion_reason) == (
        "tag", True, "binding_suspect",
    )


def test_function_local_shadow_of_sanitizer_demotes(
    specs: SpecIndex,
) -> None:
    # The demotion rule's local arm: a same-name local assignment for the
    # sanitizer's bound root inside the function body.
    src = """
import os
import shlex

def f(user, fake):
    shlex = fake
    safe = shlex.quote(user)
    os.system(safe)
"""
    s = summarize(src, specs, "f")
    # param:1 rides too — the receiver IS the tainted local — which
    # is the conservative direction; the pin is that param:0 is
    # alive (no kill) and the demotion is counted.
    assert "param:0" in sink_origins(s, "os.system")
    assert s.stat("sanitizer_kill_demotions") == 1
    assert s.stat("sanitizer_kills") == 0


def test_clean_input_through_sanitizer_is_not_an_event(
    specs: SpecIndex,
) -> None:
    src = """
import shlex

def f():
    return shlex.quote("constant")
"""
    s = summarize(src, specs, "f")
    assert s.sanitizer_events == ()
    assert s.stat("sanitizer_kills") == 0


def test_kill_census_aggregates_per_callee_and_file(
    specs: SpecIndex,
) -> None:
    src = """
import os
import shlex

def f(a):
    os.system(shlex.quote(a))

def g(b):
    os.system(shlex.quote(b))
"""
    idx = index_module_text(src, "app.py", module_name="app")
    summaries = [
        extract_summary(idx, e, specs) for e in idx.functions
    ]
    census = kill_census(summaries)
    assert census == {("shlex.quote", "app.py"): 2}


# ── builtin-name resolution (the phase-A charter item) ──────────────


def test_builtin_sink_matches_without_import(specs: SpecIndex) -> None:
    src = """
def f(code):
    eval(code)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "eval") == {"param:0"}


def test_builtin_source_input_fires(specs: SpecIndex) -> None:
    src = """
import os

def f():
    line = input("cmd> ")
    os.system(line)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"source:call_return:input"}
    assert [(e.kind, e.match) for e in s.source_events] == [
        ("call_return", "input"),
    ]


def test_builtin_kill_sanitizer_int(specs: SpecIndex) -> None:
    src = """
import os

def f(user):
    n = int(user)
    os.system(n)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()
    assert s.stat("sanitizer_kills") == 1


def test_locally_shadowed_builtin_is_not_a_sink(specs: SpecIndex) -> None:
    src = """
def f(code):
    eval = print
    eval(code)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()
    assert s.stat("builtin_shadowed") >= 1


def test_module_shadowed_builtin_is_not_a_sink(specs: SpecIndex) -> None:
    src = """
def eval(x):
    return x

def f(code):
    eval(code)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()
    assert s.stat("builtin_shadowed") >= 1


def test_shadowed_builtin_sanitizer_does_not_kill(
    specs: SpecIndex,
) -> None:
    # The conservative direction for a shadowed KILL builtin: no
    # kill to trust — the flow keeps moving and the sink fires.
    src = """
import os

def int(x):
    return x

def f(user):
    n = int(user)
    os.system(n)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}
    assert s.stat("sanitizer_kills") == 0
    assert s.stat("builtin_shadowed") >= 1


def test_unshadowed_builtin_alongside_shadowed_one(
    specs: SpecIndex,
) -> None:
    # Both directions in one file: exec stays a sink while eval is
    # shadowed away.
    src = """
def eval(x):
    return x

def f(code):
    eval(code)
    exec(code)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "exec") == {"param:0"}
    assert sink_origins(s, "eval") == set()


def test_global_write_shadow_counts_for_builtins(
    specs: SpecIndex,
) -> None:
    src = """
def rebind():
    global eval
    eval = print

def f(code):
    eval(code)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()
    assert s.stat("builtin_shadowed") >= 1


# ── sources ──────────────────────────────────────────────────────────


def test_module_attribute_source_via_from_import(
    specs: SpecIndex,
) -> None:
    src = """
import os
from flask import request

def f():
    q = request.args.get("q")
    os.system(q)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {
        "source:module_attribute:flask.request",
    }


def test_module_attribute_source_via_module_import(
    specs: SpecIndex,
) -> None:
    src = """
import os
import flask

def f():
    q = flask.request.form["q"]
    os.system(q)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {
        "source:module_attribute:flask.request",
    }


def test_bare_module_reference_is_not_the_source(
    specs: SpecIndex,
) -> None:
    # ``flask`` alone is a PREFIX of flask.request, not the source.
    src = """
import os
import flask

def f():
    os.system(flask.__name__)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()


def test_stored_read_reserved_kind_acts_as_source() -> None:
    # Compose the in-tree fixture pack that declares the reserved
    # stored kinds (pure data through the unchanged loader).
    from pathlib import Path

    fixture_dir = Path(__file__).parent / "fixtures" / "packs"
    merged = load_packs(
        ["python/web-injection-core", "python/stored-taint-demo"],
        extra_dirs=[fixture_dir],
    )
    specs = build_spec_index(merged)
    src = """
import shelve

def f(db):
    value = shelve.open("profiles")
    return value
"""
    s = summarize(src, specs, "f")
    assert [e.kind for e in s.source_events] == ["stored_read"]
    assert s.returns and any(
        f.origin == "source:stored_read:shelve.open" for f in s.returns
    )


# ── decorated handlers ───────────────────────────────────────────────


def test_decorator_is_skipped_not_a_call_site(specs: SpecIndex) -> None:
    # Route binding is resolved by the route models; the decorator
    # must not double-count as a call channel or taint movement.
    src = """
import os
from flask import Flask

app = Flask(__name__)

@app.route("/run/<name>")
def handler(name):
    os.system(name)
"""
    s = summarize(src, specs, "handler")
    assert sink_origins(s, "os.system") == {"param:0"}
    assert all("route" not in c.callee for c in s.call_channels)
    assert s.stat("decorators_skipped") == 1


def test_stacked_decorators_all_skipped(specs: SpecIndex) -> None:
    src = """
import functools

@functools.wraps(print)
@functools.lru_cache
def handler(name):
    return name
"""
    s = summarize(src, specs, "handler")
    assert s.stat("decorators_skipped") == 2
    assert s.params_to_return() == (0,)


# ── tuple unpack ─────────────────────────────────────────────────────


def test_pairwise_tuple_unpack_is_element_wise(specs: SpecIndex) -> None:
    src = """
import os

def f(a):
    x, y = a, "safe"
    os.system(x)
    os.system(y)
"""
    s = summarize(src, specs, "f")
    events = [(ev.line, sorted(f.origin for f in ev.flows))
              for ev in s.sink_events]
    assert events == [(6, ["param:0"])]


def test_opaque_tuple_unpack_taints_all_targets(specs: SpecIndex) -> None:
    # Unpacking a VALUE (not a literal tuple) is whole-value: a
    # tainted pair taints both halves — the stated approximation.
    src = """
import os

def f(pair):
    x, y = pair
    os.system(y)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}


def test_starred_unpack_propagates(specs: SpecIndex) -> None:
    src = """
import os

def f(items):
    first, *rest = items
    os.system(rest)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}


# ── evaluation order: swaps and chains ───────────────────────────────


def test_swap_preserves_taint(specs: SpecIndex) -> None:
    # Python evaluates the whole right side before any target binds:
    # ``x, y = y, x`` moves x's taint into y. Binding pairwise as
    # evaluated would read the already-overwritten x — a
    # strong-position taint erasure.
    src = """
import os

def f(x):
    y = "clean"
    x, y = y, x
    os.system(y)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}


def test_swap_taint_reaches_return(specs: SpecIndex) -> None:
    src = """
def f(x):
    y = "clean"
    x, y = y, x
    return y
"""
    s = summarize(src, specs, "f")
    assert s.params_to_return() == (0,)


def test_self_referencing_unpack(specs: SpecIndex) -> None:
    # ``x, y = p, x``: y must get x's PRE-statement flows.
    src = """
import os

def f(p, q):
    x = q
    x, y = p, x
    os.system(y)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:1"}


def test_chained_assignment_taints_all_targets(specs: SpecIndex) -> None:
    src = """
import os

def f(p):
    a = b = p
    os.system(a)
    os.system(b)
"""
    s = summarize(src, specs, "f")
    assert len(s.sink_events) == 2


# ── delete strength ──────────────────────────────────────────────────


def test_branch_local_del_is_weak(specs: SpecIndex) -> None:
    # ``del`` erases taint state — a strong effect. Inside a branch
    # it may never execute: the old flow must survive, or a
    # branch-local ``del x; x = "safe"`` silently certifies the
    # fall-through path.
    src = """
import os

def f(p, c):
    x = p
    if c:
        del x
        x = "safe"
    os.system(x)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}


def test_top_level_del_is_strong(specs: SpecIndex) -> None:
    src = """
import os

def f(p):
    x = p
    del x
    x = "safe"
    os.system(x)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()


# ── rebind detection: every module-scope binding form ────────────────

_REBIND_BODY = """
def f(p):
    p = shlex.quote(p)
    os.system(p)
"""


@pytest.mark.parametrize("label,prelude", [
    ("assign", "import os, shlex\nshlex = object()\n"),
    ("for-target", "import os, shlex\nfor shlex in [object()]:\n    pass\n"),
    ("with-as", "import os, shlex\nwith open('/dev/null') as shlex:\n    pass\n"),
    ("walrus", "import os, shlex\nif (shlex := object()):\n    pass\n"),
    ("match-case",
     "import os, shlex\nmatch 1:\n    case _:\n        shlex = object()\n"),
    ("except-as",
     "import os, shlex\ntry:\n    pass\nexcept Exception as shlex:\n    pass\n"),
    # A def's DEFAULTS and DECORATORS execute at module scope when
    # the module imports — a walrus inside either rebinds the module
    # name even though the def's body is a separate scope.
    ("default-arg-walrus",
     "import os, shlex\ndef other(a=(shlex := object())):\n    pass\n"),
    ("decorator-walrus",
     "import os, shlex\n@(shlex := staticmethod)\ndef other():\n    pass\n"),
])
def test_every_module_rebind_form_demotes_kill(
    specs: SpecIndex, label: str, prelude: str,
) -> None:
    # A rebind detector that only sees plain assignment hands the
    # kill-demotion rule an evasion catalogue: for-targets, with-as,
    # walrus, match captures and except-as all rebind the written
    # name just as effectively.
    s = summarize(prelude + _REBIND_BODY, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}, label
    assert s.stat("sanitizer_kill_demotions") == 1, label
    assert s.stat("sanitizer_kills") == 0, label


def test_other_functions_body_rebind_does_not_demote(
    specs: SpecIndex,
) -> None:
    # The body-skip's counter-direction: a rebind INSIDE another
    # function's body is local to that function and must not demote
    # f's kill (only defaults/decorators/annotations of a def run at
    # module scope; its body does not).
    src = """
import os
import shlex

def other():
    shlex = object()
    return shlex

def f(p):
    p = shlex.quote(p)
    os.system(p)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()
    assert s.stat("sanitizer_kills") == 1
    assert s.stat("sanitizer_kill_demotions") == 0


def test_module_attr_patch_demotes_kill(specs: SpecIndex) -> None:
    # ``shlex.quote = str`` does not rebind the NAME but patches the
    # bound object's member — kills through the root demote (fail
    # toward the sink firing, never toward suppression).
    src = """
import os
import shlex

shlex.quote = str

def f(p):
    p = shlex.quote(p)
    os.system(p)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}
    assert s.stat("sanitizer_kill_demotions") == 1


def test_local_import_with_local_rebind_demotes(specs: SpecIndex) -> None:
    # A function-local import followed by a function-local rebind of
    # the same name: the written-name resolution is suspect exactly
    # like a module-scope rebind — the kill demotes, the sink fires.
    src = """
import os

def f(p):
    import shlex
    shlex = object()
    p = shlex.quote(p)
    os.system(p)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}
    assert s.stat("sanitizer_kill_demotions") == 1
    assert s.stat("sanitizer_kills") == 0


def test_clean_local_import_still_kills(specs: SpecIndex) -> None:
    # The suspect signal needs a REBIND: a plain local import with no
    # shadow anywhere keeps its kill.
    src = """
import os

def f(p):
    import shlex
    p = shlex.quote(p)
    os.system(p)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()
    assert s.stat("sanitizer_kills") == 1
    assert s.stat("sanitizer_kill_demotions") == 0


# ── finally: temporal ordering of the strong position ────────────────


def test_finally_kill_does_not_erase_try_body_sink(
    specs: SpecIndex,
) -> None:
    # The sink fired BEFORE the finally ran: statement order keeps
    # the try-body event.
    src = """
import os
import shlex

def f(p):
    try:
        os.system(p)
    finally:
        p = shlex.quote(p)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}


def test_finally_kill_certifies_post_try_sink(specs: SpecIndex) -> None:
    # finally always runs before anything after the try: a kill
    # there dominates the post-try statements (strong, counted).
    src = """
import os
import shlex

def f(p):
    try:
        x = 1
    finally:
        p = shlex.quote(p)
    os.system(p)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()
    assert s.stat("sinks_suppressed_killed") == 1


# ── NFKC identifiers ─────────────────────────────────────────────────


def test_nfkc_fullwidth_spelling_matches_sink(specs: SpecIndex) -> None:
    # CPython NFKC-normalises identifiers at parse: a fullwidth
    # spelling of ``os`` IS the identifier ``os`` — NFKC-equivalent
    # respellings of sink names match rather than evade. (Cross-script
    # homoglyphs are NOT NFKC-equivalent — different identifiers, the
    # documented dynamic-binding miss class.)
    src = "import ｏｓ\ndef f(a):\n    ｏｓ.system(a)\n"
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}


def test_nfkc_fullwidth_shadow_counts_as_shadow(
    specs: SpecIndex,
) -> None:
    src = "import os\nｏｓ = 1\ndef f(a):\n    return a\n"
    idx = index_module_text(src, "app.py", module_name="app")
    assert "os" in idx.module_assigned
    assert "os" in idx.import_rebound


# ── propagators ──────────────────────────────────────────────────────


def test_pack_propagator_star_args_to_return(specs: SpecIndex) -> None:
    src = """
import os
import os.path

def f(base, user):
    p = os.path.join(base, user)
    os.system(p)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0", "param:1"}
    # Declared propagation is not the assumed floor: no assumed tag.
    flows = [f for ev in s.sink_events for f in ev.flows]
    assert all(MARKER_ASSUMED_PROPAGATION not in f.markers for f in flows)


def test_declared_propagator_narrows_to_its_cells(
    specs: SpecIndex,
) -> None:
    # os.path.abspath declares Argument[0] -> ReturnValue only: taint
    # in an UNDECLARED argument position of a declared propagator
    # does not ride (that is what distinguishes a declared row from
    # the assumed-propagation floor).
    src = """
import os
import os.path

def f(user):
    p = os.path.abspath("static", user)
    os.system(p)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()


# ── custom-spec pins (shapes the seed packs do not carry) ────────────


def _custom_specs() -> SpecIndex:
    from core.taint.packs import (
        SEMANTICS_KILL,
        SINK_KIND_DOTTED_CALLEE,
        PackSet,
        SanitizerSpec,
        SinkSpec,
    )

    return build_spec_index(PackSet(
        packs=(),
        sources=(),
        sinks=(
            SinkSpec(kind=SINK_KIND_DOTTED_CALLEE, sink_class="command-injection",
                     cwe="CWE-78", match="proc.launch", kwargs=("cmd",)),
            SinkSpec(kind=SINK_KIND_DOTTED_CALLEE, sink_class="command-injection",
                     cwe="CWE-78", match="multi.sink", args=(0,),
                     unless_kwargs=(("safe", "True"), ("shell", "False"))),
        ),
        sanitizers=(
            SanitizerSpec(kind="dotted_callee", match="clean.er",
                          semantics=SEMANTICS_KILL,
                          sink_classes=("command-injection",)),
        ),
        propagators=(),
    ))


def test_star_args_binds_kwargs_declared_sink() -> None:
    # ``launch(*args)`` can positionally fill a pos-or-keyword param
    # the sink declared by NAME — the star approximation covers
    # kwargs-declared sinks too (recall direction).
    specs = _custom_specs()
    src = """
import proc

def f(p):
    args = [p]
    proc.launch(*args)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "proc.launch") == {"param:0"}
    flows = [f for ev in s.sink_events for f in ev.flows]
    assert all(MARKER_BINDING_APPROX in f.markers for f in flows)


def test_unless_kwargs_multi_pair_is_conjunction() -> None:
    # Multi-pair unless_kwargs: EVERY pair must be literally present
    # to suppress — one of two present degrades toward firing.
    specs = _custom_specs()
    one = """
import multi

def f(p):
    multi.sink(p, shell=False)
"""
    s = summarize(one, specs, "f")
    assert sink_origins(s, "multi.sink") == {"param:0"}
    both = """
import multi

def f(p):
    multi.sink(p, shell=False, safe=True)
"""
    s = summarize(both, specs, "f")
    assert s.sink_events == ()
    assert s.stat("sinks_suppressed_unless_kwargs") == 1


# ── control-flow coverage pins ───────────────────────────────────────


def test_walrus_in_condition_taints_target(specs: SpecIndex) -> None:
    src = """
import os

def f(p):
    if (x := p):
        pass
    os.system(x)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}


def test_tainted_in_try_sink_in_except(specs: SpecIndex) -> None:
    src = """
import os

def f(p):
    try:
        x = p
        risky()
    except Exception:
        os.system(x)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}


def test_match_captures_across_cases(specs: SpecIndex) -> None:
    src = """
import os

def f(p):
    match p:
        case [x]:
            os.system(x)
        case {"k": v}:
            os.system(v)
        case y:
            os.system(y)
"""
    s = summarize(src, specs, "f")
    assert len(s.sink_events) == 3
    assert all(
        {fl.origin for fl in ev.flows} == {"param:0"}
        for ev in s.sink_events
    )


# ── strong/weak update (dominance split) ─────────────────────────────


def test_top_level_reassignment_is_strong(specs: SpecIndex) -> None:
    src = """
import os

def f(user):
    x = user
    x = "safe"
    os.system(x)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()


def test_branch_assignment_is_weak(specs: SpecIndex) -> None:
    # An assignment inside a branch may not execute: the old flow
    # survives and the sink still fires (degradation toward firing).
    src = """
import os

def f(user, cond):
    x = user
    if cond:
        x = "safe"
    os.system(x)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}


def test_branch_kill_does_not_certify_fallthrough(
    specs: SpecIndex,
) -> None:
    # A shlex.quote kill INSIDE a branch must not silence the
    # fall-through path (weak update: both flows reach the sink,
    # the unkilled one keeps it firing).
    src = """
import os
import shlex

def f(user, cond):
    x = user
    if cond:
        x = shlex.quote(x)
    os.system(x)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}


def test_with_body_kill_is_strong(specs: SpecIndex) -> None:
    # A with-body reached at top level dominates what follows.
    src = """
import os
import shlex

def f(user):
    with open("log") as fh:
        user = shlex.quote(user)
    os.system(user)
"""
    s = summarize(src, specs, "f")
    assert s.sink_events == ()
    assert s.stat("sinks_suppressed_killed") == 1


def test_try_body_kill_is_weak(specs: SpecIndex) -> None:
    # A try body can raise partway; the handler path reaches the
    # sink with the unkilled value.
    src = """
import os
import shlex

def f(user):
    try:
        user = shlex.quote(user)
    except ValueError:
        pass
    os.system(user)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}


# ── learned specs (bounded intake output consumed in-body) ──────────


def _learned(packs: PackSet, rows: list[dict]) -> SpecIndex:
    intake = intake_learned_specs(
        rows, vocabulary=packs.taint_class_vocabulary(),
    )
    return build_spec_index(packs, intake)


def test_learned_sink_matches_local_function(packs: PackSet) -> None:
    specs = _learned(packs, [{
        "role": "sink", "function": "app.run_query",
        "taint_classes": ["sql-injection"], "params_affected": [0],
        "confidence": 0.9,
    }])
    src = """
def run_query(q):
    return q

def f(user):
    run_query(user)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "app.run_query") == {"param:0"}
    flows = [f for ev in s.sink_events for f in ev.flows]
    assert all(MARKER_LEARNED in f.markers for f in flows)


def test_learned_sanitizer_is_tag_only_even_when_claiming_kill(
    packs: PackSet,
) -> None:
    # The intake demoted the kill claim to tag; in-body that means
    # the flow keeps moving and the sink fires.
    specs = _learned(packs, [{
        "role": "sanitiser", "function": "extlib.clean",
        "taint_classes": ["command-injection"], "semantics": "kill",
        "confidence": 0.9,
    }])
    src = """
import os
import extlib

def f(user):
    safe = extlib.clean(user)
    os.system(safe)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0"}
    flows = [f for ev in s.sink_events for f in ev.flows]
    assert any("extlib.clean" in f.hops for f in flows)
    assert s.stat("sanitizer_kills") == 0


def test_learned_propagator_is_additive_over_the_floor(
    packs: PackSet,
) -> None:
    # Additive-only: a learned propagator naming only Argument[0] must not
    # remove argument 1 from propagation — the floor still carries it.
    specs = _learned(packs, [{
        "role": "propagator", "function": "extlib.concat",
        "params_affected": [0], "confidence": 0.9,
    }])
    src = """
import os
import extlib

def f(a, b):
    out = extlib.concat(a, b)
    os.system(out)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {"param:0", "param:1"}


def test_learned_source_fires(packs: PackSet) -> None:
    specs = _learned(packs, [{
        "role": "source", "function": "extlib.fetch_user_text",
        "taint_classes": ["user-input"], "confidence": 0.9,
    }])
    src = """
import os
import extlib

def f():
    text = extlib.fetch_user_text()
    os.system(text)
"""
    s = summarize(src, specs, "f")
    assert sink_origins(s, "os.system") == {
        "source:learned:extlib.fetch_user_text",
    }


# ── excluded channels stay excluded (named non-goals) ────────────────


def test_global_mutation_is_not_a_taint_channel(specs: SpecIndex) -> None:
    # Writing a tainted value into a module global and reading it
    # back is the v1 non-goal: recorded informationally, never a
    # flow. The summary must NOT invent a sink event here.
    src = """
import os

STATE = ""

def writer(user):
    global STATE
    STATE = user

def reader():
    os.system(STATE)
"""
    idx = index_module_text(src, "app.py", module_name="app")
    writer = extract_summary(idx, idx.function_named("writer"), specs)
    reader = extract_summary(idx, idx.function_named("reader"), specs)
    assert writer.global_names == ("STATE",)
    assert writer.sink_events == ()
    assert reader.sink_events == ()  # honest miss, never a claim


def test_lambda_bodies_are_skipped_and_counted(specs: SpecIndex) -> None:
    src = """
def f(user):
    fn = lambda: user
    return fn
"""
    s = summarize(src, specs, "f")
    assert s.stat("lambdas_skipped") == 1
    assert s.params_to_return() == ()


def test_nested_defs_are_skipped_and_counted(specs: SpecIndex) -> None:
    src = """
import os

def f(user):
    def inner():
        os.system(user)
    return inner
"""
    s = summarize(src, specs, "f")
    assert s.stat("nested_defs_skipped") == 1
    assert s.sink_events == ()  # inner is its OWN summary subject


def test_nested_def_gets_its_own_summary(specs: SpecIndex) -> None:
    src = """
import os

def f(user):
    def inner():
        os.system(user)
    return inner
"""
    idx = index_module_text(src, "app.py", module_name="app")
    inner = idx.function_named("f.inner")
    assert inner is not None
    s = extract_summary(idx, inner, specs)
    # ``user`` is a closure name, not a param of inner: no event
    # (closure flow is interprocedural work, not P2's).
    assert s.sink_events == ()


def test_function_at_finds_innermost_enclosing(specs: SpecIndex) -> None:
    # The by-line lookup consumers use to go from a callgraph node's
    # line to its FunctionEntry: innermost enclosing function wins.
    src = """
def outer(a):
    x = a

    def inner(b):
        return b

    return inner
"""
    idx = index_module_text(src, "app.py", module_name="app")
    inner = idx.function_named("outer.inner")
    assert idx.function_at(inner.line_start + 1) is inner
    assert idx.function_at(3).qualname == "outer"
    assert idx.function_at(1) is None


# ── identity, hashing, serialization ────────────────────────────────


def test_function_id_and_content_hash_conventions(
    specs: SpecIndex,
) -> None:
    src = """
import os

def f(cmd):
    os.system(cmd)
"""
    idx = index_module_text(src, "pkg/app.py", module_name="pkg.app")
    entry = idx.function_named("f")
    s = extract_summary(idx, entry, specs)
    assert s.function_id == f"pkg/app.py::f@{entry.line_start}"
    expected = hash_spans_text(src, [(entry.line_start, entry.line_end)])[0]
    assert s.content_hash == expected
    assert len(s.content_hash) == 12


def test_extraction_is_deterministic(specs: SpecIndex) -> None:
    src = """
import os

def f(a, b, c):
    x = a + b
    y = {k: c for k in x}
    os.system(x)
    os.system(y)
    return x, y
"""
    first = summarize(src, specs, "f")
    second = summarize(src, specs, "f")
    assert first == second
