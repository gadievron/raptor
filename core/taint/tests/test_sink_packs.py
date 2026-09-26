"""Content pins for the recall-domain sink packs (second-order
stores, secrets flow, template engines) and the sink class gate.

The packs are data on the sealed pack format: the pins here load them
through the shared loader and match them through the shared extractor
— the assertions are about the data (pairing closure, vocabulary
membership, per-entry claims). The one engine seam the secrets pack
depends on — ``only_taint_classes``, the sink class gate that keeps a
data-sensitivity sink from re-reporting another pack's injection flow
— is pinned here in both directions (off-class flows gated out,
secret flows still detected)."""

from __future__ import annotations

import pytest

from core.analysis.package_callgraph import build_package_callgraph
from core.analysis.route_models import build_route_models
from core.inventory.call_graph import extract_call_graph_python
from core.inventory.extractors import PythonExtractor
from core.taint.engine import PropagationResult, propagate
from core.taint.learned_intake import intake_learned_specs
from core.taint.mad_matrix import emissibility_report, mad_emissibility
from core.taint.packs import (
    PackSet,
    default_pack_names,
    load_packs,
)
from core.taint.summaries import (
    SpecIndex,
    build_spec_index,
    extract_summary,
    index_module_text,
)


@pytest.fixture(scope="module")
def seed_packs() -> PackSet:
    return load_packs(default_pack_names("python"))


@pytest.fixture(scope="module")
def specs(seed_packs: PackSet) -> SpecIndex:
    return build_spec_index(seed_packs)


def summarize(source: str, specs: SpecIndex, qualname: str):
    idx = index_module_text(source, "app.py", module_name="app")
    entry = idx.function_named(qualname)
    assert entry is not None, f"fixture must define {qualname}"
    return extract_summary(idx, entry, specs)


def pack_named(seed_packs: PackSet, name: str):
    matches = [p for p in seed_packs.packs if p.name == name]
    assert len(matches) == 1, f"{name} must ship exactly once"
    return matches[0]


def propagate_tree(
    tmp_path, files: dict[str, str], packs: PackSet,
) -> PropagationResult:
    """Real builder chain end to end (inventory extractors → package
    callgraph → route models → engine), the test_engine plumbing."""
    records = []
    for rel, content in sorted(files.items()):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        items = [
            i.to_dict() for i in PythonExtractor().extract(rel, content)
        ]
        records.append({
            "path": rel,
            "language": "python",
            "items": items,
            "call_graph": extract_call_graph_python(content).to_dict(),
        })
    inventory = {"files": records}
    graph = build_package_callgraph(inventory)
    routes = build_route_models(inventory, graph)
    return propagate(graph, routes, packs, target_root=tmp_path)


# ── second-order-stores ──────────────────────────────────────────────


def test_second_order_pack_ships_as_pure_data(seed_packs: PackSet):
    """The pack rides the default name glob — shipping it changed no
    loader, matcher, or intake code."""
    assert "python/second-order-stores" in default_pack_names("python")
    pack = pack_named(seed_packs, "second-order-stores")
    assert all(s.kind == "stored_read" for s in pack.sources)
    kinds = {s.kind for s in pack.sinks}
    assert kinds == {"stored_write", "dotted_callee"}


def test_second_order_classes_enter_the_vocabulary(seed_packs: PackSet):
    vocab = seed_packs.taint_class_vocabulary()
    assert {"stored-user-input", "stored-taint", "deserialize"} <= vocab


def test_store_key_pairing_closes_within_the_pack(seed_packs: PackSet):
    """Every declared store has BOTH halves: a read source and a write
    sink sharing the store_key label. An unpaired half would declare a
    store the cross-request join can never close."""
    pack = pack_named(seed_packs, "second-order-stores")
    read_keys = {s.store_key for s in pack.sources if s.kind == "stored_read"}
    write_keys = {s.store_key for s in pack.sinks if s.kind == "stored_write"}
    assert read_keys and read_keys == write_keys


def test_stored_kinds_refuse_in_the_matrix_with_reasons(
    seed_packs: PackSet,
):
    """Models-as-data cannot express the store pairing — every
    stored_* row from this pack must land in the counted refusals with
    a per-kind reason, while the pack's plain dotted deserialization
    sink emits."""
    report = emissibility_report(seed_packs, language="python")
    reasons = {r.row: r.reason for r in report.rejected}
    pack = pack_named(seed_packs, "second-order-stores")
    for source in pack.sources:
        row = f"source:stored_read:{source.match}"
        assert "stored_read" in reasons[row]
    for sink in pack.sinks:
        if sink.kind != "stored_write":
            continue
        row = f"sink:stored_write:{sink.match}"
        assert "stored_write" in reasons[row]
    assert "sink:dotted_callee:pickle.loads" not in reasons


def test_pickle_loads_is_both_deser_sink_and_stored_source(
    specs: SpecIndex,
):
    """One callee, two independent claims: tainted INPUT fires the
    CWE-502 sink; the OUTPUT carries the stored-read taint either
    way."""
    src = """
import pickle

def f(blob):
    data = pickle.loads(blob)
    return data
"""
    s = summarize(src, specs, "f")
    deser = [ev for ev in s.sink_events if ev.match == "pickle.loads"]
    assert [ev.sink_class for ev in deser] == ["deserialize"]
    assert deser[0].cwe == "CWE-502"
    assert {f.origin for ev in deser for f in ev.flows} == {"param:0"}
    assert "stored_read" in {e.kind for e in s.source_events}
    assert any(
        f.origin == "source:stored_read:pickle.loads" for f in s.returns
    )


def test_deserialize_label_joins_the_learned_channel(seed_packs: PackSet):
    """The store's raw ``deserialize`` spelling used to refuse counted
    (no pack declared the class); the second-order pack declaring it
    is the pure-data unlock."""
    result = intake_learned_specs(
        [{
            "role": "sink", "function": "app.codec.load_state",
            "taint_classes": ["deserialize"], "confidence": 0.8,
        }],
        vocabulary=seed_packs.taint_class_vocabulary(),
    )
    assert [s.taint_classes for s in result.sinks] == [("deserialize",)]


def test_execute_storage_claim_is_disjoint_from_the_sqli_claim(
    seed_packs: PackSet,
):
    """cursor.execute carries two claims in the shipped set: the
    web-injection-core sqli claim on the STATEMENT (argument 0 of the
    bound method_name spelling) and this pack's storage claim on the
    PARAMETERS (argument 2 of the unbound dotted spelling, past the
    cursor and the statement). They must not restate each other."""
    stored = [
        s for s in seed_packs.sinks
        if s.kind == "stored_write" and s.match.endswith(".execute")
    ]
    assert stored
    for sink in stored:
        assert sink.args == (2,)
        assert sink.sink_class == "stored-taint"
    sqli = [
        s for s in seed_packs.sinks
        if s.kind == "method_name" and s.match == "execute"
    ]
    assert sqli
    for sink in sqli:
        assert sink.args == (0,)
        assert sink.sink_class == "sql-injection"


# ── secrets-flow ─────────────────────────────────────────────────────


def test_secrets_pack_ships_as_pure_data(seed_packs: PackSet):
    assert "python/secrets-flow" in default_pack_names("python")
    vocab = seed_packs.taint_class_vocabulary()
    assert {"secret", "secret-exposure"} <= vocab


def test_env_secret_reaches_the_logging_sink(specs: SpecIndex):
    """End-to-end through the unchanged extractor: a credential read
    seeds the secret class and the printf-style logging argument
    (position 1, not just the message) fires the sink."""
    src = """
import os
import logging

def f():
    token = os.environ.get("API_TOKEN")
    logging.info("using token %s", token)
"""
    s = summarize(src, specs, "f")
    hits = [ev for ev in s.sink_events if ev.match == "logging.info"]
    assert [ev.sink_class for ev in hits] == ["secret-exposure"]
    assert hits[0].cwe == "CWE-532"
    origins = {f.origin for ev in hits for f in ev.flows}
    assert origins == {"source:call_return:os.environ.get"}


def test_logger_instance_spelling_fires_heuristically(specs: SpecIndex):
    """logger.debug has no import binding — the method_name entry
    gated on the receiver named logger is what catches it."""
    src = """
import logging

logger = logging.getLogger(__name__)

def f(secret):
    logger.debug("key=%s", secret)
"""
    s = summarize(src, specs, "f")
    hits = [ev for ev in s.sink_events if ev.match == "debug"]
    assert [ev.sink_class for ev in hits] == ["secret-exposure"]
    assert {f.origin for ev in hits for f in ev.flows} == {"param:0"}


def test_warning_tier_secrets_sinks_declare_heuristic_confidence(
    seed_packs: PackSet,
):
    """print and Exception fire on ubiquitous calls — the entries must
    carry the weaker confidence so consumers can weigh them."""
    pack = pack_named(seed_packs, "secrets-flow")
    by_match = {s.match: s for s in pack.sinks}
    assert by_match["print"].confidence == "heuristic"
    assert by_match["Exception"].confidence == "heuristic"
    assert by_match["logging.info"].confidence == "exact"


def test_argv_claim_carries_no_shell_suppression(seed_packs: PackSet):
    """Both subprocess.run claims ship: the command-injection entry is
    suppressed by a literal shell=False, the argv-visibility entry is
    not — shell mode changes interpretation, not process-table
    visibility."""
    runs = {
        s.sink_class: s for s in seed_packs.sinks
        if s.match == "subprocess.run"
    }
    assert set(runs) == {"command-injection", "secret-exposure"}
    assert ("shell", "False") in runs["command-injection"].unless_kwargs
    assert runs["secret-exposure"].unless_kwargs == ()
    assert runs["secret-exposure"].cwe == "CWE-214"


def test_user_input_argv_flow_is_not_a_secret_finding(
    tmp_path, seed_packs: PackSet,
):
    """The class gate in the flow direction that matters most: a route
    parameter reaching subprocess.run is ONE finding — the
    command-injection claim. The argv-visibility entry consumes only
    secret-classed flows, and the off-class suppression is counted,
    never silent."""
    files = {
        "app/__init__.py": "",
        "app/views.py": (
            "import subprocess\n"
            "from flask import Flask\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/run/<cmd>')\n"
            "def run_cmd(cmd):\n"
            "    subprocess.run(cmd, shell=True)\n"
            "    return 'ok'\n"
        ),
    }
    res = propagate_tree(tmp_path, files, seed_packs)
    runs = [c for c in res.candidates if c.sink_match == "subprocess.run"]
    assert [c.sink_class for c in runs] == ["command-injection"]
    assert res.stat("candidates_class_gated") >= 1


def test_secret_to_argv_flow_survives_the_class_gate(
    tmp_path, seed_packs: PackSet,
):
    """The positive direction the narrowing must preserve: a genuine
    credential read handed to subprocess.run argv is still detected,
    with the finding naming its own defect mechanism (CWE-214 on the
    secret class)."""
    files = {
        "app/__init__.py": "",
        "app/deploy.py": (
            "import os\n"
            "\n"
            "from .exec_layer import launch\n"
            "\n"
            "def deploy():\n"
            "    token = os.environ.get('API_TOKEN')\n"
            "    return launch(token)\n"
        ),
        "app/exec_layer.py": (
            "import subprocess\n"
            "\n"
            "def launch(token):\n"
            "    subprocess.run(token)\n"
            "    return None\n"
        ),
    }
    res = propagate_tree(tmp_path, files, seed_packs)
    secrets = [c for c in res.candidates
               if c.sink_class == "secret-exposure"]
    assert len(secrets) == 1
    assert secrets[0].sink_match == "subprocess.run"
    assert secrets[0].sink_cwe == "CWE-214"
    assert secrets[0].taint_class == "secret"


def test_off_class_local_flow_never_reaches_a_gated_sink(
    tmp_path, seed_packs: PackSet,
):
    """Same gate on the in-body source path: request data logged in
    the function that read it is not a secret-exposure finding, and
    the suppression is counted."""
    files = {
        "app/__init__.py": "",
        "app/views.py": (
            "import logging\n"
            "\n"
            "from flask import request\n"
            "\n"
            "def audit():\n"
            "    logging.info(request.get_data())\n"
        ),
    }
    res = propagate_tree(tmp_path, files, seed_packs)
    assert not [c for c in res.candidates
                if c.sink_class == "secret-exposure"]
    assert res.stat("candidates_class_gated") >= 1


def test_redaction_sanitizers_are_tag_only(seed_packs: PackSet):
    """Redaction completeness is a call-site property — the pack may
    record the hop but never kill the flow."""
    pack = pack_named(seed_packs, "secrets-flow")
    assert pack.sanitizers
    for sanitizer in pack.sanitizers:
        assert sanitizer.semantics == "tag"
        assert sanitizer.sink_classes == ("secret-exposure",)


def test_secrets_rows_emit_or_refuse_accountably(seed_packs: PackSet):
    """Every secrets sink is class-gated, and a models-as-data row has
    no taint-class dimension — so ALL of them land in the counted
    refusals (method_name entries with the per-kind reason, dotted
    entries with the class-gate reason). Sources and ungated sinks
    from the other packs still emit."""
    report = emissibility_report(seed_packs, language="python")
    reasons = {r.row: r.reason for r in report.rejected}
    assert "method_name" in reasons["sink:method_name:info"]
    assert "method_name" in reasons["sink:method_name:debug"]
    for row in ("sink:dotted_callee:logging.info",
                "sink:dotted_callee:urllib.parse.urlencode",
                "sink:dotted_callee:subprocess.run"):
        assert "class-gated" in reasons[row], row
    emitted_ok = {"source:call_return:os.environ.get"}
    assert not (emitted_ok & set(reasons))
    # The command-injection subprocess.run row from web-injection-core
    # shares the refused row's coordinate but is ungated — it must
    # still emit, so the label above can only be the secrets entry.
    assert report.emissible_rows > 0


def test_class_gated_cell_refuses_in_the_matrix():
    """Unit pin on the matrix cell: an otherwise-emissible sink cell
    flips to a reasoned refusal when the entry is class-gated."""
    open_cell = mad_emissibility(
        language="python", role="sink", kind="dotted_callee",
        provenance="framework_catalog",
    )
    assert open_cell.emissible
    gated = mad_emissibility(
        language="python", role="sink", kind="dotted_callee",
        provenance="framework_catalog", class_gated=True,
    )
    assert not gated.emissible
    assert "class-gated" in gated.reason


def test_every_secrets_sink_declares_the_class_gate(
    seed_packs: PackSet,
):
    """A secret-exposure claim depends on what the value IS, so every
    sink of that class must restrict itself to secret-classed flows —
    an ungated one would re-report every tracked flow into a shared
    coordinate under the wrong label (the subprocess.run seam)."""
    exposure = [s for s in seed_packs.sinks
                if s.sink_class == "secret-exposure"]
    assert exposure
    for sink in exposure:
        assert sink.only_taint_classes == ("secret",), sink.match


def test_shared_coordinates_across_packs_are_class_disjoint(
    seed_packs: PackSet,
):
    """Regression pin for the adjudicated semantics: when two shipped
    packs claim the same (kind, match) coordinate, at most one claim
    may be ungated — a second ungated claim would fire twice on every
    flow into the coordinate, re-creating the double-finding seam a
    new pack could otherwise ship silently."""
    by_coord: dict[tuple[str, str], list] = {}
    for sink in seed_packs.sinks:
        by_coord.setdefault((sink.kind, sink.match), []).append(sink)
    for coord, sinks in by_coord.items():
        ungated = [s for s in sinks if not s.only_taint_classes]
        assert len(ungated) <= 1, (
            f"{coord}: ungated claims from "
            f"{sorted(s.pack for s in ungated)} double-fire every flow"
        )


# ── template-engines ─────────────────────────────────────────────────


def test_template_pack_ships_as_pure_data(seed_packs: PackSet):
    assert "python/template-engines" in default_pack_names("python")
    pack = pack_named(seed_packs, "template-engines")
    assert pack.sinks and not pack.sources
    assert {s.sink_class for s in pack.sinks} == {"template-injection"}
    assert {s.cwe for s in pack.sinks} == {"CWE-1336", "CWE-94"}


def test_no_shipped_pack_restates_another_packs_sink(
    seed_packs: PackSet,
):
    """De-dup census over the whole shipped set: the same claim —
    (kind, match, sink class) — may ship once. Deliberate same-callee
    overlaps (subprocess.run argv vs shell, execute statement vs
    parameters, pickle.loads input vs output) differ in class or kind
    and pass; a restated row would be pure noise."""
    seen: dict[tuple[str, str, str], str] = {}
    for sink in seed_packs.sinks:
        claim = (sink.kind, sink.match, sink.sink_class)
        assert claim not in seen, (
            f"{sink.pack} restates {claim} from {seen[claim]}"
        )
        seen[claim] = sink.pack


def test_constructor_level_ssti_fires_via_the_env_hint(
    specs: SpecIndex,
):
    """env.from_string(user) has no import binding — the
    receiver-hinted method_name entry is what catches the dominant
    spelling."""
    src = """
import jinja2

def f(user):
    env = jinja2.Environment()
    return env.from_string(user)
"""
    s = summarize(src, specs, "f")
    hits = [ev for ev in s.sink_events if ev.match == "from_string"]
    assert [ev.sink_class for ev in hits] == ["template-injection"]
    assert hits[0].confidence == "heuristic"
    assert {f.origin for ev in hits for f in ev.flows} == {"param:0"}


def test_unbound_from_string_spelling_carries_self_offset(
    seed_packs: PackSet,
):
    """The dotted from_string entries describe the unbound spelling
    Environment.from_string(env, source) — the tainted source is
    position 1, and the keyword spelling is declared beside it so
    from_string(source=...) is not a miss."""
    pack = pack_named(seed_packs, "template-engines")
    for sink in pack.sinks:
        if sink.kind != "dotted_callee":
            continue
        if sink.match.endswith(".from_string"):
            assert sink.args == (1,)
            assert sink.kwargs
        else:
            # Constructor calls have no explicit self.
            assert sink.args == (0,)
