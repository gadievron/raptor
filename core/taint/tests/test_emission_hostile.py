"""Hostile-shape, amplification and fuzz batteries for emission.

Synthetic candidate sets (constructed records — no builder chain
needed at this boundary) attack the artifact rail with the measured
amplification shapes: hostile-length names multiplied across steps ×
candidates, hostile bytes through the SARIF egress, wall behaviour on
megabyte prose, and a mutation fuzz whose oracle demands no
exceptions, byte-inert ASCII output, valid-parsing SARIF, exact
emitted+refused partition, CWE on every result, and no
refutation-shaped key — every time."""

from __future__ import annotations

import json
import random
import time

import pytest

from core.analysis.package_callgraph import (
    TIER_HEURISTIC_DYNAMIC,
    TIER_RESOLVED_CONVENTION,
    TIER_RESOLVED_STATIC,
)
from core.config import RaptorConfig
from core.sarif.parser import parse_sarif_findings, validate_sarif
from core.taint.emission import (
    MAX_EMISSION_ARTIFACT_BYTES,
    EmissionLimits,
    emit,
    sarif_bytes,
)
from core.taint.engine import (
    Candidate,
    FrontierRecord,
    Hop,
    PropagationResult,
)
from core.taint.packs import PackSet, default_pack_names, load_packs
from core.taint.paths import AlternativePath, KilledOrigin, Step


@pytest.fixture(scope="module")
def packs() -> PackSet:
    return load_packs(default_pack_names())


_HOSTILE_TEXTS = (
    "evil\x1b[2J\x1b]0;pwn\x07",              # ESC / OSC
    "bidi‮override‬",                 # bidi controls
    "c1\x85controls\x9b",                       # C1 set
    "null\x00byte\ttab\nnewline",
    "plain_ok",
)

_FORBIDDEN_KEYS = ("refut", "disproven", "suppress", "clean",
                   "no_flow", "not_vulnerable", "is_dead", "ruled_out")


def _step(function: str, file: str, line: int, *, kind: str = "call",
          tier: str = TIER_RESOLVED_STATIC, excerpt: str = "",
          tags: tuple = (), sanitizers: tuple = (),
          killed: tuple = ()) -> Step:
    return Step(
        function=function, file=file, function_line=max(line, 1),
        tier=tier, kind=kind, call_file=file, call_line=max(line, 1),
        tags=tags, sanitizers=sanitizers, killed_classes=killed,
        excerpt=excerpt,
    )


def _chain_steps(function: str, file: str, depth: int,
                 **step_kw) -> tuple:
    steps = [_step(function, file, 1, kind="seed", **step_kw)]
    steps += [_step(function, file, i + 2, **step_kw)
              for i in range(depth)]
    steps.append(_step(function, file, depth + 3, kind="sink",
                       **step_kw))
    return tuple(steps)


def _candidate(function: str = "a.py::f@1", file: str = "a.py", *,
               depth: int = 2, sink_line: int = 9,
               sink_cwe: str = "CWE-78",
               sink_class: str = "command-injection",
               sink_match: str = "subprocess.run",
               path_tier: str = TIER_RESOLVED_STATIC,
               steps: tuple | None = None,
               alternatives: tuple = (),
               killed_origins: tuple = (),
               source_extra: tuple = ()) -> Candidate:
    if steps is None:
        steps = _chain_steps(function, file, depth)
    return Candidate(
        taint_class="user-input",
        source=(("kind", "route_param"), ("handler", function),
                *source_extra),
        sink_function=function,
        sink_line=sink_line,
        sink_class=sink_class,
        sink_cwe=sink_cwe,
        sink_match=sink_match,
        sink_confidence="exact",
        spec_tier="pack",
        pack="web-injection-core",
        hops=(Hop(function=function, tier=path_tier, kind="seed",
                  line=1),),
        path_tier=path_tier,
        steps=steps,
        alternatives=alternatives,
        killed_origins=killed_origins,
    )


def _result(candidates, frontier: tuple = ()) -> PropagationResult:
    return PropagationResult(candidates=tuple(candidates),
                             frontier=frontier)


def _walk_keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _walk_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_keys(v)


# ── the measured amplification shapes ────────────────────────────────


class TestAmplificationShapes:
    def test_8kib_names_shape_stays_megabyte_class(self, packs) -> None:
        """The measured 47 MB shape: 400 candidates whose node ids are
        8 KiB. Name caps hold the emitted artifact to single-digit MB
        — the name-length lever contributes its capped prefix, not
        its full length, per field."""
        cands = []
        for i in range(400):
            name = ("n" * 8192) + f"::f{i}@1"
            cands.append(_candidate(name, "m.py", depth=3,
                                     sink_line=i + 1))
        rep = emit(_result(cands), packs)
        assert rep.emitted == 400 and rep.refused == 0
        assert rep.stats["name_fields_capped"] > 0
        assert rep.artifact_bytes < 8 * 1024 * 1024
        assert len(sarif_bytes(rep)) < 9 * 1024 * 1024

    def test_64kib_names_shape_caps_with_markers_not_gigabytes(
            self, packs) -> None:
        """The 184 MB / GB-class shape: 64 KiB names on every step of
        every flow. The rail caps each field WITH its elision marker
        — the artifact lands orders of magnitude below the unbounded
        exposure and every capped field says so."""
        cands = []
        for i in range(100):
            name = ("x" * 65536) + f"::g{i}@1"
            file = "y" * 65536 + f"{i}.py"
            cands.append(_candidate(name, file, depth=8,
                                     sink_line=i + 1))
        rep = emit(_result(cands), packs)
        # Unbounded exposure for this set: >= 100 cands × 10 steps ×
        # 2 name fields × 64 KiB ≈ 130 MB. The rail holds it to a few
        # MB (capped prefixes + markers).
        assert rep.emitted == 100
        assert rep.artifact_bytes < 4 * 1024 * 1024
        assert rep.stats["name_fields_capped"] >= 100 * 10 * 2
        result = rep.sarif["runs"][0]["results"][0]
        name = (result["codeFlows"][0]["threadFlows"][0]["locations"]
                [0]["location"]["logicalLocations"][0]["name"])
        assert name.endswith("chars]")  # marker, not silent drop
        assert len(name) < 65536

    def test_frontier_bloat_shape_bounded_not_13mb(self, packs) -> None:
        """The frontier-regression shape at emission level: 200
        frontier records with 64 KiB target-derived callee names —
        13.1 MB raw pre-rail. The bounded block lands in KB-class,
        every field capped with its marker, bytes accounted."""
        flood = tuple(
            FrontierRecord(
                function=f"app/views_{i % 10}.py::run_cmd_{i % 10}@6",
                line=7 + i,
                callee=f"callee_{i:03d}_" + "z" * 65520,
                resolution="unresolved",
                taint_class="user-input")
            for i in range(200))
        rep = emit(_result([], frontier=flood), packs)
        assert len(rep.frontier) == 200
        block_bytes = rep.stats["frontier_bytes_emitted"]
        assert block_bytes == rep.artifact_bytes
        assert block_bytes < 256 * 1024  # KB-class, not 13.1 MB
        assert rep.stats["name_fields_capped"] >= 200
        assert all(len(r["callee"]) < 1024 for r in rep.frontier)
        assert all(r["callee"].endswith("chars]")
                   for r in rep.frontier)
        data = json.dumps(rep.frontier)
        assert len(data) < 512 * 1024

    def test_frontier_flood_refuses_past_budget(self, packs) -> None:
        flood = tuple(
            FrontierRecord(function="a.py::f@1", line=i + 1,
                           callee=f"callee_{i}",
                           resolution="unresolved",
                           taint_class="user-input")
            for i in range(500))
        rep = emit(_result([], frontier=flood), packs,
                   limits=EmissionLimits(max_artifact_bytes=8192))
        assert rep.artifact_bytes <= 8192
        assert len(rep.frontier) + rep.stats[
            "frontier_refused_budget"] == 500
        assert "artifact_budget" in rep.caps_hit

    def test_budget_still_binds_on_crafted_volume(self, packs) -> None:
        """Volume instead of length: enough capped-size records to
        cross the run budget refuses the tail, counted + marked —
        the artifact can never exceed the budget by more than one
        record's floor."""
        cands = [_candidate(f"c{i}.py::f@1", f"c{i}.py", depth=20,
                            sink_line=i + 1,
                            steps=_chain_steps(
                                f"c{i}.py::f@1", f"c{i}.py", 20,
                                excerpt="e" * 160))
                 for i in range(50)]
        budget = 64 * 1024
        rep = emit(_result(cands), packs,
                   limits=EmissionLimits(max_artifact_bytes=budget))
        assert rep.refused > 0
        assert rep.emitted + rep.refused == 50
        assert rep.artifact_bytes <= budget
        assert "artifact_budget" in rep.caps_hit
        assert rep.stats["records_refused_budget"] == rep.refused


# ── hostile bytes through the SARIF egress ───────────────────────────


class TestHostileBytes:
    def _hostile_candidates(self) -> list:
        cands = []
        for i, text in enumerate(_HOSTILE_TEXTS):
            steps = _chain_steps(
                f"{text}::f@1", f"{text}.py", 2,
                sanitizers=(text,), excerpt=text)
            cands.append(_candidate(
                f"{text}::f@1", f"{text}.py", sink_line=i + 1,
                sink_match=text, steps=steps,
                source_extra=(("route_pattern", text),)))
        return cands

    def test_egress_bytes_are_ascii_and_control_free(
            self, packs) -> None:
        """The pinned byte-inert egress: whatever rode in the
        candidates, the SARIF file bytes contain no control byte and
        nothing past ASCII — every hostile byte is a JSON escape."""
        rep = emit(_result(self._hostile_candidates()), packs)
        data = sarif_bytes(rep)
        body, newline = data[:-1], data[-1:]
        assert newline == b"\n"
        assert all(0x20 <= b < 0x7F for b in body)
        json.loads(data)

    def test_render_prose_escaped_at_emission(self, packs) -> None:
        """Messages and flow labels go through the log-sanitisation
        contract AT BUILD TIME: the in-memory strings already carry
        \\xHH escapes instead of raw controls (idempotent under the
        parser's own re-escape)."""
        rep = emit(_result(self._hostile_candidates()), packs)
        result = rep.sarif["runs"][0]["results"][0]
        message = result["message"]["text"]
        assert "\x1b" not in message and "\\x1b" in message
        label = (result["codeFlows"][0]["threadFlows"][0]["locations"]
                 [0]["location"]["message"]["text"])
        assert "\x1b" not in label
        assert "‮" not in message

    def test_hostile_sarif_parses_clean(self, tmp_path, packs) -> None:
        rep = emit(_result(self._hostile_candidates()), packs)
        out = tmp_path / "hostile.sarif"
        out.write_bytes(sarif_bytes(rep))
        assert validate_sarif(out) is not False
        parsed = parse_sarif_findings(out)
        assert len(parsed) == len(_HOSTILE_TEXTS)
        for f in parsed:
            assert f["cwe_id"] == "CWE-78"
            # The parser escapes label/snippet on read; nothing
            # printable-hostile survives into its dataflow steps.
            dp = f["dataflow_path"]
            assert "\x1b" not in dp["source"]["label"]

    def test_megabyte_prose_is_windowed_not_scanned(
            self, packs) -> None:
        """A crafted megabyte sink match cannot buy a full escape
        scan per candidate (the 4x-window discipline)."""
        cands = [_candidate(sink_match="A" * 1_000_000 + "\x1b[2J",
                            sink_line=i + 1) for i in range(20)]
        started = time.monotonic()
        rep = emit(_result(cands), packs)
        elapsed = time.monotonic() - started
        assert rep.emitted == 20
        # Generous wall (host-speed sensitive in the safe direction
        # only): unwindowed escaping of 20 MB of prose measures far
        # above this on any host.
        assert elapsed < 2.0
        message = rep.sarif["runs"][0]["results"][0]["message"]["text"]
        assert message.endswith("chars]")
        assert len(message) < 2048


# ── degraded shapes ──────────────────────────────────────────────────


class TestDegradedShapes:
    def test_steps_less_candidate_emits_without_codeflows(
            self, packs) -> None:
        """The wall-skip shape: hop chain but no rendered steps — the
        result ships with its sink location derived from the node id,
        no codeFlows, counted."""
        c = _candidate(steps=())
        rep = emit(_result([c]), packs)
        result = rep.sarif["runs"][0]["results"][0]
        assert "codeFlows" not in result
        assert rep.stats["results_without_codeflows"] == 1
        assert result["locations"][0]["physicalLocation"][
            "artifactLocation"]["uri"] == "a.py"
        assert rep.findings[0]["has_dataflow"] is False

    def test_nodeless_sink_id_omits_location_marked(
            self, packs) -> None:
        c = _candidate(function="not-a-node-id", steps=())
        rep = emit(_result([c]), packs)
        result = rep.sarif["runs"][0]["results"][0]
        assert "locations" not in result
        assert result["properties"]["location_unavailable"] is True
        assert rep.stats["sink_location_unavailable"] == 1
        # Still parseable — file comes back None, the finding exists.
        assert rep.findings[0]["file"] is None

    def test_single_step_flow_never_padded(self, packs) -> None:
        """A one-step chain is not a flow — no codeFlows, no
        fabricated second location."""
        c = _candidate(steps=(_step("a.py::f@1", "a.py", 1,
                                    kind="sink"),))
        rep = emit(_result([c]), packs)
        assert "codeFlows" not in rep.sarif["runs"][0]["results"][0]
        assert rep.findings[0]["dataflow_path"] is None


# ── mutation fuzz ────────────────────────────────────────────────────


_TIERS = (TIER_RESOLVED_STATIC, TIER_RESOLVED_CONVENTION,
          TIER_HEURISTIC_DYNAMIC)


def _fuzz_text(rng: random.Random) -> str:
    kind = rng.randrange(5)
    if kind == 0:
        return ""
    if kind == 1:
        return rng.choice(_HOSTILE_TEXTS)
    if kind == 2:
        return "n" * rng.choice((1, 63, 511, 512, 513, 4096))
    if kind == 3:
        return f"pkg/mod{rng.randrange(9)}.py::fn@{rng.randrange(99)}"
    return "".join(chr(rng.randrange(1, 0x2FFF))
                   for _ in range(rng.randrange(1, 40)))


def _fuzz_candidate(rng: random.Random) -> Candidate:
    function = _fuzz_text(rng) or "f.py::f@1"
    file = _fuzz_text(rng)
    depth = rng.randrange(0, 8)
    n_steps = rng.randrange(0, 4)
    if n_steps:
        steps = _chain_steps(
            function, file, depth,
            tier=rng.choice(_TIERS),
            excerpt=_fuzz_text(rng)[:200],
            tags=tuple(rng.sample(
                ("assumed_propagation", "binding_approx", "learned",
                 "sanitizer_demoted"), rng.randrange(0, 3))),
            sanitizers=tuple(_fuzz_text(rng)
                             for _ in range(rng.randrange(0, 20))),
            killed=tuple(_fuzz_text(rng)
                         for _ in range(rng.randrange(0, 3))),
        )
    else:
        steps = ()
    alternatives = tuple(
        AlternativePath(
            source=(("kind", _fuzz_text(rng)),),
            steps=_chain_steps(function, file, rng.randrange(0, 3)),
            path_tier=rng.choice(_TIERS))
        for _ in range(rng.randrange(0, 3)))
    killed_origins = tuple(
        KilledOrigin(sink_class=_fuzz_text(rng),
                     step=rng.choice((None, 0, 1)),
                     sanitizers=(_fuzz_text(rng),))
        for _ in range(rng.randrange(0, 2)))
    return Candidate(
        taint_class=_fuzz_text(rng) or "user-input",
        source=tuple((_fuzz_text(rng) or "k", _fuzz_text(rng))
                     for _ in range(rng.randrange(0, 4))),
        sink_function=function,
        sink_line=rng.randrange(0, 10_000),
        sink_class=rng.choice(("command-injection", "sql-injection",
                               "user-input", _fuzz_text(rng))),
        sink_cwe=rng.choice(("CWE-78", "CWE-89", "")),
        sink_match=_fuzz_text(rng),
        sink_confidence=rng.choice(("exact", "heuristic")),
        spec_tier=rng.choice(("pack", "learned")),
        pack=rng.choice(("web-injection-core", "")),
        hops=(Hop(function=function, tier=rng.choice(_TIERS),
                  kind="seed", line=1),),
        path_tier=rng.choice(_TIERS),
        steps=steps,
        alternatives=alternatives,
        killed_origins=killed_origins,
    )


class TestEmissionFuzz:
    def test_fuzz_generated_candidate_sets(self, packs) -> None:
        """No exception outside contract, ASCII-inert bytes, parseable
        SARIF, exact partition, CWE always set, detection tier always
        candidate, no refutation key — over every generated set."""
        rng = random.Random(0xD1E51)
        # Full-schema arm only where a deployment ships the schema
        # file AND jsonschema — hermetic degrade to the structural
        # oracle everywhere else (the validate_sarif tri-state
        # posture).
        validator = None
        schema = None
        schema_path = RaptorConfig.SCHEMAS_DIR / "sarif-2.1.0.json"
        if schema_path.exists():
            try:
                import jsonschema as validator
            except ImportError:
                validator = None
            else:
                schema = json.loads(schema_path.read_text())

        emitted_total = 0
        capped_fields_total = 0
        refused_total = 0
        for _ in range(1000):
            cands = [_fuzz_candidate(rng)
                     for _ in range(rng.randrange(0, 6))]
            frontier = tuple(
                FrontierRecord(
                    function=_fuzz_text(rng),
                    line=rng.randrange(0, 10_000),
                    callee=_fuzz_text(rng),
                    resolution=rng.choice(("unresolved", "external",
                                           _fuzz_text(rng))),
                    taint_class=_fuzz_text(rng))
                for _ in range(rng.randrange(0, 4)))
            limits = EmissionLimits(
                max_name_field_chars=rng.choice((8, 64, 512)),
                max_message_chars=rng.choice((16, 400)),
                max_list_items=rng.choice((1, 4, 16)),
                max_record_bytes=rng.choice((256, 4096, 256 * 1024)),
                max_artifact_bytes=rng.choice(
                    (512, 65536, MAX_EMISSION_ARTIFACT_BYTES)),
            )
            rep = emit(_result(cands, frontier=frontier), packs,
                       limits=limits)

            assert rep.emitted + rep.refused == len(cands)
            assert rep.artifact_bytes <= limits.max_artifact_bytes
            # Frontier partition + field bound hold on every set.
            assert len(rep.frontier) + rep.stats.get(
                "frontier_refused_budget", 0) == len(frontier)
            cap = limits.max_name_field_chars
            for record in rep.frontier:
                assert len(record["callee"]) <= cap + 32
            data = sarif_bytes(rep)
            assert all(0x20 <= b < 0x7F for b in data[:-1])
            doc = json.loads(data)
            assert doc["version"] == "2.1.0" and doc["runs"]
            if validator is not None and schema is not None:
                validator.validate(instance=doc, schema=schema)
            for result in doc["runs"][0]["results"]:
                assert result["ruleId"].startswith(
                    "raptor.taint.crossfile.")
                assert result["properties"]["cwe"].startswith("CWE-")
                assert (result["properties"]["detection_tier"]
                        == "candidate")
            for key in _walk_keys(doc):
                for bad in _FORBIDDEN_KEYS:
                    assert bad not in key.lower(), key
            for f in rep.findings:
                assert f["cwe_id"].startswith("CWE-")
                assert f["tool"] == "taint-crossfile"

            emitted_total += rep.emitted
            refused_total += rep.refused
            capped_fields_total += rep.stats.get(
                "name_fields_capped", 0)

        # Meaningfulness floors: the fuzz must actually exercise the
        # rails, not pass vacuously on empty sets.
        assert emitted_total >= 1000
        assert refused_total >= 60
        assert capped_fields_total >= 600
