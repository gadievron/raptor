"""Cross-artifact hypothesis routing (``core.engagement.router``).

Fixture discipline mirrors the ledger/governor batteries: synthetic
ledger documents are passed directly (the extraction itself is the
ledger battery's subject), sibling seed files are real on-disk JSON
loaded through the intake's own loader, the binary bridge and the ELF
fact extractors are stubbed at their module seams (no host binaries,
no sandboxed probes), and sibling discovery is pinned to the test
tree so a host ``out/`` directory can never leak into a run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.audit.hypothesis_intake import (
    MAX_SEED_RECORDS,
    SEEDS_FILENAME,
    load_seed_files,
)
from core.engagement import router
from core.engagement.router import (
    PRODUCER_CLASSES,
    QUOTA_SHARES,
    ROUTING_DIR_NAME,
    ROUTING_REPORT_FILENAME,
    route_hypotheses,
)

ANCHOR_A = "aa" * 8
SHA_A = "11" * 32
ANCHOR_B = "bb" * 8
SHA_B = "22" * 32
ART_A = f"elf_build_id-{ANCHOR_A}"
ART_B = f"elf_build_id-{ANCHOR_B}"


def _row(anchor: str, sha: str, path: str, **over: Any) -> dict:
    base: dict[str, Any] = {
        "artifact_id": f"elf_build_id-{anchor}",
        "class": "elf-exe",
        "path": path,
        "provenance": {"origin": "target_walk"},
        "identity": {"kind": "elf_build_id", "value": anchor,
                     "anchor": anchor, "sha256": sha},
        "links": {"needed": [], "soname": ""},
        "exposure": [],
    }
    base.update(over)
    return base


def _ledger(target: Path, rows: list[dict],
            reverse_needed: list[dict] | None = None) -> dict:
    return {
        "schema_version": 1,
        "target_root": str(target),
        "rows": rows,
        "reverse_needed": reverse_needed or [],
    }


class _Edge:
    def __init__(self, caller: str, sink: str, tier: str = "xref_backed",
                 confidence: str = "high", binary_path: str = "") -> None:
        self.caller = caller
        self.sink = sink
        self.evidence_tier = tier
        self.confidence = confidence
        self.binary_path = binary_path


class _Boundary:
    def __init__(self, function: str, ingress: str = "main",
                 score: float = 5.0) -> None:
        self.function = function
        self.ingress_function = ingress
        self.depth = 1
        self.score = score
        self.evidence_tier = "heuristic"


class _Bridge:
    def __init__(self, edges: list | None = None,
                 boundaries: list | None = None) -> None:
        self.sink_edges = edges or []
        self.parser_boundaries = boundaries or []


@pytest.fixture(autouse=True)
def _hermetic_seams(monkeypatch):
    """No host leakage: sibling discovery starts empty (each test
    plants its own), the bridge starts absent."""
    monkeypatch.setattr(
        router, "_load_bridge", lambda out_dir, target_root: None,
    )
    import core.orchestration.run_discovery as rd
    monkeypatch.setattr(
        rd, "collect_sibling_runs",
        lambda *a, **k: [],
    )


@pytest.fixture()
def run(tmp_path):
    target = tmp_path / "target"
    (target / "bin").mkdir(parents=True)
    out_dir = tmp_path / "out" / "audit_run"
    out_dir.mkdir(parents=True)
    return out_dir, target


def _plant_sibling(monkeypatch, out_dir: Path, seeds: list[dict]) -> Path:
    sib = out_dir.parent / "study_run"
    sib.mkdir(exist_ok=True)
    (sib / SEEDS_FILENAME).write_text(json.dumps({"seeds": seeds}))
    import core.orchestration.run_discovery as rd
    monkeypatch.setattr(
        rd, "collect_sibling_runs", lambda *a, **k: [sib],
    )
    return sib


def _seed_doc(out_dir: Path, artifact_id: str) -> dict:
    path = out_dir / ROUTING_DIR_NAME / f"{artifact_id}.hypotheses.json"
    return json.loads(path.read_text())


class TestEntryGate:
    def test_no_ledger_returns_none_and_writes_nothing(self, run):
        out_dir, _target = run
        assert route_hypotheses(out_dir) is None
        assert not (out_dir / ROUTING_DIR_NAME).exists()

    def test_empty_rows_refuse(self, run):
        out_dir, target = run
        assert route_hypotheses(out_dir, ledger=_ledger(target, [])) \
            is None

    def test_quota_shares_cover_every_class(self):
        assert set(QUOTA_SHARES) == set(PRODUCER_CLASSES)
        assert sum(QUOTA_SHARES.values()) <= 1.0


class TestSiblingRouting:
    def test_identity_join_routes_seed_to_owner(
        self, run, monkeypatch,
    ):
        out_dir, target = run
        _plant_sibling(monkeypatch, out_dir, [{
            "file": "binary:renamed-copy", "function": "parse_channel",
            "fid": f"{ANCHOR_A}:0x1da0", "module_sha256": SHA_A,
            "claim": "length is trusted",
            "evidence_tier": "xref_backed",
        }])
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        report = route_hypotheses(out_dir, ledger=doc)
        stats = report["producers"]["sibling_hypotheses"]
        assert stats["candidates"] == 1
        assert stats["joins"] == {"identity": 1, "name_fallback": 0}
        (seed,) = _seed_doc(out_dir, ART_A)["seeds"]
        assert seed["fid"] == f"{ANCHOR_A}:0x1da0"
        assert seed["module_sha256"] == SHA_A

    def test_content_mismatch_refuses_never_name_falls_back(
        self, run, monkeypatch,
    ):
        """A matching anchor over mismatched bytes is the forged
        identity shape — the join refuses, and the seed must not
        reroute through the stem it also happens to name."""
        out_dir, target = run
        _plant_sibling(monkeypatch, out_dir, [{
            "file": "binary:acmed", "function": "parse_channel",
            "fid": f"{ANCHOR_A}:0x1da0", "module_sha256": "33" * 32,
            "claim": "forged identity",
        }])
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        report = route_hypotheses(out_dir, ledger=doc)
        stats = report["producers"]["sibling_hypotheses"]
        assert stats["candidates"] == 0
        assert stats["misses"] == {"module_content_mismatch": 1}
        assert not (
            out_dir / ROUTING_DIR_NAME / f"{ART_A}.hypotheses.json"
        ).exists()

    def test_name_fallback_counted_and_sha_backfilled(
        self, run, monkeypatch,
    ):
        out_dir, target = run
        _plant_sibling(monkeypatch, out_dir, [{
            "file": "binary:acmed", "function": "lp_decode",
            "claim": "name fallback",
        }])
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        report = route_hypotheses(out_dir, ledger=doc)
        stats = report["producers"]["sibling_hypotheses"]
        assert stats["joins"] == {"identity": 0, "name_fallback": 1}
        # The routed seed carries the LEDGER's content hash: the
        # downstream intake can refuse if the file has changed.
        (seed,) = _seed_doc(out_dir, ART_A)["seeds"]
        assert seed["module_sha256"] == SHA_A

    def test_ambiguous_stem_and_unknown_owner_are_recorded_misses(
        self, run, monkeypatch,
    ):
        out_dir, target = run
        _plant_sibling(monkeypatch, out_dir, [
            {"file": "binary:acmed", "function": "f",
             "claim": "two rows share this stem"},
            {"file": "binary:nosuch", "function": "g",
             "claim": "no row has this stem"},
        ])
        doc = _ledger(target, [
            _row(ANCHOR_A, SHA_A, "bin/acmed"),
            _row(ANCHOR_B, SHA_B, "sbin/acmed"),
        ])
        report = route_hypotheses(out_dir, ledger=doc)
        misses = report["producers"]["sibling_hypotheses"]["misses"]
        assert misses == {"owner_ambiguous": 1, "owner_unknown": 1}
        misses_doc = json.loads(
            (out_dir / "fid-misses.json").read_text(),
        )
        (op,) = misses_doc["operations"]
        assert op["operation"] == "engagement-routing"
        assert {m["reason"] for m in op["misses"]} == {
            "owner_ambiguous", "owner_unknown",
        }

    def test_routed_file_loads_through_the_real_intake(
        self, run, monkeypatch,
    ):
        out_dir, target = run
        _plant_sibling(monkeypatch, out_dir, [{
            "file": "binary:acmed", "function": "parse_channel",
            "fid": f"{ANCHOR_A}:0x1da0", "module_sha256": SHA_A,
            "claim": "length is trusted",
            "disproof": "show the dominating compare",
            "evidence_tier": "xref_backed",
        }])
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        route_hypotheses(out_dir, ledger=doc)
        seed_file = (
            out_dir / ROUTING_DIR_NAME / f"{ART_A}.hypotheses.json"
        )
        seeds, skips, _sources = load_seed_files([seed_file])
        assert skips == {}
        (seed,) = seeds
        assert seed.fid == f"{ANCHOR_A}:0x1da0"
        assert seed.module_sha256 == SHA_A
        assert seed.evidence_tier == "xref_backed"


class TestSinkRouting:
    def test_edge_routes_by_stem_when_binary_gone(
        self, run, monkeypatch,
    ):
        out_dir, target = run
        bridge = _Bridge(edges=[
            _Edge("do_copy", "strcpy",
                  binary_path=str(target / "bin" / "acmed")),
        ])
        monkeypatch.setattr(
            router, "_load_bridge", lambda o, t: bridge,
        )
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        report = route_hypotheses(out_dir, ledger=doc)
        stats = report["producers"]["context_map_sinks"]
        assert stats["candidates"] == 1
        assert stats["joins"]["name_fallback"] == 1
        (seed,) = _seed_doc(out_dir, ART_A)["seeds"]
        assert seed["function"] == "do_copy"
        assert "strcpy" in seed["claim"]
        assert seed["module_sha256"] == SHA_A
        assert seed["evidence_tier"] == "xref_backed"

    def test_identity_probe_matching_no_row_never_stem_guesses(
        self, run, monkeypatch,
    ):
        """A readable binary that identifies as something OUTSIDE the
        ledger is not a target artifact — falling to its stem would
        route foreign analysis onto a same-named target file."""
        out_dir, target = run
        foreign = target / "bin" / "acmed"
        foreign.write_bytes(b"\x00" * 64)
        bridge = _Bridge(edges=[
            _Edge("do_copy", "strcpy", binary_path=str(foreign)),
        ])
        monkeypatch.setattr(
            router, "_load_bridge", lambda o, t: bridge,
        )
        import core.binary.addrmap as addrmap
        monkeypatch.setattr(
            addrmap, "content_anchor", lambda *a, **k: "cc" * 8,
        )
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        report = route_hypotheses(out_dir, ledger=doc)
        stats = report["producers"]["context_map_sinks"]
        assert stats["candidates"] == 0
        assert stats["misses"] == {"owner_unknown": 1}

    def test_incomplete_edge_and_hostile_sink_text(
        self, run, monkeypatch,
    ):
        out_dir, target = run
        bridge = _Bridge(edges=[
            _Edge("do_copy", "str\x1b[31mcpy",
                  binary_path=str(target / "bin" / "acmed")),
            _Edge("", "strcpy"),
        ])
        monkeypatch.setattr(
            router, "_load_bridge", lambda o, t: bridge,
        )
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        report = route_hypotheses(out_dir, ledger=doc)
        stats = report["producers"]["context_map_sinks"]
        assert stats["misses"] == {"edge_incomplete": 1}
        (seed,) = _seed_doc(out_dir, ART_A)["seeds"]
        assert "\x1b" not in seed["claim"]
        assert "\\x1b" in seed["claim"]

    def test_invalid_tier_spelling_dropped_not_forwarded(
        self, run, monkeypatch,
    ):
        """A junk tier must not ride into the seed file — the intake
        fail-closes on unknown tiers and would skip the whole record."""
        out_dir, target = run
        bridge = _Bridge(edges=[
            _Edge("do_copy", "strcpy", tier="very_sure",
                  binary_path=str(target / "bin" / "acmed")),
        ])
        monkeypatch.setattr(
            router, "_load_bridge", lambda o, t: bridge,
        )
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        route_hypotheses(out_dir, ledger=doc)
        (seed,) = _seed_doc(out_dir, ART_A)["seeds"]
        assert "evidence_tier" not in seed
        seeds, skips, _ = load_seed_files([
            out_dir / ROUTING_DIR_NAME / f"{ART_A}.hypotheses.json",
        ])
        assert len(seeds) == 1 and skips == {}


class TestAbiRouting:
    def _stub_elf(self, monkeypatch, exports: list[str],
                  imports: set[str]) -> None:
        import core.binary.elf as elf_mod

        class _Facts:
            pass

        facts = _Facts()
        facts.exports = exports

        class _Meta:
            pass

        meta = _Meta()
        meta.imports = imports
        monkeypatch.setattr(
            elf_mod, "extract_elf_facts", lambda p: facts,
        )
        monkeypatch.setattr(elf_mod, "parse_elf", lambda p: meta)

    def _linked_ledger(self, target: Path) -> dict:
        (target / "lib").mkdir(exist_ok=True)
        (target / "lib" / "libparse.so").write_bytes(b"p" * 8)
        (target / "bin" / "acmed").write_bytes(b"c" * 8)
        provider = _row(
            ANCHOR_B, SHA_B, "lib/libparse.so", **{
                "class": "elf-shared",
                "links": {"needed": [], "soname": "libparse.so"},
            },
        )
        consumer = _row(ANCHOR_A, SHA_A, "bin/acmed", **{
            "links": {"needed": ["libparse.so"], "soname": ""},
        })
        return _ledger(target, [provider, consumer], [
            {"name": "libparse.so", "providers": [ART_B],
             "consumers": [ART_A]},
        ])

    def test_symbol_overlap_seeds_the_provider(self, run, monkeypatch):
        out_dir, target = run
        self._stub_elf(
            monkeypatch,
            exports=["lp_decode", "lp_version"],
            imports={"lp_decode", "printf"},
        )
        doc = self._linked_ledger(target)
        report = route_hypotheses(out_dir, ledger=doc)
        stats = report["producers"]["abi_facts"]
        assert stats["candidates"] == 1
        (seed,) = _seed_doc(out_dir, ART_B)["seeds"]
        assert seed["function"] == "lp_decode"
        assert seed["evidence_tier"] == "header_backed"
        assert seed["module_sha256"] == SHA_B
        assert "1 in-target consumer(s)" in seed["claim"]

    def test_no_overlap_is_a_counted_miss(self, run, monkeypatch):
        out_dir, target = run
        self._stub_elf(
            monkeypatch, exports=["lp_other"], imports={"printf"},
        )
        report = route_hypotheses(
            out_dir, ledger=self._linked_ledger(target),
        )
        stats = report["producers"]["abi_facts"]
        assert stats["candidates"] == 0
        assert stats["misses"] == {"no_symbol_overlap": 1}

    def test_traversal_path_in_ledger_refused(self, run, monkeypatch):
        """A tampered ledger row path must not read outside the
        target root."""
        out_dir, target = run
        called: list[Path] = []
        import core.binary.elf as elf_mod
        monkeypatch.setattr(
            elf_mod, "extract_elf_facts",
            lambda p: called.append(p),
        )
        doc = self._linked_ledger(target)
        doc["rows"][0]["path"] = "../../../etc/passwd"
        report = route_hypotheses(out_dir, ledger=doc)
        stats = report["producers"]["abi_facts"]
        assert stats["misses"] == {"provider_unreadable": 1}
        assert called == []

    def test_archive_member_rows_never_probed(self, run, monkeypatch):
        out_dir, target = run
        called: list[Path] = []
        import core.binary.elf as elf_mod
        monkeypatch.setattr(
            elf_mod, "extract_elf_facts",
            lambda p: called.append(p),
        )
        doc = self._linked_ledger(target)
        doc["rows"][0]["provenance"] = {"origin": "archive_member"}
        report = route_hypotheses(out_dir, ledger=doc)
        assert report["producers"]["abi_facts"]["misses"] == {
            "provider_unreadable": 1,
        }
        assert called == []


class TestCorpusRouting:
    def _corpus_ledger(self, target: Path, readers: int = 1) -> dict:
        rows = [
            {
                "artifact_id": "corpus-family-" + "cd" * 8,
                "class": "corpus-family",
                "path": "share/samples",
                "family": {
                    "key": "CAFE|bin|template", "member_count": 12,
                    "examples_escaped": ["sample1.bin"],
                },
            },
        ]
        anchors = [ANCHOR_A, ANCHOR_B]
        shas = [SHA_A, SHA_B]
        for i in range(readers):
            rows.append(_row(anchors[i], shas[i], f"bin/reader{i}", **{
                "exposure": [{
                    "feature": "input_channels",
                    "value": ["file"], "extractor": "x",
                }],
            }))
        return _ledger(target, rows)

    def test_single_file_reader_gets_boundary_seeds(
        self, run, monkeypatch,
    ):
        out_dir, target = run
        bridge = _Bridge(boundaries=[
            _Boundary("parse_hdr", score=9.0),
            _Boundary("parse_body", score=7.0),
        ])
        monkeypatch.setattr(
            router, "_load_bridge", lambda o, t: bridge,
        )
        report = route_hypotheses(
            out_dir, ledger=self._corpus_ledger(target),
        )
        stats = report["producers"]["corpus_facts"]
        assert stats["candidates"] == 2
        seeds = _seed_doc(out_dir, ART_A)["seeds"]
        assert {s["function"] for s in seeds} == {
            "parse_hdr", "parse_body",
        }
        assert all("CAFE|bin|template" in s["claim"] for s in seeds)
        assert all(s["evidence_tier"] == "heuristic" for s in seeds)

    def test_two_file_readers_refuse_attribution(
        self, run, monkeypatch,
    ):
        out_dir, target = run
        bridge = _Bridge(boundaries=[_Boundary("parse_hdr")])
        monkeypatch.setattr(
            router, "_load_bridge", lambda o, t: bridge,
        )
        report = route_hypotheses(
            out_dir, ledger=self._corpus_ledger(target, readers=2),
        )
        stats = report["producers"]["corpus_facts"]
        assert stats["candidates"] == 0
        assert stats["misses"] == {"corpus_attribution_ambiguous": 1}
        assert any("attribution refused" in n for n in report["notes"])

    def test_no_boundaries_no_corpus_seeds(self, run, monkeypatch):
        out_dir, target = run
        monkeypatch.setattr(
            router, "_load_bridge", lambda o, t: _Bridge(),
        )
        report = route_hypotheses(
            out_dir, ledger=self._corpus_ledger(target),
        )
        assert report["producers"]["corpus_facts"]["candidates"] == 0


class TestAllocation:
    def _flood(self, monkeypatch, out_dir: Path, count: int) -> None:
        _plant_sibling(monkeypatch, out_dir, [
            {"file": "binary:acmed", "function": f"fn_{i}",
             "fid": f"{ANCHOR_A}:0x{0x1000 + i * 64:x}",
             "module_sha256": SHA_A, "claim": f"claim {i}"}
            for i in range(count)
        ])

    def test_over_cap_escalates_to_the_governor(
        self, run, monkeypatch,
    ):
        out_dir, target = run
        # The intake loader caps one file at MAX_SEED_RECORDS; the
        # mechanical producers push the pool past it.
        self._flood(monkeypatch, out_dir, MAX_SEED_RECORDS)
        bridge = _Bridge(edges=[
            _Edge(f"caller_{i}", "strcpy",
                  binary_path=str(target / "bin" / "acmed"))
            for i in range(30)
        ])
        monkeypatch.setattr(
            router, "_load_bridge", lambda o, t: bridge,
        )
        calls: list[dict] = []
        import core.engagement.governor as gov
        monkeypatch.setattr(
            gov, "record_escalation",
            lambda out, *, kind, message: calls.append(
                {"kind": kind, "message": message},
            ) or True,
        )
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        report = route_hypotheses(out_dir, ledger=doc)
        entry = report["artifacts"][ART_A]
        assert entry["written"] == MAX_SEED_RECORDS
        assert entry["over_cap"] == 30
        assert report["escalations"] == 1
        (call,) = calls
        assert call["kind"] == "routing_saturated"
        assert ART_A in call["message"]
        seeds = _seed_doc(out_dir, ART_A)["seeds"]
        assert len(seeds) == MAX_SEED_RECORDS

    def test_floors_keep_every_class_represented_under_flood(
        self, run, monkeypatch,
    ):
        """S10: a sibling flood must not consume the sink class's
        floor — the strongest mechanical lead survives allocation."""
        out_dir, target = run
        self._flood(monkeypatch, out_dir, MAX_SEED_RECORDS)
        bridge = _Bridge(edges=[
            _Edge("dsci_si", "system",
                  binary_path=str(target / "bin" / "acmed")),
        ])
        monkeypatch.setattr(
            router, "_load_bridge", lambda o, t: bridge,
        )
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        report = route_hypotheses(out_dir, ledger=doc)
        by_class = report["artifacts"][ART_A]["by_class"]
        assert by_class["context_map_sinks"] == 1
        seeds = _seed_doc(out_dir, ART_A)["seeds"]
        assert any(s["function"] == "dsci_si" for s in seeds)

    def test_rank_orders_within_class(self, run, monkeypatch):
        out_dir, target = run
        bridge = _Bridge(edges=[
            _Edge("weak", "memcpy", tier="heuristic",
                  binary_path=str(target / "bin" / "acmed")),
            _Edge("strong", "system", tier="observed_runtime",
                  binary_path=str(target / "bin" / "acmed")),
        ])
        monkeypatch.setattr(
            router, "_load_bridge", lambda o, t: bridge,
        )
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        route_hypotheses(out_dir, ledger=doc)
        seeds = _seed_doc(out_dir, ART_A)["seeds"]
        assert seeds[0]["function"] == "strong"

    def test_per_function_cap_counted(self, run, monkeypatch):
        from core.audit.hypothesis_intake import MAX_SEEDS_PER_FUNCTION
        out_dir, target = run
        bridge = _Bridge(edges=[
            _Edge("hot_fn", f"sink_{i}",
                  binary_path=str(target / "bin" / "acmed"))
            for i in range(MAX_SEEDS_PER_FUNCTION + 3)
        ])
        monkeypatch.setattr(
            router, "_load_bridge", lambda o, t: bridge,
        )
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        report = route_hypotheses(out_dir, ledger=doc)
        entry = report["artifacts"][ART_A]
        assert entry["function_capped"] == 3
        assert entry["written"] == MAX_SEEDS_PER_FUNCTION

    def test_intra_file_junk_flood_cannot_evict_ranked_signal(
        self, run, monkeypatch,
    ):
        """One sibling file: 300 rank-0 junk records ABOVE 5
        xref_backed signal seeds. Loading at the intake's own
        first-come cap would truncate the file before the allocator
        ever saw the signal (0/5 survive, over_cap 0, nothing
        escalated); the router's raised per-file loader bound must
        rank the WHOLE file, so every signal seed survives and the
        junk residue escalates as quota saturation."""
        out_dir, target = run
        junk = [
            {"file": "binary:acmed", "function": f"junk_{i}",
             "fid": f"{ANCHOR_A}:0x{0x9000 + i * 64:x}",
             "module_sha256": SHA_A, "claim": f"junk {i}"}
            for i in range(300)
        ]
        signal = [
            {"file": "binary:acmed", "function": f"signal_{i}",
             "fid": f"{ANCHOR_A}:0x{0x1000 + i * 64:x}",
             "module_sha256": SHA_A, "claim": f"signal {i}",
             "evidence_tier": "xref_backed"}
            for i in range(5)
        ]
        _plant_sibling(monkeypatch, out_dir, junk + signal)
        calls: list[str] = []
        import core.engagement.governor as gov
        monkeypatch.setattr(
            gov, "record_escalation",
            lambda out, *, kind, message: calls.append(message)
            or True,
        )
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        report = route_hypotheses(out_dir, ledger=doc)
        seeds = _seed_doc(out_dir, ART_A)["seeds"]
        assert len(seeds) == MAX_SEED_RECORDS
        assert [s["function"] for s in seeds[:5]] == [
            f"signal_{i}" for i in range(5)
        ]
        entry = report["artifacts"][ART_A]
        assert entry["over_cap"] == 105
        assert report["escalations"] == 1
        stats = report["producers"]["sibling_hypotheses"]
        assert stats["candidates"] == 305
        assert "loader_over_cap" not in stats["misses"]
        (message,) = calls
        assert ART_A in message

    def test_loader_ceiling_saturation_counted_and_escalated(
        self, run, monkeypatch,
    ):
        """A sibling file bigger than the per-file validation ceiling
        cannot be ranked in full — the truncated residue surfaces as
        a loader_over_cap miss, a report note, and its own
        routing_saturated escalation, never a silent drop."""
        out_dir, target = run
        ceiling = router._LOADER_RECORDS_PER_FILE
        _plant_sibling(monkeypatch, out_dir, [
            {"file": "binary:acmed", "function": f"fn_{i}",
             "fid": f"{ANCHOR_A}:0x{0x1000 + i * 64:x}",
             "module_sha256": SHA_A, "claim": f"claim {i}"}
            for i in range(ceiling + 3)
        ])
        calls: list[dict] = []
        import core.engagement.governor as gov
        monkeypatch.setattr(
            gov, "record_escalation",
            lambda out, *, kind, message: calls.append(
                {"kind": kind, "message": message},
            ) or True,
        )
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        report = route_hypotheses(out_dir, ledger=doc)
        stats = report["producers"]["sibling_hypotheses"]
        assert stats["misses"]["loader_over_cap"] == 3
        # quota saturation (ceiling - cap beyond quota) AND loader
        # saturation each escalate
        assert report["escalations"] == 2
        assert {c["kind"] for c in calls} == {"routing_saturated"}
        assert any("loader" in c["message"] for c in calls)
        assert any(
            "loader saturated" in note for note in report["notes"]
        )

    def test_flood_fills_cap_exactly_when_floors_do_not_sum(self):
        """Floor rounding never overshoots: at caps where the int()
        floors do not sum to the cap (cap=7 gives 3/1/1/0), the
        allocator must fill EXACTLY to cap via rank-ordered
        redistribution — oversubscribed floors (the int(cap*share)+1
        shape) would write past what the intake accepts."""
        from core.engagement.router import _Candidate, _allocate
        for cap in (1, 3, 7, 10, 13, MAX_SEED_RECORDS):
            cands = [
                _Candidate(
                    artifact_id=ART_A, producer=cls, rank=0.0,
                    seed={"file": "binary:t", "claim": f"{cls} {i}"},
                    join="identity",
                )
                for cls in PRODUCER_CLASSES for i in range(cap * 2)
            ]
            written, over_cap, fn_capped, _by = _allocate(cands, cap)
            assert len(written) == cap, f"cap={cap}"
            assert len(written) + over_cap + fn_capped == len(cands)

    def test_empty_class_slack_redistributes_in_rank_order(self):
        """One class empty under flood: its unused floor must flow to
        the STRONGEST class first (sibling), not be handed out in
        reversed order to the weakest producers."""
        from core.engagement.router import _Candidate, _allocate
        cands = [
            _Candidate(
                artifact_id=ART_A, producer=cls, rank=0.0,
                seed={"file": "binary:t", "claim": f"{cls} {i}"},
                join="identity",
            )
            for cls in (
                "sibling_hypotheses", "abi_facts", "corpus_facts",
            )
            for i in range(500)
        ]
        written, _over, _fc, by_class = _allocate(cands, 200)
        assert len(written) == 200
        assert by_class == {
            "sibling_hypotheses": 150,
            "abi_facts": 30,
            "corpus_facts": 20,
        }

    def test_unknown_producer_class_refuses_loudly(self):
        """A candidate from an unregistered producer class must
        refuse, not vanish from every allocation counter — the q4
        flip's fifth class extends PRODUCER_CLASSES consciously."""
        from core.engagement.router import _Candidate, _allocate
        ghost = _Candidate(
            artifact_id=ART_A, producer="carved_anomalies", rank=5.0,
            seed={"file": "binary:t", "claim": "x"}, join="identity",
        )
        with pytest.raises(ValueError, match="producer class"):
            _allocate([ghost], 10)


class TestReportShape:
    def test_report_written_and_returned_identically(
        self, run, monkeypatch,
    ):
        out_dir, target = run
        _plant_sibling(monkeypatch, out_dir, [{
            "file": "binary:acmed", "function": "f", "claim": "c",
        }])
        doc = _ledger(target, [_row(ANCHOR_A, SHA_A, "bin/acmed")])
        report = route_hypotheses(out_dir, ledger=doc)
        on_disk = json.loads((
            out_dir / ROUTING_DIR_NAME / ROUTING_REPORT_FILENAME
        ).read_text())
        assert on_disk == report
        assert on_disk["schema_version"] == 1
        assert set(on_disk["producers"]) == set(PRODUCER_CLASSES)
        assert on_disk["artifacts"][ART_A]["seed_file"] == (
            f"{ROUTING_DIR_NAME}/{ART_A}.hypotheses.json"
        )

    def test_hostile_artifact_id_never_becomes_a_path(
        self, run, monkeypatch,
    ):
        """A tampered ledger row with a traversal-shaped artifact_id
        is dropped at table build — no file write outside routing/."""
        out_dir, target = run
        _plant_sibling(monkeypatch, out_dir, [{
            "file": "binary:acmed", "function": "f", "claim": "c",
        }])
        row = _row(ANCHOR_A, SHA_A, "bin/acmed")
        row["artifact_id"] = "../escape"
        report = route_hypotheses(out_dir, ledger=_ledger(target, [row]))
        assert report["artifacts"] == {}
        assert not (out_dir.parent / "escape.hypotheses.json").exists()
        misses = report["producers"]["sibling_hypotheses"]["misses"]
        assert misses == {"owner_unknown": 1}

    def test_anchor_collision_refuses_identity_joins(
        self, run, monkeypatch,
    ):
        """Two rows claiming one anchor is the copied-identity shape;
        the anchor joins neither."""
        out_dir, target = run
        _plant_sibling(monkeypatch, out_dir, [{
            "file": "binary:zzz", "function": "f",
            "fid": f"{ANCHOR_A}:0x10", "claim": "c",
        }])
        doc = _ledger(target, [
            _row(ANCHOR_A, SHA_A, "bin/acmed"),
            _row(ANCHOR_A, SHA_B, "bin/imposter"),
        ])
        report = route_hypotheses(out_dir, ledger=doc)
        misses = report["producers"]["sibling_hypotheses"]["misses"]
        assert misses == {"owner_unknown": 1}
