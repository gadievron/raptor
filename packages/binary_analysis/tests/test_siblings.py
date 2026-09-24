"""/binary siblings — formation + vectors + the real engine, e2e.

Fixtures are persisted-artifact shaped (manifest, context map, hunt
family artifact, decompilations); the call substrate is injected so
no radare2 runs. The batteries pin: the outlier surfacing through
the REAL sibling_analysis pass, the uniform-weakness cluster that
must surface NOTHING plus the unexamined-not-safe line, the honesty
lines in artifact and report, hypothesis emission in the audit
intake's schema (round-tripped through the intake's own loader when
present), checklist-space seed identity via a co-located
re-database, refusal modes, and escaped operator surfaces.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.evidence import EvidenceTier
from core.json import load_json, save_json
from packages.binary_analysis.hunt import CallGraph, HuntError
from packages.binary_analysis.siblings import (
    ALTERNATIVE_EXPLANATIONS,
    ASYMMETRY_ONLY_NOTE,
    CLUSTERING_RECALL_NOTE,
    CLUSTERS_FILENAME,
    HYPOTHESES_FILENAME,
    REPORT_FILENAME,
    run_siblings,
)

_ANCHOR = "ab" * 8
SHA = "cd" * 32
_MEMBERS = ["parse_a", "parse_b", "parse_c", "parse_d"]

_BODY_CHECKED = (
    "int {name}(char *p, uint n) {{ "
    "if (p == (char *)0x0) return -1; "
    "if (n < 0x100) {{ memcpy(dst, p, n); }} return 0; }}"
)
_BODY_UNCHECKED = (
    "int {name}(char *p, uint n) {{ memcpy(dst, p, n); return 0; }}"
)


def _fid(rel: int) -> str:
    return f"{_ANCHOR}:{rel:#x}"


def _write_run_dir(
    tmp: Path,
    *,
    weak: tuple[str, ...] = ("parse_d",),
    hunt_family: bool = True,
) -> Path:
    run_dir = tmp / "run"
    run_dir.mkdir(exist_ok=True)
    save_json(run_dir / "binary-manifest.json", {
        "schema_version": 1,
        "binary_path": str(tmp / "acmed"),
        "binary_sha256": SHA,
        "size_bytes": 128,
        "executable": True,
        "target_kind": "binary",
        "arch": "x86",
        "bits": 64,
        "binary_format": "elf",
        "build_id": _ANCHOR,
        "image_base": 0x400000,
    })
    functions = [
        {
            "id": f"BFN-{0x401000 + i * 0x100:x}",
            "name": name,
            "address": hex(0x401000 + i * 0x100),
            "size": 64,
            "fid": _fid(0x1000 + i * 0x100),
            "is_exported": True,
        }
        for i, name in enumerate(_MEMBERS)
    ]
    functions.append({
        "id": "BFN-402000", "name": "check_len",
        "address": "0x402000", "size": 32, "fid": _fid(0x2000),
    })
    save_json(run_dir / "binary-context-map.json", {
        "interesting_functions": functions,
    })
    if hunt_family:
        save_json(run_dir / "binary-hunt-anchor-frame.json", {
            "schema_version": 1,
            "mode": "anchor",
            "families": [{
                "id": "BHUNTFAM-feed01",
                "members": [
                    {"name": name, "fid": _fid(0x1000 + i * 0x100),
                     "address": hex(0x401000 + i * 0x100)}
                    for i, name in enumerate(_MEMBERS)
                ],
                "sample_strings": ["frame %d truncated"],
            }],
        })
    save_json(run_dir / "binary-decompilations.json", {
        "coverage": {},
        "functions": [
            {
                "name": name,
                "address": hex(0x401000 + i * 0x100),
                "body": (
                    _BODY_UNCHECKED if name in weak else _BODY_CHECKED
                ).format(name=name),
            }
            for i, name in enumerate(_MEMBERS)
        ],
    })
    return run_dir


def _graph(weak: tuple[str, ...] = ("parse_d",)) -> CallGraph:
    callees = {
        name: ({"emit"} if name in weak else {"check_len", "emit"})
        for name in _MEMBERS
    }
    # Give check_len enough callers to be distinctive but under the
    # hub ceiling; emit gets hub-many callers.
    for i in range(20):
        callees[f"noise_{i:02d}"] = {"emit"}
    callees["extra_caller"] = {"check_len"}
    meta = {
        name: {"address": 0x401000 + i * 0x100,
               "fid": _fid(0x1000 + i * 0x100), "size": 64}
        for i, name in enumerate(_MEMBERS)
    }
    meta["check_len"] = {
        "address": 0x402000, "fid": _fid(0x2000), "size": 32,
    }
    return CallGraph(substrate="test substrate", callees=callees, meta=meta)


def _loader(graph: CallGraph):
    def load(_run_dir, _manifest):
        return graph
    return load


class TestOutlierEndToEnd:
    def test_missing_check_member_flagged_with_recipes(self, tmp_path):
        run_dir = _write_run_dir(tmp_path)
        payload = run_siblings(run_dir, graph_loader=_loader(_graph()))
        rows = payload["asymmetries"]
        assert rows, "expected asymmetries"
        by_prop = {r["property"]: r for r in rows
                   if r["kind"] == "binary_anchor_family"}
        calls_row = next(
            r for k, r in by_prop.items() if k.startswith("calls:")
        )
        assert calls_row["outliers"] == ["parse_d"]
        assert calls_row["evidence_tier"] == "xref_backed"
        assert "Disproof:" in calls_row["disproof"]
        assert calls_row["alternative_explanations"] == (
            ALTERNATIVE_EXPLANATIONS
        )
        cap_row = by_prop["length_cap_present"]
        assert cap_row["outliers"] == ["parse_d"]
        assert cap_row["evidence_tier"] == "decompiler_inferred"
        # Matrix carries the member×check grid.
        (cluster,) = payload["clusters"]
        member_names = [
            m["function"] for m in cluster["matrix"]["members"]
        ]
        assert member_names == _MEMBERS
        # Artifacts on disk.
        assert (run_dir / CLUSTERS_FILENAME).is_file()
        assert (run_dir / HYPOTHESES_FILENAME).is_file()
        assert (run_dir / REPORT_FILENAME).is_file()

    def test_uniform_weakness_flags_nothing_and_says_unexamined(
        self, tmp_path,
    ):
        run_dir = _write_run_dir(tmp_path, weak=tuple(_MEMBERS))
        payload = run_siblings(
            run_dir, graph_loader=_loader(_graph(weak=tuple(_MEMBERS))),
        )
        assert payload["asymmetries"] == []
        (cluster,) = payload["clusters"]
        assert cluster["consistent_note"] == ASYMMETRY_ONLY_NOTE
        report = (run_dir / REPORT_FILENAME).read_text()
        assert "No asymmetry." in report
        assert "unexamined, not safe" in report

    def test_honesty_lines_in_artifact_and_report(self, tmp_path):
        run_dir = _write_run_dir(tmp_path)
        payload = run_siblings(run_dir, graph_loader=_loader(_graph()))
        assert ASYMMETRY_ONLY_NOTE in payload["honesty"]
        assert CLUSTERING_RECALL_NOTE in payload["honesty"]
        assert any("syntactic" in h for h in payload["honesty"])
        report = (run_dir / REPORT_FILENAME).read_text()
        assert "unexamined, not safe" in report
        assert "syntactic" in report
        assert "Alternative explanations" in report

    def test_export_contract_rows_ride_the_same_surfaces(self, tmp_path):
        run_dir = _write_run_dir(tmp_path)
        payload = run_siblings(run_dir, graph_loader=_loader(_graph()))
        contract = [
            r for r in payload["asymmetries"]
            if r["kind"] == "export_contract"
        ]
        assert contract, "exported parse_* family should form"
        assert {r["property"] for r in contract} <= {
            "length_cap_present", "null_check_present",
        }
        assert payload["export_contract_asymmetries"] == len(contract)
        # Emission order: contract rows lead (the scarcer, less
        # attacker-shapeable signal survives the seed cap first).
        kinds = [r["kind"] for r in payload["asymmetries"]]
        assert kinds[:len(contract)] == ["export_contract"] * len(contract)

    def test_seed_cap_is_noted_and_contract_rows_survive(
        self, tmp_path, monkeypatch,
    ):
        import packages.binary_analysis.siblings as siblings_mod
        monkeypatch.setattr(siblings_mod, "MAX_HYPOTHESES", 1)
        run_dir = _write_run_dir(tmp_path)
        payload = run_siblings(run_dir, graph_loader=_loader(_graph()))
        assert payload["hypothesis_seeds_emitted"] == 1
        assert any("hypothesis seeds capped" in n
                   for n in payload["notes"])
        # The surviving seed is an export-contract row (emitted first).
        doc = load_json(run_dir / HYPOTHESES_FILENAME)
        (seed,) = doc["seeds"]
        assert "export_contract" in seed["claim"]

    def test_formation_degradation_reaches_payload_and_report(
        self, tmp_path, monkeypatch,
    ):
        """The decomp-similarity pairwise budget degrading to
        hash-only groups must surface on operator surfaces, not just
        in debug logs."""
        import core.analysis.peer_groups as pg
        monkeypatch.setattr(pg, "MAX_DECOMP_PAIRWISE", 0)
        run_dir = _write_run_dir(tmp_path)
        payload = run_siblings(
            run_dir, auto=True, graph_loader=_loader(_graph()),
        )
        assert any("pairwise similarity skipped" in n
                   for n in payload["notes"])
        report = (run_dir / REPORT_FILENAME).read_text()
        assert "pairwise similarity skipped" in report

    def test_shift_dense_export_member_gets_no_length_cap(
        self, tmp_path,
    ):
        """C5 headline-signal honesty: a shift-dense exported member
        with no bound check must not read length_cap_present=True
        (shift operators are arithmetic, not compares)."""
        run_dir = _write_run_dir(tmp_path, weak=())
        # Rewrite parse_d's decompilation to shift-dense, compare-free.
        doc = load_json(run_dir / "binary-decompilations.json")
        for fn in doc["functions"]:
            if fn["name"] == "parse_d":
                fn["body"] = (
                    "int parse_d(uint x) { x <<= 2; "
                    "return (x << 4) | (x >> 3); }"
                )
        save_json(run_dir / "binary-decompilations.json", doc)
        payload = run_siblings(run_dir, graph_loader=_loader(_graph(weak=())))
        (cluster,) = payload["clusters"]
        by_fn = {
            m["function"]: m for m in cluster["matrix"]["members"]
        }
        assert by_fn["parse_d"].get("checks", {}).get(
            "length_cap_present") is False


class TestHypothesisEmission:
    def test_schema_shape_and_tier_spellings(self, tmp_path):
        run_dir = _write_run_dir(tmp_path)
        payload = run_siblings(run_dir, graph_loader=_loader(_graph()))
        doc = load_json(run_dir / HYPOTHESES_FILENAME)
        seeds = doc["seeds"]
        assert len(seeds) == payload["hypothesis_seeds_emitted"] > 0
        valid_tiers = {tier.value for tier in EvidenceTier}
        for seed in seeds:
            assert seed["file"] == "binary:acmed"
            assert seed["function"]
            assert seed["claim"].startswith("Sibling asymmetry")
            assert seed["evidence_tier"] in valid_tiers
            assert seed["disproof"].startswith("Disproof:")
            assert seed["evidence"][0]["artifact"] == CLUSTERS_FILENAME
            assert seed["derived_from_target"] == {
                "claim": True, "disproof": True,
            }
            assert isinstance(seed.get("address"), int)

    def test_round_trip_through_the_intake_loader(self, tmp_path):
        """Emit → load with the audit intake's OWN loader → zero
        skipped records. Runs on trees where the intake series is
        composed; hermetically skipped elsewhere (the schema-shape
        battery above always runs)."""
        intake = pytest.importorskip(
            "core.audit.hypothesis_intake",
            reason="audit hypothesis-seed intake not in this tree",
        )
        import packages.binary_analysis.siblings as siblings_mod
        # Cap parity: emitting more than the intake can load would
        # silently truncate at the consumer.
        assert siblings_mod.MAX_HYPOTHESES == intake.MAX_SEED_RECORDS
        run_dir = _write_run_dir(tmp_path)
        payload = run_siblings(run_dir, graph_loader=_loader(_graph()))
        seeds, skips, sources = intake.load_seed_files(
            [run_dir / HYPOTHESES_FILENAME],
        )
        assert skips == {}
        assert len(seeds) == payload["hypothesis_seeds_emitted"]
        # Source records: name-string or provenance-dict shape,
        # depending on the intake revision — pin only the identity.
        (source,) = sources
        assert HYPOTHESES_FILENAME in str(source)
        assert all(s.fid for s in seeds)

    def test_checklist_space_identity_via_re_database(self, tmp_path):
        """With a co-located re-database at a DIFFERENT image base,
        seed addresses land in the re-database's space (the space the
        audit checklist is built from) and carry its names."""
        run_dir = _write_run_dir(tmp_path)
        redb_base = 0x100000
        save_json(run_dir / "re-database.json", {
            "source_tool": "ghidra",
            "binary_path": str(tmp_path / "acmed"),
            "metadata": {"binary_sha256": SHA,
                         "image_base": redb_base},
            "functions": [
                {
                    "name": f"g_{name}",
                    "address": redb_base + 0x1000 + i * 0x100,
                    "size": 64,
                    "fid": _fid(0x1000 + i * 0x100),
                }
                for i, name in enumerate(_MEMBERS)
            ],
            "xrefs": [],
        })
        run_siblings(run_dir, graph_loader=_loader(_graph()))
        doc = load_json(run_dir / HYPOTHESES_FILENAME)
        outlier_seeds = [
            s for s in doc["seeds"] if s["fid"] == _fid(0x1300)
        ]
        assert outlier_seeds
        for seed in outlier_seeds:
            assert seed["function"] == "g_parse_d"
            assert seed["address"] == redb_base + 0x1300


class TestRefusals:
    def test_unknown_family_refused(self, tmp_path):
        run_dir = _write_run_dir(tmp_path)
        with pytest.raises(HuntError, match="not found"):
            run_siblings(
                run_dir, family="BHUNTFAM-doesnotexist",
                graph_loader=_loader(_graph()),
            )
        assert not (run_dir / CLUSTERS_FILENAME).exists()

    def test_no_families_without_auto_points_at_auto(self, tmp_path):
        run_dir = _write_run_dir(tmp_path, hunt_family=False)
        with pytest.raises(HuntError, match="--auto"):
            run_siblings(run_dir, graph_loader=_loader(_graph()))

    def test_auto_forms_groups_without_hunt_artifacts(self, tmp_path):
        run_dir = _write_run_dir(tmp_path, hunt_family=False)
        graph = _graph()
        # Two shared distinctive callees (K=2) across all members.
        for name in _MEMBERS:
            graph.callees[name] = {"check_len", "read_hdr"}
        graph.callees["extra_caller"] = {"check_len", "read_hdr"}
        payload = run_siblings(
            run_dir, auto=True, graph_loader=_loader(graph),
        )
        assert payload["clusters"]
        kinds = {c["kind"] for c in payload["clusters"]}
        assert "shared_callee_signature" in kinds


class TestEscapedSurfaces:
    def test_hostile_names_never_reach_artifacts_raw(self, tmp_path):
        hostile = "evil\x1b]0;pwn\x07_d"
        run_dir = _write_run_dir(tmp_path)
        # Rebuild the fixtures with a hostile member name — via the
        # JSON writer, as a real (unescaped-at-capture) producer
        # would persist it.
        for artifact in ("binary-context-map.json",
                         "binary-hunt-anchor-frame.json",
                         "binary-decompilations.json"):
            path = run_dir / artifact
            doc = json.loads(path.read_text())
            doc = json.loads(
                json.dumps(doc).replace(
                    "parse_d", json.dumps(hostile)[1:-1],
                ),
            )
            save_json(path, doc)
        graph = _graph(weak=(hostile,))
        graph.callees[hostile] = graph.callees.pop("parse_d")
        graph.meta[hostile] = graph.meta.pop("parse_d")
        run_siblings(run_dir, graph_loader=_loader(graph))
        for name in (CLUSTERS_FILENAME, HYPOTHESES_FILENAME,
                     REPORT_FILENAME):
            content = (run_dir / name).read_text()
            assert "\x1b" not in content, name
        assert "\\x1b" in (run_dir / CLUSTERS_FILENAME).read_text()


class TestCliSurface:
    def _patched(self, monkeypatch, graph):
        import packages.binary_analysis.siblings as siblings_mod
        monkeypatch.setattr(
            siblings_mod, "load_call_graph", _loader(graph),
        )

    def test_run_dir_mode_no_lifecycle_events(
        self, tmp_path, monkeypatch, capsys,
    ):
        """Parity with hunt's run-dir mode: operating inside an
        existing run starts no new lifecycle run."""
        from unittest.mock import patch

        from packages.binary_analysis.cli import main
        run_dir = _write_run_dir(tmp_path)
        self._patched(monkeypatch, _graph())
        with (
            patch("packages.binary_analysis.cli.start_run") as start,
            patch("packages.binary_analysis.cli.complete_run") as done,
            patch("packages.binary_analysis.cli.fail_run") as fail,
        ):
            rc = main(["siblings", str(run_dir)])
        assert rc == 0
        start.assert_not_called()
        done.assert_not_called()
        fail.assert_not_called()
        out = capsys.readouterr().out
        assert "Mode: siblings" in out
        assert "not findings" in out
        assert "unexamined, not safe" in out

    def test_json_mode_is_ascii_safe(self, tmp_path, monkeypatch, capsys):
        from packages.binary_analysis.cli import main
        run_dir = _write_run_dir(tmp_path)
        self._patched(monkeypatch, _graph())
        rc = main(["siblings", str(run_dir), "--json"])
        assert rc == 0
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert payload["mode"] == "siblings"
        assert out.isascii()

    def test_refusal_exit_code_and_scrubbed_message(
        self, tmp_path, monkeypatch, capsys,
    ):
        from packages.binary_analysis.cli import main
        run_dir = _write_run_dir(tmp_path)
        self._patched(monkeypatch, _graph())
        rc = main([
            "siblings", str(run_dir),
            "--family", "BHUNTFAM-\x1b]0;pwn\x07nope",
        ])
        assert rc == 2
        err = capsys.readouterr().err
        assert "siblings refused" in err
        assert "\x1b" not in err

    def test_missing_run_dir_refused(self, tmp_path, capsys):
        from packages.binary_analysis.cli import main
        rc = main(["siblings", str(tmp_path / "nope")])
        assert rc == 2
        assert "not a run directory" in capsys.readouterr().err
