"""Hypothesis-seed intake: loader validation battery + flag plumbing.

The loader treats every field of sibling-hypotheses.json as
untrusted: hostile text is escaped at load, junk records are skipped
with counted reasons, the record cap is enforced, fids ride the
strict addrmap parser (junk collapses to absent). A hostile or
truncated file must never crash the audit — it degrades to counted
skips.
"""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

from core.audit.hypothesis_intake import (
    MAX_SEED_FILE_BYTES,
    MAX_SEED_RECORDS,
    SEEDS_FILENAME,
    discover_seed_paths,
    load_seed_files,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"

_VALID_FID = "a" * 16 + ":0x1da0"


def _seed(**over):
    base = {
        "file": "binary:acmed",
        "function": "parse_channel",
        "address": 0x161DA0,
        "fid": _VALID_FID,
        "claim": "length field used before bounds check",
        "disproof": "show the dominating compare against hdr->len",
        "evidence_tier": "xref_backed",
        "evidence": [
            {"artifact": "binary-hunt-channel.json", "pointer": "families[0]"},
        ],
        "derived_from_target": {"claim": True, "disproof": True},
    }
    base.update(over)
    return base


def _write_seeds(path: Path, records) -> Path:
    path.write_text(json.dumps({"seeds": records}))
    return path


class TestLoader:
    def test_valid_record_loads_all_fields(self, tmp_path):
        import hashlib
        f = _write_seeds(tmp_path / "s.json", [_seed()])
        seeds, skips, sources = load_seed_files([f])
        assert skips == {}
        # Content-bound source receipt: id carries the path-derived
        # disambiguator, path is the resolved file, sha256 is the
        # consumed bytes.
        h8 = hashlib.sha256(
            str(f.resolve()).encode(),
        ).hexdigest()[:8]
        (src,) = sources
        assert src["id"] == f"s.json@{h8}"
        assert src["path"] == str(f.resolve())
        assert src["sha256"] == hashlib.sha256(f.read_bytes()).hexdigest()
        (seed,) = seeds
        assert seed.seed_id == f"s.json@{h8}#0"
        assert seed.source == f"s.json@{h8}"
        assert seed.file == "binary:acmed"
        assert seed.function == "parse_channel"
        assert seed.address == 0x161DA0
        assert seed.fid == _VALID_FID
        assert seed.claim.startswith("length field")
        assert seed.evidence_tier == "xref_backed"
        assert seed.evidence == [{
            "artifact": "binary-hunt-channel.json",
            "pointer": "families[0]",
        }]
        assert seed.derived_from_target == {"claim": True, "disproof": True}

    def test_hostile_text_escaped_at_load(self, tmp_path):
        hostile = "evil\x1b]0;pwned\x07claim‮txet"
        f = _write_seeds(tmp_path / "s.json", [
            _seed(claim=hostile, disproof="run\x1b[2Jthis",
                  function="fn\x00name",
                  evidence=[{"artifact": "a\x9bb", "pointer": "p\rq"}]),
        ])
        (seed,), _, _ = load_seed_files([f])
        for text in (seed.claim, seed.disproof, seed.function,
                     seed.evidence[0]["artifact"],
                     seed.evidence[0]["pointer"]):
            assert all(c.isprintable() for c in text), text
        assert "\\x1b" in seed.claim
        assert "\\u202e" in seed.claim
        assert "\\x00" in seed.function

    def test_junk_records_skipped_with_counted_reasons(self, tmp_path):
        f = _write_seeds(tmp_path / "s.json", [
            "not-a-dict",
            {"claim": "no file"},
            {"file": "x.c"},
            _seed(evidence_tier="PROVEN_BY_VIBES"),
            _seed(evidence_tier="XREF_BACKED"),  # spelling is the value
            _seed(),
        ])
        seeds, skips, _ = load_seed_files([f])
        assert len(seeds) == 1
        assert skips == {
            "not_a_dict": 1,
            "missing_file": 1,
            "missing_claim": 1,
            "bad_tier": 2,
        }

    def test_record_cap_enforced_and_counted(self, tmp_path):
        f = _write_seeds(
            tmp_path / "s.json",
            [_seed(claim=f"claim {i}") for i in range(MAX_SEED_RECORDS + 7)],
        )
        seeds, skips, _ = load_seed_files([f])
        assert len(seeds) == MAX_SEED_RECORDS
        assert skips["over_cap"] == 7

    def test_cap_spans_multiple_sources(self, tmp_path):
        f1 = _write_seeds(
            tmp_path / "a.json",
            [_seed(claim=f"a {i}") for i in range(MAX_SEED_RECORDS)],
        )
        f2 = _write_seeds(tmp_path / "b.json", [_seed(claim="late")])
        seeds, skips, sources = load_seed_files([f1, f2])
        assert len(seeds) == MAX_SEED_RECORDS
        assert skips["over_cap"] == 1
        assert [s["id"].split("@")[0] for s in sources] == [
            "a.json", "b.json",
        ]

    def test_field_length_caps(self, tmp_path):
        f = _write_seeds(tmp_path / "s.json", [
            _seed(claim="c" * 5000, disproof="d" * 5000,
                  function="f" * 5000, file="binary:" + "x" * 5000),
        ])
        (seed,), _, _ = load_seed_files([f])
        assert len(seed.claim) == 300
        assert len(seed.disproof) == 300
        assert len(seed.function) == 256
        assert len(seed.file) == 512

    def test_fid_normalised_strictly_junk_collapses(self, tmp_path):
        f = _write_seeds(tmp_path / "s.json", [
            _seed(fid=_VALID_FID),
            _seed(fid="fcn.00161da0"),          # r2 label, not a fid
            _seed(fid="zz:0x10"),               # non-hex anchor
            _seed(fid={"anchor": "a" * 16}),    # wrong type
        ])
        seeds, skips, _ = load_seed_files([f])
        assert [s.fid for s in seeds] == [_VALID_FID, None, None, None]
        # The collapse is COUNTED (producer minting garbage fids is
        # visible) but the record survives on its other join keys.
        assert skips["fid_collapsed"] == 3
        assert len(seeds) == 4

    def test_address_parsing(self, tmp_path):
        f = _write_seeds(tmp_path / "s.json", [
            _seed(address=0x10), _seed(address="0x1f"),
            _seed(address="31"), _seed(address="junk"),
            _seed(address=True), _seed(address=-4), _seed(address=None),
        ])
        seeds, _, _ = load_seed_files([f])
        assert [s.address for s in seeds] == [
            0x10, 0x1F, 31, None, None, None, None,
        ]

    def test_evidence_refs_capped_and_junk_tolerated(self, tmp_path):
        refs = [{"artifact": f"a{i}", "pointer": f"p{i}"} for i in range(9)]
        refs.insert(0, "junk-ref")
        f = _write_seeds(tmp_path / "s.json", [_seed(evidence=refs)])
        (seed,), skips, _ = load_seed_files([f])
        assert skips == {}
        assert len(seed.evidence) == 3  # 4-ref window minus the junk one

    def test_unreadable_and_oversized_files_counted_never_raise(
        self, tmp_path,
    ):
        missing = tmp_path / "missing.json"
        garbage = tmp_path / "garbage.json"
        garbage.write_text("{not json")
        big = tmp_path / "big.json"
        with big.open("w") as fh:
            fh.write('{"seeds": [')
            fh.write(" " * (MAX_SEED_FILE_BYTES + 1))
            fh.write("]}")
        seeds, skips, sources = load_seed_files([missing, garbage, big])
        assert seeds == []
        assert sources == []
        assert skips["unreadable_file"] == 3

    def test_wrong_top_level_shape_counted(self, tmp_path):
        bare_list = tmp_path / "list.json"
        bare_list.write_text(json.dumps([_seed()]))
        no_seeds = tmp_path / "noseeds.json"
        no_seeds.write_text(json.dumps({"records": [_seed()]}))
        seeds, skips, _ = load_seed_files([bare_list, no_seeds])
        assert seeds == []
        assert skips["bad_shape"] == 2

    def test_duplicate_paths_deduplicated(self, tmp_path):
        f = _write_seeds(tmp_path / "s.json", [_seed()])
        seeds, _, sources = load_seed_files([f, f, tmp_path / "s.json"])
        assert len(seeds) == 1
        assert len(sources) == 1

    def test_same_basename_sources_get_distinct_seed_ids(self, tmp_path):
        """Path-derived id component: two files both named
        sibling-hypotheses.json must not mint colliding seed ids."""
        d1 = tmp_path / "a"
        d2 = tmp_path / "b"
        d1.mkdir()
        d2.mkdir()
        f1 = _write_seeds(d1 / SEEDS_FILENAME, [_seed()])
        f2 = _write_seeds(d2 / SEEDS_FILENAME, [_seed()])
        seeds, _, sources = load_seed_files([f1, f2])
        assert len(seeds) == 2
        assert seeds[0].seed_id != seeds[1].seed_id
        assert sources[0]["id"] != sources[1]["id"]


class TestDiscovery:
    def test_co_located_file_discovered(self, tmp_path):
        co = _write_seeds(tmp_path / SEEDS_FILENAME, [_seed()])
        assert discover_seed_paths(tmp_path) == [co]

    def test_explicit_paths_appended_even_when_missing(self, tmp_path):
        co = _write_seeds(tmp_path / SEEDS_FILENAME, [_seed()])
        explicit = tmp_path / "extra.json"
        missing = tmp_path / "typo.json"
        _write_seeds(explicit, [_seed()])
        paths = discover_seed_paths(tmp_path, [explicit, missing])
        # The missing explicit path stays in the list: the loader
        # counts it as unreadable so a typo'd flag surfaces in the
        # intake receipt instead of vanishing.
        assert paths == [co, explicit, missing]

    def test_nothing_to_discover(self, tmp_path):
        assert discover_seed_paths(tmp_path) == []


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_hyp_seeds", str(_SCRIPT))
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_hyp_seeds", loader,
    )
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _run_args(**over):
    base = dict(
        scope=None, scope_floor=True, pin=None, strategy=None,
        budget=None, model=None, max_cost=None, max_time=None,
        review_passes=1, batch_sloc_threshold=None,
        include_kinds=None, adversarial=False, rank_gaps=False,
        edges=False, max_propagation_depth=None, subsystem_depth=0,
        no_validate=False, no_binary_oracle=False,
        annotations_dir=None, codeql_db=None, dynamic=False,
        no_dynamic=False, no_verdict_reuse=False, pre_scan=False,
        no_caller_contract_context=False,
        no_caller_contract_demotion=False, schedule="cost",
        no_on_demand_synthesis=False, no_vendored_triage=False,
        probe_determine_value=False, no_environment_breaker=False,
        deepen_reserve=None, prior_journal=None, prior_claims=3,
        max_workers=0,
    )
    base.update(over)
    return SimpleNamespace(**base)


class TestFlagPlumbing:
    def test_run_config_persists_seed_paths(self, tmp_path):
        mod = _load_cli()
        args = _run_args(hypothesis_seeds=["/a/s.json", "/b/s.json"])
        cfg = mod._run_config_from_args(args, tmp_path)
        assert cfg["hypothesis_seeds"] == ["/a/s.json", "/b/s.json"]

    def test_run_config_tolerates_absent_attr(self, tmp_path):
        mod = _load_cli()
        cfg = mod._run_config_from_args(_run_args(), tmp_path)
        assert cfg["hypothesis_seeds"] is None

    def test_opts_field_reaches_orchestrator_config(self, tmp_path):
        from core.audit.pipeline import (
            AuditPipelineOpts,
            _build_orchestrator_config,
        )
        opts = AuditPipelineOpts(
            target_path=tmp_path, out_dir=tmp_path,
            hypothesis_seed_paths=[Path("/a/s.json")],
        )
        config = _build_orchestrator_config(opts, object(), ["m"], opts.mode)
        assert config.hypothesis_seed_paths == [Path("/a/s.json")]

    def test_resume_rebuilds_seed_paths_from_persisted_config(self):
        # The resume passthrough is the persisted-config key: assert
        # the exact spelling both sides use, so a rename on either
        # side breaks here instead of silently dropping seeds on
        # segment 2+.
        mod = _load_cli()
        args = _run_args(hypothesis_seeds=["/a/s.json"])
        cfg = mod._run_config_from_args(args, Path("/tmp/x"))
        assert cfg.get("hypothesis_seeds") == ["/a/s.json"]
        import inspect
        src = inspect.getsource(mod.cmd_resume)
        assert 'run_cfg["hypothesis_seeds"]' in src
        assert "hypothesis_seed_paths=" in src
