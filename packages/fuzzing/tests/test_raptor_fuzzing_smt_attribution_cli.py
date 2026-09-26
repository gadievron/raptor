"""The /fuzz CLI's crash attribution trusts only its OWN synthesis.

The post-campaign attribution block in ``raptor_fuzzing.main()`` runs
on every crash-collecting legacy run, and the run dir is reused and
target-writable — so the block must key off the in-memory manifest the
run's own ``--from-smt-witness`` synthesis returned, never a read-back
of ``smt-seeds-manifest.json`` from disk. Both directions are pinned
against the REAL CLI (``main()`` with only the fuzzer and the LLM
analyser stubbed):

* a run that never synthesised seeds ignores a planted REAL seed dir
  containing a REGULAR manifest that names a predictable built-in
  corpus seed — the plant's ``origin_id`` must never become
  ``outcome_detail["finding_id"]`` on the crash Witness (that field
  surfaces in raptor-verified-outcomes as an oracle-verified finding
  confirmation);
* a witness-seeded run still attributes — from the in-memory manifest,
  so a same-run content swap of the disk manifest (the campaign's
  sandboxed target can write it between the pre-campaign write and
  any post-campaign read) changes nothing;
* a witness run whose seed-dir name was planted (synthesis refused)
  attributes nothing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import raptor_fuzzing

# A built-in corpus seed name (packages.fuzzing.seed_corpus) — exactly
# the kind of predictable name a planted manifest would claim so that
# ordinary non-witness campaigns root their crash lineages in it.
_BUILTIN_SEED = "seed-0003-json-object"
_ATTACKER_MANIFEST = {
    "seeds": [
        {
            "seed": _BUILTIN_SEED,
            "origin_id": "FAKE-FINDING-1",
            "source_file": "attack-paths.json",
        },
    ],
}


class _FakeAFLRunner:
    """Stands in for AFLRunner: writes a crash whose recorded mutation
    lineage roots in this run's first SMT seed when one exists, else in
    the predictable built-in seed name."""

    # Class-level knob: content to swap into the on-disk manifest
    # DURING the campaign (the same-run swap window). None = no swap.
    swap_manifest_with: dict | None = None
    campaign_failed = False

    def __init__(self, *args, output_dir: Path, **kwargs) -> None:
        self.output_dir = Path(output_dir)

    def run_fuzzing(self, **kwargs) -> tuple[int, Path]:
        queue = self.output_dir / "main" / "queue"
        crashes = self.output_dir / "main" / "crashes"
        queue.mkdir(parents=True)
        crashes.mkdir(parents=True)
        run_dir = self.output_dir.parent
        seed_dir = run_dir / "smt-seeds"
        smt_seeds = (
            sorted(p.name for p in seed_dir.glob("smt_*"))
            if seed_dir.is_dir() else []
        )
        orig = smt_seeds[0] if smt_seeds else _BUILTIN_SEED
        (queue / f"id:000000,time:0,execs:0,orig:{orig}").write_bytes(b"q")
        (crashes / "id:000000,sig:06,src:000000,op:havoc,rep:2").write_bytes(
            b"crash-bytes")
        if self.swap_manifest_with is not None:
            # The campaign's sandboxed target owns the run dir while
            # AFL runs: emulate it replacing the manifest content.
            (seed_dir / "smt-seeds-manifest.json").write_text(
                json.dumps(self.swap_manifest_with), encoding="utf-8")
        return 1, crashes


class _StopBeforeLLM:
    """Stands in for CrashAnalyser: aborts phase 2 right after the
    witness records (and their attribution) are written."""

    def __init__(self, *args, **kwargs) -> None:
        msg = "test stop: no LLM analysis"
        raise RuntimeError(msg)


def _run_cli(tmp_path: Path, monkeypatch, extra_argv: list[str]) -> Path:
    """Drive the real main() with the fuzzer + analyser stubbed.

    Returns the run's witnesses/manifests dir."""
    binary = tmp_path / "target-bin"
    binary.write_bytes(b"\x7fELF-stub")
    out_dir = tmp_path / "run"
    monkeypatch.setattr(raptor_fuzzing, "AFLRunner", _FakeAFLRunner)
    monkeypatch.setattr(raptor_fuzzing, "CrashAnalyser", _StopBeforeLLM)
    # SAGE recall is best-effort; keep the test offline and fast.
    monkeypatch.setattr(
        raptor_fuzzing, "recall_context_for_fuzzing_strategy",
        lambda **kwargs: [])
    monkeypatch.setattr(sys, "argv", [
        "raptor_fuzzing.py",
        "--binary", str(binary),
        "--legacy",
        "--project", "-",
        "--out", str(out_dir),
        "--duration", "1",
        *extra_argv,
    ])
    with pytest.raises(SystemExit) as excinfo:
        raptor_fuzzing.main()
    # The analyser stub aborts phase 2 -> CLI-boundary exit(1); the
    # witness records were already written by then.
    assert excinfo.value.code == 1
    return out_dir / "witnesses" / "manifests"


def _outcome_details(manifests_dir: Path) -> list[dict]:
    records = sorted(manifests_dir.glob("*.json"))
    assert records, "no witness records written — the run died too early"
    return [
        json.loads(p.read_text(encoding="utf-8")).get("outcome_detail", {})
        for p in records
    ]


def _witness_source(tmp_path: Path) -> Path:
    source = tmp_path / "validate_run"
    source.mkdir()
    (source / "attack-paths.json").write_text(
        json.dumps([{"id": "AP-001", "smt_model": {"buf_len": 24}}]),
        encoding="utf-8")
    return source


class TestNonWitnessRunReadBack:
    def test_planted_regular_manifest_never_labels_crashes(
            self, tmp_path, monkeypatch):
        # The previous campaign's target left a REAL directory at the
        # predictable seed-dir name with a REGULAR manifest inside —
        # both pass lstat checks; only "this run synthesised these
        # seeds" can refuse the content.
        out_dir = tmp_path / "run"
        seed_dir = out_dir / "smt-seeds"
        seed_dir.mkdir(parents=True)
        (seed_dir / "smt-seeds-manifest.json").write_text(
            json.dumps(_ATTACKER_MANIFEST), encoding="utf-8")

        manifests = _run_cli(tmp_path, monkeypatch, [])

        for detail in _outcome_details(manifests):
            assert "finding_id" not in detail
            assert "smt_attribution" not in detail
            assert "smt_seed" not in detail

    def test_clean_non_witness_run_records_unattributed(
            self, tmp_path, monkeypatch):
        manifests = _run_cli(tmp_path, monkeypatch, [])
        for detail in _outcome_details(manifests):
            assert "finding_id" not in detail


class TestWitnessRunAttribution:
    def test_attributes_from_in_memory_manifest(self, tmp_path, monkeypatch):
        source = _witness_source(tmp_path)
        manifests = _run_cli(
            tmp_path, monkeypatch, ["--from-smt-witness", str(source)])
        details = _outcome_details(manifests)
        attributed = [d for d in details if "finding_id" in d]
        assert attributed, "witness-seeded crash lost its attribution"
        for detail in attributed:
            assert detail["finding_id"] == "AP-001"
            assert detail["smt_attribution"] == "exact-lineage"

    def test_same_run_manifest_swap_cannot_relabel(
            self, tmp_path, monkeypatch):
        # The campaign swaps the DISK manifest's content mid-run,
        # re-pointing this run's real seed at a fabricated finding.
        # The attribution must come from the in-memory manifest.
        source = _witness_source(tmp_path)
        monkeypatch.setattr(
            _FakeAFLRunner, "swap_manifest_with", {
                "seeds": [{
                    # Same seed names the synthesis used — cover both
                    # rules so whichever roots the lineage is hit.
                    "seed": f"smt_000_buf_len_{suffix}",
                    "origin_id": "ATTACKER-SWAP",
                    "source_file": "attack-paths.json",
                } for suffix in ("len24", "raw")],
            })
        manifests = _run_cli(
            tmp_path, monkeypatch, ["--from-smt-witness", str(source)])
        details = _outcome_details(manifests)
        attributed = [d for d in details if "finding_id" in d]
        assert attributed, "witness-seeded crash lost its attribution"
        for detail in attributed:
            assert detail["finding_id"] == "AP-001"

    def test_refused_seed_dir_suppresses_attribution(
            self, tmp_path, monkeypatch):
        # A plant at the seed-dir name: synthesis refuses and sets
        # seed_dir_refused — nothing was written, so nothing this run
        # can vouch for; no attribution.
        source = _witness_source(tmp_path)
        out_dir = tmp_path / "run"
        out_dir.mkdir()
        (out_dir / "smt-seeds").write_text("occupied", encoding="utf-8")
        manifests = _run_cli(
            tmp_path, monkeypatch, ["--from-smt-witness", str(source)])
        for detail in _outcome_details(manifests):
            assert "finding_id" not in detail
