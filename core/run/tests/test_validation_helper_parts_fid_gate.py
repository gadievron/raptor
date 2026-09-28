"""Parts-channel gate on hostile ``updates{}`` keys.

A part file's ``updates`` map is keyed by finding id — the join key
the assembled stage document persists byte-exact. These tests pin the
quarantine-grade contract at the assembly channel:

  * a part whose ``updates`` carries a key that fails the finding-id
    contract (charset/shape via the id pattern, length via the bound)
    is QUARANTINED whole — never assembled, never rewritten;
  * the assembled stage document's on-disk bytes stay free of raw
    control/bidi bytes (ESC, C1 CSI, RLO) — the terminal-injection /
    prompt-stuffing channel a hostile key rode in on;
  * the quarantine reason record embeds the offending key escaped and
    bounded, so the record itself is safe to ``cat`` and to quote;
  * valid sibling parts still assemble, and VALID keys survive
    byte-exact — the gate refuses, it never repairs.

The helper module is loaded lazily (fixture) so this file still
collects on a tree whose lint lacks the gate (failing-first
discipline).
"""

import importlib.util
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
HELPER = REPO_ROOT / "libexec" / "raptor-validation-helper"

sys.path.insert(0, str(REPO_ROOT))

from core.json import load_json, save_json  # noqa: E402

# Drill-shaped hostile fid: ANSI colour ESC, OSC title-set, C1 CSI
# (U+009B), bidi override (RLO/PDF pair), then a large printable tail.
HOSTILE_FID = (
    "\x1b[31m\x1b]0;pwned\x07FIND-1\x9b6n\u202eevil\u202c"
    + "A" * 100_000
)

# Raw byte forms that must never reach an assembled artifact or a
# quarantine reason record on disk (UTF-8 of the characters above).
RAW_ESC = b"\x1b"
RAW_C1_CSI = "\u009b".encode()
RAW_RLO = "\u202e".encode()

VALID_PART = {
    "stage": "F",
    "updates": {"FIND-1": {"status": "confirmed"}},
    "stage_f_review": "Review note: FIND-1 confirmed.",
}


@pytest.fixture(scope="module")
def helper():
    script = str(HELPER)
    loader = SourceFileLoader("raptor_validation_helper_fid_gate", script)
    spec = importlib.util.spec_from_loader(
        "raptor_validation_helper_fid_gate", loader,
    )
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _mkparts(tmp_path: Path, stage: str) -> Path:
    parts_dir = tmp_path / f"stage-{stage.lower()}-parts"
    parts_dir.mkdir()
    save_json(tmp_path / "findings.json", {"findings": [
        {"id": "FIND-1", "file": "src/a.c", "function": "f", "line": 1,
         "vuln_type": "buffer_overflow", "status": "not_disproven"},
    ]})
    return parts_dir


def _reason_record(parts_dir: Path, part_name: str) -> dict:
    path = parts_dir / "quarantine" / f"{part_name}.reason.json"
    assert path.is_file(), f"no quarantine reason record for {part_name}"
    record = load_json(path)
    assert record is not None
    return record


class TestHostileFidQuarantined:
    """Drill shape: one valid part, one part whose updates key is a
    100KB fid carrying ESC / C1 CSI / RLO."""

    def test_hostile_part_quarantined_and_stage_f_clean(
            self, helper, tmp_path):
        parts_dir = _mkparts(tmp_path, "F")
        save_json(parts_dir / "part-001-valid.json", VALID_PART)
        save_json(parts_dir / "part-002-hostile.json",
                  {"stage": "F",
                   "updates": {HOSTILE_FID: {"status": "confirmed"}}})

        assert helper.assemble_parts("F", tmp_path) is True

        # The hostile key never reaches the assembled document — not
        # raw, not sanitised, not excerpted. The valid sibling's key
        # survives byte-exact.
        stage_f = load_json(tmp_path / "stage-f.json")
        assert list(stage_f["updates"]) == ["FIND-1"]
        assert stage_f["updates"]["FIND-1"]["status"] == "confirmed"

        # On-disk byte audit: no raw ESC / C1 CSI / RLO bytes.
        raw = (tmp_path / "stage-f.json").read_bytes()
        assert RAW_ESC not in raw
        assert RAW_C1_CSI not in raw
        assert RAW_RLO not in raw

        # The hostile part is quarantined with a named reason, and the
        # receipt accounts it; the part file itself stays put.
        record = _reason_record(parts_dir, "part-002-hostile.json")
        assert record["reasons"], "empty quarantine reasons"
        assert any("updates key" in r for r in record["reasons"])
        receipt = load_json(tmp_path / "stage-f-assembly-receipt.json")
        assert [q["part"] for q in receipt["quarantined"]] == [
            "part-002-hostile.json"]
        assert [p["name"] for p in receipt["parts"]] == [
            "part-001-valid.json"]
        assert (parts_dir / "part-002-hostile.json").is_file()

    def test_reason_record_bytes_are_escaped_and_bounded(
            self, helper, tmp_path):
        parts_dir = _mkparts(tmp_path, "F")
        save_json(parts_dir / "part-001-valid.json", VALID_PART)
        save_json(parts_dir / "part-002-hostile.json",
                  {"stage": "F",
                   "updates": {HOSTILE_FID: {"status": "confirmed"}}})

        assert helper.assemble_parts("F", tmp_path) is True

        # The reason record embeds the offending key escaped and
        # bounded at composition — safe to cat and to quote even on a
        # tree with no record-level write net.
        qpath = parts_dir / "quarantine" / (
            "part-002-hostile.json.reason.json")
        raw = qpath.read_bytes()
        assert RAW_ESC not in raw
        assert RAW_C1_CSI not in raw
        assert RAW_RLO not in raw
        record = load_json(qpath)
        for reason in record["reasons"]:
            assert len(reason) < 600
        assert any("...[+" in r for r in record["reasons"])

    def test_part_with_hostile_and_valid_keys_quarantined_whole(
            self, helper, tmp_path):
        # The gate refuses the PART, it does not repair the map: a
        # part mixing one valid and one hostile key contributes
        # neither.
        parts_dir = _mkparts(tmp_path, "F")
        save_json(parts_dir / "part-001-valid.json", VALID_PART)
        save_json(parts_dir / "part-002-mixed.json",
                  {"stage": "F",
                   "updates": {"FIND-2": {"status": "ruled_out"},
                               HOSTILE_FID: {"status": "confirmed"}}})

        assert helper.assemble_parts("F", tmp_path) is True

        stage_f = load_json(tmp_path / "stage-f.json")
        assert list(stage_f["updates"]) == ["FIND-1"]
        _reason_record(parts_dir, "part-002-mixed.json")

    def test_every_part_hostile_is_loud_refusal(self, helper, tmp_path):
        parts_dir = _mkparts(tmp_path, "F")
        save_json(parts_dir / "part-001-hostile.json",
                  {"stage": "F",
                   "updates": {HOSTILE_FID: {"status": "confirmed"}}})

        assert helper.assemble_parts("F", tmp_path) is False
        assert not (tmp_path / "stage-f.json").exists()
        _reason_record(parts_dir, "part-001-hostile.json")

    def test_stage_b_updates_keys_share_the_gate(self, helper, tmp_path):
        # Stage B parts carry the same updates{} slice through the
        # same lint machinery — the gate must hold there too.
        parts_dir = _mkparts(tmp_path, "B")
        save_json(parts_dir / "part-001-valid.json",
                  {"stage": "B",
                   "updates": {"FIND-1": {"status": "not_disproven"}}})
        save_json(parts_dir / "part-002-hostile.json",
                  {"stage": "B",
                   "updates": {HOSTILE_FID: {"status": "not_disproven"}}})

        assert helper.assemble_parts("B", tmp_path) is True

        stage_b = load_json(tmp_path / "stage-b.json")
        assert list(stage_b["updates"]) == ["FIND-1"]
        raw = (tmp_path / "stage-b.json").read_bytes()
        assert RAW_ESC not in raw
        assert RAW_C1_CSI not in raw
        assert RAW_RLO not in raw
        _reason_record(parts_dir, "part-002-hostile.json")


class TestValidKeysSurviveByteExact:
    """The other direction of the gate: keys the pipeline can mint
    pass through byte-exact — the gate must never quarantine an
    honest part or rewrite an accepted key."""

    def test_maximal_legitimate_fid_assembles_byte_exact(
            self, helper, tmp_path):
        from packages.exploitability_validation.lint import (
            UPDATE_KEY_MAX_LEN,
        )
        fid = "FIND-" + "9" * (UPDATE_KEY_MAX_LEN - len("FIND-"))
        assert len(fid) == UPDATE_KEY_MAX_LEN
        parts_dir = _mkparts(tmp_path, "C")
        save_json(parts_dir / "part-001.json",
                  {"stage": "C", "updates": {fid: {"status": "confirmed"}}})

        assert helper.assemble_parts("C", tmp_path) is True

        stage_c = load_json(tmp_path / "stage-c.json")
        assert list(stage_c["updates"]) == [fid]
        # Byte-exact on disk: the exact ASCII key, unescaped and
        # unexcerpted, is present in the assembled document.
        assert fid.encode() in (tmp_path / "stage-c.json").read_bytes()

    def test_one_over_the_bound_is_quarantined(self, helper, tmp_path):
        from packages.exploitability_validation.lint import (
            UPDATE_KEY_MAX_LEN,
        )
        over = "FIND-" + "9" * (UPDATE_KEY_MAX_LEN - len("FIND-") + 1)
        assert len(over) == UPDATE_KEY_MAX_LEN + 1
        parts_dir = _mkparts(tmp_path, "C")
        save_json(parts_dir / "part-001-valid.json",
                  {"stage": "C",
                   "updates": {"FIND-1": {"status": "confirmed"}}})
        save_json(parts_dir / "part-002-over.json",
                  {"stage": "C", "updates": {over: {"status": "confirmed"}}})

        assert helper.assemble_parts("C", tmp_path) is True

        stage_c = load_json(tmp_path / "stage-c.json")
        assert list(stage_c["updates"]) == ["FIND-1"]
        record = _reason_record(parts_dir, "part-002-over.json")
        assert any("exceeds the finding-id bound" in r
                   for r in record["reasons"])

    def test_sarif_prefixed_fid_assembles(self, helper, tmp_path):
        parts_dir = _mkparts(tmp_path, "C")
        save_json(parts_dir / "part-001.json",
                  {"stage": "C",
                   "updates": {"SARIF-0042": {"status": "confirmed"}}})

        assert helper.assemble_parts("C", tmp_path) is True
        stage_c = load_json(tmp_path / "stage-c.json")
        assert list(stage_c["updates"]) == ["SARIF-0042"]
