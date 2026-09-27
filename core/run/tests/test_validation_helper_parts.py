"""Tests for raptor-validation-helper's `parts` assembly subcommand.

The first test class pins the angle-bracket placeholder shape on the
ingest/sanitise/stamp path: placeholder text like "<payload>" must
survive ingestion sanitisation and assembly with EXACTLY one escape —
"&amp;lt;" in an assembled artifact means a re-sanitisation pass
corrupted it.

Colocated with the helper's flag-parsing tests. The helper module is
loaded lazily (fixture) so this file still collects on a tree whose
helper lacks the subcommand (failing-first discipline).
"""

import importlib.util
import json
import os
import subprocess
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
HELPER = REPO_ROOT / "libexec" / "raptor-validation-helper"

sys.path.insert(0, str(REPO_ROOT))

from core.json import load_json, save_json  # noqa: E402


@pytest.fixture(scope="module")
def helper():
    script = str(HELPER)
    loader = SourceFileLoader("raptor_validation_helper_parts", script)
    spec = importlib.util.spec_from_loader(
        "raptor_validation_helper_parts", loader,
    )
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    return subprocess.run(
        [sys.executable, str(HELPER), *[str(a) for a in args]],
        capture_output=True, text=True, env=env, cwd=REPO_ROOT,
    )


def _finding(fid: str = "FIND-001", **over) -> dict:
    base = {
        "id": fid,
        "file": "src/db.c",
        "function": "run_query",
        "line": 42,
        "vuln_type": "sql_injection",
        "status": "pending",
    }
    base.update(over)
    return base


def _hypothesis(hid: str = "HYP-001", **over) -> dict:
    base = {
        "id": hid,
        "finding": "FIND-001",
        "claim": "user input reaches the query without quoting",
        "status": "testing",
    }
    base.update(over)
    return base


PLACEHOLDER = "ESC k <payload> ESC backslash sets the <title>"


# ---------------------------------------------------------------------------
# FIRST: the angle-bracket double-escape regression
# ---------------------------------------------------------------------------

class TestAngleBracketPlaceholderSurvivesAssembly:

    def test_placeholder_escaped_exactly_once(self, helper, tmp_path):
        parts_dir = tmp_path / "stage-b-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "window.json", {
            "hypotheses": [_hypothesis(claim=PLACEHOLDER)],
        })

        assert helper.assemble_parts("B", tmp_path) is True

        claim = load_json(tmp_path / "hypotheses.json")[0]["claim"]
        assert claim.count("&lt;payload>") == 1
        assert claim.count("&lt;title>") == 1
        assert "&amp;" not in claim

    def test_reassembly_is_byte_identical_no_double_escape(
            self, helper, tmp_path):
        parts_dir = tmp_path / "stage-b-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "window.json", {
            "hypotheses": [_hypothesis(claim=PLACEHOLDER)],
        })

        assert helper.assemble_parts("B", tmp_path) is True
        first = (tmp_path / "hypotheses.json").read_bytes()
        assert helper.assemble_parts("B", tmp_path) is True
        second = (tmp_path / "hypotheses.json").read_bytes()

        assert first == second
        assert b"&amp;lt;" not in second

    def test_already_escaped_part_text_unchanged(self, helper, tmp_path):
        parts_dir = tmp_path / "stage-b-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "window.json", {
            "hypotheses": [_hypothesis(claim="&lt;payload> stays as-is")],
        })

        assert helper.assemble_parts("B", tmp_path) is True
        claim = load_json(tmp_path / "hypotheses.json")[0]["claim"]
        assert claim == "&lt;payload> stays as-is"

    def test_receipt_records_the_sanitised_field(self, helper, tmp_path):
        parts_dir = tmp_path / "stage-b-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "window.json", {
            "hypotheses": [_hypothesis(claim=PLACEHOLDER)],
        })

        assert helper.assemble_parts("B", tmp_path) is True
        receipt = load_json(tmp_path / "stage-b-assembly-receipt.json")
        (entry,) = receipt["parts"]
        assert entry["name"] == "window.json"
        assert any("claim" in p for p in entry["sanitised_fields"])


# ---------------------------------------------------------------------------
# Byte-stable, order-independent assembly
# ---------------------------------------------------------------------------

class TestOrderIndependence:

    UPDATE_X = {"FIND-001": {"status": "confirmed"},
                "FIND-003": {"status": "ruled_out"}}
    UPDATE_Y = {"FIND-002": {"status": "disproven"}}

    def _assemble(self, helper, tmp_path, sub: str,
                  first: dict, second: dict) -> bytes:
        workdir = tmp_path / sub
        parts_dir = workdir / "stage-c-parts"
        parts_dir.mkdir(parents=True)
        save_json(parts_dir / "part-aa.json", {"updates": first})
        save_json(parts_dir / "part-bb.json", {"updates": second})
        assert helper.assemble_parts("C", workdir) is True
        return (workdir / "stage-c.json").read_bytes()

    def test_same_parts_different_order_identical_bytes(
            self, helper, tmp_path):
        one = self._assemble(helper, tmp_path, "one",
                             self.UPDATE_X, self.UPDATE_Y)
        two = self._assemble(helper, tmp_path, "two",
                             self.UPDATE_Y, self.UPDATE_X)
        assert one == two
        assert list(json.loads(one)["updates"]) == sorted(
            list(self.UPDATE_X) + list(self.UPDATE_Y))


# ---------------------------------------------------------------------------
# Quarantine-and-proceed
# ---------------------------------------------------------------------------

class TestQuarantine:

    def test_bad_part_is_quarantined_merge_proceeds(self, helper, tmp_path):
        parts_dir = tmp_path / "stage-b-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "good-one.json",
                  {"hypotheses": [_hypothesis("HYP-001")]})
        save_json(parts_dir / "bad.json", {
            "hypotheses": [_hypothesis("HYP-002", predictions=[
                {"id": "P1", "prediction": "p", "status": "untested"},
            ])],
        })
        save_json(parts_dir / "good-two.json",
                  {"hypotheses": [_hypothesis("HYP-003")]})

        assert helper.assemble_parts("B", tmp_path) is True

        merged_ids = [h["id"] for h in load_json(tmp_path / "hypotheses.json")]
        assert merged_ids == ["HYP-001", "HYP-003"]

        reason = load_json(
            parts_dir / "quarantine" / "bad.json.reason.json")
        assert reason["part"] == "bad.json"
        assert any("untested" in r for r in reason["reasons"])
        # Immutability: the bad part is never moved or deleted.
        assert (parts_dir / "bad.json").is_file()

        receipt = load_json(tmp_path / "stage-b-assembly-receipt.json")
        assert [q["part"] for q in receipt["quarantined"]] == ["bad.json"]
        assert [p["name"] for p in receipt["parts"]] == [
            "good-one.json", "good-two.json"]

    def test_duplicate_update_key_quarantines_later_part_only(
            self, helper, tmp_path):
        parts_dir = tmp_path / "stage-c-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "part-1.json",
                  {"updates": {"FIND-001": {"status": "confirmed"}}})
        save_json(parts_dir / "part-2.json",
                  {"updates": {"FIND-001": {"status": "ruled_out"}}})

        assert helper.assemble_parts("C", tmp_path) is True

        # Never last-writer-wins: the earlier part's value stands and
        # the colliding part is quarantined with the owner named.
        assembled = load_json(tmp_path / "stage-c.json")
        assert assembled["updates"]["FIND-001"]["status"] == "confirmed"
        reason = load_json(
            parts_dir / "quarantine" / "part-2.json.reason.json")
        assert any("part-1.json" in r for r in reason["reasons"])

    def test_within_part_duplicate_finding_id_quarantined(
            self, helper, tmp_path):
        parts_dir = tmp_path / "stage-a-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "dupes.json",
                  [_finding("FIND-001"), _finding("FIND-001")])
        save_json(parts_dir / "clean.json", [_finding("FIND-002")])

        assert helper.assemble_parts("A", tmp_path) is True
        assembled = load_json(tmp_path / "stage-a.json")
        assert [f["id"] for f in assembled["findings"]] == ["FIND-002"]

    def test_all_parts_quarantined_fails(self, helper, tmp_path):
        parts_dir = tmp_path / "stage-c-parts"
        parts_dir.mkdir()
        (parts_dir / "broken.json").write_text("{not json", encoding="utf-8")
        assert helper.assemble_parts("C", tmp_path) is False


# ---------------------------------------------------------------------------
# Stage A assembly
# ---------------------------------------------------------------------------

class TestStageA:

    def test_append_sort_and_target_path(self, helper, tmp_path):
        parts_dir = tmp_path / "stage-a-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "zz.json", [_finding("FIND-001")])
        save_json(parts_dir / "aa.json",
                  {"findings": [_finding("FIND-002")]})
        save_json(tmp_path / "checklist.json",
                  {"target_path": "/src/tree"})

        assert helper.assemble_parts("A", tmp_path) is True
        assembled = load_json(tmp_path / "stage-a.json")
        assert assembled["stage"] == "A"
        assert assembled["target_path"] == "/src/tree"
        assert [f["id"] for f in assembled["findings"]] == [
            "FIND-001", "FIND-002"]

    def test_id_set_mismatch_warns_but_proceeds(self, helper, tmp_path,
                                                capsys):
        parts_dir = tmp_path / "stage-a-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "only.json", [_finding("FIND-001")])
        save_json(tmp_path / "findings.json", {
            "stage": "0",
            "findings": [_finding("FIND-001"), _finding("FIND-002")],
        })

        assert helper.assemble_parts("A", tmp_path) is True
        err = capsys.readouterr().err
        assert "FIND-002" in err and "missing" in err

    def test_alias_vuln_type_is_not_a_false_quarantine(
            self, helper, tmp_path):
        # The promoter accepts and normalises alias vuln_type
        # spellings; a part using one must assemble cleanly (with the
        # canonical value promoted), while a genuinely unknown enum
        # value still quarantines.
        parts_dir = tmp_path / "stage-a-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "alias.json",
                  [_finding("FIND-001", vuln_type="sqli")])
        save_json(parts_dir / "bad.json",
                  [_finding("FIND-002", vuln_type="not_a_vuln_type")])

        assert helper.assemble_parts("A", tmp_path) is True

        assembled = load_json(tmp_path / "stage-a.json")
        by_id = {f["id"]: f for f in assembled["findings"]}
        assert by_id["FIND-001"]["vuln_type"] == "sql_injection"
        assert "FIND-002" not in by_id
        assert (parts_dir / "quarantine"
                / "bad.json.reason.json").is_file()

    def test_a_part_feasibility_alias_assembles_canonical(
            self, helper, tmp_path, capsys):
        # An A-part finding row carrying the alias feasibility status
        # (plus the null binary_path the same producer writes) must
        # assemble cleanly with the CANONICAL values in stage-a.json —
        # ingestion normalises the row, never false-quarantines it.
        parts_dir = tmp_path / "stage-a-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "scan.json", [dict(
            _finding("FIND-001"),
            feasibility={"status": "binary_not_found",
                         "binary_path": None},
        )])

        assert helper.assemble_parts("A", tmp_path) is True
        assert "QUARANTINED" not in capsys.readouterr().err

        assembled = load_json(tmp_path / "stage-a.json")
        feas = assembled["findings"][0]["feasibility"]
        assert feas["status"] == "skipped"
        assert "binary_path" not in feas


# ---------------------------------------------------------------------------
# Stage B hybrid merge
# ---------------------------------------------------------------------------

class TestStageBHybrid:

    def test_six_outputs_cross_part_links_and_root_synthesis(
            self, helper, tmp_path, capsys):
        parts_dir = tmp_path / "stage-b-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "part-1.json", {
            "hypotheses": [_hypothesis("HYP-001")],
            # leads_to as a list is normalised to the canonical
            # comma-separated string at ingestion; N2 lives in the
            # OTHER part (cross-part link).
            "attack_tree_nodes": [
                {"id": "N1", "goal": "reach sink", "status": "exploring",
                 "leads_to": ["N2"]},
            ],
            "updates": {"FIND-001": {"status": "confirmed"}},
            "attack_surface": {
                "sources": [{"type": "socket", "entry": "recv_cmd"}],
            },
        })
        save_json(parts_dir / "part-2.json", {
            "attack_tree_nodes": [
                {"id": "N2", "goal": "corrupt state",
                 "status": "unexplored", "leads_to": ""},
            ],
            "attack_paths": [{"id": "PATH-001", "proximity": 4,
                              "status": "uncertain"}],
            "disproven": [{"finding": "FIND-009",
                           "why_wrong": "bounds checked"}],
            "updates": {"FIND-002": {"status": "disproven"}},
            "attack_surface": {
                "sources": [{"type": "socket", "entry": "recv_cmd"}],
                "sinks": [{"type": "exec", "location": "spawn.c:10"}],
            },
        })

        assert helper.assemble_parts("B", tmp_path) is True
        err = capsys.readouterr().err
        # The cross-part N1 -> N2 link resolves at assembly: no
        # dangling-target warning for it.
        assert "leads_to N2" not in err

        tree = load_json(tmp_path / "attack-tree.json")
        by_id = {n["id"]: n for n in tree["nodes"]}
        assert by_id["N1"]["leads_to"] == "N2"
        assert tree["root"] == "ROOT"
        assert "N1" in by_id["ROOT"]["leads_to"]  # unreferenced top level
        assert "N2" not in by_id["ROOT"]["leads_to"]

        stage_b = load_json(tmp_path / "stage-b.json")
        assert sorted(stage_b["updates"]) == ["FIND-001", "FIND-002"]

        surface = load_json(tmp_path / "attack-surface.json")
        assert len(surface["sources"]) == 1  # dedup by (type, entry)
        assert len(surface["sinks"]) == 1

        disproven = load_json(tmp_path / "disproven.json")
        assert disproven["disproven"][0]["finding"] == "FIND-009"

        # Per-element provenance stamps on the array documents.
        for name in ("hypotheses.json", "attack-paths.json"):
            for el in load_json(tmp_path / name):
                assert el["provenance"]["untrusted"] is True

    def test_part_entry_replaces_preexisting_doc_entry(
            self, helper, tmp_path):
        save_json(tmp_path / "hypotheses.json",
                  [_hypothesis("HYP-001", status="testing")])
        parts_dir = tmp_path / "stage-b-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "part-1.json", {
            "hypotheses": [_hypothesis("HYP-001", status="confirmed")],
        })

        assert helper.assemble_parts("B", tmp_path) is True
        (merged,) = load_json(tmp_path / "hypotheses.json")
        assert merged["status"] == "confirmed"

    def test_same_id_in_two_parts_is_a_conflict(self, helper, tmp_path):
        parts_dir = tmp_path / "stage-b-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "part-1.json",
                  {"hypotheses": [_hypothesis("HYP-001", status="testing")]})
        save_json(parts_dir / "part-2.json",
                  {"hypotheses": [_hypothesis("HYP-001",
                                              status="confirmed")]})

        assert helper.assemble_parts("B", tmp_path) is True
        (merged,) = load_json(tmp_path / "hypotheses.json")
        assert merged["status"] == "testing"  # earlier part stands
        assert (parts_dir / "quarantine"
                / "part-2.json.reason.json").is_file()

    def test_within_part_duplicate_collection_ids_quarantined(
            self, helper, tmp_path):
        # Two rows with the same id INSIDE one part must not silently
        # collapse via the keyed merge (last row winning) — the part
        # is quarantined, exactly like Stage A's within-part check.
        parts_dir = tmp_path / "stage-b-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "dup.json", {
            "hypotheses": [
                _hypothesis("HYP-001", status="testing",
                            claim="first copy - real work"),
                _hypothesis("HYP-001", status="confirmed",
                            claim="second copy must not win"),
            ],
            "attack_tree_nodes": [
                {"id": "N1", "goal": "real node", "status": "exploring",
                 "leads_to": ""},
                {"id": "N1", "goal": "shadowing node",
                 "status": "disproven", "leads_to": ""},
            ],
        })
        save_json(parts_dir / "good.json",
                  {"hypotheses": [_hypothesis("HYP-002")]})

        assert helper.assemble_parts("B", tmp_path) is True

        reasons = " | ".join(load_json(
            parts_dir / "quarantine" / "dup.json.reason.json")["reasons"])
        assert ("hypotheses entry HYP-001 appears more than once "
                "in this part") in reasons
        assert ("attack_tree_nodes entry N1 appears more than once "
                "in this part") in reasons
        assert [h["id"] for h in load_json(tmp_path / "hypotheses.json")
                ] == ["HYP-002"]
        tree = load_json(tmp_path / "attack-tree.json")
        assert all(n["id"] != "N1" for n in tree["nodes"])
        receipt = load_json(tmp_path / "stage-b-assembly-receipt.json")
        assert [q["part"] for q in receipt["quarantined"]] == ["dup.json"]

    def test_dangling_leads_to_warns(self, helper, tmp_path, capsys):
        parts_dir = tmp_path / "stage-b-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "part-1.json", {
            "attack_tree_nodes": [
                {"id": "N1", "status": "exploring",
                 "leads_to": "N-NOWHERE"},
            ],
        })
        assert helper.assemble_parts("B", tmp_path) is True
        assert "N-NOWHERE" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Promotion guards: the pre-write validation gate and the atomic write
# ---------------------------------------------------------------------------

class TestPromotionGuards:

    def test_poisoned_merge_base_refuses_promotion(self, helper, tmp_path):
        # Pre-existing working docs join the merge WITHOUT fragment
        # lint; the pre-write validation gate is the only thing
        # standing between an invalid merge-base row and promotion.
        save_json(tmp_path / "hypotheses.json",
                  [_hypothesis("HYP-900", status="nope")])
        baseline = (tmp_path / "hypotheses.json").read_bytes()
        parts_dir = tmp_path / "stage-b-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "good.json",
                  {"hypotheses": [_hypothesis("HYP-001")]})

        assert helper.assemble_parts("B", tmp_path) is False

        # Nothing promoted: the poisoned doc is untouched and no
        # assembled output or receipt appeared.
        assert (tmp_path / "hypotheses.json").read_bytes() == baseline
        for fname in ("stage-b.json", "attack-tree.json",
                      "attack-paths.json", "disproven.json",
                      "attack-surface.json",
                      "stage-b-assembly-receipt.json"):
            assert not (tmp_path / fname).exists(), fname

    def test_every_promoted_output_routes_through_save_json(
            self, helper, tmp_path, monkeypatch):
        # The atomic tempfile+rename promote lives in save_json; a
        # direct write to the final path would bypass it and leave a
        # torn file on interruption.
        recorded: list = []
        real_save = helper.save_json

        def recording(path, data, *args, **kwargs):
            recorded.append(Path(path).name)
            return real_save(path, data, *args, **kwargs)

        monkeypatch.setattr(helper, "save_json", recording)

        parts_dir = tmp_path / "stage-b-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "window.json", {
            "hypotheses": [_hypothesis()],
            "updates": {"FIND-001": {"status": "not_disproven"}},
        })

        assert helper.assemble_parts("B", tmp_path) is True

        expected = {
            "hypotheses.json", "attack-paths.json", "attack-tree.json",
            "disproven.json", "attack-surface.json", "stage-b.json",
            "stage-b-assembly-receipt.json",
        }
        missing = expected - set(recorded)
        assert not missing, (
            f"promoted without save_json (non-atomic write?): {missing}")


# ---------------------------------------------------------------------------
# Degenerate single-part stages + CLI surface
# ---------------------------------------------------------------------------

class TestSinglePartAndCli:

    def test_single_part_stage_d(self, tmp_path):
        parts_dir = tmp_path / "stage-d-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "all.json", {
            "updates": {"FIND-001": {
                "ruling": {"status": "confirmed", "rationale": "poc ran"},
            }},
        })

        proc = _run_cli("parts", "D", tmp_path)
        assert proc.returncode == 0, proc.stderr
        assembled = load_json(tmp_path / "stage-d.json")
        assert assembled["stage"] == "D"
        assert "FIND-001" in assembled["updates"]
        assert (tmp_path / "stage-d-assembly-receipt.json").is_file()

    def test_cli_exit_1_when_nothing_merges(self, tmp_path):
        parts_dir = tmp_path / "stage-d-parts"
        parts_dir.mkdir()
        (parts_dir / "broken.json").write_text("{not json", encoding="utf-8")
        proc = _run_cli("parts", "D", tmp_path)
        assert proc.returncode == 1
        assert "QUARANTINED" in proc.stderr

    def test_hostile_part_filename_never_reaches_stderr_raw(
            self, tmp_path):
        # Part filenames are producer-chosen; a name carrying terminal
        # control bytes must be escaped on EVERY stderr path (the
        # sanitisation WARNING here), not just the quarantine one.
        parts_dir = tmp_path / "stage-b-parts"
        parts_dir.mkdir()
        evil = "evil\x1b[31mred\x1b]0;title\x07.json"
        save_json(parts_dir / evil, {
            "hypotheses": [_hypothesis(claim="raw \x1b[35m text")],
        })

        proc = _run_cli("parts", "B", tmp_path)

        assert proc.returncode == 0, proc.stderr
        assert "WARNING" in proc.stderr
        assert "\x1b" not in proc.stderr
        assert "\x07" not in proc.stderr

    def test_cli_usage_errors(self, tmp_path):
        assert _run_cli("parts").returncode == 1
        assert _run_cli("parts", "Z", tmp_path).returncode == 1
        assert _run_cli("parts", "D", tmp_path / "missing").returncode == 1

    def test_assembled_output_passes_the_promote_gate(self, tmp_path):
        # Assembly and the promote gate compose: what `parts` writes,
        # raptor-validate-schema accepts.
        parts_dir = tmp_path / "stage-c-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "part-1.json",
                  {"updates": {"FIND-001": {"status": "confirmed"}}})
        proc = _run_cli("parts", "C", tmp_path)
        assert proc.returncode == 0, proc.stderr

        env = dict(os.environ)
        env["_RAPTOR_TRUSTED"] = "1"
        gate = subprocess.run(
            [sys.executable,
             str(REPO_ROOT / "libexec" / "raptor-validate-schema"),
             "stage", str(tmp_path / "stage-c.json")],
            capture_output=True, text=True, env=env, cwd=REPO_ROOT,
        )
        assert gate.returncode == 0, gate.stderr


# ---------------------------------------------------------------------------
# Real Stage E producer shape: E-5 verdict vocabulary in the status
# channel + null binary_path (copied from a real quarantined part,
# run-specific paths stripped). Ingestion normalises instead of
# quarantining — a single-part E stage no longer aborts on it.
# ---------------------------------------------------------------------------

class TestStageEStatusAliasIngestion:

    @staticmethod
    def _binary_not_found_part() -> dict:
        return {"updates": {"FIND-004": {
            "final_status": "confirmed_unverified",
            "feasibility": {
                "status": "binary_not_found",
                "binary_path": None,
                "note": "Binary not found - feasibility analysis skipped",
                "guidance": "Build the target, then re-run with "
                            "--binary <path>",
            },
            "stage_e_summary": {
                "verdict": "binary_not_found",
                "binary_path": None,
                "impact": "code_execution",
            },
        }}}

    def test_unhashable_status_part_quarantined_merge_proceeds(self, tmp_path):
        # A part whose feasibility.status is a JSON array (unhashable)
        # must be QUARANTINED with the merge proceeding over the healthy
        # part — never a crash that aborts assembly and loses good parts.
        parts_dir = tmp_path / "stage-e-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "bad.json", {"updates": {"FIND-001": {
            "feasibility": {"status": ["binary_not_found"]},
        }}})
        save_json(parts_dir / "good.json", {"updates": {"FIND-002": {
            "feasibility": {"status": "skipped"},
        }}})

        proc = _run_cli("parts", "E", tmp_path)

        assert proc.returncode == 0, proc.stderr
        assert "Traceback" not in proc.stderr
        assembled = load_json(tmp_path / "stage-e.json")
        assert list(assembled["updates"]) == ["FIND-002"]
        assert "QUARANTINED" in proc.stderr
        assert "feasibility.status" in proc.stderr

    def test_non_array_findings_key_on_e_part_not_a_crash(self, tmp_path):
        # A stray non-array "findings" key on a B–F part must not crash
        # the normalisation walk — the shape is the schema's to refuse.
        parts_dir = tmp_path / "stage-e-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "odd.json", {
            "updates": {"FIND-001": {"feasibility": {"status": "skipped"}}},
            "findings": 5,
        })

        proc = _run_cli("parts", "E", tmp_path)

        assert proc.returncode == 0, proc.stderr
        assert "Traceback" not in proc.stderr
        assembled = load_json(tmp_path / "stage-e.json")
        assert "FIND-001" in assembled["updates"]

    def test_real_shape_assembles_with_canonical_values(self, tmp_path):
        parts_dir = tmp_path / "stage-e-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "all.json", self._binary_not_found_part())
        before = (parts_dir / "all.json").read_bytes()

        proc = _run_cli("parts", "E", tmp_path)

        assert proc.returncode == 0, proc.stderr
        assert "QUARANTINED" not in proc.stderr
        assembled = load_json(tmp_path / "stage-e.json")
        feas = assembled["updates"]["FIND-004"]["feasibility"]
        assert feas["status"] == "skipped"
        assert "binary_path" not in feas
        # Verdict-channel fields pass through untouched.
        summary = assembled["updates"]["FIND-004"]["stage_e_summary"]
        assert summary["verdict"] == "binary_not_found"
        # Part files are an immutable audit record: normalisation
        # happens in memory at ingestion, never on the part on disk.
        assert (parts_dir / "all.json").read_bytes() == before


# ---------------------------------------------------------------------------
# Stage F review passthrough. stage-f-review.md [F-4] instructs a
# top-level stage_f_review field and report.py consumes it from
# findings.json — the updates{}-only assembly used to DROP it, so a
# sharded run silently lost its Stage F notes.
# ---------------------------------------------------------------------------

class TestStageFReviewPassthrough:

    @staticmethod
    def _f_part(fid: str, note: str) -> dict:
        return {
            "updates": {fid: {"stage_f_summary": {
                "review_notes": "checked",
            }}},
            "stage_f_review": note,
        }

    def test_single_part_review_survives_assembly(self, helper, tmp_path):
        parts_dir = tmp_path / "stage-f-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "all.json",
                  self._f_part("FIND-001", "No corrections needed."))

        assert helper.assemble_parts("F", tmp_path) is True
        assembled = load_json(tmp_path / "stage-f.json")
        assert assembled["stage_f_review"] == "No corrections needed."

    def test_two_part_notes_join_in_filename_order(self, helper, tmp_path):
        parts_dir = tmp_path / "stage-f-parts"
        parts_dir.mkdir()
        # Written in reverse order — the join follows filename sort,
        # not write order (order-independent reassembly).
        save_json(parts_dir / "zz.json",
                  self._f_part("FIND-002", "Second window clean."))
        save_json(parts_dir / "aa.json",
                  self._f_part("FIND-001", "Corrected FIND-001 CWE."))

        assert helper.assemble_parts("F", tmp_path) is True
        assembled = load_json(tmp_path / "stage-f.json")
        assert assembled["stage_f_review"] == (
            "Corrected FIND-001 CWE.\n\nSecond window clean.")

    def test_quarantined_part_note_never_joins(self, helper, tmp_path):
        # The join reads MERGED parts only: a part quarantined at
        # ingestion (duplicate update key here) must not leak its
        # review prose into the assembled note.
        parts_dir = tmp_path / "stage-f-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "aa.json",
                  self._f_part("FIND-001", "Kept: first window clean."))
        save_json(parts_dir / "bb.json",
                  self._f_part("FIND-001",
                               "POISON note from a quarantined part."))

        assert helper.assemble_parts("F", tmp_path) is True
        assembled = load_json(tmp_path / "stage-f.json")
        assert assembled["stage_f_review"] == "Kept: first window clean."
        assert "POISON" not in json.dumps(assembled)

    def test_key_absent_when_no_part_carries_it(self, helper, tmp_path):
        parts_dir = tmp_path / "stage-f-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "all.json",
                  {"updates": {"FIND-001": {"stage_f_summary": {}}}})

        assert helper.assemble_parts("F", tmp_path) is True
        assert "stage_f_review" not in load_json(tmp_path / "stage-f.json")

    def test_review_reaches_findings_json_via_stage_merge(
            self, helper, tmp_path):
        # End-to-end seam: assembled stage-f.json -> _apply_stage_file
        # -> findings.json, where report.py reads stage_f_review.
        parts_dir = tmp_path / "stage-f-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "all.json",
                  self._f_part("FIND-001", "Corrected FIND-001 CWE."))
        save_json(tmp_path / "findings.json",
                  {"findings": [_finding("FIND-001")]})

        assert helper.assemble_parts("F", tmp_path) is True
        assert helper._apply_stage_file(tmp_path, "F") is True
        merged = load_json(tmp_path / "findings.json")
        assert merged["stage_f_review"] == "Corrected FIND-001 CWE."

    def test_hostile_review_text_sanitised_at_ingestion(
            self, helper, tmp_path):
        parts_dir = tmp_path / "stage-f-parts"
        parts_dir.mkdir()
        save_json(parts_dir / "all.json",
                  self._f_part("FIND-001", "raw \x1b]0;title\x07 note"))

        assert helper.assemble_parts("F", tmp_path) is True
        note = load_json(tmp_path / "stage-f.json")["stage_f_review"]
        assert "\x1b" not in note
        assert "\x07" not in note
