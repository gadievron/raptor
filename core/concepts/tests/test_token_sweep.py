"""Class-sweep seed generator: trigger discipline, emission, contract.

The strongest pin here is the round trip through the REAL /audit
intake (``core.audit.hypothesis_intake.load_seed_files``): every seed
this generator writes must load with zero skips — the sweep reuses the
sibling-hypotheses contract exactly, and a drift on either side breaks
here instead of silently dropping seeds at the consumer.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.concepts.token_map import build_token_map
from core.concepts.token_sweep import (
    FALLBACK_SEEDS_FILENAME,
    MAX_SWEEP_SEEDS,
    SWEEP_PRODUCER,
    finding_is_token_premised,
    sweep_seeds_for_finding,
    write_sweep_payload,
)

FIXTURE = Path(__file__).parent / "fixtures" / "token_php_app"

MODEL = {
    "token_checks": [
        {"name": "om_verify_request_stamp", "kind": "csrf",
         "provenance": "mechanical"},
    ],
}


def _token_map() -> dict:
    entries = [
        {"entry": p.name, "file": f"web/{p.name}"}
        for p in sorted((FIXTURE / "web").glob("*.php"))
    ]
    return build_token_map(MODEL, entries, FIXTURE)


def _finding(**over) -> dict:
    base = {
        "id": "F-7",
        "status": "exploitable",
        "file": "web/export_data.php",
        "title": "State change without om_verify_request_stamp",
        "description": (
            "the handler mutates preferences without calling "
            "om_verify_request_stamp"
        ),
    }
    base.update(over)
    return base


class TestTrigger:
    def test_learned_check_name_triggers(self):
        assert finding_is_token_premised(_finding(), _token_map())

    def test_cwe_352_tag_triggers(self):
        f = _finding(title="forgeable state change", description="",
                     cwe="CWE-352")
        assert finding_is_token_premised(f, _token_map())

    def test_unrelated_finding_never_triggers(self):
        f = _finding(title="SQL injection in search",
                     description="string-built query")
        assert not finding_is_token_premised(f, _token_map())

    def test_generic_seed_words_alone_never_trigger(self):
        # "csrf token" prose without the learned name or the CWE tag:
        # the trigger vocabulary is the map's own, not the discovery
        # seeds.
        f = _finding(title="csrf token missing somewhere",
                     description="a token would help")
        assert not finding_is_token_premised(f, _token_map())

    def test_unconfirmed_finding_emits_nothing(self):
        seeds = sweep_seeds_for_finding(
            _finding(status="ruled_out"), _token_map(),
        )
        assert seeds == []


class TestEmission:
    def test_only_not_enforced_entries_swept(self):
        seeds = sweep_seeds_for_finding(_finding(), _token_map())
        files = {s["file"] for s in seeds}
        # export_data is the finding's own entry — excluded; late_check
        # is the other not_enforced entry. enforced/indirect/unknown
        # entries never emit (unknown would overstate the evidence).
        assert files == {"web/late_check.php"}

    def test_origin_entry_included_when_finding_is_elsewhere(self):
        seeds = sweep_seeds_for_finding(
            _finding(file="web/options_save.php"), _token_map(),
        )
        assert {s["file"] for s in seeds} == {
            "web/export_data.php", "web/late_check.php",
        }

    def test_evidence_pointer_is_index_accurate(self):
        token_map = _token_map()
        seeds = sweep_seeds_for_finding(
            _finding(file="web/options_save.php"), token_map,
        )
        for seed in seeds:
            (ref,) = seed["evidence"]
            assert ref["artifact"] == "token-map.json"
            idx = int(ref["pointer"][len("entries["):-1])
            assert token_map["entries"][idx]["file"] == seed["file"]
            assert token_map["entries"][idx]["status"] == "not_enforced"

    def test_seed_fields_follow_the_intake_contract(self):
        (seed,) = sweep_seeds_for_finding(_finding(), _token_map())
        assert seed["evidence_tier"] == "heuristic"
        assert seed["derived_from_target"] == {
            "claim": True, "disproof": True,
        }
        assert "F-7" in seed["claim"]
        assert "om_verify_request_stamp" in seed["claim"]
        assert "pre-output prefix" in seed["disproof"]

    def test_checklist_resolves_script_handler_name(self):
        checklist = {"files": [
            {"path": "web/late_check.php",
             "items": [
                 {"name": "helper", "kind": "function"},
                 {"name": "interstitial:1-11", "kind": "interstitial",
                  "script_handler": True},
             ]},
        ]}
        (seed,) = sweep_seeds_for_finding(
            _finding(), _token_map(), checklist,
        )
        assert seed["function"] == "interstitial:1-11"

    def test_without_checklist_no_function_key(self):
        (seed,) = sweep_seeds_for_finding(_finding(), _token_map())
        assert "function" not in seed

    def test_emission_cap(self):
        token_map = _token_map()
        token_map["entries"] = [
            {"file": f"web/gen{i}.php", "status": "not_enforced"}
            for i in range(MAX_SWEEP_SEEDS + 50)
        ]
        seeds = sweep_seeds_for_finding(_finding(file=""), token_map)
        assert len(seeds) == MAX_SWEEP_SEEDS


class TestWriteAndIntakeRoundTrip:
    def test_canonical_write_loads_through_real_intake(self, tmp_path):
        from core.audit.hypothesis_intake import (
            SEEDS_FILENAME,
            discover_seed_paths,
            load_seed_files,
        )
        seeds = sweep_seeds_for_finding(
            _finding(file="web/options_save.php"), _token_map(),
        )
        path, canonical = write_sweep_payload(tmp_path, seeds)
        assert canonical and path == tmp_path / SEEDS_FILENAME
        # Co-located discovery finds it.
        assert discover_seed_paths(tmp_path) == [path]
        loaded, skips, sources = load_seed_files([path])
        assert len(loaded) == len(seeds)
        assert skips == {}
        payload = json.loads(path.read_text())
        assert payload["producer"] == SWEEP_PRODUCER
        # Provenance stamp present and honest about trust.
        assert "untrusted" in json.dumps(payload)

    def test_never_overwrites_another_producer(self, tmp_path):
        from core.audit.hypothesis_intake import SEEDS_FILENAME
        existing = tmp_path / SEEDS_FILENAME
        existing.write_text('{"seeds": []}')
        seeds = sweep_seeds_for_finding(_finding(), _token_map())
        path, canonical = write_sweep_payload(tmp_path, seeds)
        assert not canonical
        assert path == tmp_path / FALLBACK_SEEDS_FILENAME
        assert existing.read_text() == '{"seeds": []}'

    def test_nothing_to_write(self, tmp_path):
        assert write_sweep_payload(tmp_path, []) == (None, False)
