"""Validate-bridge consumer: advisory token-enforcement attach.

The bridge stamps each mapped entry point in attack-surface.json with
its token-enforcement fact when the imported understand run carries a
token-map.json. Advisory only — pinned in both directions: the fact
appears, and NOTHING else about the entry (no status, no priority)
changes; without a map the surface is byte-identical to a bridge run
with no token map at all.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.concepts.token_map import build_token_map, save_token_map
from core.orchestration.understand_bridge import _merge_attack_surface

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "concepts" / "tests" / "fixtures" / "token_php_app"
)

MODEL = {
    "token_checks": [
        {"name": "om_verify_request_stamp", "kind": "csrf",
         "provenance": "mechanical"},
    ],
}


def _context_map() -> dict:
    return {
        "sources": [{"type": "http", "entry": "POST params"}],
        "sinks": [{"type": "state_change",
                   "location": "web/export_data.php"}],
        "trust_boundaries": [],
        "entry_points": [
            {"id": "EP-001", "type": "http_route",
             "file": "web/export_data.php", "line": 1,
             "auth_required": False},
            {"id": "EP-002", "type": "http_route",
             "file": "web/save_prefs.php", "line": 1,
             "auth_required": False},
            {"id": "EP-003", "type": "http_route",
             "file": "web/unmapped.php", "line": 1},
        ],
    }


def _understand_dir(tmp_path: Path, with_map: bool) -> Path:
    u_dir = tmp_path / "understand"
    u_dir.mkdir()
    (u_dir / "context-map.json").write_text(json.dumps(_context_map()))
    if with_map:
        entries = [
            {"entry": p.name, "file": f"web/{p.name}"}
            for p in sorted((FIXTURE / "web").glob("*.php"))
        ]
        save_token_map(build_token_map(MODEL, entries, FIXTURE), u_dir)
    return u_dir


def _bridge(tmp_path: Path, with_map: bool) -> dict:
    u_dir = _understand_dir(tmp_path, with_map)
    v_dir = tmp_path / "validate"
    v_dir.mkdir()
    _merge_attack_surface(
        _context_map(), v_dir, u_dir / "context-map.json",
    )
    return json.loads((v_dir / "attack-surface.json").read_text())


class TestAdvisoryAttach:
    def test_mapped_entries_carry_the_fact(self, tmp_path):
        surface = _bridge(tmp_path, with_map=True)
        by_id = {ep["id"]: ep for ep in surface["entry_points"]}
        assert by_id["EP-001"]["token_enforcement"]["status"] == (
            "not_enforced"
        )
        assert by_id["EP-002"]["token_enforcement"]["status"] == "enforced"
        assert by_id["EP-002"]["token_enforcement"]["via"] == (
            "om_verify_request_stamp"
        )
        assert "token_enforcement" not in by_id["EP-003"]

    def test_attach_is_advisory_only(self, tmp_path):
        (tmp_path / "b").mkdir()
        with_map = _bridge(tmp_path, with_map=True)
        without = _bridge(tmp_path / "b", with_map=False)
        strip = lambda eps: [  # noqa: E731
            {k: v for k, v in ep.items() if k != "token_enforcement"}
            for ep in eps
        ]
        # Removing the advisory field yields the no-map surface:
        # no status, priority, or any other key was touched.
        assert strip(with_map["entry_points"]) == without["entry_points"]

    def test_no_map_no_field(self, tmp_path):
        surface = _bridge(tmp_path, with_map=False)
        assert all(
            "token_enforcement" not in ep
            for ep in surface["entry_points"]
        )
