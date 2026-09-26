"""End-to-end: study learns token_checks → save hook projects the map.

One test, whole chain: the mocked study response carries an
``api_vocabulary.token_checks`` claim (name present in the item
universe, corroborated by gate_checks), and the save chokepoint's
projection hook finds the co-located context-map.json and writes
token-map.json — no separate wiring call, exactly what a real
``/understand --study`` run does.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from core.concepts.study import run_study
from core.concepts.token_map import load_token_map

FIXTURE = Path(__file__).parent / "fixtures" / "token_php_app"


class TestStudyProjectionHook:
    def test_learned_checks_project_at_save_time(self, tmp_path):
        study_list = {
            "target": str(FIXTURE),
            "source_root": str(FIXTURE),
            "file_count": 1,
            "resolved_includes": 0,
            "items": [
                {
                    "id": "php_function_om_verify_request_stamp",
                    "kind": "function",
                    "name": "om_verify_request_stamp",
                    "file": "lib/guard.php",
                    "line": 21,
                    "definition": (
                        "function om_verify_request_stamp() { "
                        "if (!hash_equals(...)) { die('bad'); } }"
                    ),
                    "gate_checks": ["if (!om_verify_request_stamp())"],
                    "calls": [],
                    "callers": [],
                },
            ],
        }
        (tmp_path / "study-list.json").write_text(json.dumps(study_list))
        (tmp_path / "context-map.json").write_text(json.dumps({
            "entry_points": [
                {"id": "EP-1", "file": "web/save_prefs.php", "line": 5},
                {"id": "EP-2", "file": "web/export_data.php", "line": 1},
            ],
        }))

        mock_response = MagicMock()
        mock_response.result = {
            "concepts": [],
            "invariants": [],
            "contracts": [],
            "api_vocabulary": {
                "token_checks": [
                    {"name": "om_verify_request_stamp", "kind": "csrf",
                     "when": "dies on stamp mismatch"},
                ],
            },
        }
        client = MagicMock()
        client.generate_structured.return_value = mock_response

        progress: list[tuple[str, str]] = []
        model = run_study(
            tmp_path / "study-list.json", tmp_path, client,
            on_progress=lambda p, m: progress.append((p, m)),
        )

        assert model.token_checks
        assert model.token_checks[0]["name"] == "om_verify_request_stamp"
        assert model.token_checks[0]["provenance"] == "mechanical"

        payload = load_token_map(tmp_path)
        assert payload is not None
        statuses = {r["file"]: r["status"] for r in payload["entries"]}
        assert statuses == {
            "web/save_prefs.php": "enforced",
            "web/export_data.php": "not_enforced",
        }
        assert any(p == "token_map" for p, _ in progress)

    def test_no_learned_checks_no_artifact(self, tmp_path):
        study_list = {
            "target": str(FIXTURE),
            "source_root": str(FIXTURE),
            "file_count": 1,
            "resolved_includes": 0,
            "items": [{
                "id": "php_function_om_load_data",
                "kind": "function",
                "name": "om_load_data",
                "file": "lib/guard.php",
                "line": 39,
                "definition": "function om_load_data($key) { ... }",
                "calls": [],
                "callers": [],
            }],
        }
        (tmp_path / "study-list.json").write_text(json.dumps(study_list))
        (tmp_path / "context-map.json").write_text(json.dumps({
            "entry_points": [{"file": "web/save_prefs.php"}],
        }))
        mock_response = MagicMock()
        mock_response.result = {
            "concepts": [], "invariants": [], "contracts": [],
        }
        client = MagicMock()
        client.generate_structured.return_value = mock_response
        run_study(tmp_path / "study-list.json", tmp_path, client)
        assert load_token_map(tmp_path) is None
