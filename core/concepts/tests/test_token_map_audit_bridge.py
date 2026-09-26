"""Audit consumer of the token map: hint line, projection, defence.

Pins the consumer contract from the design:

- the block appears ONLY on mapped entry-point files, carries the
  verify-against-source framing, and names its non-verdict nature in
  both directions ("enforced" never refutes; "NOT enforced" never
  proves);
- the run-level chokepoint projects the map on the fly from the
  discoverable domain model when the study did not co-locate one;
- target-derived text is escaped before rendering.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from core.concepts.audit_bridge import (
    _load_cached,
    _token_map_for_run,
    _token_source_drift,
    ensure_token_map,
    token_enforcement_context,
)
from core.concepts.token_map import build_token_map, save_token_map

FIXTURE = Path(__file__).parent / "fixtures" / "token_php_app"

MODEL = {
    "token_checks": [
        {"name": "om_verify_request_stamp", "kind": "csrf",
         "provenance": "mechanical"},
    ],
}


def _map_payload() -> dict:
    entries = [
        {"entry": p.name, "file": f"web/{p.name}"}
        for p in sorted((FIXTURE / "web").glob("*.php"))
    ]
    return build_token_map(MODEL, entries, FIXTURE)


def _fresh_caches():
    _token_map_for_run.cache_clear()
    _load_cached.cache_clear()


class TestHintBlock:
    def test_entry_file_gets_status_line(self, tmp_path):
        _fresh_caches()
        save_token_map(_map_payload(), tmp_path)
        block = token_enforcement_context(tmp_path, "web/export_data.php")
        assert block is not None
        assert "token-enforcement: NOT enforced" in block
        assert "om_verify_request_stamp() [mechanical]" in block
        assert "verify against source" in block
        # Both non-verdict directions are named.
        assert "never rule out" in block
        assert "not proof of exploitability" in block

    def test_enforced_line_names_call_presence_only(self, tmp_path):
        _fresh_caches()
        save_token_map(_map_payload(), tmp_path)
        block = token_enforcement_context(tmp_path, "web/save_prefs.php")
        assert "enforced-via om_verify_request_stamp()" in block
        assert "call-presence witness only" in block

    def test_conditional_skip_path_is_visible(self, tmp_path):
        _fresh_caches()
        save_token_map(_map_payload(), tmp_path)
        block = token_enforcement_context(tmp_path, "web/options_save.php")
        assert "CONDITIONAL branch" in block

    def test_indirect_line_carries_the_chain(self, tmp_path):
        _fresh_caches()
        save_token_map(_map_payload(), tmp_path)
        block = token_enforcement_context(tmp_path, "web/delete_item.php")
        assert "INDIRECTLY" in block
        assert "om_require_valid_request -> om_verify_request_stamp" in block

    def test_unknown_line_states_the_reason(self, tmp_path):
        _fresh_caches()
        save_token_map(_map_payload(), tmp_path)
        block = token_enforcement_context(tmp_path, "web/dispatch.php")
        assert "token-enforcement: unknown" in block
        assert "dynamic dispatch" in block

    def test_unmapped_file_gets_no_block(self, tmp_path):
        _fresh_caches()
        save_token_map(_map_payload(), tmp_path)
        assert token_enforcement_context(
            tmp_path, "lib/guard.php",
        ) is None

    def test_no_map_no_block(self, tmp_path):
        _fresh_caches()
        assert token_enforcement_context(
            tmp_path, "web/save_prefs.php",
        ) is None

    def test_hostile_map_text_is_escaped(self, tmp_path):
        _fresh_caches()
        payload = _map_payload()
        for rec in payload["entries"]:
            if rec["file"] == "web/export_data.php":
                rec["evidence"] = "x\x1b]0;owned\x07y"
        payload["check_functions"][0]["name"] = "evil\x1bcheck"
        save_token_map(payload, tmp_path)
        block = token_enforcement_context(tmp_path, "web/export_data.php")
        assert "\x1b" not in block
        assert "\x07" not in block


class TestSourceDriftMarker:
    def test_fresh_source_has_no_marker(self, tmp_path):
        _fresh_caches()
        save_token_map(_map_payload(), tmp_path)
        block = token_enforcement_context(
            tmp_path, "web/save_prefs.php", FIXTURE,
        )
        assert block is not None
        assert "since projection" not in block

    def test_drifted_source_is_flagged(self, tmp_path):
        # Map projected, then the entry source edited: the hint line
        # carries the drift marker so a reviewer never leans on a
        # stale projection.
        _fresh_caches()
        root = tmp_path / "app"
        shutil.copytree(FIXTURE, root)
        out = tmp_path / "out"
        out.mkdir()
        entries = [
            {"entry": "save_prefs.php", "file": "web/save_prefs.php"},
        ]
        save_token_map(build_token_map(MODEL, entries, root), out)
        f = root / "web" / "save_prefs.php"
        f.write_text(f.read_text() + "\n$om_rev = 2;\n")
        block = token_enforcement_context(out, "web/save_prefs.php", root)
        assert block is not None
        assert "source drifted since projection" in block

    def test_missing_source_is_flagged(self, tmp_path):
        _fresh_caches()
        root = tmp_path / "app"
        shutil.copytree(FIXTURE, root)
        out = tmp_path / "out"
        out.mkdir()
        entries = [
            {"entry": "save_prefs.php", "file": "web/save_prefs.php"},
        ]
        save_token_map(build_token_map(MODEL, entries, root), out)
        (root / "web" / "save_prefs.php").unlink()
        block = token_enforcement_context(out, "web/save_prefs.php", root)
        assert block is not None
        assert "source missing since projection" in block

    def test_legacy_record_without_stamp_is_quiet(self, tmp_path):
        # Maps written before the digest existed carry no stamp — the
        # marker stays silent (the block already says verify-against-
        # source) instead of guessing.
        _fresh_caches()
        payload = _map_payload()
        for rec in payload["entries"]:
            rec.pop("source_sha256", None)
        save_token_map(payload, tmp_path)
        block = token_enforcement_context(
            tmp_path, "web/save_prefs.php", FIXTURE,
        )
        assert block is not None
        assert "since projection" not in block

    def test_traversal_shaped_record_file_is_never_read(self, tmp_path):
        # The map file is untrusted content — a tampered record's file
        # field must not steer reads outside the target root.
        for hostile in ("../outside.php", "/etc/hostname", ""):
            rec = {"file": hostile, "source_sha256": "0" * 16}
            assert _token_source_drift(rec, tmp_path) == ""


class TestOnTheFlyProjection:
    def test_projects_from_domain_model_and_checklist(self, tmp_path):
        _fresh_caches()
        (tmp_path / "domain-model.json").write_text(json.dumps(MODEL))
        checklist = {"files": [
            {"path": f"web/{p.name}",
             "items": [{"name": f"interstitial:1-{i + 2}",
                        "script_handler": True}]}
            for i, p in enumerate(sorted((FIXTURE / "web").glob("*.php")))
        ]}
        (tmp_path / "checklist.json").write_text(json.dumps(checklist))
        payload = ensure_token_map(tmp_path, FIXTURE)
        assert payload is not None
        assert (tmp_path / "token-map.json").is_file()
        block = token_enforcement_context(
            tmp_path, "web/export_data.php", FIXTURE,
        )
        assert block and "NOT enforced" in block

    def test_no_learned_checks_projects_nothing(self, tmp_path):
        _fresh_caches()
        (tmp_path / "domain-model.json").write_text(json.dumps(
            {"token_checks": []},
        ))
        (tmp_path / "checklist.json").write_text(json.dumps(
            {"files": [{"path": "web/a.php",
                        "items": [{"script_handler": True}]}]},
        ))
        assert ensure_token_map(tmp_path, FIXTURE) is None
        assert not (tmp_path / "token-map.json").exists()

    def test_no_target_no_projection(self, tmp_path):
        _fresh_caches()
        (tmp_path / "domain-model.json").write_text(json.dumps(MODEL))
        assert token_enforcement_context(
            tmp_path, "web/export_data.php",
        ) is None


class TestContextAssemblyWiring:
    def test_block_reaches_the_review_prompt_enveloped(self, tmp_path):
        _fresh_caches()
        save_token_map(_map_payload(), tmp_path)
        from core.audit.context import (
            assemble_context,
            format_context_for_prompt,
        )
        ctx = assemble_context(
            target_path=FIXTURE,
            file_path="web/export_data.php",
            function_name="interstitial:1-9",
            line_start=1,
            line_end=9,
            out_dir=tmp_path,
        )
        assert "token_enforcement" in ctx
        prompt = format_context_for_prompt(ctx)
        assert "token-enforcement: NOT enforced" in prompt
        assert "never treat as a verdict input" in prompt

    def test_unmapped_file_adds_no_section(self, tmp_path):
        _fresh_caches()
        save_token_map(_map_payload(), tmp_path)
        from core.audit.context import assemble_context
        ctx = assemble_context(
            target_path=FIXTURE,
            file_path="lib/guard.php",
            function_name="om_load_data",
            line_start=39,
            line_end=41,
            out_dir=tmp_path,
        )
        assert "token_enforcement" not in ctx
