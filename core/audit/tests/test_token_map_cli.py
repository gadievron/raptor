"""raptor-audit token-map subcommand: project / drift / sweep.

Handler-level tests via the same SourceFileLoader pattern as the other
raptor-audit CLI batteries — the subcommand is the operator surface
for the token-enforcement map; the substrate is pinned in
core/concepts/tests.
"""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

from core.concepts.token_map import build_token_map, save_token_map

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"

FIXTURE = (
    _REPO_ROOT / "core" / "concepts" / "tests" / "fixtures"
    / "token_php_app"
)

MODEL = {
    "token_checks": [
        {"name": "om_verify_request_stamp", "kind": "csrf",
         "provenance": "mechanical"},
    ],
}


def _load_cli():
    loader = SourceFileLoader("raptor_audit_cli_token_map", str(_SCRIPT))
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_token_map", loader,
    )
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _map_payload() -> dict:
    entries = [
        {"entry": p.name, "file": f"web/{p.name}"}
        for p in sorted((FIXTURE / "web").glob("*.php"))
    ]
    return build_token_map(MODEL, entries, FIXTURE)


def _fresh_caches():
    from core.concepts.audit_bridge import _load_cached, _token_map_for_run
    _token_map_for_run.cache_clear()
    _load_cached.cache_clear()


class TestProject:
    def test_projects_and_reports_census(self, tmp_path, capsys):
        _fresh_caches()
        mod = _load_cli()
        (tmp_path / "domain-model.json").write_text(json.dumps(MODEL))
        (tmp_path / "context-map.json").write_text(json.dumps({
            "entry_points": [
                {"id": "EP-1", "file": "web/save_prefs.php", "line": 5},
                {"id": "EP-2", "file": "web/export_data.php", "line": 1},
            ],
        }))
        rc = mod.cmd_token_map(SimpleNamespace(
            token_map_action="project", out=str(tmp_path),
            target=str(FIXTURE),
        ))
        out = capsys.readouterr().out
        assert rc == 0
        assert "enforced=1" in out
        assert "not_enforced=1" in out
        assert (tmp_path / "token-map.json").is_file()

    def test_tampered_census_keys_render_inert(self, tmp_path, capsys):
        # token-map.json may pre-exist the run (ensure semantics) —
        # its census keys are untrusted content and must reach the
        # operator terminal escaped, never as raw control bytes.
        _fresh_caches()
        payload = _map_payload()
        payload["census"] = {"enforced\x1b]0;pwned\x07": 1}
        save_token_map(payload, tmp_path)
        mod = _load_cli()
        rc = mod.cmd_token_map(SimpleNamespace(
            token_map_action="project", out=str(tmp_path),
            target=str(FIXTURE),
        ))
        out = capsys.readouterr().out
        assert rc == 0
        assert "\x1b" not in out
        assert "\x07" not in out
        assert "pwned" in out  # still visible, just inert

    def test_nothing_to_project_is_a_loud_nonzero(self, tmp_path, capsys):
        _fresh_caches()
        mod = _load_cli()
        rc = mod.cmd_token_map(SimpleNamespace(
            token_map_action="project", out=str(tmp_path),
            target=str(FIXTURE),
        ))
        assert rc == 1
        assert "nothing to project" in capsys.readouterr().out


class TestDrift:
    def test_reports_changes(self, tmp_path, capsys):
        prior_dir = tmp_path / "prior"
        current_dir = tmp_path / "current"
        prior_dir.mkdir()
        current_dir.mkdir()
        prior = _map_payload()
        current = json.loads(json.dumps(prior))
        for rec in current["entries"]:
            if rec["file"] == "web/save_prefs.php":
                rec["status"] = "not_enforced"
        save_token_map(prior, prior_dir)
        save_token_map(current, current_dir)
        mod = _load_cli()
        rc = mod.cmd_token_map(SimpleNamespace(
            token_map_action="drift", prior=str(prior_dir),
            current=str(current_dir), json=False,
        ))
        out = capsys.readouterr().out
        assert rc == 0
        assert "lost_enforcement" in out
        assert "never an auto-overturn" in out

    def test_missing_map_errors(self, tmp_path, capsys):
        (tmp_path / "prior").mkdir()
        (tmp_path / "current").mkdir()
        save_token_map(_map_payload(), tmp_path / "current")
        mod = _load_cli()
        rc = mod.cmd_token_map(SimpleNamespace(
            token_map_action="drift", prior=str(tmp_path / "prior"),
            current=str(tmp_path / "current"), json=False,
        ))
        assert rc == 1
        assert "--prior" in capsys.readouterr().err


class TestSweep:
    def _finding(self):
        return {
            "id": "F-1", "status": "exploitable",
            "file": "web/options_save.php",
            "title": "bypass of om_verify_request_stamp",
        }

    def test_emits_seeds_from_confirmed_finding(self, tmp_path, capsys):
        save_token_map(_map_payload(), tmp_path)
        (tmp_path / "findings.json").write_text(json.dumps(
            [self._finding()],
        ))
        mod = _load_cli()
        rc = mod.cmd_token_map(SimpleNamespace(
            token_map_action="sweep", out=str(tmp_path),
            findings=None, finding_id=None,
        ))
        out = capsys.readouterr().out
        assert rc == 0
        assert "hypothesis seed(s)" in out
        payload = json.loads(
            (tmp_path / "sibling-hypotheses.json").read_text(),
        )
        assert {s["file"] for s in payload["seeds"]} == {
            "web/export_data.php", "web/late_check.php",
        }

    def test_no_confirmed_finding_no_seeds(self, tmp_path, capsys):
        save_token_map(_map_payload(), tmp_path)
        (tmp_path / "findings.json").write_text(json.dumps(
            [{**self._finding(), "status": "ruled_out"}],
        ))
        mod = _load_cli()
        rc = mod.cmd_token_map(SimpleNamespace(
            token_map_action="sweep", out=str(tmp_path),
            findings=None, finding_id=None,
        ))
        assert rc == 0
        assert "no seeds" in capsys.readouterr().out
        assert not (tmp_path / "sibling-hypotheses.json").exists()

    def test_existing_producer_gets_fallback_file(self, tmp_path, capsys):
        save_token_map(_map_payload(), tmp_path)
        (tmp_path / "sibling-hypotheses.json").write_text(
            '{"seeds": []}',
        )
        (tmp_path / "findings.json").write_text(json.dumps(
            [self._finding()],
        ))
        mod = _load_cli()
        rc = mod.cmd_token_map(SimpleNamespace(
            token_map_action="sweep", out=str(tmp_path),
            findings=None, finding_id=None,
        ))
        out = capsys.readouterr().out
        assert rc == 0
        assert "--hypothesis-seeds" in out
        assert (tmp_path / "token-sweep-hypotheses.json").is_file()
        assert (tmp_path / "sibling-hypotheses.json").read_text() == (
            '{"seeds": []}'
        )


class TestDispatchSurface:
    def test_subcommand_registered(self):
        src = _SCRIPT.read_text(encoding="utf-8")
        assert '"token-map": cmd_token_map' in src
        assert 'sub.add_parser(\n        "token-map"' in src
