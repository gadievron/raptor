"""Stage C gadget-oracle fact attachment (PHP gadget-surface facts).

The prep annotates deserialization-shaped findings with hint-tier,
census-qualified gadget evidence from gadget-chains.json — advisory
like include_facts, never a status writer. Colocated with the other
validation-helper prep tests.
"""

import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_helper():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    script = str(REPO_ROOT / "libexec" / "raptor-validation-helper")
    loader = SourceFileLoader("raptor_validation_helper", script)
    spec = importlib.util.spec_from_loader(
        "raptor_validation_helper", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _report():
    return {
        "tier": "hint",
        "target_path": "/srv/app",
        "census": {"complete": True, "php_files": 4,
                   "parsed_clean": 4, "incomplete_reasons": []},
        "chains": [{
            "class": "TempLogger", "file": "lib/logger.php",
            "magic_method": "__destruct", "line": 4,
            "trigger": "unserialize", "steps": [],
            "property_path": "path",
            "sink": {"category": "file", "callee": "unlink",
                     "line": 5, "excerpt": "unlink($this->path)"},
            "availability": "not_established",
        }],
        "unserialize_sites": [{
            "file": "handler.php", "line": 2,
            "request_derived": True, "excerpt": "($_COOKIE['s'])",
        }],
    }


def _findings(*rows, status="not_disproven"):
    return {"findings": [
        {"id": f"FIND-{i}", "line": 1, "status": status, **row}
        for i, row in enumerate(rows, 1)
    ]}


class TestAttachGadgetFacts:
    def test_attaches_to_cwe502_finding(self, tmp_path):
        mod = _load_helper()
        (tmp_path / "gadget-chains.json").write_text(
            json.dumps(_report()))
        data = _findings(
            {"file": "handler.php", "cwe": "CWE-502"},
            {"file": "handler.php", "cwe": "CWE-89",
             "title": "sql injection"},
        )
        mod._attach_gadget_facts(str(tmp_path), data, target="/srv/app")
        f1, f2 = data["findings"]
        facts = f1["gadget_facts"]
        assert facts["tier"] == "hint"
        assert facts["chains_total"] == 1
        assert facts["unserialize_sites_in_file"][0]["line"] == 2
        assert facts["qualifier"]
        # non-deserialization finding: untouched
        assert "gadget_facts" not in f2

    def test_prose_shape_matches_without_cwe(self, tmp_path):
        mod = _load_helper()
        (tmp_path / "gadget-chains.json").write_text(
            json.dumps(_report()))
        data = _findings({
            "file": "handler.php",
            "title": "object injection via unserialize of cookie",
        })
        mod._attach_gadget_facts(str(tmp_path), data, target="/srv/app")
        assert "gadget_facts" in data["findings"][0]

    def test_status_never_written(self, tmp_path):
        mod = _load_helper()
        (tmp_path / "gadget-chains.json").write_text(
            json.dumps(_report()))
        data = _findings({"file": "handler.php", "cwe": "CWE-502"})
        mod._attach_gadget_facts(str(tmp_path), data, target="/srv/app")
        assert data["findings"][0]["status"] == "not_disproven"

    def test_disproven_findings_skipped(self, tmp_path):
        mod = _load_helper()
        (tmp_path / "gadget-chains.json").write_text(
            json.dumps(_report()))
        data = _findings({"file": "handler.php", "cwe": "CWE-502"},
                         status="disproven")
        mod._attach_gadget_facts(str(tmp_path), data, target="/srv/app")
        assert "gadget_facts" not in data["findings"][0]

    def test_missing_artifact_is_silent(self, tmp_path):
        mod = _load_helper()
        data = _findings({"file": "handler.php", "cwe": "CWE-502"})
        mod._attach_gadget_facts(str(tmp_path), data, target="/srv/app")
        assert "gadget_facts" not in data["findings"][0]

    def test_chain_file_finding_gets_file_scoped_chains(self, tmp_path):
        mod = _load_helper()
        (tmp_path / "gadget-chains.json").write_text(
            json.dumps(_report()))
        data = _findings({"file": "lib/logger.php", "cwe": "CWE-502"})
        mod._attach_gadget_facts(str(tmp_path), data, target="/srv/app")
        facts = data["findings"][0]["gadget_facts"]
        assert facts["chains_in_file"][0]["class"] == "TempLogger"

    def test_absolute_paths_resolve_via_target_prefix_only(
            self, tmp_path):
        mod = _load_helper()
        (tmp_path / "gadget-chains.json").write_text(
            json.dumps(_report()))
        data = _findings(
            {"file": "/srv/app/lib/logger.php", "cwe": "CWE-502"},
            {"file": "/elsewhere/lib/logger.php", "cwe": "CWE-502"},
        )
        mod._attach_gadget_facts(str(tmp_path), data, target="/srv/app")
        f1, f2 = data["findings"]
        assert (f1["gadget_facts"]["chains_in_file"][0]["class"]
                == "TempLogger")
        # Foreign absolute path — refused, never another tree's facts.
        assert "gadget_facts" not in f2

    def test_schema_valid_finding_with_gadget_facts(self, tmp_path):
        mod = _load_helper()
        (tmp_path / "gadget-chains.json").write_text(
            json.dumps(_report()))
        data = _findings({"file": "handler.php", "cwe": "CWE-502"})
        mod._attach_gadget_facts(str(tmp_path), data, target="/srv/app")
        from packages.exploitability_validation.schemas import (
            validate_findings,
        )
        payload = {"stage": "C", "findings": [{
            "id": "FIND-0001", "file": "handler.php", "function": "f",
            "line": 1, "vuln_type": "deserialization",
            "status": "not_disproven",
            "gadget_facts": data["findings"][0]["gadget_facts"]}]}
        valid, errors = validate_findings(payload)
        assert valid, errors

    def test_no_target_fails_closed(self, tmp_path):
        # One-target rule: without a usable run target the artifact
        # could belong to any tree — the gate refuses, never guesses.
        mod = _load_helper()
        (tmp_path / "gadget-chains.json").write_text(
            json.dumps(_report()))
        data = _findings({"file": "handler.php", "cwe": "CWE-502"})
        mod._attach_gadget_facts(str(tmp_path), data)
        assert "gadget_facts" not in data["findings"][0]

    def test_foreign_target_artifact_refused(self, tmp_path):
        # A shared --out holding another tree's artifact must never
        # attach that tree's chains/absence census to this run.
        mod = _load_helper()
        (tmp_path / "gadget-chains.json").write_text(
            json.dumps(_report()))
        data = _findings({"file": "handler.php", "cwe": "CWE-502"})
        mod._attach_gadget_facts(str(tmp_path), data,
                                 target="/srv/other-app")
        assert "gadget_facts" not in data["findings"][0]

    def test_tampered_artifact_strings_bounded(self, tmp_path):
        mod = _load_helper()
        report = _report()
        report["chains"][0]["class"] = "X" * 50_000
        report["chains"][0]["file"] = "handler.php"
        (tmp_path / "gadget-chains.json").write_text(
            json.dumps(report))
        data = _findings({"file": "handler.php", "cwe": "CWE-502"})
        mod._attach_gadget_facts(str(tmp_path), data, target="/srv/app")
        facts = data["findings"][0]["gadget_facts"]
        assert len(facts["chains_in_file"][0]["class"]) <= 256
