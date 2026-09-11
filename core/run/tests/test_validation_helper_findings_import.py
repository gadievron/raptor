"""Tests for libexec/raptor-validation-helper ``--findings`` imports.

The import chokepoint must accept the canonical findings container,
a bare finding list, and the /understand --hunt variants.json
container (whose skill documents "Pass variants.json to /validate
--findings"), while degrading unrecognisable payloads to the legacy
verbatim copy. Colocated with the run-lifecycle CLI tests.
"""

import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

from core.json import load_json

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_helper():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    script = str(REPO_ROOT / "libexec" / "raptor-validation-helper")
    loader = SourceFileLoader("raptor_validation_helper", script)
    spec = importlib.util.spec_from_loader("raptor_validation_helper", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _finding(fid: str, **overrides) -> dict:
    base = {
        "id": fid,
        "file": "a.c",
        "function": "add",
        "line": 3,
        "vuln_type": "buffer_overflow",
        "status": "not_disproven",
    }
    base.update(overrides)
    return base


def _variant(vid: str, **overrides) -> dict:
    base = {
        "id": vid,
        "file": "src/query.py",
        "function": "run_query",
        "line": 31,
        "vuln_type": "sqli",
        "status": "not_disproven",
        "taint_status": "confirmed_tainted",
    }
    base.update(overrides)
    return base


class TestCoerceFindingsContainer:

    def test_canonical_container_passes_through(self):
        mod = _load_helper()
        data = {"findings": [_finding("FIND-1")], "target_path": "/t",
                "extra_key": {"kept": True}}
        container, note = mod._coerce_findings_container(data)
        assert container is data  # untouched, extra keys preserved
        assert note is None

    def test_bare_list_wrapped(self):
        mod = _load_helper()
        container, note = mod._coerce_findings_container(
            [_finding("FIND-1"), "not-a-dict"], target_path="/t")
        assert [f["id"] for f in container["findings"]] == ["FIND-1"]
        assert container["target_path"] == "/t"
        assert "bare finding list" in note

    def test_variants_container_converted(self):
        mod = _load_helper()
        data = {
            "meta": {"seed": "FIND-001 | pattern"},
            "variants": [
                _variant("VAR-001"),
                _variant("VAR-002", taint_status="false_positive"),
                _variant("VAR-003", status=None),
            ],
        }
        # Remove the explicit None status so setdefault applies.
        del data["variants"][2]["status"]
        container, note = mod._coerce_findings_container(
            data, target_path="/t")
        ids = [f["id"] for f in container["findings"]]
        # false_positive variants are audit-trail-only in variants.json
        # and documented as excluded from validation scope.
        assert ids == ["VAR-001", "VAR-003"]
        assert container["findings"][1]["status"] == "not_disproven"
        assert container["target_path"] == "/t"
        assert "1 false_positive variant(s) excluded" in note

    def test_unrecognisable_shapes_rejected(self):
        mod = _load_helper()
        for payload in (None, "text", {"neither": []},
                        {"findings": "not-a-list"}):
            container, note = mod._coerce_findings_container(payload)
            assert container is None
            assert note is None


class TestImportFindingsFile:

    def test_variants_file_imported_with_normalised_ids(self, tmp_path,
                                                        capsys):
        mod = _load_helper()
        src = tmp_path / "variants.json"
        src.write_text(json.dumps({"variants": [_variant("VAR-001")]}))
        dest = tmp_path / "findings.json"
        mod._import_findings_file(src, dest, target="/t")
        saved = load_json(dest)
        assert saved["findings"][0]["id"] == "FIND-1"
        assert saved["findings"][0]["source_id"] == "VAR-001"
        out = capsys.readouterr().out
        assert "Pre-existing findings: 1 from variants.json" in out

    def test_canonical_file_findings_unchanged(self, tmp_path, capsys):
        mod = _load_helper()
        finding = _finding("FIND-7", description="keep me")
        src = tmp_path / "exported.json"
        src.write_text(json.dumps({"findings": [finding],
                                   "target_path": "/orig"}))
        dest = tmp_path / "findings.json"
        mod._import_findings_file(src, dest, target="/other")
        saved = load_json(dest)
        # Conforming ids and the container's own target_path survive.
        assert saved["findings"] == [finding]
        assert saved["target_path"] == "/orig"
        out = capsys.readouterr().out
        assert "Pre-existing findings: 1 from exported.json" in out

    def test_unrecognisable_file_copied_verbatim(self, tmp_path, capsys):
        mod = _load_helper()
        src = tmp_path / "weird.json"
        src.write_text(json.dumps({"neither": "shape"}))
        dest = tmp_path / "findings.json"
        mod._import_findings_file(src, dest)
        assert json.loads(dest.read_text()) == {"neither": "shape"}
        captured = capsys.readouterr()
        assert "Pre-existing findings: 0 from weird.json" in captured.out
        assert "no recognisable findings/variants" in captured.err
