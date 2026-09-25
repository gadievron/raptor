"""NodeGoat manifest generator: pin, overlay wrap, label_kind contract."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.recall.manifest import parse_manifest
from core.recall.nodegoat_manifest import (
    NODEGOAT_PINNED_SHA,
    NodegoatManifestError,
    generate_manifest,
    main as ng_main,
)


@pytest.fixture
def clone(tmp_path):
    d = tmp_path / "nodegoat"
    (d / "app").mkdir(parents=True)
    (d / "server.js").write_text("// app\n", encoding="utf-8")
    return d


def _pinned(*_a, **_k):
    return SimpleNamespace(stdout=NODEGOAT_PINNED_SHA + "\n", stderr="",
                           returncode=0)


def _overlay(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "overlay.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# SYNTHETIC fixture entry — invented path/case, per the fixture
# convention (never a real suite location).
_ENTRY = {
    "id": "case-1",
    "file": "app/routes/demo-example.js",
    "line_start": 10,
    "line_end": 20,
    "cwe": "CWE-94",
    "provenance": {"kind": "benchmark", "suite": "owasp-nodegoat",
                   "case": "case-1"},
}


class TestGenerate:
    def test_overlay_wraps_into_valid_manifest(self, clone, tmp_path):
        overlay = _overlay(tmp_path, {"expected": [dict(_ENTRY)]})
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            m = generate_manifest(clone, overlay)
        parsed = parse_manifest(m)
        assert parsed.name == "owasp-nodegoat"
        assert parsed.language == "javascript"
        assert m["target"]["pinned_sha"] == NODEGOAT_PINNED_SHA
        assert m["expected"][0]["id"] == "case-1"

    def test_entry_extra_keys_carried_verbatim(self, clone, tmp_path):
        entry = dict(_ENTRY, custom_key="kept")
        overlay = _overlay(tmp_path, {"expected": [entry]})
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            m = generate_manifest(clone, overlay)
        assert m["expected"][0]["custom_key"] == "kept"

    def test_default_provenance_only_when_absent(self, clone, tmp_path):
        entry = {k: v for k, v in _ENTRY.items() if k != "provenance"}
        overlay = _overlay(tmp_path, {"expected": [entry]})
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            m = generate_manifest(clone, overlay)
        prov = m["expected"][0]["provenance"]
        assert prov == {"kind": "benchmark", "suite": "owasp-nodegoat",
                        "case": "case-1"}

    def test_declared_provenance_never_overwritten(self, clone,
                                                   tmp_path):
        entry = dict(_ENTRY, provenance={
            "kind": "cve", "cve_id": "CVE-2020-99999",
            "fix_commit": "0" * 40})
        overlay = _overlay(tmp_path, {"expected": [entry]})
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            m = generate_manifest(clone, overlay)
        assert m["expected"][0]["provenance"]["kind"] == "cve"

    def test_invalid_overlay_refused_via_schema(self, clone, tmp_path):
        entry = dict(_ENTRY, cwe="not-a-cwe")
        overlay = _overlay(tmp_path, {"expected": [entry]})
        with patch("core.recall.pinned_clone.subprocess.run", _pinned), \
                pytest.raises(NodegoatManifestError, match="CWE"):
            generate_manifest(clone, overlay)

    def test_missing_clone_refused(self, tmp_path):
        overlay = _overlay(tmp_path, {"expected": [dict(_ENTRY)]})
        with pytest.raises(NodegoatManifestError, match="acquire"):
            generate_manifest(tmp_path / "nope", overlay)

    def test_wrong_sha_refused(self, clone, tmp_path):
        overlay = _overlay(tmp_path, {"expected": [dict(_ENTRY)]})
        wrong = SimpleNamespace(stdout="0" * 40 + "\n", stderr="",
                                returncode=0)
        with patch("core.recall.pinned_clone.subprocess.run",
                   return_value=wrong), \
                pytest.raises(NodegoatManifestError, match="pinned"):
            generate_manifest(clone, overlay)

    def test_fp_only_overlay(self, clone, tmp_path):
        overlay = _overlay(tmp_path, {
            "corpus_kind": "fp-only",
            "clean_regions": [dict(_ENTRY)],
        })
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            m = generate_manifest(clone, overlay)
        assert parse_manifest(m).corpus_kind == "fp-only"


class TestLabelKindContract:
    def test_overlay_kind_carried_verbatim_and_inherited(self, clone,
                                                         tmp_path):
        overlay = _overlay(tmp_path, {
            "label_kind": "some_future_kind",
            "expected": [dict(_ENTRY)],
        })
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            m = generate_manifest(clone, overlay)
        assert m["label_kind"] == "some_future_kind"
        # kind-less entry inherits the overlay kind
        assert m["expected"][0]["label_kind"] == "some_future_kind"

    def test_entry_kind_mismatch_refused(self, clone, tmp_path):
        overlay = _overlay(tmp_path, {
            "label_kind": "kind_a",
            "expected": [dict(_ENTRY, label_kind="kind_b")],
        })
        with patch("core.recall.pinned_clone.subprocess.run", _pinned), \
                pytest.raises(NodegoatManifestError,
                              match="contradicts"):
            generate_manifest(clone, overlay)

    def test_absent_kind_never_defaulted(self, clone, tmp_path):
        overlay = _overlay(tmp_path, {"expected": [dict(_ENTRY)]})
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            m = generate_manifest(clone, overlay)
        assert "label_kind" not in m
        assert "label_kind" not in m["expected"][0]

    def test_entry_kind_without_meta_carried(self, clone, tmp_path):
        overlay = _overlay(tmp_path, {
            "expected": [dict(_ENTRY, label_kind="kind_a")],
        })
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            m = generate_manifest(clone, overlay)
        assert "label_kind" not in m
        assert m["expected"][0]["label_kind"] == "kind_a"


class TestCli:
    def test_template_mode_needs_no_clone(self, capsys):
        rc = ng_main(["--print-overlay-template"])
        assert rc == 0
        template = json.loads(capsys.readouterr().out)
        assert "expected" in template

    def test_no_overlay_names_the_local_label_step(self, capsys):
        rc = ng_main([])
        assert rc == 2
        assert "local labeling step" in capsys.readouterr().err

    def test_end_to_end(self, clone, tmp_path, capsys):
        overlay = _overlay(tmp_path, {"expected": [dict(_ENTRY)]})
        out = tmp_path / "nodegoat.json"
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            rc = ng_main(["--clone-dir", str(clone),
                          "--labels-overlay", str(overlay),
                          "--out", str(out)])
        assert rc == 0
        assert json.loads(out.read_text())["name"] == "owasp-nodegoat"
        assert "1 expected" in capsys.readouterr().out
