"""CLI profile override: closed vocabulary + LLM cost gate."""

from __future__ import annotations

import json
from pathlib import Path

from core.recall.cli import main


def _manifest(tmp_path: Path, profile: str = "scan") -> Path:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    m = tmp_path / "m.json"
    m.write_text(json.dumps({
        "schema_version": 1,
        "name": "profile-gate-fixture",
        "target": {"repo_url": "https://x/y",
                   "pinned_sha": "a" * 40,
                   "local_path": str(target)},
        "language": "java",
        "profile": profile,
        "tolerance": {"line_drift": 2, "cwe_family_match": True},
        "expected": [{
            "id": "e1", "file": "src/A.java",
            "line_start": None, "line_end": None,
            "cwe": "CWE-89",
            "provenance": {"kind": "benchmark", "suite": "s",
                           "case": "c1"},
        }],
        "clean_regions": [],
    }), encoding="utf-8")
    return m


class TestProfileOverrideGate:
    def test_unknown_override_refused(self, tmp_path, capsys):
        # Refusal semantics survive the new profile: an unknown name
        # exits 2 before any run starts, listing the closed vocabulary.
        rc = main(["run", "--manifest", str(_manifest(tmp_path)),
                   "--profile", "agentic_taint"])
        assert rc == 2
        err = capsys.readouterr().err
        assert "unknown profile" in err
        assert "agentic-taint" in err  # the vocabulary names it

    def test_agentic_taint_override_needs_allow_llm(self, tmp_path,
                                                    capsys):
        # agentic-taint runs the full agentic LLM pipeline; the cost
        # gate applies to it exactly as to agentic.
        rc = main(["run", "--manifest", str(_manifest(tmp_path)),
                   "--profile", "agentic-taint"])
        assert rc == 2
        assert "--allow-llm" in capsys.readouterr().err

    def test_manifest_profile_agentic_taint_needs_allow_llm(
            self, tmp_path, capsys):
        rc = main(["run", "--manifest",
                   str(_manifest(tmp_path, profile="agentic-taint"))])
        assert rc == 2
        assert "--allow-llm" in capsys.readouterr().err
