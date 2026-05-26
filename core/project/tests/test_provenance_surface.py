"""E2E: `/project provenance` rollup and `/project show <run>` render real run
directories (with real .raptor-run.json manifests) through the cli helpers."""

import json
from pathlib import Path

from core.project.cli import _print_provenance, _print_run_provenance


class _StubProject:
    """Minimal project: the cli helpers only need .name + .get_run_dirs()."""

    def __init__(self, name, runs):
        self.name = name
        self._runs = runs

    def get_run_dirs(self, sweep=False):
        return self._runs


def _mk_run(parent: Path, name: str, manifest: dict, *,
            command: str = "scan", status: str = "completed") -> Path:
    d = parent / name
    d.mkdir()
    (d / ".raptor-run.json").write_text(json.dumps({
        "version": 2, "command": command, "status": status,
        "timestamp": "2026-05-25T10:00:00+00:00", "manifest": manifest,
    }))
    return d


def test_provenance_rollup_and_show(tmp_path, capsys):
    r1 = _mk_run(tmp_path, "scan-1", {
        "source_control": {"base_sha": "9668aa8c3b0f", "dirty": True},
        "environment": {"python": "3.14.4", "os": "Linux", "arch": "x86_64"},
        "engines": {"semgrep": "1.79.0"},
        "deterministically_reproducible": True,
    })
    r2 = _mk_run(tmp_path, "agentic-1", {
        "source_control": {"base_sha": "9668aa8c3b0f", "dirty": True},
        "models": [{"alias": "gemini-2.5-pro", "resolved": "gemini-2.5-pro",
                    "role": "primary", "calls": 5}],
        "deterministically_reproducible": False,
    }, command="agentic")
    proj = _StubProject("demo", [r1, r2])

    # Rollup across runs.
    _print_provenance(proj)
    out = capsys.readouterr().out
    assert "Provenance across 2 run" in out
    assert "9668aa8c3b0f (2)" in out          # same SHA, both runs
    assert "Modified-tree runs: 2/2" in out
    assert "1 deterministic, 1 LLM-mediated" in out

    # Per-run detail.
    _print_run_provenance(proj, "agentic-1")
    out = capsys.readouterr().out
    assert "Run: agentic-1" in out
    assert "gemini-2.5-pro" in out
    assert "no (LLM-mediated)" in out

    # Substring match.
    _print_run_provenance(proj, "scan")
    assert "Run: scan-1" in capsys.readouterr().out

    # Missing run — graceful, no crash.
    _print_run_provenance(proj, "nonexistent")
    assert "No run matching" in capsys.readouterr().out


def test_show_run_with_no_manifest_is_graceful(tmp_path, capsys):
    d = tmp_path / "legacy-run"
    d.mkdir()
    (d / ".raptor-run.json").write_text(json.dumps(
        {"version": 1, "command": "scan", "status": "completed"}))  # no manifest
    _print_run_provenance(_StubProject("demo", [d]), "legacy-run")
    out = capsys.readouterr().out
    assert "Run: legacy-run" in out
    assert "no provenance manifest" in out
