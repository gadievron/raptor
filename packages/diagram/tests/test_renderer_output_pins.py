"""Rendered-output pins for renderer.py behavior worth keeping.

These drive the real render entry (render_and_write → diagrams.md
content) and pin what the OUTPUT must contain: the em-dash section
headings, the disproven.json envelope unwrap surfacing why-wrong text,
and unwrap_list picking the KNOWN payload key of a metadata-first
attack-paths envelope instead of whichever value comes first.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..renderer import render_and_write


def _write(out_dir: Path, name: str, payload: object) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / name).write_text(json.dumps(payload), encoding="utf-8")


def _render(out_dir: Path) -> str:
    path = render_and_write(out_dir, target="pin-target")
    assert path == out_dir / "diagrams.md"
    return path.read_text(encoding="utf-8")


def test_hypotheses_em_dash_heading_appears_verbatim(tmp_path: Path) -> None:
    _write(tmp_path, "hypotheses.json", {"hypotheses": [{
        "id": "H1",
        "finding": "F1",
        "claim": "user length reaches memcpy unchecked",
        "status": "confirmed",
        "predictions": [{
            "id": "P1", "prediction": "crash at 64 bytes",
            "result": "crashed", "status": "confirmed",
        }],
    }]})

    out = _render(tmp_path)
    assert "## Hypotheses — Evidence Chain" in out
    assert "Hypotheses -- Evidence Chain" not in out
    assert "Hypotheses, Evidence Chain" not in out


def test_disproven_envelope_unwrap_reaches_attack_tree_labels(
        tmp_path: Path) -> None:
    _write(tmp_path, "attack-tree.json", {
        "root": "ROOT",
        "nodes": [
            {"id": "ROOT", "goal": "compromise service",
             "status": "exploring"},
            {"id": "F1", "goal": "overflow parse buffer",
             "status": "disproven", "parent": "ROOT"},
        ],
    })
    # The dict envelope shape _load_disproven exists to unwrap.
    _write(tmp_path, "disproven.json", {"disproven": [{
        "finding": "F1",
        "why_wrong": "input is length-capped upstream",
    }]})

    out = _render(tmp_path)
    assert "## Attack Tree" in out
    assert "ruled out: input is length-capped upstream" in out


class TestUnwrapListEnvelopeSelection:
    """A metadata-first envelope must not out-rank the payload key."""

    _PATH = {
        "id": "PATH-1",
        "name": "Overflow chain",
        "proximity": 5,
        "status": "uncertain",
        "steps": [
            {"type": "call", "description": "read attacker frame"},
            {"type": "sink", "description": "memcpy into fixed buffer"},
        ],
    }

    def test_poison_non_list_first_value_is_ignored(
            self, tmp_path: Path) -> None:
        _write(tmp_path, "attack-paths.json", {
            "metadata": {"generator": "poison", "note": "not the payload"},
            "attack_paths": [self._PATH],
        })

        out = _render(tmp_path)
        assert "## Attack Paths" in out
        assert "PATH-1: Overflow chain" in out
        assert "read attacker frame" in out
        assert "memcpy into fixed buffer" in out

    def test_wrong_list_first_value_is_ignored(self, tmp_path: Path) -> None:
        _write(tmp_path, "attack-paths.json", {
            "provenance": ["stamp-not-a-path"],
            "attack_paths": [self._PATH],
        })

        out = _render(tmp_path)
        assert "PATH-1: Overflow chain" in out
        assert "memcpy into fixed buffer" in out
        # The metadata list must not be rendered as the path set.
        assert "stamp-not-a-path" not in out
