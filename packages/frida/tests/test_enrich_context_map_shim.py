"""Skip-silent contract of libexec/raptor-enrich-context-map-frida.

The shim is a best-effort enricher: an oversize, malformed, or
non-object context-map must not fail the calling pipeline — it skips
(exit 0) and leaves the file untouched. Executed in-process via runpy
so the shared read-cap constant can be monkeypatched to a test-sized
value (a real cap-sized fixture would be tens of MiB).
"""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-enrich-context-map-frida"


def _run_shim(workdir: Path, monkeypatch) -> int:
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(workdir)])
    try:
        with patch.object(sys, "path", sys.path.copy()):
            runpy.run_path(str(SCRIPT), run_name="__main__")
    except SystemExit as e:
        return int(e.code or 0)
    return 0


def test_oversize_context_map_skips_silently(tmp_path, monkeypatch):
    import core.artifacts.context_map_budget as cmb
    monkeypatch.setattr(cmb, "CONTEXT_MAP_CONSUMER_MAX_BYTES", 16)
    ctx_path = tmp_path / "context-map.json"
    content = json.dumps({"entry_points": [], "padding": "x" * 64})
    assert len(content) > 16
    ctx_path.write_text(content)

    assert _run_shim(tmp_path, monkeypatch) == 0
    assert ctx_path.read_text() == content  # untouched


def test_malformed_context_map_skips_silently(tmp_path, monkeypatch):
    ctx_path = tmp_path / "context-map.json"
    ctx_path.write_text("{not json")

    assert _run_shim(tmp_path, monkeypatch) == 0
    assert ctx_path.read_text() == "{not json"


def test_non_object_context_map_skips_silently(tmp_path, monkeypatch):
    ctx_path = tmp_path / "context-map.json"
    ctx_path.write_text("[]")

    assert _run_shim(tmp_path, monkeypatch) == 0
    assert ctx_path.read_text() == "[]"
