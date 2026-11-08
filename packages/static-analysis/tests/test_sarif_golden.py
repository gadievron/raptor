"""Byte-level golden tests for the static-analysis SARIF emitters.

Same hyphenated-package importlib pattern as the other scanner tests.

SARIF artifacts are written with ``save_json(sort_keys=False)``, so
dict insertion order is the on-disk byte order. The golden files were
captured from the emitters BEFORE they moved onto ``core.sarif.emit``;
these tests pin the shared-skeleton output bytes, including member order.
Intentional location fixes update only the affected expected regions;
normal-location cases continue to pin their existing bytes.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if __name__ == "__main__":
    if _REPO_ROOT not in sys.path:
        sys.path.insert(0, _REPO_ROOT)

from core.testing.module_registry import fresh_module_tree

_PKG_DIR = Path(__file__).resolve().parents[1]
_DATA = Path(__file__).parent / "data"


@pytest.fixture(autouse=True)
def _golden_module_scope():
    with fresh_module_tree("compiler_scan_golden_test"), fresh_module_tree("scanner_golden_test"):
        yield


def _load(name: str, filename: str):
    mod = sys.modules.get(name)
    if mod is not None:
        return mod
    spec = importlib.util.spec_from_file_location(name, _PKG_DIR / filename)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    with patch.object(sys, "path", sys.path.copy()):
        spec.loader.exec_module(mod)
    return mod


def _golden(filename: str) -> str:
    return (_DATA / filename).read_text(encoding="utf-8")


def _dumps(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=False) + "\n"


def test_compiler_scan_sarif_byte_identical_to_golden():
    """Covers: rule dedup (first finding defines the rule), CWE rule
    properties + tags, CWE-less rule (no properties member), empty
    message (default text), per-result compiler/cwe properties."""
    cs = _load("compiler_scan_golden_test", "compiler_scan.py")
    result = cs.CompilerScanResult(
        ok=True, tus_total=3, tus_analyzed=3, findings=[
            {"rule_id": "-Wanalyzer-null-dereference", "cwe": "CWE-476",
             "file": "src/a.c", "line": 12,
             "message": "dereference of NULL 'p'", "compiler": "gcc"},
            {"rule_id": "-Wanalyzer-null-dereference", "cwe": "CWE-476",
             "file": "src/b.c", "line": 40, "message": "", "compiler": "gcc"},
            {"rule_id": "core.CallAndMessage", "file": "src/c.cc", "line": 7,
             "message": "uninitialized argument", "compiler": "clang"},
        ],
    )
    assert _dumps(cs.to_sarif(result)) == _golden(
        "compiler_scan_sarif_golden.json")


def _stage_inputs() -> list[tuple[str, dict]]:
    return [
        ("wrap-src-1", {"rule_id": "srcwrap:wrap-src-1", "file": "src/a.java",
                        "line": 3, "line_end": 9,
                        "message": "wrapper taints return"}),
        ("wrap-src-1", {"file": "src/b.java", "start_line": 5,
                        "end_line": 6, "message": ""}),
        ("wrap-sink-2.sink", {"rule_id": "other:wrap-sink-2.sink",
                              "path": "src/c.java", "level": "error",
                              "message": "sink hit"}),
        ("bare", {}),
    ]


def test_stage_findings_sarif_byte_identical_to_golden():
    """Covers: ruleId prefixing (present / re-prefixed / synthesized),
    cwe_by_suffix rule properties, file/path and line/start_line
    aliases, level override, and unknown locations without invented lines."""
    sc = _load("scanner_golden_test", "scanner.py")
    doc = sc._stage_findings_to_sarif(
        _stage_inputs(), tool_name="raptor-srcwrap", rule_prefix="srcwrap",
        cwe_by_suffix={".sink": "CWE-89"},
    )
    assert _dumps(doc) == _golden("stage_sarif_golden.json")


def _graduated_inputs() -> list[tuple[str, dict]]:
    return [
        ("lib-rule-1", {"rule_id": "llm-kebab-rule", "file": "src/a.py",
                        "line": 12, "message": "graduated hit",
                        "level": "error"}),
        ("lib-rule-1", {"file": "src/b.py", "line": 0, "message": ""}),
        ("lib-rule-2", {"rule_id": "another-kebab", "file": "src/c.py",
                        "line": 3, "message": "second rule"}),
    ]


def test_graduated_findings_sarif_byte_identical_to_golden():
    """Covers: synthesized: rule-id prefix + dedup, default message,
    unknown line, semgrep-internal rule id preserved in properties."""
    sc = _load("scanner_golden_test", "scanner.py")
    doc = sc._graduated_findings_to_sarif(_graduated_inputs())
    assert _dumps(doc) == _golden("graduated_sarif_golden.json")
