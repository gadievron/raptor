"""Wiring tests: block_sibling_analysis + dispatch_completeness feed
the mechanical-detector pass.

Both modules shipped complete public APIs (unit-tested in their own
files) but had no production caller — their findings never reached
mechanical-findings.json or the review prompt. These tests exercise
the real ``_run_mechanical_detectors`` seam on tmp_path fixtures.

Hermetic: no LLM, no Joern (server=None), no Coccinelle needed (the
standing-cocci leg is try/except'd and only walks C files).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

# Four-branch if/elif chain: three branches validate, the fourth
# doesn't — the block-level sibling outlier shape.
_BLOCK_SIBLING_SRC = textwrap.dedent('''\
    def route_request(kind, payload):
        if kind == "create":
            validate(payload)
            audit_log(kind)
            return do_create(payload)
        elif kind == "update":
            validate(payload)
            audit_log(kind)
            return do_update(payload)
        elif kind == "replace":
            validate(payload)
            audit_log(kind)
            return do_replace(payload)
        elif kind == "delete":
            return do_delete(payload)
''')

# Dict dispatch table missing a key another function produces.
_DISPATCH_GAP_SRC = textwrap.dedent('''\
    HANDLERS = {
        "python": handle_python,
        "java": handle_java,
        "go": handle_go,
    }


    def detect_language(path):
        if path.endswith(".py"):
            return "python"
        if path.endswith(".java"):
            return "java"
        if path.endswith(".go"):
            return "go"
        if path.endswith(".rs"):
            return "rust"
''')


def _run_detectors(tmp_path: Path, files: dict[str, str], gaps: list[dict]):
    from core.audit.orchestrator import (
        OrchestratorConfig,
        _run_mechanical_detectors,
    )

    target = tmp_path / "target"
    target.mkdir()
    for rel, src in files.items():
        (target / rel).write_text(src)
    out = tmp_path / "out"
    out.mkdir()

    config = OrchestratorConfig(target_path=target, out_dir=out)
    findings, _clean = _run_mechanical_detectors(gaps, config)
    return findings


class TestBlockSiblingWiring:
    def test_branch_outlier_reaches_mechanical_findings(self, tmp_path):
        findings = _run_detectors(
            tmp_path,
            {"router.py": _BLOCK_SIBLING_SRC},
            [{
                "file": "router.py",
                "name": "route_request",
                "line_start": 1,
                "line_end": 15,
            }],
        )
        entries = findings.get("router.py:route_request", [])
        block = [
            e for e in entries if e.get("detector") == "block_sibling"
        ]
        assert block, f"no block_sibling finding: {findings}"
        assert any("validates_input" in e["description"] for e in block)

    def test_uniform_branches_produce_no_block_finding(self, tmp_path):
        uniform = _BLOCK_SIBLING_SRC.replace(
            '    elif kind == "delete":\n        return do_delete(payload)\n',
            '    elif kind == "delete":\n'
            '        validate(payload)\n'
            '        audit_log(kind)\n'
            '        return do_delete(payload)\n',
        )
        findings = _run_detectors(
            tmp_path,
            {"router.py": uniform},
            [{
                "file": "router.py",
                "name": "route_request",
                "line_start": 1,
                "line_end": 17,
            }],
        )
        entries = findings.get("router.py:route_request", [])
        assert not any(
            e.get("detector") == "block_sibling" for e in entries
        )


class TestDispatchCompletenessWiring:
    def test_missing_key_reaches_mechanical_findings(self, tmp_path):
        findings = _run_detectors(
            tmp_path,
            {"handlers.py": _DISPATCH_GAP_SRC},
            [{
                "file": "handlers.py",
                "name": "detect_language",
                "line_start": 8,
                "line_end": 15,
            }],
        )
        dispatch = [
            e
            for entries in findings.values()
            for e in entries
            if e.get("detector") == "dispatch_gap"
        ]
        assert dispatch, f"no dispatch_gap finding: {findings}"
        assert any("'rust'" in e["description"] for e in dispatch)

    def test_complete_table_produces_no_dispatch_finding(self, tmp_path):
        complete = _DISPATCH_GAP_SRC.replace(
            '    "go": handle_go,\n',
            '    "go": handle_go,\n    "rust": handle_rust,\n',
        )
        findings = _run_detectors(
            tmp_path,
            {"handlers.py": complete},
            [{
                "file": "handlers.py",
                "name": "detect_language",
                "line_start": 9,
                "line_end": 16,
            }],
        )
        assert not any(
            e.get("detector") == "dispatch_gap"
            for entries in findings.values()
            for e in entries
        )
