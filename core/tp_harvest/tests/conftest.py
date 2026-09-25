"""Shared synthetic fixtures for the tp_harvest tests.

Everything is synthetic: a fake target tree, a fake run dir with
``.raptor-run.json`` + ``findings.json``. No live LLM, no real corpus
content, no network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

TARGET_SOURCE = """\
#include <string.h>

void copy_name(char *dst, const char *src) {
    strcpy(dst, src);
}

int main(int argc, char **argv) {
    char buf[16];
    copy_name(buf, argv[1]);
    return 0;
}
"""

# Line of the strcpy call in TARGET_SOURCE (1-indexed).
SINK_LINE = 4


def make_finding(**overrides) -> dict:
    finding = {
        "id": "FIND-1",
        "file": "src/copy.c",
        "function": "copy_name",
        "line": SINK_LINE,
        "vuln_type": "buffer_overflow",
        "cwe_id": "CWE-121",
        "rule_id": "raptor.c.strcpy",
        "message": "strcpy into fixed buffer",
        "status": "confirmed",
        "final_status": "exploitable",
        "ruling": {"status": "exploitable", "reason": "PoC crashed under ASAN"},
        "poc": {"description": "overflow", "harmless": True},
        "proof": {"flow": ["argv[1] -> copy_name(src)", "strcpy(dst, src)"]},
    }
    finding.update(overrides)
    return finding


@pytest.fixture
def target_tree(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "copy.c").write_text(TARGET_SOURCE, encoding="utf-8")
    return target


@pytest.fixture
def run_dir(tmp_path: Path, target_tree: Path) -> Path:
    run = tmp_path / "run"
    run.mkdir()
    (run / ".raptor-run.json").write_text(
        json.dumps({
            "version": 2,
            "command": "validate",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "status": "completed",
            "target_path": str(target_tree),
        }),
        encoding="utf-8",
    )
    findings = [
        make_finding(),
        make_finding(
            id="FIND-2", function="main", line=9, final_status="ruled_out",
            status="ruled_out", ruling={"status": "ruled_out", "reason": "dead"},
        ),
        make_finding(
            id="FIND-3", function="main", line=10,
            final_status="confirmed_unverified", status="confirmed_unverified",
        ),
    ]
    (run / "findings.json").write_text(
        json.dumps({"stage": "1", "findings": findings}), encoding="utf-8",
    )
    return run
