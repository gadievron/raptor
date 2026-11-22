"""Shared synthetic fixtures for the tp_harvest tests.

Everything is synthetic: a fake target tree, a fake run dir with
``.raptor-run.json`` + ``findings.json``. No live LLM, no real corpus
content, no network.

The harvest clamps evidence provenance before classification
(``sanitise_findings_evidence``), so rows that must stay harvestable
carry genuine receipts: ``make_verified_finding`` stamps a feasibility
record (vouching for the tier channels) and a ruling-confirmation
receipt (vouching for the plain-confirmed / ruling channels) against
the test's run dir. ``make_finding`` stays receipt-less — the shape of
a planted claim.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.testing.module_state import isolated_module_state
from core.testing.tempdirs import isolated_test_dir
from core.witness import provenance

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


@pytest.fixture(autouse=True)
def _isolated_witness_mac_key(tmp_path_factory, monkeypatch):
    """Private ``XDG_DATA_HOME`` per test: fixture stamping mints with
    the witness-provenance MAC, whose key is created lazily under the
    data dir — tests must never mint against (or create) the
    operator's real key store."""
    with isolated_module_state(provenance, {"_warned_paths": set()}):
        try:
            monkeypatch.setenv(
                "XDG_DATA_HOME", str(isolated_test_dir(tmp_path_factory, "xdg")),
            )
            yield
        finally:
            monkeypatch.undo()


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


def stamp_verified(finding: dict, run_dir: Path) -> dict:
    """Stamp the receipts a finished /validate leaves on a verified
    finding, so it survives the harvest's evidence-provenance clamp."""
    feasibility = finding.get("feasibility")
    if isinstance(feasibility, dict):
        provenance.stamp_feasibility(finding, feasibility, run_dir)
    ruling = finding.get("ruling")
    if isinstance(ruling, dict):
        provenance.stamp_ruling_confirmation(finding, ruling, run_dir)
    return finding


def make_verified_finding(run_dir: Path, **overrides) -> dict:
    """A finding whose confirmation survives the provenance clamp:
    an analyzed feasibility record (verdict matching the default
    ``exploitable`` tier claims) plus stamps minted against *run_dir*."""
    finding = make_finding(**overrides)
    finding.setdefault(
        "feasibility", {"status": "analyzed", "verdict": "exploitable"})
    return stamp_verified(finding, run_dir)


@pytest.fixture
def target_tree(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "copy.c").write_text(TARGET_SOURCE, encoding="utf-8")
    return target


@pytest.fixture
def run_dir(tmp_path: Path, target_tree: Path,
            _isolated_witness_mac_key) -> Path:
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
        make_verified_finding(run),
        make_finding(
            id="FIND-2", function="main", line=9, final_status="ruled_out",
            status="ruled_out", ruling={"status": "ruled_out", "reason": "dead"},
        ),
        make_finding(
            id="FIND-3", function="main", line=10,
            final_status="confirmed_unverified", status="confirmed_unverified",
            ruling={"status": "confirmed_unverified",
                    "reason": "witness pending"},
        ),
    ]
    (run / "findings.json").write_text(
        json.dumps({"stage": "1", "findings": findings}), encoding="utf-8",
    )
    return run
