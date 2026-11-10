"""Bounded coverage lists disclose omitted detail without changing evidence."""
from copy import deepcopy

from core.reporting.renderers import render_document
from packages.sca.sbom_inventory.model import Inventory, Record
from packages.sca.sbom_inventory.reporting import build_sbom_report
from packages.sca.sbom_inventory.tests.test_verification import verify


def test_verification_declares_coverage_gap_detail_limit():
    inventory = Inventory("owned fixture", "c" * 64, records=[
        Record("one", "one", "1", "library", purl="pkg:npm/one@1"),
        Record("two", "two", "1", "library", purl="pkg:npm/two@1"),
    ])
    payload = verify(inventory, coverage={})
    before = deepcopy(payload)
    assert len(payload["coverage"]["uncovered_packages"]) == 2
    context, document = build_sbom_report("verify-plan", payload=payload, limit=1)
    text = render_document(document).content.decode()
    assert "Showing 1 of 2 recorded coverage gaps" in text
    gaps = next(block for block in document.blocks if block.title == "Unavailable coverage")
    assert len(gaps.items) == 1
    assert context.extensions["raptor.result"] == before and payload == before
    assert context.state == "partial" and payload["exit_code"] == 2
    _, full = build_sbom_report("verify-plan", payload=payload, limit=None)
    full_gaps = next(block for block in full.blocks if block.title == "Unavailable coverage")
    assert len(full_gaps.items) == 2
    assert "recorded coverage gaps" not in render_document(full).content.decode()
