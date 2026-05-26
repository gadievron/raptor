"""Tests for ``packages.sca.llm.exemplars``."""

from __future__ import annotations

from packages.sca.llm.exemplars import (
    exfil_destinations_block,
    exemplar_blocks_for_supply_chain,
    popular_names_block,
)


def test_popular_names_block_npm():
    block = popular_names_block("npm")
    assert block is not None
    assert block.kind == "EXEMPLAR_POPULAR_NAMES"
    assert "lodash" in block.content or "react" in block.content


def test_popular_names_block_pypi():
    block = popular_names_block("PyPI")
    assert block is not None
    assert "PyPI" in block.content


def test_popular_names_block_unknown_ecosystem():
    block = popular_names_block("FortranPM")
    assert block is None


def test_exfil_destinations_block_loads():
    block = exfil_destinations_block()
    assert block is not None
    assert block.kind == "EXEMPLAR_EXFIL_DESTINATIONS"
    assert "paste" in block.content or "tor" in block.content


def test_exfil_block_contains_categories():
    block = exfil_destinations_block()
    assert block is not None
    assert "paste:" in block.content
    assert "tor:" in block.content


def test_exemplar_blocks_for_supply_chain_returns_both():
    blocks = exemplar_blocks_for_supply_chain("npm")
    kinds = {b.kind for b in blocks}
    assert "EXEMPLAR_POPULAR_NAMES" in kinds
    assert "EXEMPLAR_EXFIL_DESTINATIONS" in kinds


def test_exemplar_blocks_for_unknown_ecosystem_still_has_exfil():
    blocks = exemplar_blocks_for_supply_chain("FortranPM")
    kinds = {b.kind for b in blocks}
    assert "EXEMPLAR_POPULAR_NAMES" not in kinds
    assert "EXEMPLAR_EXFIL_DESTINATIONS" in kinds
