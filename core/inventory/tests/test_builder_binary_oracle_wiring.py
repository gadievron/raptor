"""The identity-pin channel's ONLY production wiring.

``build_inventory`` passing
``identity_pins=RaptorConfig.BINARY_ORACLE_IDENTITY_PINS`` into the
binary-oracle enrichment is the single line that connects the load
seam's fd-honest witness verification (which fills the RaptorConfig
channel) to the classify-pass bracket (which consumes it). Dropping
the argument disables the whole seam while every unit test of either
side stays green — so the wiring itself is pinned here.
"""

from __future__ import annotations

from unittest.mock import patch

from core.config import RaptorConfig
from core.inventory.builder import build_inventory

_ORACLE_FIELDS = (
    "BINARY_ORACLE_PATHS",
    "BINARY_ORACLE_NO_SUPPRESS",
    "BINARY_ORACLE_DECLARED",
    "BINARY_ORACLE_IDENTITY_PINS",
)


class TestBinaryOracleWiring:
    def test_build_inventory_passes_the_identity_pins_channel(
            self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "a.c").write_text("int live_fn(void) { return 1; }\n")

        calls: list[dict] = []

        def recorder(inventory, binaries, **kwargs):
            calls.append(kwargs)
            return {}

        pins_value = {"/some/bin": (1, 2, 3, "0" * 64)}
        prev = tuple(getattr(RaptorConfig, f) for f in _ORACLE_FIELDS)
        try:
            RaptorConfig.BINARY_ORACLE_PATHS = ("/some/bin",)
            RaptorConfig.BINARY_ORACLE_NO_SUPPRESS = ()
            RaptorConfig.BINARY_ORACLE_DECLARED = ()
            RaptorConfig.BINARY_ORACLE_IDENTITY_PINS = pins_value
            with patch("core.analysis.binary_oracle."
                       "enrich_inventory_with_binary_oracle",
                       side_effect=recorder):
                build_inventory(str(repo),
                                output_dir=str(tmp_path / "out"))
        finally:
            for f, v in zip(_ORACLE_FIELDS, prev):
                setattr(RaptorConfig, f, v)

        assert len(calls) == 1, "enrichment was not invoked"
        assert calls[0].get("identity_pins") == pins_value, (
            "build_inventory must wire "
            "RaptorConfig.BINARY_ORACLE_IDENTITY_PINS into the "
            "enrichment's identity_pins parameter")
