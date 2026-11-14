"""One malformed sidecar identifier must not hide healthy siblings."""
import json

import pytest

from core.recall.env_overlay import SIDECAR_SUFFIX, load_overlay


@pytest.mark.parametrize("identifier", [["owned"], {"id": "owned"}, 7, True])
def test_non_string_sidecar_id_does_not_hide_healthy_sibling(tmp_path, identifier):
    payloads = {
        "a-malformed": {"cve_id": identifier, "verification": "env-verified"},
        "b-healthy": {"cve_id": "CVE-2026-12345", "verification": "env-verified"},
    }
    for name, data in payloads.items():
        (tmp_path / (name + SIDECAR_SUFFIX)).write_text(json.dumps(data))
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    assert load_overlay(tmp_path) == {"CVE-2026-12345": payloads["b-healthy"]}
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


def test_nonempty_string_id_and_forward_tier_remain_unchanged(tmp_path):
    row = {"cve_id": "owned-future-id", "verification": "owned-future-tier"}
    (tmp_path / ("owned" + SIDECAR_SUFFIX)).write_text(json.dumps(row))
    assert load_overlay(tmp_path) == {"owned-future-id": row}
