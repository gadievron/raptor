"""An explicit unknown tier cannot ground a static broken-hop refutation."""

from core.dataflow.structural_validator import validate_structurally


def test_unknown_explicit_tiers_cannot_refute_hops(tmp_path):
    (tmp_path / "app.py").write_text(
        "def first(value):\n    return value\n\n"
        "def second(value):\n    return value\n"
    )
    path = {
        "source": {"file": "app.py", "line": 2},
        "sink": {"file": "app.py", "line": 5},
    }
    # Preserve the legacy producer without tier metadata and the explicit
    # static contract. Only inert fixture parsing is performed.
    assert validate_structurally(path, tmp_path, language="python").refuted
    path["source"]["properties"] = {"tier": "resolved_static"}
    assert validate_structurally(path, tmp_path, language="python").refuted
    for tier in (3, True, False, None, "", [], {}, "future-tier"):
        path["source"]["properties"]["tier"] = tier
        result = validate_structurally(path, tmp_path, language="python")
        assert result.verdict == "inconclusive", repr(tier)
        assert not result.refuted
        assert result.evidence[0]["link_tier_gated"] is True
