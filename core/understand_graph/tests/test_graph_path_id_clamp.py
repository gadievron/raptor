"""Graph-path compound-id clamp — mint-side length bounding.

``_path_item`` mints ``graph-path-<ep_id>-<sink_id>`` from two
LLM-authored graph node ids that ingest neutralises for charset but
never for length, so an honest pair of verbose node ids can compose
past the downstream Mermaid id bound (``packages/diagram/sanitize.
ID_MAX_LEN`` = 128), where distinct long ids silently collapse into
one rendered node. The mint-side clamp bounds the COMPOSED id with a
truncate+hash-suffix scheme that keeps long compounds distinct and
leaves every short honest compound byte-identical. Length-bounding
only: no row is ever dropped, refused, or renamed away from its short
honest form; the component ids stay verbatim in the entry/sink
sub-objects.
"""

from typing import Any

from packages.diagram.sanitize import ID_MAX_LEN, sanitize_id

from core.understand_graph.queries import _path_item


def _mint(ep_id: str, sink_id: str) -> dict[str, Any]:
    return _path_item(
        {},
        ep_id,
        {"id": ep_id, "name": "entry"},
        sink_id,
        {"id": sink_id, "name": "sink"},
        [],
        [],
        set(),
    )


# Two honest-verbose ~70-char node ids: the compound exceeds 128.
_LONG_EP = "EP-" + "handler-segment-" * 4 + "alpha"
_LONG_SINK = "SINK-" + "query-builder-segment-" * 3 + "omega"


# ---------------------------------------------------------------------------
# Red at pre-clamp base: the composed id violates the downstream bound.
# ---------------------------------------------------------------------------


def test_long_compound_respects_downstream_bound() -> None:
    item = _mint(_LONG_EP, _LONG_SINK)
    assert len(item["id"]) <= ID_MAX_LEN, (
        f"minted compound id is {len(item['id'])} chars — exceeds the "
        f"downstream Mermaid id bound ({ID_MAX_LEN}); the diagram lane "
        "truncates it silently"
    )


def test_distinct_long_compounds_stay_distinct_downstream() -> None:
    sink_x = "SINK-" + "s" * 110 + "-x"
    sink_y = "SINK-" + "s" * 110 + "-y"
    id_x = _mint(_LONG_EP, sink_x)["id"]
    id_y = _mint(_LONG_EP, sink_y)["id"]
    assert id_x != id_y
    # The actual downstream contract: after the diagram lane's
    # truncating sanitizer, the two paths must still be two nodes.
    assert sanitize_id(id_x) != sanitize_id(id_y), (
        "two distinct long compounds collapse into one Mermaid node id "
        "after downstream truncation"
    )


# ---------------------------------------------------------------------------
# Pins on the clamp itself (behavior-invisible for honest vocabulary).
# ---------------------------------------------------------------------------


def test_short_honest_compound_passes_byte_identical() -> None:
    item = _mint("EP-001", "SINK-001")
    assert item["id"] == "graph-path-EP-001-SINK-001"


def test_component_ids_stay_verbatim() -> None:
    item = _mint(_LONG_EP, _LONG_SINK)
    assert item["entry"]["id"] == _LONG_EP
    assert item["sink"]["id"] == _LONG_SINK


def test_clamp_identity_distinctness_idempotence() -> None:
    from core.understand_graph.queries import (
        _ELEMENT_ID_MAX_LEN,
        _clamp_element_id,
    )

    # Identity, both directions of the bound.
    at_bound = "s" * _ELEMENT_ID_MAX_LEN
    assert _clamp_element_id(at_bound) == at_bound
    over = "s" * (_ELEMENT_ID_MAX_LEN + 1)
    clamped = _clamp_element_id(over)
    assert clamped != over
    assert len(clamped) == _ELEMENT_ID_MAX_LEN

    # Distinctness: shared truncated prefix, different full ids.
    long_x = "p" * 200 + "x"
    long_y = "p" * 200 + "y"
    assert _clamp_element_id(long_x) != _clamp_element_id(long_y)

    # Determinism, idempotence, and same-mapping as the bridge mirror.
    assert _clamp_element_id(long_x) == _clamp_element_id(long_x)
    assert _clamp_element_id(clamped) == clamped

    from core.orchestration.understand_bridge import (
        _clamp_element_id as _bridge_clamp,
    )
    assert _bridge_clamp(long_x) == _clamp_element_id(long_x)


def test_bound_mirror_matches_downstream_constant() -> None:
    from core.understand_graph.queries import _ELEMENT_ID_MAX_LEN

    assert _ELEMENT_ID_MAX_LEN == ID_MAX_LEN
