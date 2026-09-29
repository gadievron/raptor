"""sanitize_id length cap — both directions, plus collision surfacing.

Mermaid node ids land UNQUOTED in diagram positions and diagrams.md is
catted to operator terminals; the charset strip already makes the bytes
inert, so length is the remaining channel — without a cap a
megabyte-long alnum id survives verbatim into the rendered document.
"""

from ..sanitize import detect_id_collisions, sanitize_id

_CAP = 128  # asserted equal to sanitize.ID_MAX_LEN below


def test_cap_constant_pinned() -> None:
    from .. import sanitize
    assert sanitize.ID_MAX_LEN == _CAP


def test_at_cap_unchanged() -> None:
    node_id = "A" * _CAP
    assert sanitize_id(node_id) == node_id


def test_over_cap_truncated() -> None:
    assert sanitize_id("A" * (_CAP + 1)) == "A" * _CAP


def test_flood_id_bounded() -> None:
    assert len(sanitize_id("Z" * 1_000_000)) == _CAP


def test_observed_honest_ids_identity() -> None:
    # Every observed honest id family (max observed length 116) stays
    # byte-identical under the cap.
    for honest in (
        "H1",
        "AP-001",
        "ROOT",
        "TRACE-001",
        "H-nosemgrep-FIND-001",
        "map-flow-1a2b3c4d5e6f",
        "binary-handoff_" + "x" * 100,
    ):
        assert sanitize_id(honest) == honest


def test_truncation_collision_surfaces() -> None:
    # Two ids identical through the cap and differing only after it
    # collapse to one sanitized id; detect_id_collisions (which groups
    # by sanitize_id output) must surface that as a collision.
    a = "A" * _CAP + "X"
    b = "A" * _CAP + "Y"
    assert detect_id_collisions([a, b]) == [("A" * _CAP, [a, b])]
