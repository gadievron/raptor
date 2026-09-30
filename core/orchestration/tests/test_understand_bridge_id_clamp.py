"""Flow-trace stem-fallback id clamp — mint-side length bounding.

The bridge's fallback attack-path id is the trace FILENAME STEM
(``flow-trace-<entry-id>.json``, LLM-named with an unpinned entry id),
so honest stems run up to ~250 filesystem-bounded chars. Downstream,
Mermaid node ids are truncated at ``packages/diagram/sanitize.
ID_MAX_LEN`` (=128), where two distinct long ids silently collapse
into one rendered node. The mint-side clamp bounds the fallback with a
truncate+hash-suffix scheme that keeps long ids distinct and leaves
every short honest id byte-identical. Length-bounding only: no row is
ever dropped, refused, or renamed away from its short honest form.
"""

import json
from pathlib import Path

from packages.diagram.sanitize import ID_MAX_LEN, sanitize_id

from core.orchestration.understand_bridge import _import_flow_traces

# 235 filename chars keeps "flow-trace-" + tail + ".json" at 251
# bytes, under the 255-byte filesystem name bound, while the stem
# (246 chars) still far exceeds ID_MAX_LEN.
_LONG_TAIL = "a" * 235
# Two tails sharing a >128-char prefix so naive truncation at the
# downstream bound collapses them into the same id.
_TAIL_X = "p" * 200 + "x" * 30
_TAIL_Y = "p" * 200 + "y" * 30


def _write_trace(understand_dir: Path, tail: str) -> Path:
    """A trace whose non-string id forces the filename-stem fallback."""
    trace_file = understand_dir / f"flow-trace-{tail}.json"
    trace_file.write_text(json.dumps({"id": {}, "steps": []}))
    return trace_file


def _imported_ids(tmp_path: Path, tails: list[str]) -> list[str]:
    understand_dir = tmp_path / "understand"
    validate_dir = tmp_path / "validate"
    understand_dir.mkdir()
    validate_dir.mkdir()
    for tail in tails:
        _write_trace(understand_dir, tail)
    result = _import_flow_traces(understand_dir, validate_dir)
    assert result["imported_as_paths"] == len(tails)
    paths = json.loads((validate_dir / "attack-paths.json").read_text())
    return [p["id"] for p in paths if isinstance(p, dict) and "id" in p]


# ---------------------------------------------------------------------------
# Red at pre-clamp base: the fallback id violates the downstream bound.
# ---------------------------------------------------------------------------


def test_long_stem_fallback_respects_downstream_bound(tmp_path: Path) -> None:
    ids = _imported_ids(tmp_path, [_LONG_TAIL])
    assert len(ids) == 1
    assert len(ids[0]) <= ID_MAX_LEN, (
        f"minted fallback id is {len(ids[0])} chars — exceeds the "
        f"downstream Mermaid id bound ({ID_MAX_LEN}); the diagram lane "
        "truncates it silently"
    )


def test_distinct_long_stems_stay_distinct_downstream(tmp_path: Path) -> None:
    ids = _imported_ids(tmp_path, [_TAIL_X, _TAIL_Y])
    assert len(ids) == 2
    assert ids[0] != ids[1]
    # The actual downstream contract: after the diagram lane's
    # truncating sanitizer, the two paths must still be two nodes.
    assert sanitize_id(ids[0]) != sanitize_id(ids[1]), (
        "two distinct long stems collapse into one Mermaid node id "
        "after downstream truncation"
    )


# ---------------------------------------------------------------------------
# Pins on the clamp itself (behavior-invisible for honest vocabulary).
# ---------------------------------------------------------------------------


def test_short_honest_stem_passes_byte_identical(tmp_path: Path) -> None:
    ids = _imported_ids(tmp_path, ["entry-1"])
    assert ids == ["flow-trace-entry-1"]


def test_honest_string_trace_id_untouched(tmp_path: Path) -> None:
    understand_dir = tmp_path / "understand"
    validate_dir = tmp_path / "validate"
    understand_dir.mkdir()
    validate_dir.mkdir()
    trace_file = understand_dir / "flow-trace-login.json"
    trace_file.write_text(json.dumps({"id": "TRACE-001", "steps": []}))
    result = _import_flow_traces(understand_dir, validate_dir)
    assert result["imported_as_paths"] == 1
    paths = json.loads((validate_dir / "attack-paths.json").read_text())
    assert paths[0]["id"] == "TRACE-001"


def test_clamped_id_is_stable_dedup_key(tmp_path: Path) -> None:
    """Persisted id and dedup key agree: a re-import is a no-op."""
    understand_dir = tmp_path / "understand"
    validate_dir = tmp_path / "validate"
    understand_dir.mkdir()
    validate_dir.mkdir()
    _write_trace(understand_dir, _LONG_TAIL)
    first = _import_flow_traces(understand_dir, validate_dir)
    assert first["imported_as_paths"] == 1
    second = _import_flow_traces(understand_dir, validate_dir)
    assert second["imported_as_paths"] == 0
    paths = json.loads((validate_dir / "attack-paths.json").read_text())
    assert len(paths) == 1


def test_clamp_identity_distinctness_idempotence() -> None:
    from core.orchestration.understand_bridge import (
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

    # Determinism and idempotence.
    assert _clamp_element_id(long_x) == _clamp_element_id(long_x)
    assert _clamp_element_id(clamped) == clamped
    assert _clamp_element_id(_clamp_element_id(over)) == _clamp_element_id(over)


def test_bound_mirrors_are_coherent() -> None:
    """The mirrored constants must stay equal — cross-reference fence."""
    from core.orchestration.understand_bridge import _ELEMENT_ID_MAX_LEN
    from core.understand_graph import queries

    assert _ELEMENT_ID_MAX_LEN == ID_MAX_LEN
    assert queries._ELEMENT_ID_MAX_LEN == ID_MAX_LEN
