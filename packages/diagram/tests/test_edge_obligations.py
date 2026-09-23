"""Mermaid rendering for edge-obligations.json."""

from packages.diagram import edge_obligations


def _data(n1=1, n2=1, blind=0, degraded=None):
    return {
        "tier1": [{"caller_file": "a.c", "caller": f"c{i}",
                   "callee_file": "b.c", "callee": f"e{i}",
                   "call_line": i, "reason": "boundary:x"}
                  for i in range(n1)],
        "tier2": [{"caller_file": "a.c", "caller": f"t{i}",
                   "callee_file": "b.c", "callee": f"u{i}",
                   "call_line": i, "reason": "on-path"}
                  for i in range(n2)],
        "blind_spots": [{"file": "a.c", "caller": None,
                         "kind": "indirection", "name": f"p{i}"}
                        for i in range(blind)],
        "stats": {"degraded": degraded or []},
    }


def test_tiers_render_solid_and_dashed():
    out = edge_obligations.generate(_data())
    assert out.startswith("flowchart LR")
    # Quote-delimited edge-label forms (the context_map/graph_memory
    # idiom): inside |…| pipes, an in-value `|` may terminate Mermaid's
    # edgeText even when quoted — this generator was the only
    # pipe-delimited user, and tier-1 reasons quote target identifiers.
    assert '-- "boundary:x" -->' in out
    assert '-. "folded" .->' in out
    assert "|" not in out


def test_pipe_in_reason_cannot_break_edge_label():
    data = _data()
    data["tier1"][0]["reason"] = "boundary:a|b"
    out = edge_obligations.generate(data)
    assert "|" not in out
    assert "a&#124;b" in out


def test_caps_are_stated_never_silent():
    out = edge_obligations.generate(_data(n1=35, n2=25))
    assert "+5 more tier-1 edges" in out
    assert "+5 more tier-2 edges" in out
    # The BOUND itself, not just the marker string: deleting a cap
    # slice must fail here, not only change the (unpinned) node count.
    tier1_edges = [ln for ln in out.splitlines() if "-->" in ln]
    assert len(tier1_edges) == 30
    tier2_edges = [ln for ln in out.splitlines() if "folded" in ln]
    assert len(tier2_edges) == 20


def test_blind_spots_and_degradation_noted():
    out = edge_obligations.generate(
        _data(blind=7, degraded=["no-domain-model"]))
    assert "Blind spots: 7" in out
    assert "no-domain-model" in out


def test_degraded_overflow_carries_more_marker():
    """The module claims "never a silent cap" — the degraded arm
    dropped entries past four with no marker."""
    out = edge_obligations.generate(
        _data(degraded=[f"d{i}" for i in range(1, 7)]))
    assert "d1" in out
    assert "d4" in out
    assert "(+2 more)" in out


def test_degraded_at_cap_has_no_marker():
    out = edge_obligations.generate(
        _data(degraded=[f"d{i}" for i in range(1, 5)]))
    assert "d4" in out
    assert "more)" not in out
