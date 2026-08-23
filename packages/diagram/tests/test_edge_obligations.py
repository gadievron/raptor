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
    assert '-->|"boundary:x"|' in out
    assert "-.->|folded|" in out


def test_caps_are_stated_never_silent():
    out = edge_obligations.generate(_data(n1=35, n2=25))
    assert "+5 more tier-1 edges" in out
    assert "+5 more tier-2 edges" in out


def test_blind_spots_and_degradation_noted():
    out = edge_obligations.generate(
        _data(blind=7, degraded=["no-domain-model"]))
    assert "Blind spots: 7" in out
    assert "no-domain-model" in out
