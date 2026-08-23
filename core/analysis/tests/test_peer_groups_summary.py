"""Resolver summary-line truthfulness (midpoint-audit anomaly A8).

The old line — ``peer group resolver: 0 groups (0 functions claimed by
L0-L3, …)`` — could not distinguish an exclusive layer that was
skipped for lack of input from one that ran and claimed nothing, and
its "L0" vocabulary collided with the unrelated mechanical "Layer 0"
pattern sweep, so the two lines side by side read as a contradiction.
Kept in its own file: the resolver's layer producers are under
concurrent development elsewhere; this covers only the summary line.
"""

from __future__ import annotations

import logging

from core.analysis.peer_groups import resolve_peer_groups

_FUNCS = [
    {"name": "conn_open", "file": "a.c", "line": 1, "source": ""},
    {"name": "conn_close", "file": "a.c", "line": 9, "source": ""},
]


def _summary(caplog) -> str:
    lines = [
        r.getMessage() for r in caplog.records
        if "peer group resolver" in r.getMessage()
    ]
    assert lines, "resolver summary line missing"
    return lines[-1]


class TestResolverSummaryLine:
    def test_missing_inputs_reported_as_skipped(self, caplog):
        with caplog.at_level(logging.INFO, "core.analysis.peer_groups"):
            resolve_peer_groups(_FUNCS)
        line = _summary(caplog)
        assert "joern co-callee skipped (no server)" in line
        assert "binary co-callee skipped (no edge index)" in line
        assert "dispatch-site skipped (no tables)" in line
        assert "domain-model skipped (no model)" in line
        assert "type-cohort skipped (no index)" in line

    def test_layer_zero_vocabulary_retired(self, caplog):
        # No "L0-L3" phrasing — it collided with the mechanical
        # "Layer 0" findings sweep in run output.
        with caplog.at_level(logging.INFO, "core.analysis.peer_groups"):
            resolve_peer_groups(_FUNCS)
        assert "L0-L3" not in _summary(caplog)

    def test_ran_layer_reports_group_count_not_skip(self, caplog):
        domain_model = {"concepts": []}  # present input, yields 0 groups
        with caplog.at_level(logging.INFO, "core.analysis.peer_groups"):
            resolve_peer_groups(_FUNCS, domain_model=domain_model)
        line = _summary(caplog)
        assert "domain-model 0" in line
        assert "domain-model skipped" not in line

    def test_heuristic_layer_counts_present(self, caplog):
        with caplog.at_level(logging.INFO, "core.analysis.peer_groups"):
            groups = resolve_peer_groups(_FUNCS)
        line = _summary(caplog)
        assert "verb-prefix" in line
        assert "paired-op" in line
        assert f"{len(groups)} groups" in line
