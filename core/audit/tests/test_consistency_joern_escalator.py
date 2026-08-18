"""Joern-flow reachability escalator for consistency verdicts (§2.3).

Outcome-gated and fail-open: the flow leg runs only for
promote-capable confirmations whose cheap entry-reachability leg
answered unknown; any query failure degrades to unknown and the
verdict itself never changes — only the finding-vs-suspicious status
mapping does. The prepass charges a bounded per-run budget.
"""

from __future__ import annotations

import textwrap

from core.audit import cross_function_verify
from core.audit.callsite_consistency import build_return_census
from core.audit.consistency_verify import (
    _escalate_reachability,
    census_verdict,
)
from core.audit.fail_open_roles import RoleContext


def _wur_texts() -> dict[str, str]:
    parts = [
        "__attribute__((warn_unused_result)) int do_auth(void);\n",
    ]
    for i in range(3):
        parts.append(textwrap.dedent(f"""\
            int caller_{i}(void) {{
                if (do_auth() != 0)
                    return -1;
                return 0;
            }}
        """))
    parts.append(
        "int caller_dev(void) {\n    do_auth();\n    return 0;\n}\n"
    )
    return {"src/callers.c": "\n".join(parts)}


_CONTEXT_MAP = {
    "entry_points": [{"function": "main", "file": "src/main.c"}],
}


class _StubServer:
    """Sentinel — queries are intercepted at _run_query."""


def _patch_query(monkeypatch, result):
    calls: list[str] = []

    def fake(server, query):
        calls.append(query)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(cross_function_verify, "_run_query", fake)
    return calls


class TestFlowLeg:
    def test_flow_hit_escalates_unknown_to_entry_reachable(
        self, monkeypatch,
    ):
        calls = _patch_query(
            monkeypatch, ["helper_a", "main", "caller_dev"],
        )
        ctx = RoleContext(context_map=_CONTEXT_MAP)
        reach = _escalate_reachability(
            ctx, None, "src/callers.c", "caller_dev", _StubServer(),
        )
        assert reach["status"] == "entry_reachable"
        assert reach["via"] == "joern_flow"
        assert "main" in reach["detail"]
        assert len(calls) == 1
        assert "caller_dev" in calls[0]

    def test_flow_miss_stays_unknown(self, monkeypatch):
        _patch_query(monkeypatch, ["helper_a", "helper_b"])
        ctx = RoleContext(context_map=_CONTEXT_MAP)
        reach = _escalate_reachability(
            ctx, None, "src/callers.c", "caller_dev", _StubServer(),
        )
        assert reach["status"] == "unknown"

    def test_query_error_degrades_to_unknown(self, monkeypatch):
        _patch_query(monkeypatch, RuntimeError("cpg gone"))
        ctx = RoleContext(context_map=_CONTEXT_MAP)
        reach = _escalate_reachability(
            ctx, None, "src/callers.c", "caller_dev", _StubServer(),
        )
        assert reach["status"] == "unknown"

    def test_no_server_keeps_cheap_leg_only(self):
        ctx = RoleContext(context_map=_CONTEXT_MAP)
        reach = _escalate_reachability(
            ctx, None, "src/callers.c", "caller_dev", None,
        )
        # Cheap leg alone: no inventory call graph → unknown, and no
        # joern annotation anywhere.
        assert reach["status"] == "unknown"
        assert "via" not in reach and "joern_flow" not in reach

    def test_cheap_hit_never_spends_a_query(self, monkeypatch):
        calls = _patch_query(monkeypatch, ["main"])
        ctx = RoleContext(context_map={
            "entry_points": [
                {"function": "caller_dev", "file": "src/callers.c"},
            ],
        })
        reach = _escalate_reachability(
            ctx, None, "src/callers.c", "caller_dev", _StubServer(),
        )
        assert reach["status"] == "entry_reachable"
        assert calls == []


class TestVerdictIntegration:
    def test_confirmed_verdict_promotes_via_flow(self, monkeypatch):
        from core.audit.consistency_prepass import _status_for

        _patch_query(monkeypatch, ["main"])
        texts = _wur_texts()
        census = build_return_census(texts)
        entry = census["do_auth"]
        ctx = RoleContext(
            context_map=_CONTEXT_MAP,
            wur_functions=frozenset({"do_auth"}),
        )
        res = census_verdict(
            entry, entry.deviants[0], context=ctx,
            source_texts=texts, joern_server=_StubServer(),
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == "consistency:return-check"
        assert res.reachability["status"] == "entry_reachable"
        assert res.reachability["via"] == "joern_flow"
        assert _status_for(res, detection=False) == "finding"

    def test_without_flow_confirmation_stands_as_suspicious(self):
        from core.audit.consistency_prepass import _status_for

        texts = _wur_texts()
        census = build_return_census(texts)
        entry = census["do_auth"]
        ctx = RoleContext(
            context_map=_CONTEXT_MAP,
            wur_functions=frozenset({"do_auth"}),
        )
        res = census_verdict(
            entry, entry.deviants[0], context=ctx, source_texts=texts,
        )
        assert res.outcome == "confirmed"
        assert (res.reachability or {}).get("status") != \
            "entry_reachable"
        assert _status_for(res, detection=False) == "suspicious"


class TestPrepassBudget:
    def test_flow_queries_charged_and_capped(self, monkeypatch, tmp_path):
        from core.audit import consistency_prepass as cp

        calls = _patch_query(monkeypatch, ["main"])
        monkeypatch.setattr(cp, "MAX_JOERN_ESCALATIONS", 1)
        # Two independent wur-carrying callees, each with a deviant —
        # only the first escalation may spend the single query.
        parts = [
            "__attribute__((warn_unused_result)) int do_auth(void);\n",
            "__attribute__((warn_unused_result)) int do_sign(void);\n",
        ]
        for callee in ("do_auth", "do_sign"):
            for i in range(3):
                parts.append(textwrap.dedent(f"""\
                    int {callee}_ok_{i}(void) {{
                        if ({callee}() != 0)
                            return -1;
                        return 0;
                    }}
                """))
            parts.append(
                f"int {callee}_dev(void) {{\n"
                f"    {callee}();\n    return 0;\n}}\n"
            )
        # Neutralise the census's own CPG supplement so every query
        # we observe is the escalator's.
        monkeypatch.setattr(
            cp, "build_return_census",
            lambda texts, joern_server=None: build_return_census(texts),
        )
        res = cp.run_consistency_prepass(
            {"src/callers.c": "\n".join(parts)},
            out_dir=tmp_path,
            context_map=_CONTEXT_MAP,
            joern_server=_StubServer(),
        )
        assert res["telemetry"].get("joern_escalations") == 1
        assert len(calls) == 1
