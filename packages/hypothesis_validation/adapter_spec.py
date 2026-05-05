"""Bridge legacy `ToolAdapter` into the typed `AdapterSpec` surface.

The four existing adapters (Coccinelle, Semgrep, CodeQL, SMT) keep
their `ToolAdapter` shape so the Phase A runner is untouched. This
module wraps each one as an `AdapterSpec` so the typed-plan layer
can dispatch over them uniformly without forcing a rewrite.

`from_tool_adapter` is the only public entry point; the per-adapter
projection templates live below as private helpers and mirror the
prompt phrasing the LLM already sees in `runner._GENERATE_RULE_PROMPT`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from .adapters.base import ToolAdapter
from .types import (
    AdapterQuery,
    AdapterSpec,
    Cost,
    Effect,
    SinkKind,
    TypedHypothesis,
)


# Effect declarations per tool. None of the four adapters need network
# (registry packs are pre-resolved, queries run locally) — the `network`
# effect remains absent so the typed scheduler can prove no plan needs
# network access.
_EFFECTS = {
    "coccinelle": frozenset({Effect.SUBPROCESS, Effect.FS_READ}),
    "semgrep": frozenset({Effect.SUBPROCESS, Effect.FS_READ}),
    "codeql": frozenset({Effect.SUBPROCESS, Effect.FS_READ}),
    "smt": frozenset({Effect.PURE}),
}


def _applicable_coccinelle(h: TypedHypothesis) -> bool:
    """C/C++ source patterns and control-flow shape questions."""
    f = (h.sink.file or h.source.file).lower()
    if f and not f.endswith((".c", ".h", ".cc", ".cpp", ".hpp", ".cxx")):
        return False
    return True


def _applicable_semgrep(h: TypedHypothesis) -> bool:
    """Pattern matching across many languages."""
    return True


def _applicable_codeql(h: TypedHypothesis) -> bool:
    """Inter-procedural dataflow — the hypothesis must have a flow."""
    return bool(h.flow) or h.sink.kind in {
        SinkKind.SQL, SinkKind.EXEC, SinkKind.WRITE, SinkKind.INDEX,
    }


def _applicable_smt(h: TypedHypothesis) -> bool:
    """Path satisfiability questions."""
    return bool(h.smt_constraints)


_APPLICABLE = {
    "coccinelle": _applicable_coccinelle,
    "semgrep": _applicable_semgrep,
    "codeql": _applicable_codeql,
    "smt": _applicable_smt,
}


def _project_default(h: TypedHypothesis, tool: str) -> AdapterQuery:
    """Default projection: empty body (the LLM still fills it in).

    The legacy runner already drives the LLM to produce the rule body;
    `project` keeps that contract by returning a shaped query whose body
    the runner replaces. When the typed layer eventually owns the
    projection, the per-tool helpers below take over.
    """
    return AdapterQuery(tool=tool, body="", refers_to="")


def _wrap_run(adapter: ToolAdapter):
    """Adapter.run with a query-shaped signature.

    The typed surface accepts an `AdapterQuery`; the underlying
    `ToolAdapter.run` takes a rule string. Bridge here so the legacy
    adapter can stay untouched.
    """

    def run(
        query: AdapterQuery,
        target: Path,
        *,
        timeout: int = 300,
        env: Optional[dict] = None,
    ) -> Any:
        return adapter.run(query.body, target, timeout=timeout, env=env)

    return run


def from_tool_adapter(adapter: ToolAdapter) -> AdapterSpec:
    """Wrap a legacy `ToolAdapter` as a typed `AdapterSpec`.

    The wrapped spec re-uses the adapter's existing `run`, keeps the
    same `name`, and attaches the per-tool `applicable` filter and
    declared `effects`. Adapters whose name isn't in the per-tool tables
    fall back to permissive defaults so third-party adapters work
    without modification.
    """
    name = adapter.name
    return AdapterSpec(
        name=name,
        applicable=_APPLICABLE.get(name, lambda _h: True),
        project=lambda h, _name=name: _project_default(h, _name),
        run=_wrap_run(adapter),
        effects=_EFFECTS.get(name, frozenset({Effect.SUBPROCESS})),
        cost=Cost(seconds=0.0, cpu_bound=True),
    )


__all__ = ["from_tool_adapter"]
