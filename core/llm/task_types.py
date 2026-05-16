"""Canonical ``task_type`` names recognised by the LLM router.

Pass one of these as ``task_type=`` to
:meth:`~core.llm.client.LLMClient.generate` /
:meth:`~core.llm.client.LLMClient.generate_structured` so the client
can route the call to a model appropriate for the workload's shape
rather than always going to the configured primary.

Routing layers:
  1. Explicit ``model_config=`` kwarg wins.
  2. Otherwise ``LLMConfig.specialized_models[task_type]`` if set
     (operators can override anything by populating this dict).
  3. Otherwise ``LLMConfig.primary_model``.

The fast tier (``FAST_TIER_TASKS``) is auto-populated at
:class:`~core.llm.config.LLMConfig` construction time when the primary
model's provider has a known fast-model mapping (see
:data:`~core.llm.model_data.PROVIDER_FAST_MODELS`). Operators who set
their own ``specialized_models`` entry for a fast-tier task keep that
override.

Adding a new task_type:
  1. Add a constant on :class:`TaskType`.
  2. Decide whether it routes fast or to the primary by default; if
     fast, add it to ``FAST_TIER_TASKS``.
  3. Document the workload shape in the constant's docstring so future
     callers can pick the right one without reading the source.

Why a constants class rather than enum:
  ``task_type`` is a string everywhere it crosses an LLM-provider
  boundary (logged, recorded in telemetry, used as a cost-attribution
  key). Stringly-typed callers continue to work; the constants only
  add type-safety for callers that adopt them.
"""

from __future__ import annotations


class TaskType:
    """Canonical task_type names. Use as ``task_type=TaskType.<X>``."""

    # Yes/no, safe/risky/block, true-positive/false-positive — short
    # categorical answers from a fixed set. Routes fast.
    VERDICT_BINARY = "verdict_binary"

    # Severity triage, label-from-set classification of a finding,
    # CWE bucket selection. Routes fast.
    CLASSIFY = "classify"

    # Report condensation, multi-finding rollup. Quality matters but
    # the input is dense and structured. Routes to primary by default
    # — fast-tier models tend to drop nuance in summarisation.
    SUMMARISE = "summarise"

    # Default for analysis-shaped workloads: dataflow validation,
    # vulnerability review, cross-finding correlation. Routes to
    # primary.
    ANALYSE = "analyse"

    # PoC / exploit / patch generation. Routes to primary; the
    # quality cost of routing fast here is too high.
    GENERATE_CODE = "generate_code"

    # Multi-turn tool-using orchestrators (cve-diff, agentic). Routes
    # to primary. Fast models often misuse tools.
    AGENT_LOOP = "agent_loop"

    # Legacy: pre-existing task_type used in dataflow validation.
    # Equivalent to ANALYSE; kept for backwards compatibility with
    # call sites that haven't migrated yet.
    AUDIT = "audit"


# Task types that default to the provider's fast-tier model when the
# primary's provider has a fast mapping. See module docstring for
# how operators override.
FAST_TIER_TASKS: frozenset[str] = frozenset({
    TaskType.VERDICT_BINARY,
    TaskType.CLASSIFY,
})


__all__ = ["TaskType", "FAST_TIER_TASKS"]
