"""
AgentLoop — explore-first tool-use loop for CVE → fix-commit discovery.

Delegates to :class:`core.llm.tool_use.loop.ToolUseLoop` for the
provider-agnostic agentic runner. Domain-specific logic (verified-SHA
gate, SHA-existence gate, source-class surrender) lives in the
``submit_result`` handler and events callback, not inside the loop
itself.

Dataclasses live in ``agent/types.py``; tools in ``agent/tools.py``.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from core.llm.config import ModelConfig
from core.llm.providers import create_provider
from core.llm.tool_use.loop import ToolUseLoop
from core.llm.tool_use.types import (
    CacheControl,
    ContextPolicy,
    CostBudgetExceeded,
    LoopEvent,
    ToolCallDispatched,
    ToolCallReturned,
    ToolDef,
    ToolLoopResult,
    TurnCompleted,
)

from cve_diff.agent import source_classes
from cve_diff.agent.tools import Tool
from cve_diff.agent.types import AgentContext, AgentOutput, AgentResult, AgentSurrender
from core.url_patterns import SHA_DISPLAY_LEN, extract_github_slug
from cve_diff.infra import github_client
from cve_diff.llm.client import MODEL_PRICES


@dataclass(frozen=True, slots=True)
class AgentConfig:
    """What one run of the loop needs."""
    system_prompt: str
    user_message: str
    tools: tuple[Tool, ...]
    validator: Callable[[dict, AgentContext], AgentResult]
    model_id: str = "claude-opus-4-7"
    budget_tokens: int = 400000
    budget_cost_usd: float = 2.00
    budget_s: float = 720.0
    max_iterations: int = 30
    temperature: float | None = None
    enable_task_budgets: bool = True


def _rules_disabled() -> bool:
    return os.environ.get("CVE_DIFF_DISABLE_RULES") == "1"


_MAX_UNVERIFIED_SUBMITS = 2
_MAX_NOT_FOUND_SUBMITS = 2


def _is_verified(slug: str, sha: str, verified: list[tuple[str, str]]) -> bool:
    if not slug or not sha:
        return False
    sha = sha.lower()
    for vslug, vsha in verified:
        if vslug != slug:
            continue
        if vsha.startswith(sha) or sha.startswith(vsha):
            return True
    return False


def _price(
    model_id: str,
    in_t: int,
    out_t: int,
    cache_create_t: int = 0,
    cache_read_t: int = 0,
) -> float:
    key = model_id.lower()
    for token, (in_per_M, out_per_M) in MODEL_PRICES.items():
        if token in key:
            return (
                in_t * in_per_M
                + out_t * out_per_M
                + cache_create_t * in_per_M * 1.25
                + cache_read_t * in_per_M * 0.1
            ) / 1_000_000
    return 0.0


@dataclass
class AgentLoop:
    timeout_s: float = 60.0
    last_telemetry: dict[str, Any] | None = field(default=None, init=False, repr=False)

    def run(self, config: AgentConfig, ctx: AgentContext) -> AgentResult:
        prompt_hash = hashlib.sha256(
            (config.system_prompt + "\n" + config.user_message).encode("utf-8")
        ).hexdigest()[:12]

        # ---- State tracked across the loop via closures ----
        tool_call_log: list[str] = []
        verified: list[tuple[str, str]] = []
        tool_calls_with_args: list[tuple[str, str]] = []
        unverified_submits = 0
        not_found_submits = 0
        last_dispatched_input: list[dict[str, Any] | None] = [None]
        # Set to non-None when a submit gate wants to hard-stop the loop.
        gate_hard_stop_reason: list[str | None] = [None]
        # The final accepted submit payload.
        submit_payload: list[dict[str, Any] | None] = [None]
        rules_disabled = _rules_disabled()

        start = time.monotonic()

        # ---- Build the submit_result handler with gate logic ----
        # Rejections raise ValueError so the ToolUseLoop treats the
        # call as is_error=True (feeds error text back to model, does
        # NOT terminate). Accepted submissions return normally —
        # ToolUseLoop sees a successful terminal_tool and stops.
        def _submit_handler(args: dict[str, Any]) -> str:
            nonlocal unverified_submits, not_found_submits

            outcome = (args.get("outcome") or "").lower()
            if outcome == "rescued":
                slug = extract_github_slug(args.get("repository_url") or "") or ""
                sha = (args.get("fix_commit") or "").strip().lower()

                # Verified-SHA gate
                if slug and sha and not _is_verified(slug, sha, verified):
                    unverified_submits += 1
                    if unverified_submits > _MAX_UNVERIFIED_SUBMITS:
                        gate_hard_stop_reason[0] = "submit_unverified_sha"
                        raise ValueError(json.dumps({
                            "submit_rejected": True,
                            "reason": "too many unverified submits",
                        }))
                    verified_brief = ", ".join(
                        f"{vs}@{vh[:SHA_DISPLAY_LEN]}" for vs, vh in verified[:5]
                    ) or "(none)"
                    raise ValueError(json.dumps({
                        "submit_rejected": True,
                        "reason": (
                            "the (slug, sha) you submitted was not "
                            "verified by gh_commit_detail in this run."
                        ),
                        "submitted": {"slug": slug, "sha": sha},
                        "verified_pairs": verified_brief,
                        "next_step": (
                            "call gh_commit_detail on the SHA you "
                            "intend to submit, or submit one of the "
                            "verified pairs. You have "
                            f"{_MAX_UNVERIFIED_SUBMITS - unverified_submits + 1} "
                            "attempt(s) left."
                        ),
                    }))

                # SHA-existence gate
                if slug and sha and github_client.commit_exists(slug, sha) is False:
                    not_found_submits += 1
                    if not_found_submits > _MAX_NOT_FOUND_SUBMITS:
                        gate_hard_stop_reason[0] = "sha_not_found_in_repo"
                        raise ValueError(json.dumps({
                            "submit_rejected": True,
                            "reason": "too many sha-not-found submits",
                        }))
                    raise ValueError(json.dumps({
                        "submit_rejected": True,
                        "reason": (
                            "sha_not_found: GitHub returned 404. "
                            "Submit the FULL 40-char SHA exactly as "
                            "gh_commit_detail returned it."
                        ),
                        "submitted": {"slug": slug, "sha": sha},
                        "next_step": (
                            "submit a verified pair verbatim. You "
                            f"have {_MAX_NOT_FOUND_SUBMITS - not_found_submits + 1} "
                            "attempt(s) left."
                        ),
                    }))

            # Accept the submission
            submit_payload[0] = args
            return json.dumps({"accepted": True})

        # ---- Build ToolDef list from cve-diff Tools + submit handler ----
        tool_defs: list[ToolDef] = [t.to_tool_def() for t in config.tools]
        submit_tool_def = ToolDef(
            name="submit_result",
            description=(
                "Terminal call. Use to return your final answer. "
                "``outcome`` controls how the pipeline treats your "
                "answer: ``rescued`` (supply repository_url + fix_commit), "
                "``unsupported`` (closed-source), ``no_evidence``."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "outcome": {"type": "string", "enum": ["rescued", "unsupported", "no_evidence"]},
                    "repository_url": {"type": "string"},
                    "fix_commit": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["outcome", "rationale"],
            },
            handler=_submit_handler,
        )
        tool_defs.append(submit_tool_def)

        # ---- Events callback for telemetry + domain bookkeeping ----
        cost_usd = 0.0
        tokens_total = 0
        iterations_count = 0

        def _on_event(event: LoopEvent) -> None:
            nonlocal cost_usd, tokens_total, iterations_count

            if isinstance(event, TurnCompleted):
                resp = event.response
                cost_usd += event.cost_usd
                tokens_total += resp.input_tokens + resp.output_tokens + resp.cache_write_tokens + resp.cache_read_tokens
                iterations_count = event.iteration + 1

            elif isinstance(event, ToolCallDispatched):
                call = event.call
                tool_call_log.append(call.name)
                args_repr = json.dumps(call.input, sort_keys=True, default=str)[:120]
                tool_calls_with_args.append((call.name, args_repr))
                last_dispatched_input[0] = call.input

            elif isinstance(event, ToolCallReturned):
                result = event.result
                # Find which tool this was from the most recent dispatch
                call_name = tool_call_log[-1] if tool_call_log else ""
                if call_name == "gh_commit_detail" and not result.is_error:
                    try:
                        parsed = json.loads(result.content)
                        if isinstance(parsed, dict) and "error" not in parsed:
                            slug = (parsed.get("slug") or "").strip().lower()
                            sha = (parsed.get("sha") or "").strip().lower()
                            if slug and sha and (slug, sha) not in verified:
                                verified.append((slug, sha))
                    except (ValueError, AttributeError):
                        pass
                elif call_name in ("cgit_fetch", "gitlab_commit") and not result.is_error:
                    try:
                        parsed = json.loads(result.content)
                        if isinstance(parsed, dict) and "error" not in parsed and last_dispatched_input[0] is not None:
                            a = last_dispatched_input[0]
                            slug = (a.get("slug") or "").strip().lower()
                            sha = (a.get("sha") or "").strip().lower()
                            if slug and sha and (slug, sha) not in verified:
                                verified.append((slug, sha))
                    except (ValueError, AttributeError):
                        pass

        # ---- Create the provider ----
        try:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                raise RuntimeError("ANTHROPIC_API_KEY not set")
            model_config = ModelConfig(
                provider="anthropic",
                model_name=config.model_id,
                api_key=api_key,
                timeout=int(self.timeout_s),
            )
            provider = create_provider(model_config)
        except Exception as exc:
            return self._finalize(
                AgentSurrender(reason="client_init_failed", detail=str(exc)[:200]),
                0, 0.0, time.monotonic() - start, tuple(tool_call_log),
                tuple(verified),
            )

        # ---- Build provider-specific kwargs ----
        provider_kw: dict[str, Any] = {}
        if config.enable_task_budgets:
            provider_kw["anthropic_task_budget_beta"] = True
            provider_kw["anthropic_task_budget_tokens"] = config.budget_tokens

        # ---- Build and run the ToolUseLoop ----
        loop = ToolUseLoop(
            provider=provider,
            tools=tool_defs,
            system=config.system_prompt,
            terminal_tool="submit_result",
            max_iterations=config.max_iterations,
            max_cost_usd=config.budget_cost_usd,
            max_seconds=config.budget_s,
            tool_timeout_s=self.timeout_s,
            context_policy=ContextPolicy.RAISE,
            max_tokens_per_turn=2048,
            cache_control=CacheControl(system=True, tools=True),
            events=_on_event,
            terminate_on_handler_error=False,
            **provider_kw,
        )

        try:
            loop_result = loop.run(config.user_message)
        except CostBudgetExceeded:
            return self._finalize(
                AgentSurrender(
                    reason="budget_cost_usd",
                    detail=f"iterations={iterations_count} tokens={tokens_total} "
                           f"cost=${cost_usd:.4f} elapsed={time.monotonic() - start:.1f}s",
                ),
                tokens_total, cost_usd, time.monotonic() - start,
                tuple(tool_call_log), tuple(verified),
                iterations=iterations_count,
                tool_calls_with_args=tuple(tool_calls_with_args),
                unverified_submits=unverified_submits,
                not_found_submits=not_found_submits,
            )
        except Exception as exc:
            reason = gate_hard_stop_reason[0] or "llm_error"
            return self._finalize(
                AgentSurrender(reason=reason, detail=str(exc)[:200]),
                tokens_total, cost_usd, time.monotonic() - start,
                tuple(tool_call_log), tuple(verified),
                iterations=iterations_count,
                tool_calls_with_args=tuple(tool_calls_with_args),
                unverified_submits=unverified_submits,
                not_found_submits=not_found_submits,
            )

        # ---- Map ToolLoopResult back to AgentResult ----
        tokens_total = loop_result.total_input_tokens + loop_result.total_output_tokens
        cost_usd = loop_result.total_cost_usd
        elapsed_s = time.monotonic() - start

        # Gate hard-stop: submit handler set a rejection flag
        if gate_hard_stop_reason[0] is not None:
            return self._finalize(
                AgentSurrender(
                    reason=gate_hard_stop_reason[0],
                    detail=f"gate hard stop after {unverified_submits} unverified / {not_found_submits} not-found submits",
                ),
                tokens_total, cost_usd, elapsed_s,
                tuple(tool_call_log), tuple(verified),
                iterations=iterations_count,
                tool_calls_with_args=tuple(tool_calls_with_args),
                unverified_submits=unverified_submits,
                not_found_submits=not_found_submits,
            )

        # Source-class surrender check (pre-terminal-tool only)
        if (
            loop_result.terminated_by != "terminal_tool"
            and not rules_disabled
            and source_classes.should_surrender_no_evidence(tool_call_log, cost_usd)
        ):
            tried = source_classes.tried_classes(tool_call_log)
            return self._finalize(
                AgentSurrender(
                    reason="no_evidence",
                    detail=(
                        f"iter={iterations_count} cost=${cost_usd:.4f}: "
                        f"all source classes tried ({', '.join(sorted(tried))}) "
                        f"with zero verification calls."
                    ),
                ),
                tokens_total, cost_usd, elapsed_s,
                tuple(tool_call_log), tuple(verified),
                iterations=iterations_count,
                tool_calls_with_args=tuple(tool_calls_with_args),
            )

        # Budget / non-terminal termination
        _BUDGET_REASONS = {"max_iterations", "max_cost_usd", "max_seconds"}
        if loop_result.terminated_by in _BUDGET_REASONS:
            reason_map = {
                "max_iterations": "budget_iterations",
                "max_cost_usd": "budget_cost_usd",
                "max_seconds": "budget_s",
            }
            return self._finalize(
                AgentSurrender(
                    reason=reason_map[loop_result.terminated_by],
                    detail=f"iterations={loop_result.iterations} tokens={tokens_total} "
                           f"cost=${cost_usd:.4f} elapsed={elapsed_s:.1f}s",
                ),
                tokens_total, cost_usd, elapsed_s,
                tuple(tool_call_log), tuple(verified),
                iterations=iterations_count,
                tool_calls_with_args=tuple(tool_calls_with_args),
                unverified_submits=unverified_submits,
                not_found_submits=not_found_submits,
            )

        if loop_result.terminated_by in ("complete", "max_tokens", "refused", "provider_error"):
            return self._finalize(
                AgentSurrender(
                    reason="model_stopped_without_submit",
                    detail=loop_result.final_text[:200],
                ),
                tokens_total, cost_usd, elapsed_s,
                tuple(tool_call_log), tuple(verified),
                iterations=iterations_count,
                tool_calls_with_args=tuple(tool_calls_with_args),
            )

        # Terminal tool fired — run the validator on the submit payload
        payload = submit_payload[0] or loop_result.terminal_tool_input or {}
        try:
            validated = config.validator(payload, ctx)
        except Exception as exc:
            self.last_telemetry = {
                "reason": f"raised:{type(exc).__name__}",
                "detail": str(exc)[:300],
                "tokens": tokens_total,
                "cost_usd": round(cost_usd, 6),
                "elapsed_s": round(elapsed_s, 3),
                "tool_calls": tuple(tool_call_log),
            }
            raise

        return self._finalize(
            validated, tokens_total, cost_usd, elapsed_s,
            tuple(tool_call_log), tuple(verified),
            iterations=iterations_count,
            tool_calls_with_args=tuple(tool_calls_with_args),
            unverified_submits=unverified_submits,
            not_found_submits=not_found_submits,
        )

    def _finalize(
        self,
        result: AgentResult,
        tokens: int,
        cost_usd: float,
        elapsed_s: float,
        tool_calls: tuple[str, ...],
        verified_candidates: tuple[tuple[str, str], ...] = (),
        *,
        iterations: int = 0,
        tool_calls_with_args: tuple[tuple[str, str], ...] = (),
        unverified_submits: int = 0,
        not_found_submits: int = 0,
    ) -> AgentResult:
        cost_usd = round(cost_usd, 6)
        elapsed_s = round(elapsed_s, 3)
        self.last_telemetry = {
            "iterations": iterations,
            "tokens": tokens,
            "cost_usd": cost_usd,
            "elapsed_s": elapsed_s,
            "tool_calls": list(tool_calls),
            "tool_calls_with_args": [list(t) for t in tool_calls_with_args],
            "unverified_submits": unverified_submits,
            "not_found_submits": not_found_submits,
        }
        if isinstance(result, AgentSurrender):
            out = AgentSurrender(
                reason=result.reason,
                detail=result.detail,
                tool_calls=result.tool_calls or tool_calls,
                tokens=tokens,
                cost_usd=cost_usd,
                elapsed_s=elapsed_s,
                verified_candidates=result.verified_candidates or verified_candidates,
            )
            return out
        out_ok = AgentOutput(
            value=result.value,
            rationale=result.rationale,
            tool_calls=result.tool_calls or tool_calls,
            tokens=tokens,
            cost_usd=cost_usd,
            elapsed_s=elapsed_s,
            verified_candidates=verified_candidates,
        )
        return out_ok
