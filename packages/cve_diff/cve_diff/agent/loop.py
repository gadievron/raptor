"""
AgentLoop — explore-first tool-use loop for CVE → fix-commit discovery.

Forked from ``cve_diff/recovery/engine.py`` during the 2026-04-24
agentic-first pivot. The fork strips:

  * stage-coupling (``RecoveryConfig.stage`` / ``Stage`` enum) — this
    loop *is* the discover path, not a fallback over four stages.
  * the ``_best_scored`` validator coupling — invariants live in
    ``cve_diff/agent/invariants.py`` (three hard checks, not seven
    gates).
  * Jinja2 prompt templates — the system prompt is a plain string
    constant in ``agent/prompt.py``.
  * the ``CVE_DIFF_LLM_BASE_URL`` env-var routing through LiteLLM —
    this loop goes direct to the Anthropic API via the native SDK.

Dataclasses live in ``agent/types.py``; tools in ``agent/tools.py``.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from anthropic import Anthropic, APIConnectionError, APIError, APIStatusError

from cve_diff.agent import source_classes
from cve_diff.agent.tools import Tool
from cve_diff.agent.types import AgentContext, AgentOutput, AgentResult, AgentSurrender
from cve_diff.core.url_re import extract_github_slug
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
    # Token + cost budgets are loose because Opus 4.7 input pricing
    # ($15/M) makes raw OSV/NVD payload roundtrips expensive. Smoke on
    # CVE-2023-38545 (curl) cost $0.72 in 8 tool calls under prompt
    # caching. Cap at $2.00 is runaway protection; expected P50 ~$0.20,
    # P95 ~$1.00. Doubled from $1.00/$200K/360s/15 on 2026-04-26 — the
    # prior caps occasionally truncated CVEs that needed parent-chain
    # probes after gh_commit_detail confirmation; the loose ceiling
    # gives headroom for those without affecting the modal CVE cost.
    budget_tokens: int = 400000
    budget_cost_usd: float = 2.00
    # 720 s wall-clock covers OSV-thin CVEs (BootHole-class) on
    # Anthropic-slow days. The agent's per-iteration cost is dominated
    # by Anthropic latency × tool calls per iteration; on a slow API
    # day 5 iterations can take 250-300s before reaching
    # gh_commit_detail (the verification gate that populates
    # verified_candidates for meta-retry). Co-tuned with
    # pipeline._maybe_retry's 720s retry budget.
    budget_s: float = 720.0
    max_iterations: int = 30
    temperature: float | None = None
    # When True, send requests via `client.beta.messages.create` with
    # the `task-budgets-2026-03-13` beta header and an
    # `output_config.task_budget` keyed to `budget_tokens`. The server
    # tracks the running countdown and the model self-regulates. We
    # keep `_Budget` as the hard backstop. Set to False to revert to
    # the non-beta path if the beta API misbehaves.
    enable_task_budgets: bool = True


_SUBMIT_TOOL = Tool(
    name="submit_result",
    description=(
        "Terminal call. Use to return your final answer. The loop ends on "
        "this call. ``outcome`` controls how the pipeline treats your "
        "answer: ``rescued`` (supply repository_url + fix_commit), "
        "``unsupported`` (closed-source), ``no_evidence`` (genuinely "
        "missing public source — only after exploring)."
    ),
    parameters={
        "type": "object",
        "properties": {
            "outcome": {"type": "string", "enum": ["rescued", "unsupported", "no_evidence"]},
            "repository_url": {"type": "string"},
            "fix_commit": {"type": "string"},
            "rationale": {"type": "string"},
        },
        "required": ["outcome", "rationale"],
    },
    impl=lambda **_: "",
)


def _rules_disabled() -> bool:
    """Variant-2 toggle: skip cascade-surrender.

    Set ``CVE_DIFF_DISABLE_RULES=1`` to test the purely-agentic path
    where only the hard caps ($2/30 iter/720s) backstop.
    """
    return os.environ.get("CVE_DIFF_DISABLE_RULES") == "1"


# How many times the agent may submit an unverified (slug, sha) before
# the loop hard-stops. Calibrated from 2026-04-26 OSS 2022-2024 bench:
# only 2 of 501 CVEs hit ``sha_not_found_in_repo`` (agent picked a SHA
# ``gh_commit_detail`` never returned). Allowing two re-tries gives the
# agent room to either re-verify the typo'd SHA or pick a different
# verified candidate; 3 strikes means structural integrity is
# impossible for this CVE on this run.
_MAX_UNVERIFIED_SUBMITS = 2

# How many times the agent may submit a (slug, sha) that does not resolve
# on the GitHub remote (``commit_exists`` → False) before the loop
# surrenders ``sha_not_found_in_repo``. Distinct from
# ``_MAX_UNVERIFIED_SUBMITS``: that gate catches "you didn't call
# gh_commit_detail on this pair"; this gate catches "you submitted a SHA
# that prefix-matches a verified pair but doesn't actually exist on the
# remote" — the CVE-2023-38545 stochastic where the agent emits a real
# 14-char prefix with a hallucinated tail.
_MAX_NOT_FOUND_SUBMITS = 2


def _build_rejection_feedback(
    tool_use_id: str,
    slug: str,
    sha: str,
    verified: list[tuple[str, str]],
    reason: str,
    next_step: str,
) -> dict[str, Any]:
    """Build the tool_result block sent back to the agent when a submit
    is rejected by a gate (verified-SHA or SHA-existence). Both gates
    use the same shape; the only differences are the ``reason`` line and
    the ``next_step`` instruction. Centralising keeps the two gates DRY
    and ensures the agent sees a uniform feedback schema."""
    verified_brief = ", ".join(
        f"{vs}@{vh[:12]}" for vs, vh in verified[:5]
    ) or "(none)"
    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": json.dumps({
            "submit_rejected": True,
            "reason": reason,
            "submitted": {"slug": slug, "sha": sha},
            "verified_pairs": verified_brief,
            "next_step": next_step,
        }),
    }


def _is_verified(slug: str, sha: str, verified: list[tuple[str, str]]) -> bool:
    """Prefix-tolerant lookup: (slug, sha) matches a verified entry if
    the slug matches and either side of the sha is a prefix of the
    other. The agent commonly submits a 12-char SHA after verifying a
    full 40-char one (or vice-versa).

    NOT a duplicate of ``github_client.commit_exists``: this checks
    "did the agent CALL gh_commit_detail on this exact pair this run"
    (catches typos and candidate-switches between verify and submit).
    ``commit_exists`` is the live-API "does this SHA exist on the
    remote" check, applied later by ``invariants.discover_validator``.
    Both gates run; they catch different mistake shapes.
    """
    if not slug or not sha:
        return False
    sha = sha.lower()
    for vslug, vsha in verified:
        if vslug != slug:
            continue
        if vsha.startswith(sha) or sha.startswith(vsha):
            return True
    return False


def _emit(phase: str, detail: dict[str, Any] | None = None) -> None:
    """Trace hook. Silent no-op when the out-of-tree tracer isn't wired."""
    try:
        from tools.trace import recorder  # type: ignore
        recorder.record("agent.discover", phase, detail or {})
    except Exception:
        pass


@dataclass
class _Budget:
    config: AgentConfig
    started_at: float = field(default_factory=time.monotonic)
    tokens: int = 0
    iterations: int = 0
    cost_usd: float = 0.0

    @property
    def elapsed_s(self) -> float:
        return time.monotonic() - self.started_at

    def exhausted(self) -> str | None:
        if self.tokens >= self.config.budget_tokens:
            return "budget_tokens"
        if self.cost_usd >= self.config.budget_cost_usd:
            return "budget_cost_usd"
        if self.elapsed_s >= self.config.budget_s:
            return "budget_s"
        if self.iterations >= self.config.max_iterations:
            return "budget_iterations"
        return None


def _price(
    model_id: str,
    in_t: int,
    out_t: int,
    cache_create_t: int = 0,
    cache_read_t: int = 0,
) -> float:
    """Anthropic prompt-caching rates: writes 1.25x input, reads 0.1x input."""
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
        tools: dict[str, Tool] = {t.name: t for t in config.tools}
        tools[_SUBMIT_TOOL.name] = _SUBMIT_TOOL
        tool_schemas = [t.anthropic_schema() for t in tools.values()]
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": config.user_message},
        ]
        tool_call_log: list[str] = []
        # (slug, sha) pairs that gh_commit_detail confirmed during this
        # run. The pipeline orchestrator reads these off AgentSurrender
        # to spawn a focused retry when the agent ran out of budget
        # after finding a candidate it never submitted.
        verified: list[tuple[str, str]] = []
        # How many in-loop LLM retries fired (across all iterations).
        # Surface this to the bench so the report can show retry effects.
        llm_retries: int = 0
        # Per-call (tool_name, args_repr_first_120chars) — captured to
        # validate args-novelty claims in post-hoc analysis. Privacy-safe:
        # args are CVE IDs, slugs, queries, paths — no secrets. Limited
        # to 120 chars per call to keep summary.json bounded.
        tool_calls_with_args: list[tuple[str, str]] = []
        # Verified-SHA submit gate counter — see _MAX_UNVERIFIED_SUBMITS.
        unverified_submits: int = 0
        # SHA-existence gate counter — see _MAX_NOT_FOUND_SUBMITS.
        not_found_submits: int = 0

        _emit("entry", {
            "cve": ctx.cve_id,
            "model": config.model_id,
            "prompt_hash": prompt_hash,
            "n_tools": len(tools),
        })
        start = time.monotonic()
        budget = _Budget(config=config, started_at=start)

        rules_disabled = _rules_disabled()
        if rules_disabled:
            _emit("rules_disabled", {"cve": ctx.cve_id})

        try:
            client = self._client()
        except Exception as exc:
            return self._finalize(
                AgentSurrender(reason="client_init_failed", detail=str(exc)[:200]),
                budget, start, tuple(tool_call_log), tuple(verified), llm_retries,
            )

        submit_payload: dict[str, Any] | None = None

        while submit_payload is None:
            reason = budget.exhausted()
            if reason is not None:
                return self._finalize(
                    AgentSurrender(
                        reason=reason,
                        detail=f"iterations={budget.iterations} tokens={budget.tokens} "
                               f"cost=${budget.cost_usd:.4f} elapsed={budget.elapsed_s:.1f}s",
                    ),
                    budget, start, tuple(tool_call_log), tuple(verified), llm_retries,
                    tool_calls_with_args=tuple(tool_calls_with_args),
                )
            if (
                not rules_disabled
                and source_classes.should_surrender_no_evidence(tool_call_log, budget.cost_usd)
            ):
                tried = source_classes.tried_classes(tool_call_log)
                return self._finalize(
                    AgentSurrender(
                        reason="no_evidence",
                        detail=(
                            f"iter={budget.iterations} cost=${budget.cost_usd:.4f}: "
                            f"all source classes tried ({', '.join(sorted(tried))}) "
                            f"with zero verification calls. Public data does not "
                            f"yield a fix-commit for this CVE."
                        ),
                    ),
                    budget, start, tuple(tool_call_log), tuple(verified), llm_retries,
                    tool_calls_with_args=tuple(tool_calls_with_args),
                )

            # Prompt caching: mark the system prompt as cacheable so
            # the (large, static) system + tool schema is billed at the
            # cached rate (10% of input price) on iterations 2+.
            # See Anthropic prompt-caching docs.
            create_kwargs: dict[str, Any] = {
                "model": config.model_id,
                "system": [{
                    "type": "text",
                    "text": config.system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }],
                "messages": messages,
                "tools": tool_schemas,
                "max_tokens": 2048,
            }
            if config.temperature is not None:
                create_kwargs["temperature"] = config.temperature
            # Anthropic API blip retry: 5s then 15s backoff. Covers
            # transient 529-overloaded / connection drops cleanly. The
            # 6 server-side 529s in the 2026-04-25 bench were exactly
            # this case — without retry, those CVEs landed as llm_error
            # and required manual re-bench.
            #
            # Task-budget beta: route through `client.beta.messages.create`
            # with the `task-budgets-2026-03-13` header + an
            # `output_config.task_budget` so the server tracks a running
            # countdown the model sees mid-loop and self-regulates against.
            # `remaining` is omitted per Anthropic's guidance (server
            # tracks; mutating it client-side breaks the prompt cache).
            if config.enable_task_budgets:
                create_kwargs["output_config"] = {
                    "task_budget": {
                        "type": "tokens",
                        "total": config.budget_tokens,
                    },
                }
                create_kwargs["betas"] = ["task-budgets-2026-03-13"]
                create_fn = client.beta.messages.create
            else:
                create_fn = client.messages.create
            resp = None
            last_exc: Exception | None = None
            for attempt, delay in enumerate((0.0, 5.0, 15.0)):
                if delay > 0:
                    time.sleep(delay)
                try:
                    resp = create_fn(**create_kwargs)
                    if attempt > 0:
                        llm_retries += 1
                    break
                except (APIConnectionError, APIStatusError, APIError) as exc:
                    last_exc = exc
                    continue
            if resp is None:
                return self._finalize(
                    AgentSurrender(reason="llm_error", detail=str(last_exc)[:200] if last_exc else "unknown"),
                    budget, start, tuple(tool_call_log), tuple(verified), llm_retries,
                    tool_calls_with_args=tuple(tool_calls_with_args),
                )

            budget.iterations += 1
            usage = resp.usage
            in_t = getattr(usage, "input_tokens", 0) or 0
            out_t = getattr(usage, "output_tokens", 0) or 0
            cc_t = getattr(usage, "cache_creation_input_tokens", 0) or 0
            cr_t = getattr(usage, "cache_read_input_tokens", 0) or 0
            budget.tokens += in_t + out_t + cc_t + cr_t
            budget.cost_usd += _price(config.model_id, in_t, out_t, cc_t, cr_t)

            content_blocks = list(resp.content or [])
            tool_use_blocks = [b for b in content_blocks if getattr(b, "type", "") == "tool_use"]

            assistant_content: list[dict[str, Any]] = []
            text_snippet = ""
            for b in content_blocks:
                btype = getattr(b, "type", "")
                if btype == "text":
                    text_snippet = (getattr(b, "text", "") or "")
                    assistant_content.append({"type": "text", "text": text_snippet})
                elif btype == "tool_use":
                    assistant_content.append({
                        "type": "tool_use",
                        "id": b.id,
                        "name": b.name,
                        "input": b.input or {},
                    })
            messages.append({"role": "assistant", "content": assistant_content})

            if not tool_use_blocks:
                return self._finalize(
                    AgentSurrender(reason="model_stopped_without_submit", detail=text_snippet[:200]),
                    budget, start, tuple(tool_call_log), tuple(verified), llm_retries,
                    tool_calls_with_args=tuple(tool_calls_with_args),
                )

            tool_results: list[dict[str, Any]] = []
            for b in tool_use_blocks:
                name = b.name
                args = dict(b.input or {})
                tool_call_log.append(name)
                # Capture args summary for telemetry. JSON-stringify with
                # sort_keys so the same call shows the same repr; cap at
                # 120 chars to keep summary.json bounded.
                args_repr = json.dumps(args, sort_keys=True, default=str)[:120]
                tool_calls_with_args.append((name, args_repr))
                if name == _SUBMIT_TOOL.name:
                    # Verified-SHA gate: when the agent submits
                    # ``outcome="rescued"``, validate that the (slug, sha)
                    # was confirmed by ``gh_commit_detail`` in this run.
                    # The data is already there — `verified` was populated
                    # from gh_commit_detail successes — so we don't add
                    # any new state, just enforce what the prompt asks.
                    outcome = (args.get("outcome") or "").lower()
                    if outcome == "rescued":
                        slug = extract_github_slug(args.get("repository_url") or "") or ""
                        sha = (args.get("fix_commit") or "").strip().lower()
                        if slug and sha and not _is_verified(slug, sha, verified):
                            unverified_submits += 1
                            if unverified_submits > _MAX_UNVERIFIED_SUBMITS:
                                _emit("submit_unverified_sha", {
                                    "cve": ctx.cve_id, "slug": slug, "sha": sha,
                                    "verified_count": len(verified),
                                })
                                return self._finalize(
                                    AgentSurrender(
                                        reason="submit_unverified_sha",
                                        detail=(
                                            f"agent submitted ({slug}, {sha}) "
                                            f"{unverified_submits} times without "
                                            f"a matching gh_commit_detail "
                                            f"verification. verified_pairs="
                                            f"{verified[:5]}"
                                        ),
                                    ),
                                    budget, start, tuple(tool_call_log),
                                    tuple(verified), llm_retries,
                                    tool_calls_with_args=tuple(tool_calls_with_args),
                                    unverified_submits=unverified_submits,
                                    not_found_submits=not_found_submits,
                                )
                            tool_results.append(_build_rejection_feedback(
                                tool_use_id=b.id, slug=slug, sha=sha,
                                verified=verified,
                                reason=(
                                    "the (slug, sha) you submitted was not "
                                    "verified by gh_commit_detail in this run."
                                ),
                                next_step=(
                                    "call gh_commit_detail on the SHA you "
                                    "intend to submit, or submit one of the "
                                    "verified pairs. You have "
                                    f"{_MAX_UNVERIFIED_SUBMITS - unverified_submits + 1} "
                                    "attempt(s) left."
                                ),
                            ))
                            continue
                        # SHA-existence gate: catches the prefix-tolerance
                        # hole in the verified-SHA gate (real prefix +
                        # hallucinated tail). ``commit_exists`` returns
                        # None on rate-limit / non-GitHub — treat as
                        # accept, same policy as the validator backstop.
                        if slug and sha and github_client.commit_exists(slug, sha) is False:
                            not_found_submits += 1
                            if not_found_submits > _MAX_NOT_FOUND_SUBMITS:
                                _emit("submit_sha_not_found", {
                                    "cve": ctx.cve_id, "slug": slug, "sha": sha,
                                })
                                return self._finalize(
                                    AgentSurrender(
                                        reason="sha_not_found_in_repo",
                                        detail=(
                                            f"agent submitted ({slug}, {sha[:12]}) "
                                            f"{not_found_submits} times; "
                                            f"GitHub returned 404 each time."
                                        ),
                                    ),
                                    budget, start, tuple(tool_call_log),
                                    tuple(verified), llm_retries,
                                    tool_calls_with_args=tuple(tool_calls_with_args),
                                    unverified_submits=unverified_submits,
                                    not_found_submits=not_found_submits,
                                )
                            tool_results.append(_build_rejection_feedback(
                                tool_use_id=b.id, slug=slug, sha=sha,
                                verified=verified,
                                reason=(
                                    "sha_not_found: GitHub returned 404 for the "
                                    "(slug, sha) you submitted. Common cause: "
                                    "you emitted a SHA with the right prefix "
                                    "but a hallucinated tail. Submit the FULL "
                                    "40-char SHA exactly as gh_commit_detail "
                                    "returned it, or pick a different candidate."
                                ),
                                next_step=(
                                    "submit a verified pair verbatim, or call "
                                    "gh_commit_detail on a new candidate. You "
                                    f"have {_MAX_NOT_FOUND_SUBMITS - not_found_submits + 1} "
                                    "attempt(s) left."
                                ),
                            ))
                            continue
                    submit_payload = args
                    break
                tool = tools.get(name)
                if tool is None:
                    tool_output = json.dumps({"error": f"unknown_tool:{name}"})
                else:
                    try:
                        tool_output = tool.impl(**args)
                    except TypeError as exc:
                        tool_output = json.dumps({"error": f"bad_arguments: {exc}"[:200]})
                    except Exception as exc:  # noqa: BLE001
                        tool_output = json.dumps({"error": f"{type(exc).__name__}: {exc}"[:200]})
                # Capture confirmed (slug, sha) for the retry path on
                # any verification-class tool success: gh_commit_detail,
                # cgit_fetch, gitlab_commit. ``source_classes.VERIFICATION_TOOLS``
                # is the canonical list — keep this set in sync. Each
                # tool ground-truths the SHA against its respective forge
                # (GitHub, cgit, GitLab); the (slug, sha) feeds
                # ``_maybe_retry`` if the agent later hits a budget cap.
                #
                # gh_commit_detail returns slug+sha in its body; cgit_fetch
                # and gitlab_commit don't (they return commit metadata),
                # so for those we read slug+sha from the agent's args.
                if name == "gh_commit_detail":
                    try:
                        parsed = json.loads(tool_output)
                        if isinstance(parsed, dict) and "error" not in parsed:
                            slug = (parsed.get("slug") or "").strip().lower()
                            sha = (parsed.get("sha") or "").strip().lower()
                            if slug and sha and (slug, sha) not in verified:
                                verified.append((slug, sha))
                    except (ValueError, AttributeError):
                        pass
                elif name in ("cgit_fetch", "gitlab_commit"):
                    try:
                        parsed = json.loads(tool_output)
                        if isinstance(parsed, dict) and "error" not in parsed:
                            slug = (args.get("slug") or "").strip().lower()
                            sha = (args.get("sha") or "").strip().lower()
                            if slug and sha and (slug, sha) not in verified:
                                verified.append((slug, sha))
                    except (ValueError, AttributeError):
                        pass
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": b.id,
                    "content": tool_output,
                })

            if submit_payload is None and tool_results:
                messages.append({"role": "user", "content": tool_results})

        try:
            result = config.validator(submit_payload, ctx)
        except Exception as exc:
            self.last_telemetry = {
                "reason": f"raised:{type(exc).__name__}",
                "detail": str(exc)[:300],
                "tokens": budget.tokens,
                "cost_usd": round(budget.cost_usd, 6),
                "elapsed_s": round(budget.elapsed_s, 3),
                "tool_calls": tuple(tool_call_log),
            }
            _emit("exit", {
                "outcome": "exception",
                "exc_type": type(exc).__name__,
                "cost_usd": round(budget.cost_usd, 6),
                "iterations": budget.iterations,
                "elapsed_ms": round((time.monotonic() - start) * 1000.0, 3),
                "tool_calls": tool_call_log,
            })
            raise
        return self._finalize(
            result, budget, start, tuple(tool_call_log),
            tuple(verified), llm_retries,
            tool_calls_with_args=tuple(tool_calls_with_args),
            unverified_submits=unverified_submits,
            not_found_submits=not_found_submits,
        )

    def _finalize(
        self,
        result: AgentResult,
        budget: _Budget,
        start: float,
        tool_calls: tuple[str, ...],
        verified_candidates: tuple[tuple[str, str], ...] = (),
        llm_retries: int = 0,
        *,
        tool_calls_with_args: tuple[tuple[str, str], ...] = (),
        unverified_submits: int = 0,
        not_found_submits: int = 0,
    ) -> AgentResult:
        elapsed = round(budget.elapsed_s, 3)
        elapsed_ms = round((time.monotonic() - start) * 1000.0, 3)
        tokens = budget.tokens
        cost_usd = round(budget.cost_usd, 6)
        self.last_telemetry = {
            "iterations": budget.iterations,
            "tokens": tokens,
            "cost_usd": cost_usd,
            "elapsed_s": elapsed,
            "tool_calls": list(tool_calls),
            "tool_calls_with_args": [list(t) for t in tool_calls_with_args],
            "llm_retries": llm_retries,
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
                elapsed_s=elapsed,
                verified_candidates=result.verified_candidates or verified_candidates,
            )
            _emit("exit", {
                "outcome": "surrender",
                "reason": out.reason,
                "iterations": budget.iterations,
                "tokens": tokens,
                "cost_usd": cost_usd,
                "elapsed_ms": elapsed_ms,
                "tool_calls": list(tool_calls),
            })
            return out
        out_ok = AgentOutput(
            value=result.value,
            rationale=result.rationale,
            tool_calls=result.tool_calls or tool_calls,
            tokens=tokens,
            cost_usd=cost_usd,
            elapsed_s=elapsed,
        )
        _emit("exit", {
            "outcome": "rescued",
            "iterations": budget.iterations,
            "tokens": tokens,
            "cost_usd": cost_usd,
            "elapsed_ms": elapsed_ms,
            "tool_calls": list(tool_calls),
        })
        return out_ok

    def _client(self) -> Anthropic:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        return Anthropic(api_key=api_key, timeout=self.timeout_s)
