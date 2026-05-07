"""Generic parallel dispatch for LLM tasks.

Provides DispatchTask base class and dispatch_task() function.
The dispatcher handles threading, progress, cost tracking, and error handling.
Task subclasses define semantics: what prompt, what schema, which model.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Corpora checked by dispatch preflight.  Excludes "structural_injection"
# because the assembled prompt contains RAPTOR's own JSON fields
# ("ruling": "false_positive", "is_exploitable": false) which those
# patterns legitimately match.
_DISPATCH_CORPORA = (
    "english",
    "role_injection",
    "unicode_smuggling",
    "encoding_evasion",
)


class DispatchResult:
    """Normalised result from any dispatch path (external LLM or CC)."""

    def __init__(self, result: Dict[str, Any], cost: float = 0.0,
                 tokens: int = 0, model: str = "", duration: float = 0.0,
                 quality: float = 1.0):
        self.result = result
        self.cost = cost
        self.tokens = tokens
        self.model = model
        self.duration = duration
        self.quality = quality


class DispatchTask:
    """Base class for parallel LLM dispatch tasks.

    Subclasses define what to dispatch (prompts, schemas, model selection).
    The generic dispatcher handles how (threading, progress, cost, errors).
    """

    name: str = "task"
    model_role: str = "analysis"
    temperature: float = 0.7
    budget_cutoff: float = 1.0  # 1.0 = never skip. 0.85 = skip at 85% budget

    def get_last_nonce(self) -> str:
        """Return the nonce from the most recent build_prompt call, if any.

        Subclasses that use PromptBundle should store bundle.nonce and
        return it here so the dispatcher can feed it to defense telemetry.
        """
        return ""

    def get_profile_name(self) -> str:
        """Return the defense profile name for telemetry."""
        return ""

    def select_items(self, items: list, prior_results: dict) -> list:
        """Select which items to process. Default: all items."""
        return items

    def get_models(self, role_resolution: dict) -> list:
        """Return list of models to dispatch to. Default: single model for this role."""
        model = role_resolution.get(f"{self.model_role}_model")
        return [model] if model else []

    def build_prompt(self, item: Dict[str, Any]) -> str:
        """Build the prompt for one item. Must be implemented by subclass."""
        raise NotImplementedError

    def get_schema(self, item: Dict[str, Any]) -> Optional[dict]:
        """Schema for structured output, or None for free-form generate()."""
        return None

    def get_system_prompt(self) -> Optional[str]:
        """System prompt for this task."""
        return None

    def process_result(self, item: Dict[str, Any], result: DispatchResult) -> Dict[str, Any]:
        """Post-process a single result. Default: return result dict with metadata."""
        out = dict(result.result)
        if result.cost > 0:
            out["cost_usd"] = result.cost
        if result.duration > 0:
            out["duration_seconds"] = round(result.duration, 1)
        if result.model:
            out["analysed_by"] = result.model
        return out

    def finalize(self, results: List[Dict], prior_results: dict) -> List[Dict]:
        """Post-dispatch processing. Default: no-op. Override for consensus verdicts, etc."""
        return results

    def get_item_id(self, item: Dict[str, Any]) -> str:
        """ID for result matching and progress display."""
        return item.get("finding_id", item.get("group_id", "unknown"))

    def get_item_display(self, item: Dict[str, Any]) -> str:
        """Human-readable location for progress line."""
        fp = item.get("file_path", "")
        if fp:
            fp = fp.split("/")[-1]
            line = item.get("start_line", "")
            return f"{fp}:{line}" if line else fp
        return ""


def _format_elapsed(seconds: float) -> str:
    """Format elapsed seconds. Delegates to core.reporting.formatting."""
    from core.reporting.formatting import format_elapsed
    return format_elapsed(seconds)


def _is_auth_error(error_str: str) -> bool:
    """Check if an error string indicates an authentication/billing failure."""
    lower = error_str.lower()
    return any(x in lower for x in [
        "401", "403", "authentication", "unauthorized",
        "invalid api key", "billing", "quota", "rate limit",
        "insufficient_quota", "credit",
    ])


def _classify_error(error_str: str) -> str:
    """Classify an error for structured reporting.

    Returns: 'blocked' (content filter/safety/refusal), 'auth' (key/billing/quota),
    'timeout', or 'error' (everything else).
    """
    lower = error_str.lower()
    if any(x in lower for x in ["content filter", "blocked response", "safety",
                                 "refused request", "refusal"]):
        return "blocked"
    if _is_auth_error(error_str):
        return "auth"
    if any(x in lower for x in ["timeout", "timed out"]):
        return "timeout"
    return "error"


def dispatch_task(
    task: DispatchTask,
    items: list,
    dispatch_fn: Callable,
    role_resolution: dict,
    prior_results: dict,
    cost_tracker: Any,
    max_parallel: int = 3,
    prefilter_fn: Optional[Callable] = None,
) -> List[Dict[str, Any]]:
    """Generic parallel dispatcher.

    Handles threading, progress output, cost tracking, error handling,
    and auth abort. The task defines semantics (prompts, schemas, model
    selection). The dispatch_fn abstracts the LLM interaction.

    Args:
        task: DispatchTask subclass defining what to dispatch.
        items: Raw items (findings, groups, etc) — task.select_items filters them.
        dispatch_fn: Callable(prompt, schema, system_prompt, temperature, model) → DispatchResult.
        role_resolution: Model role resolution dict from resolve_model_roles().
        prior_results: Results from earlier tasks, keyed by item ID.
        cost_tracker: CostTracker for budget enforcement.
        max_parallel: Maximum concurrent dispatches.
        prefilter_fn: Optional ``(item) -> Optional[result-dict]`` hook
            invoked before building the prompt and calling dispatch_fn.
            When it returns a dict the work item is short-circuited
            (no full ANALYSE call, no token/cost accounting beyond
            whatever the hook itself spent). Used by /agentic to wire
            in the scorecard prefilter; ``None`` for tasks that don't
            participate.

    Returns:
        List of result dicts, one per item dispatched. Failed items have "error" key.
    """
    selected = task.select_items(items, prior_results)
    if not selected:
        return []

    models = task.get_models(role_resolution)
    if not models:
        # CC path: no model resolution, dispatch_fn ignores model parameter
        models = [None]

    # Budget pre-check
    if task.budget_cutoff < 1.0:
        model_name = models[0].model_name if models[0] else ""
        total_calls = len(selected) * len(models)
        if cost_tracker.should_skip_phase(total_calls, model_name, task.budget_cutoff, task.name):
            print(f"\n  {task.name}: skipped ({len(selected)} items) — "
                  f"budget > {int(task.budget_cutoff * 100)}%"
                  f"; raise --max-cost to include")
            return []

    # Build work items: (model, item) pairs
    work = []
    for model in models:
        for item in selected:
            work.append((model, item))

    total = len(work)
    print(f"\n  {task.name}: {len(selected)} items"
          + (f" x {len(models)} models" if len(models) > 1 else "")
          + f" (max {max_parallel} parallel)")

    results = []
    completed = 0
    running_cost = 0.0
    abort = False
    consecutive_errors = 0
    start = time.monotonic()
    system_prompt = task.get_system_prompt()

    from core.security.prompt_telemetry import defense_telemetry
    from core.security.prompt_input_preflight import preflight
    profile_name = task.get_profile_name()

    import threading as _th
    # Key by (item_id, model_key) tuple — NOT just item_id. With N
    # models analysing the same item (multi-model orchestration),
    # all N writes land on the same `iid` key and last-writer-
    # wins, then the first completed future pops the entry and
    # the remaining N-1 model responses see an empty nonce →
    # `defense_telemetry.record_response` silently never fires
    # for them, defeating the entire prompt-injection / nonce-
    # leak detection layer (it can't detect leakage if it never
    # gets to compare the response against the nonce). Each
    # (item, model) pair must hold its own nonce to its own
    # completion.
    _nonces: dict[tuple, str] = {}
    _nonces_lock = _th.Lock()

    def _model_key(m) -> str:
        """Stable hashable identity for a model object — same
        formula used for telemetry's `model_id` so the nonce
        lookup matches the recorded response."""
        return getattr(m, "model_name", None) or str(m)

    with ThreadPoolExecutor(max_workers=max_parallel) as executor:
        futures = {}
        for model, item in work:
            def _do_one(m=model, it=item):
                # Prefilter hook (fast-tier scorecard) — fires before
                # prompt build and full dispatch so we don't pay for
                # token-heavy work when the cheap-tier verdict is
                # trusted. Returning a dict here ends this work item
                # with that result; ``None`` proceeds to full dispatch.
                if prefilter_fn is not None:
                    sc_result = prefilter_fn(it)
                    if sc_result is not None:
                        model_name = m.model_name if m is not None else "prefilter"
                        return DispatchResult(
                            result=sc_result,
                            cost=0.0,
                            tokens=0,
                            model=model_name,
                            duration=0.0,
                            quality=1.0,
                        )
                prompt = task.build_prompt(it)
                nonce = task.get_last_nonce()
                if nonce:
                    iid = task.get_item_id(it)
                    with _nonces_lock:
                        _nonces[(iid, _model_key(m))] = nonce
                pf = preflight(prompt, corpora=_DISPATCH_CORPORA)
                defense_telemetry.record_preflight(hit=pf.has_injection_indicators)
                schema = task.get_schema(it)
                return dispatch_fn(prompt, schema, system_prompt, task.temperature, m)

            future = executor.submit(_do_one)
            futures[future] = (model, item)

        for future in as_completed(futures):
            model, item = futures[future]
            item_id = task.get_item_id(item)
            model_key = _model_key(model)
            completed += 1
            elapsed = time.monotonic() - start

            try:
                dispatch_result = future.result()
                processed = task.process_result(item, dispatch_result)
                processed["finding_id"] = item_id  # Authoritative — overrides any LLM-set value
                processed["_quality"] = getattr(dispatch_result, "quality", 1.0)
                item_cost = processed.get("cost_usd", 0)
                running_cost += item_cost
                results.append(processed)
                consecutive_errors = 0

                # Record defense telemetry (nonce leakage, schema rejection)
                with _nonces_lock:
                    nonce = _nonces.pop((item_id, model_key), "")
                if nonce and profile_name:
                    raw = ""
                    if hasattr(dispatch_result, "result") and isinstance(dispatch_result.result, dict):
                        raw = dispatch_result.result.get("content", "")
                    raw_text = raw or str(dispatch_result.result)
                    defense_telemetry.record_response(
                        model_id=processed.get("analysed_by", "unknown"),
                        profile_name=profile_name,
                        nonce=nonce,
                        raw_response=raw_text,
                        schema_accepted=True,
                        schema_retried=False,
                    )
                    from core.security.prompt_envelope import nonce_leaked_in
                    if nonce_leaked_in(nonce, raw_text):
                        processed["_nonce_leaked"] = True

                # Feed costs AND tokens to tracker. Pre-fix only
                # `cost` was passed; the dispatch_result already
                # carried `tokens` (provider-reported usage from
                # external LLM clients, or _tokens parsed from CC
                # subprocess envelope). CostTracker stored token
                # totals (`_total_tokens`, `_thinking_tokens`)
                # but they stayed at 0 across every run because
                # this single call site was the funnel and it
                # dropped the kwarg. `get_summary()` then
                # reported `total_tokens: 0` regardless of actual
                # usage, breaking telemetry, cost-per-token
                # diagnostics, and the model-economy reports the
                # operator UI surfaces.
                if item_cost > 0:
                    model_name = processed.get("analysed_by", "unknown")
                    item_tokens = getattr(dispatch_result, "tokens", 0) or 0
                    cost_tracker.add_cost(model_name, item_cost, tokens=item_tokens)

                # Progress line
                display = task.get_item_display(item)
                if "is_exploitable" in processed:
                    exploitable = processed.get("is_exploitable", False)
                    score = processed.get("exploitability_score")
                    ruling = processed.get("ruling")
                    try:
                        status = f"exploitable ({float(score):.2f})" if exploitable else "not exploitable"
                    except (ValueError, TypeError):
                        status = "exploitable" if exploitable else "not exploitable"
                    # Show short ruling labels (enum values), not long-form text
                    valid_rulings = {"false_positive", "unreachable", "test_code", "dead_code", "mitigated"}
                    if ruling and ruling in valid_rulings and not exploitable:
                        status = ruling.replace("_", " ")
                else:
                    status = "done"
                cost = processed.get("cost_usd")
                cost_str = f"  ${cost:.2f}" if cost else ""
                print(f"  [{completed}/{total} {_format_elapsed(elapsed)} ${running_cost:.2f}] "
                      f"{display} {status}{cost_str}")

            except Exception as e:
                err_str = str(e)
                error_type = _classify_error(err_str)
                results.append({"finding_id": item_id, "error": err_str,
                                "error_type": error_type})
                display = task.get_item_display(item)
                print(f"  [{completed}/{total} {_format_elapsed(elapsed)} ${running_cost:.2f}] "
                      f"{display} FAILED — {err_str}")

                # Record schema failure telemetry (skip auth/network errors)
                if error_type not in ("auth", "timeout") and profile_name:
                    with _nonces_lock:
                        nonce = _nonces.pop((item_id, model_key), "")
                    if nonce:
                        model_id = getattr(model, "model_name", str(model))
                        defense_telemetry.record_response(
                            model_id=model_id,
                            profile_name=profile_name,
                            nonce=nonce,
                            raw_response=err_str,
                            schema_accepted=False,
                            schema_retried=False,
                        )

                if _is_auth_error(err_str):
                    print("\n  Authentication/billing error — aborting remaining")
                    abort = True
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                consecutive_errors += 1
                if consecutive_errors >= 3 and completed == consecutive_errors:
                    # Every result so far has failed — abort early
                    print(f"\n  {consecutive_errors} consecutive failures — aborting remaining")
                    abort = True
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

    if abort:
        completed_ids = {r.get("finding_id") for r in results}
        for item in selected:
            item_id = task.get_item_id(item)
            if item_id not in completed_ids:
                results.append({"finding_id": item_id, "error": "aborted (auth failure)"})

    # Finalize (e.g. consensus verdict rules)
    results = task.finalize(results, prior_results)

    return results
