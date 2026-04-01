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


class DispatchResult:
    """Normalised result from any dispatch path (external LLM or CC)."""

    def __init__(self, result: Dict[str, Any], cost: float = 0.0,
                 tokens: int = 0, model: str = "", duration: float = 0.0):
        self.result = result
        self.cost = cost
        self.tokens = tokens
        self.model = model
        self.duration = duration


class DispatchTask:
    """Base class for parallel LLM dispatch tasks.

    Subclasses define what to dispatch (prompts, schemas, model selection).
    The generic dispatcher handles how (threading, progress, cost, errors).
    """

    name: str = "task"
    model_role: str = "analysis"
    temperature: float = 0.7
    budget_cutoff: float = 1.0  # 1.0 = never skip. 0.85 = skip at 85% budget

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
    """Format elapsed seconds: '45s', '2m 15s', or '1h 05m'."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs:02d}s"
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    return f"{hours}h {minutes:02d}m"


def _is_auth_error(error_str: str) -> bool:
    """Check if an error string indicates an authentication/billing failure."""
    lower = error_str.lower()
    return any(x in lower for x in [
        "401", "403", "authentication", "unauthorized",
        "invalid api key", "billing", "quota", "rate limit",
        "insufficient_quota", "credit",
    ])


def dispatch_task(
    task: DispatchTask,
    items: list,
    dispatch_fn: Callable,
    role_resolution: dict,
    prior_results: dict,
    cost_tracker: Any,
    max_parallel: int = 3,
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

    with ThreadPoolExecutor(max_workers=max_parallel) as executor:
        futures = {}
        for model, item in work:
            def _do_one(m=model, it=item):
                prompt = task.build_prompt(it)
                schema = task.get_schema(it)
                return dispatch_fn(prompt, schema, system_prompt, task.temperature, m)

            future = executor.submit(_do_one)
            futures[future] = (model, item)

        for future in as_completed(futures):
            model, item = futures[future]
            item_id = task.get_item_id(item)
            completed += 1
            elapsed = time.monotonic() - start

            try:
                dispatch_result = future.result()
                processed = task.process_result(item, dispatch_result)
                processed["finding_id"] = item_id  # Authoritative — overrides any LLM-set value
                item_cost = processed.get("cost_usd", 0)
                running_cost += item_cost
                results.append(processed)
                consecutive_errors = 0

                # Feed costs to tracker for budget enforcement
                if item_cost > 0:
                    model_name = processed.get("analysed_by", "unknown")
                    cost_tracker.add_cost(model_name, item_cost)

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
                results.append({"finding_id": item_id, "error": err_str})
                display = task.get_item_display(item)
                print(f"  [{completed}/{total} {_format_elapsed(elapsed)} ${running_cost:.2f}] "
                      f"{display} FAILED — {err_str}")

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
