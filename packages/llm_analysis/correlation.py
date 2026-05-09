"""Multi-model correlation engine.

Pure-Python aggregation of per-model analysis results. Produces agreement
matrix, clusters, unique insights, and confidence signals. No LLM calls.
"""

from typing import Any, Dict, List


def correlate_results(results_by_id: Dict[str, Dict]) -> Dict[str, Any]:
    """Correlate multi-model analysis results for all findings.

    Only processes findings that have multi_model_analyses (i.e., were
    analysed by multiple models). Single-model findings are skipped.

    Returns a dict with:
        agreement_matrix: {finding_id: {model: {verdict, score, ruling}}}
        clusters: [{pattern, finding_ids, models_agreed}]
        unique_insights: [{finding_id, model, insight}]
        confidence_signals: {finding_id: "high"|"high-negative"|"disputed"}
        summary: {agreed, disputed, total, models}
    """
    matrix: Dict[str, Dict[str, Dict]] = {}
    confidence: Dict[str, str] = {}
    unique: List[Dict] = []

    models_seen: set[str] = set()

    for fid, result in results_by_id.items():
        analyses = result.get("multi_model_analyses")
        if not analyses or len(analyses) < 2:
            continue

        # Recompute on stale verdicts. `multi_model_analyses`
        # captures each model's verdict at INITIAL DISPATCH time;
        # later pipeline stages (RetryTask, ConsensusTask,
        # CrossFamilyCheckTask) update the top-level
        # `result["is_exploitable"]` / `ruling` /
        # `exploitability_score` for the primary model BUT do NOT
        # update the corresponding `multi_model_analyses` entry.
        # Without this normalisation step the correlation matrix
        # showed stale per-model verdicts for the active model
        # (and downstream "disputed" / "high" labels were
        # computed against pre-retry data), so a finding the
        # retry stage successfully reconciled would still show
        # as disputed in the operator's report.
        active_model = result.get("analysed_by")
        for a in analyses:
            if a.get("model") and a.get("model") == active_model:
                # Pull the post-pipeline values into the
                # multi_model_analyses entry. Only overwrite
                # fields where the top-level result has a value
                # (don't clobber per-model reasoning with None).
                for key in ("is_exploitable", "exploitability_score", "ruling"):
                    if key in result:
                        a[key] = result[key]

        per_model = {}
        for a in analyses:
            model = a.get("model", "?")
            models_seen.add(model)
            per_model[model] = {
                "is_exploitable": a.get("is_exploitable"),
                "exploitability_score": a.get("exploitability_score"),
                "ruling": a.get("ruling"),
            }
        matrix[fid] = per_model

        verdicts = [a.get("is_exploitable", False) for a in analyses]
        all_agree = len(set(verdicts)) == 1

        if all_agree and verdicts[0]:
            confidence[fid] = "high"
        elif all_agree and not verdicts[0]:
            confidence[fid] = "high-negative"
        else:
            confidence[fid] = "disputed"

            exploitable_models = [
                a["model"] for a in analyses if a.get("is_exploitable")
            ]
            non_exploitable_models = [
                a["model"] for a in analyses if not a.get("is_exploitable")
            ]
            minority = (exploitable_models if len(exploitable_models) < len(non_exploitable_models)
                        else non_exploitable_models)
            majority_verdict = len(exploitable_models) >= len(non_exploitable_models)
            for model in minority:
                reasoning = next(
                    (a.get("reasoning", "") for a in analyses if a.get("model") == model),
                    "",
                )
                unique.append({
                    "finding_id": fid,
                    "model": model,
                    "verdict": not majority_verdict,
                    "reasoning": reasoning[:200],
                })

    clusters = _build_clusters(matrix, results_by_id)

    agreed = sum(1 for s in confidence.values() if s in ("high", "high-negative"))
    disputed = sum(1 for s in confidence.values() if s == "disputed")

    return {
        "agreement_matrix": matrix,
        "clusters": clusters,
        "unique_insights": unique,
        "confidence_signals": confidence,
        "summary": {
            "total_correlated": len(matrix),
            "agreed": agreed,
            "disputed": disputed,
            "models": sorted(models_seen),
        },
    }


def _build_clusters(
    matrix: Dict[str, Dict[str, Dict]],
    results_by_id: Dict[str, Dict],
) -> List[Dict]:
    """Group findings by agreement pattern.

    Findings where the same set of models agree on the same verdict pattern
    are clustered together.
    """
    pattern_groups: Dict[str, List[str]] = {}

    for fid, per_model in matrix.items():
        verdicts = tuple(
            (model, v.get("is_exploitable", False))
            for model, v in sorted(per_model.items())
        )
        pattern_key = str(verdicts)
        pattern_groups.setdefault(pattern_key, []).append(fid)

    clusters = []
    for pattern_key, fids in pattern_groups.items():
        if len(fids) < 2:
            continue
        sample_fid = fids[0]
        per_model = matrix[sample_fid]
        # Pre-fix `list(per_model.values())[0]` was rebuilt EACH
        # iteration of the generator. For per_model with N models,
        # `all(... for v in per_model.values())` evaluates the
        # `list(...)[0]` expression N times, each materialising the
        # full values list (O(N) per call). The total cost is O(N²).
        # On CodeQL findings with 5+ analysis models, the inner
        # cost was tiny but it scaled poorly as RAPTOR added more
        # multi-model support — and the dead allocation was
        # noticeable in profiling.
        #
        # Hoist the reference once before the all(). dict insertion
        # order is preserved (Python 3.7+), so `next(iter(...))`
        # gives the same "first model" choice deterministically.
        first_value = next(iter(per_model.values()), {})
        first_is_exploitable = first_value.get("is_exploitable")
        models_agreed = all(
            v.get("is_exploitable") == first_is_exploitable
            for v in per_model.values()
        )
        shared_rules = set()
        for fid in fids:
            rule = results_by_id.get(fid, {}).get("rule_id", "")
            if rule:
                shared_rules.add(rule)

        clusters.append({
            "finding_ids": sorted(fids),
            "pattern": "unanimous" if models_agreed else "split",
            "shared_rules": sorted(shared_rules),
            "models_agreed": models_agreed,
        })

    return clusters
