"""Multi-model correlation engine.

Pure-Python aggregation of per-model analysis results. Produces agreement
matrix, clusters, unique insights, and confidence signals. No LLM calls.

Also home of the shared verdict-vote tally (`tally_verdict_votes` /
`VoteTally`) used by every surface that counts ``is_exploitable``
votes across models — this module, ``ConsensusTask.finalize`` and
``JudgeTask.finalize`` in ``tasks.py``. One counting rule everywhere:
a missing/null ``is_exploitable`` (errored model, refused response,
schema failure — ``core/llm/response_validation.py`` nulls the field)
is an ABSTENTION, excluded from both the vote count and the majority
denominator. Counting abstainers as "not exploitable" let malformed
LLM output out-vote a real exploitable verdict.
"""

from dataclasses import dataclass
from typing import Any
from collections.abc import Iterable

from core.run.finding_status import read_verdict


@dataclass(frozen=True)
class VoteTally:
    """Counted ``is_exploitable`` votes with abstentions excluded.

    ``exploitable`` / ``not_exploitable`` count models that actually
    voted; ``abstained`` counts missing/null verdicts. Majority and
    tie semantics are explicit so consumers cannot re-derive them
    divergently: a *strict* majority over the models that voted, and
    ``None`` when nobody voted or the vote is tied — the consumer
    applies its own documented tie policy.
    """

    exploitable: int
    not_exploitable: int
    abstained: int

    @property
    def voted(self) -> int:
        """Number of models that cast a real vote (abstains excluded)."""
        return self.exploitable + self.not_exploitable

    @property
    def tie(self) -> bool:
        return self.voted > 0 and self.exploitable == self.not_exploitable

    @property
    def disputed(self) -> bool:
        """True when real votes exist on BOTH sides. Abstainers can
        never create (or mask) a dispute."""
        return self.exploitable > 0 and self.not_exploitable > 0

    @property
    def unanimous(self) -> bool:
        """All actual voters agreed (requires at least one vote)."""
        return self.voted > 0 and not self.disputed

    def majority(self) -> bool | None:
        """Strict-majority verdict over the voting models.

        Returns ``None`` when no model voted (all abstained) or the
        vote is tied — there is no majority to report; the caller
        decides what an inconclusive tally means on its surface.
        """
        if self.voted == 0 or self.tie:
            return None
        return self.exploitable > self.not_exploitable

    def any_exploitable(self) -> bool:
        """Conservative-max reading: at least one real exploitable vote."""
        return self.exploitable > 0


def tally_verdict_votes(votes: Iterable[Any]) -> VoteTally:
    """Count raw ``is_exploitable`` values into a :class:`VoteTally`.

    ``None`` (the response-validation null for a missing/failed
    verdict) is an abstention; every other value is boolean-coerced
    into a real vote.
    """
    exploitable = not_exploitable = abstained = 0
    for v in votes:
        if v is None:
            abstained += 1
        elif v:
            exploitable += 1
        else:
            not_exploitable += 1
    return VoteTally(
        exploitable=exploitable,
        not_exploitable=not_exploitable,
        abstained=abstained,
    )


def correlate_results(results_by_id: dict[str, dict]) -> dict[str, Any]:
    """Correlate multi-model analysis results for all findings.

    Only processes findings that have multi_model_analyses (i.e., were
    analysed by multiple models). Single-model findings are skipped.

    Returns a dict with:
        agreement_matrix: {finding_id: {model: {verdict, score, ruling}}}
        clusters: [{pattern, finding_ids, models_agreed}]
        unique_insights: [{finding_id, model, verdict, reasoning}]
            (minority dissent; on an even split every voting model is
            listed with its own verdict and ``tie: True`` — a 50/50
            dispute has no majority to dissent from)
        confidence_signals: {finding_id:
            "high"|"high-negative"|"disputed"|"no-verdict"}
            ("no-verdict" = every model abstained — errored/refused;
            abstentions never count as votes)
        summary: {agreed, disputed, total_correlated, models}
    """
    matrix: dict[str, dict[str, dict]] = {}
    confidence: dict[str, str] = {}
    unique: list[dict] = []

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
                # fields where the top-level result has a value —
                # a present-but-None top-level field (e.g. an
                # errored retry writing the key back) must not
                # convert the active model's real vote into an
                # abstention.
                for key in ("is_exploitable", "exploitability_score", "ruling"):
                    if result.get(key) is not None:
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

        # Vote counting via the shared tally: missing/null
        # is_exploitable is an ABSTENTION (errored model, refused
        # response, schema failure), not a "not exploitable" vote —
        # pre-fix bool(None) coerced abstainers into False votes, so
        # one real "exploitable" verdict plus two errored models read
        # as a 2-1 majority AGAINST and could even mint a unanimous
        # 'high-negative' from zero actual verdicts.
        tally = tally_verdict_votes(
            a.get("is_exploitable") for a in analyses
        )

        if tally.voted == 0:
            # Every model abstained — no verdict exists to agree on.
            confidence[fid] = "no-verdict"
        elif tally.unanimous and tally.any_exploitable():
            confidence[fid] = "high"
        elif tally.unanimous:
            confidence[fid] = "high-negative"
        else:
            confidence[fid] = "disputed"

            # Majority/minority over models that actually voted.
            exploitable_models = [
                a.get("model", "?") for a in analyses
                if read_verdict(a, "is_exploitable") is True
            ]
            non_exploitable_models = [
                a.get("model", "?") for a in analyses
                if read_verdict(a, "is_exploitable") is False
            ]
            if tally.tie:
                # Even split (the common 1-vs-1 two-model dispute):
                # there is no majority — filing one side as the
                # dissenting minority would frame a 50/50 tie as
                # leaning the other way in operator reports. Surface
                # BOTH sides, each labelled with its own verdict and
                # an explicit tie marker.
                for a in analyses:
                    verdict = read_verdict(a, "is_exploitable")
                    if verdict is None:
                        continue
                    unique.append({
                        "finding_id": fid,
                        "model": a.get("model", "?"),
                        "verdict": verdict,
                        "tie": True,
                        "reasoning": (a.get("reasoning") or "")[:200],
                    })
            else:
                majority_verdict = bool(tally.majority())
                minority = (non_exploitable_models if majority_verdict
                            else exploitable_models)
                for model in minority:
                    reasoning = next(
                        (a.get("reasoning") or "" for a in analyses
                         if a.get("model") == model),
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
    matrix: dict[str, dict[str, dict]],
    results_by_id: dict[str, dict],
) -> list[dict]:
    """Group findings by agreement pattern.

    Findings where the same set of models agree on the same verdict pattern
    are clustered together.
    """
    pattern_groups: dict[str, list[str]] = {}

    for fid, per_model in matrix.items():
        # Tri-state pattern key (read_verdict): a model that
        # abstained (None) is a different agreement pattern from a
        # model that voted an explicit False. Pre-fix the default-
        # False read keyed both identically, so a finding whose
        # second model errored out clustered with findings that
        # model actually ruled not-exploitable.
        verdicts = tuple(
            (model, read_verdict(v, "is_exploitable"))
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
        # Abstention-aware agreement (same counting rule as
        # ``tally_verdict_votes``): a None verdict (errored / refused /
        # schema-failed model) is not a vote. Pre-fix an all-abstain
        # panel satisfied None == None and minted a "unanimous"
        # cluster from zero actual verdicts on the operator triage
        # surface, while the same finding's confidence signal
        # correctly read "no-verdict".
        tally = tally_verdict_votes(
            v.get("is_exploitable") for v in per_model.values()
        )
        models_agreed = tally.unanimous
        shared_rules = set()
        for fid in fids:
            rule = results_by_id.get(fid, {}).get("rule_id", "")
            if rule:
                shared_rules.add(rule)

        if tally.voted == 0:
            # Zero real verdicts — neither unanimous nor split;
            # mirror the confidence-signal vocabulary.
            pattern = "no-verdict"
        else:
            pattern = "unanimous" if models_agreed else "split"
        clusters.append({
            "finding_ids": sorted(fids),
            "pattern": pattern,
            "shared_rules": sorted(shared_rules),
            "models_agreed": models_agreed,
        })

    return clusters
