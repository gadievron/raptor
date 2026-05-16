"""Concrete base classes for the two supported item shapes.

Consumers subclass BaseVerdictAdapter or BaseSetAdapter and provide a
small number of consumer-specific methods (item_id, normalize_verdict /
item_key). The substrate-facing merge() and correlate() are inherited.

Both bases satisfy the corresponding Protocols in types.py via duck-typing
(they have the right methods); we don't make them subclass the Protocols
directly because Protocol + abc.ABC interaction is messy.
"""

from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Any, Dict, Hashable, List, Tuple


def _coerce_numeric(value: Any, default: float = 0.0) -> float:
    """Return value if it's a non-bool int/float; else default.

    Defensive helper: protects sort keys from non-numeric values that a
    consumer's schema might contain (string scores, None, etc.). Bools
    are excluded because Python treats them as ints; almost certainly a
    schema error if they appear in numeric fields.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return value


# ---------------------------------------------------------------------------
# Verdict-style adapter
# ---------------------------------------------------------------------------


class BaseVerdictAdapter(ABC):
    """Base for verdict-style multi-model tasks.

    Each model returns a verdict per input item (e.g., is_exploitable,
    is_reachable). The substrate runs N models, each producing a list of
    item-keyed results. This adapter folds them into a single item per id,
    annotated with multi_model_analyses, and computes per-id agreement.

    Subclass and implement:
      - item_id(item) — stable string id, must match across models
      - normalize_verdict(item) — return 'positive'/'negative'/'inconclusive'/'unknown'

    Optionally override:
      - select_primary(model_results) — default is prefer-positive then
        highest _quality / exploitability_score
      - extract_analysis_record(result, model_name) — what fields to put
        into multi_model_analyses (default: model + verdict + score + reasoning)
      - REASONING_TRUNCATE — class attr controlling reasoning length cap
        (default 600 chars; matches /agentic's existing convention)

    Tie-breaking notes:
      - select_primary's default sorts and takes index 0; with all keys
        equal, the alphabetically-first model_name wins (because the
        substrate hands per_model_results in sorted order).
      - correlate's minority-insight extraction arbitrarily picks the
        'negative' subset on an exact pos/neg split — matches /agentic.
    """

    REASONING_TRUNCATE: int = 600

    # ----- consumer-required -----

    @abstractmethod
    def item_id(self, item: Dict[str, Any]) -> str:
        """Stable, non-empty id consistent across models."""
        ...

    @abstractmethod
    def normalize_verdict(self, item: Dict[str, Any]) -> str:
        """Return one of: 'positive', 'negative', 'inconclusive', 'unknown'."""
        ...

    # ----- consumer-overridable -----

    def select_primary(
        self, model_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Default policy: prefer-positive, then quality, then exploitability.

        Subclasses may override for domain-specific tiebreaking. Tie-breaks
        with all-equal keys go to the alphabetically-first model_name
        (substrate sorts per_model_results upstream).

        Non-numeric `_quality` or `exploitability_score` values from a
        consumer's schema are defensively coerced to 0.0 — a buggy field
        type elsewhere shouldn't crash the sort with a confusing error.
        """
        if not model_results:
            raise ValueError("select_primary called with empty list")

        def sort_key(r: Dict[str, Any]) -> Tuple:
            verdict = self.normalize_verdict(r)
            # prefer positive (True), then inconclusive (False), then negative
            verdict_rank = 0 if verdict == "positive" else (
                1 if verdict in ("inconclusive", "unknown") else 2
            )
            quality = _coerce_numeric(r.get("_quality"))
            score = _coerce_numeric(r.get("exploitability_score"))
            # lower verdict_rank wins, higher quality and score win
            return (verdict_rank, -quality, -score)

        return dict(sorted(model_results, key=sort_key)[0])

    def extract_analysis_record(
        self, result: Dict[str, Any], model_name: str,
    ) -> Dict[str, Any]:
        """Pick the per-model record stored under multi_model_analyses.

        Reasoning is truncated to REASONING_TRUNCATE chars to keep the
        merged item compact. Override this method (or set the class
        attribute) for domains where longer reasoning is needed.
        """
        return {
            "model": model_name,
            "verdict": self.normalize_verdict(result),
            "is_exploitable": result.get("is_exploitable"),
            "exploitability_score": result.get("exploitability_score"),
            "reasoning": (result.get("reasoning") or "")[:self.REASONING_TRUNCATE],
        }

    # ----- substrate-facing -----

    def merge(
        self, per_model_results: Dict[str, List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """Fold per-model results into one item per id.

        Each merged item is a dict-copy of the primary chosen by
        select_primary, with multi_model_analyses attached when 2+
        models contributed for that id. Single-model items have NO
        multi_model_analyses key (not [], not None — absent). Consumers
        checking for multi-model context should use `if "multi_model_analyses"
        in item:` rather than `if item.get(...)`.
        """
        by_id: Dict[str, List[Tuple[str, Dict[str, Any]]]] = defaultdict(list)
        first_seen_order: List[str] = []
        for model_name, results in per_model_results.items():
            for r in results:
                rid = self.item_id(r)
                if rid not in by_id:
                    first_seen_order.append(rid)
                by_id[rid].append((model_name, r))

        merged: List[Dict[str, Any]] = []
        for rid in first_seen_order:
            entries = by_id[rid]
            results_only = [r for _, r in entries]
            primary = self.select_primary(results_only)
            # Gate on DISTINCT model count, not contribution count. A single
            # model returning the same id twice shouldn't masquerade as a
            # multi-model analysis. Mirrors BaseSetAdapter.merge's logic.
            distinct_models = {m for m, _ in entries}
            if len(distinct_models) > 1:
                primary["multi_model_analyses"] = [
                    self.extract_analysis_record(r, m)
                    for m, r in entries
                ]
            merged.append(primary)

        return merged

    def correlate(
        self,
        merged_items: List[Dict[str, Any]],
        per_model_results: Dict[str, List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """Compute agreement matrix and confidence signals.

        Returns:
            agreement_matrix: {item_id: {model_name: verdict}}
            confidence_signals: {item_id: 'high'|'high-negative'|'disputed'|'single_model'}
            unique_insights: minority-verdict reasoning surfaced for review
            summary: counts (agreed, disputed, single_model, total, models)
        """
        models = sorted(per_model_results.keys())
        # Build matrix: id → {model → verdict}
        matrix: Dict[str, Dict[str, str]] = {}
        for model_name, results in per_model_results.items():
            for r in results:
                rid = self.item_id(r)
                matrix.setdefault(rid, {})[model_name] = self.normalize_verdict(r)

        confidence: Dict[str, str] = {}
        unique_insights: List[Dict[str, Any]] = []

        for item in merged_items:
            rid = self.item_id(item)
            verdicts = list(matrix.get(rid, {}).values())
            if len(verdicts) < 2:
                confidence[rid] = "single_model"
                continue

            # Drop unknowns — they don't contribute to agreement.
            classifiable = [v for v in verdicts if v != "unknown"]
            if not classifiable:
                confidence[rid] = "single_model"
                continue

            uniq = set(classifiable)
            has_pos = "positive" in uniq
            has_neg = "negative" in uniq

            if has_pos and has_neg:
                # Strong disagreement — pos AND neg verdicts present.
                confidence[rid] = "disputed"
                analyses = item.get("multi_model_analyses", [])
                pos_models = {a["model"] for a in analyses
                              if a.get("verdict") == "positive"}
                neg_models = {a["model"] for a in analyses
                              if a.get("verdict") == "negative"}
                minority = pos_models if len(pos_models) < len(neg_models) else neg_models
                for analysis in analyses:
                    if analysis.get("model") in minority and analysis.get("reasoning"):
                        unique_insights.append({
                            "item_id": rid,
                            "model": analysis["model"],
                            "verdict": analysis.get("verdict"),
                            "reasoning": analysis["reasoning"],
                        })
            elif uniq == {"positive"}:
                confidence[rid] = "high"
            elif uniq == {"negative"}:
                confidence[rid] = "high-negative"
            elif uniq == {"inconclusive"}:
                # Mutual uncertainty — every model said "I don't know."
                # Useful signal: don't waste reviewer time, but flag for
                # external corroboration.
                confidence[rid] = "high-inconclusive"
            else:
                # Mix involving inconclusive but no pos/neg conflict —
                # softer disagreement (one or more uncertain, rest agree).
                confidence[rid] = "mixed"

        agreed = sum(1 for c in confidence.values()
                     if c in ("high", "high-negative", "high-inconclusive"))
        disputed = sum(1 for c in confidence.values() if c == "disputed")
        mixed = sum(1 for c in confidence.values() if c == "mixed")
        single = sum(1 for c in confidence.values() if c == "single_model")

        return {
            "agreement_matrix": matrix,
            "confidence_signals": confidence,
            "unique_insights": unique_insights,
            "summary": {
                "agreed": agreed,
                "disputed": disputed,
                "mixed": mixed,
                "single_model": single,
                "total": len(confidence),
                "models": models,
            },
        }


# ---------------------------------------------------------------------------
# Set-style adapter
# ---------------------------------------------------------------------------


class BaseSetAdapter(ABC):
    """Base for set-style multi-model tasks.

    Each model returns its own list of items found (e.g., variants, sinks,
    entry points). Items don't pre-exist; they're discovered. The substrate
    runs N models, produces N result lists, and this adapter unions them
    by item_key, annotating each merged item with which models found it.

    Subclass and implement:
      - item_id(item) — stable string id (typically derived from item_key)
      - item_key(item) — hashable dedup key; items with the same key are
        the same logical item even if their other fields differ slightly

    Optionally override:
      - extract_set_record(item, model_name) — what fields to keep from
        each model's version of the item (default: copy the whole item)
    """

    # ----- consumer-required -----

    @abstractmethod
    def item_id(self, item: Dict[str, Any]) -> str:
        """Stable, non-empty id."""
        ...

    @abstractmethod
    def item_key(self, item: Dict[str, Any]) -> Hashable:
        """Hashable dedup key. Items with equal keys are the same item.

        Implementations should normalize before key generation (e.g.,
        lowercase paths, strip whitespace) to avoid spurious duplicates.
        """
        ...

    # ----- consumer-overridable -----

    def extract_set_record(
        self, item: Dict[str, Any], model_name: str,
    ) -> Dict[str, Any]:
        """Per-model record stored under multi_model_finds.

        Default keeps the whole item with a model annotation. Override if
        items contain heavy fields (e.g., full source snippets).
        """
        return {"model": model_name, **item}

    # ----- substrate-facing -----

    def merge(
        self, per_model_results: Dict[str, List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """Union by item_key. Each merged item gets:
           - found_by_models: sorted list of distinct model names
           - multi_model_finds: per-model records (only when 2+ DISTINCT
             models contributed — intra-model duplicates don't qualify)
           - all original non-key fields from the first model that found
             it (alphabetically-first model name wins on ties because the
             substrate sorts per_model_results upstream)
        """
        by_key: Dict[Hashable, Dict[str, Any]] = {}
        first_seen_order: List[Hashable] = []
        finds_by_key: Dict[Hashable, List[Dict[str, Any]]] = defaultdict(list)

        for model_name, results in per_model_results.items():
            for item in results:
                k = self.item_key(item)
                if k not in by_key:
                    by_key[k] = dict(item)
                    by_key[k]["found_by_models"] = [model_name]
                    first_seen_order.append(k)
                else:
                    by_key[k]["found_by_models"].append(model_name)
                finds_by_key[k].append(self.extract_set_record(item, model_name))

        merged: List[Dict[str, Any]] = []
        for k in first_seen_order:
            item = by_key[k]
            item["found_by_models"] = sorted(set(item["found_by_models"]))
            # Gate on DISTINCT model count, not total contribution count.
            # A single model returning the same item twice shouldn't masquerade
            # as a multi-model find.
            if len(item["found_by_models"]) > 1:
                item["multi_model_finds"] = finds_by_key[k]
            merged.append(item)

        return merged

    def correlate(
        self,
        merged_items: List[Dict[str, Any]],
        per_model_results: Dict[str, List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """Compute recall signals: how many models found each item.

        Returns:
            recall_signals: {item_id: 'all_models'|'majority'|'minority'|'single_model'}
            presence_matrix: {item_id: [model_names]}
            summary: counts per recall bucket plus total and models
        """
        n_models = len(per_model_results)
        models = sorted(per_model_results.keys())

        recall: Dict[str, str] = {}
        presence: Dict[str, List[str]] = {}

        for item in merged_items:
            rid = self.item_id(item)
            # Dedupe: a single model returning the same item twice
            # shouldn't show up as two separate "finders" in the matrix.
            unique_models = sorted(set(item.get("found_by_models", [])))
            presence[rid] = unique_models
            n_found = len(unique_models)

            if n_models <= 1:
                recall[rid] = "single_model"
            elif n_found == n_models:
                recall[rid] = "all_models"
            elif n_found * 2 > n_models:
                recall[rid] = "majority"
            else:
                recall[rid] = "minority"

        bucket_counts = {
            "all_models": sum(1 for r in recall.values() if r == "all_models"),
            "majority": sum(1 for r in recall.values() if r == "majority"),
            "minority": sum(1 for r in recall.values() if r == "minority"),
            "single_model": sum(1 for r in recall.values() if r == "single_model"),
        }

        return {
            "recall_signals": recall,
            "presence_matrix": presence,
            "summary": {
                **bucket_counts,
                "total": len(recall),
                "models": models,
            },
        }
