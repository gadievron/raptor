"""Multi-model substrate adapters for /understand --hunt and --trace.

These are the concrete consumer-side glue between /understand's two
verdict/set-style modes and core.llm.multi_model. They define how
variant items and trace verdicts are identified, merged, and correlated.

PR2a scope: adapters only. PR2b will wire actual LLM dispatch using
these adapters.
"""

from typing import Any, Dict, Hashable, Tuple

from core.llm.multi_model import BaseSetAdapter, BaseVerdictAdapter


# ---------------------------------------------------------------------------
# /understand --hunt: set-style (each model returns a list of variants)
# ---------------------------------------------------------------------------


class VariantAdapter(BaseSetAdapter):
    """Adapter for hunt-style variant findings.

    Each model returns a list of dicts of the shape:
        {
          "file": "src/parser.c",
          "line": 42,
          "function": "parse_header",  # optional
          "snippet": "strcpy(buf, untrusted)",  # optional, for context
          "confidence": "high" | "medium" | "low",  # optional
        }

    Two finds at the same (file, line, function) are considered the same
    variant — even if their snippets/confidence differ across models.
    Function name is included in the dedup key because the same line
    number can appear in different functions after refactors.

    Note: BaseSetAdapter's default `extract_set_record` produces
    `{"model": model_name, **item}` for each per-model record stored
    under `multi_model_finds`. If your variant dicts include a `"model"`
    field (e.g., a model-name annotation produced by the LLM), the
    substrate-added `model` key takes precedence and overwrites it.
    Override `extract_set_record` if you need to preserve a different
    `model` field semantically.
    """

    def item_id(self, item: Dict[str, Any]) -> str:
        # variants don't have a stable upstream id; synthesize from the
        # canonical (file, line, function) so the same variant gets the
        # same id regardless of which model contributed first.
        file_path, line, function = self._canonical_parts(item)
        if function:
            return f"{file_path}:{line}:{function}"
        return f"{file_path}:{line}"

    def item_key(self, item: Dict[str, Any]) -> Hashable:
        # Same canonicalization as item_id so two finds the substrate
        # would unify (key) also produce the same id.
        return self._canonical_parts(item)

    @staticmethod
    def _canonical_parts(item: Dict[str, Any]) -> Tuple[str, Any, str]:
        """Normalize file path for cross-model comparison.

        - Strip whitespace from file and function.
        - Drop a leading "./" (NOT lstrip("./") — that strips any combination
          of dots and slashes; we want only the literal "./" prefix).
        - Don't lowercase: file paths are case-sensitive on Linux/macOS.
        - Coerce `line` to int when possible so models returning "5"
          (string) and 5 (int) don't get bucketed separately. Non-numeric
          line values are preserved as-is and surface upstream.
        """
        file_path = (item.get("file") or "").strip().removeprefix("./")
        function = (item.get("function") or "").strip()

        line_raw = item.get("line")
        if isinstance(line_raw, str):
            stripped = line_raw.strip()
            try:
                line = int(stripped)
            except ValueError:
                # Non-numeric string: keep stripped form so trailing-whitespace
                # variants don't bucket separately ("junk" and "junk " unify).
                line = stripped
        else:
            line = line_raw

        return (file_path, line, function)


# ---------------------------------------------------------------------------
# /understand --trace: verdict-style (each model returns a verdict per trace)
# ---------------------------------------------------------------------------


class TraceAdapter(BaseVerdictAdapter):
    """Adapter for trace-style flow analysis.

    Each model returns a list of dicts of the shape:
        {
          "trace_id": "EP-001-to-sink-3",
          "verdict": "reachable" | "not_reachable" | "uncertain",
          "confidence": "high" | "medium" | "low",
          "steps": [...],   # optional
          "reasoning": "...",  # short justification
        }

    select_primary defaults to BaseVerdictAdapter's prefer-positive
    rule, mapped through normalize_verdict — so a "reachable" verdict
    wins over "not_reachable" or "uncertain" when models disagree.
    """

    # Trace reasoning can include a step chain — slightly bigger budget
    # than the default 600 chars, but still bounded.
    REASONING_TRUNCATE: int = 1200

    def item_id(self, item: Dict[str, Any]) -> str:
        # Strip — models occasionally return surrounded-by-whitespace ids,
        # which would otherwise count as a different trace from the
        # original. Substrate's item_id contract requires non-empty str.
        tid = item.get("trace_id")
        if tid is None:
            raise ValueError(
                f"trace verdict dict missing required 'trace_id' field: "
                f"{sorted(item.keys())}"
            )
        return tid.strip() if isinstance(tid, str) else tid

    def normalize_verdict(self, item: Dict[str, Any]) -> str:
        # Defensive: model output occasionally has type drift on enum
        # fields. Non-string verdicts → "unknown" rather than AttributeError.
        v = item.get("verdict")
        if not isinstance(v, str):
            return "unknown"
        v = v.strip().lower()
        if v == "reachable":
            return "positive"
        if v == "not_reachable":
            return "negative"
        if v == "uncertain":
            return "inconclusive"
        return "unknown"
