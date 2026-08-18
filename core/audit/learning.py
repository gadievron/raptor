"""Learning loop for /audit prompt refinement.

Analyses corpus results to extract FP patterns and generate correction
rules that are injected into the system prompt for subsequent runs.

The loop is intentionally conservative:
  - Only patterns that appear in >=3 FPs are considered
  - Each correction is a single sentence added to the system prompt
  - Corrections are stored in a JSON file alongside the corpus results
  - The system prompt loads corrections at runtime
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .strategy_stats import _safe_mtime

logger = logging.getLogger(__name__)

_FP_CATEGORY_PATTERNS = [
    (
        "caller_contract",
        re.compile(
            r"caller|upstream|invoke|passes?\s+(?:null|invalid|bad)",
            re.IGNORECASE,
        ),
        ("Do not flag a function as suspicious solely because a caller "
        "COULD pass invalid input — check whether any actual caller "
        "shown in context does."),
    ),
    (
        "speculative_race",
        re.compile(
            r"race\s+condition|concurren|toctou|lock.*not.*held|"
            r"without.*lock|after.*unlock",
            re.IGNORECASE,
        ),
        ("Do not flag race conditions when the code is protected by a "
        "lock that covers the critical section — verify the lock scope "
        "before hypothesising."),
    ),
    (
        "wrapper_distrust",
        re.compile(
            r"wrapper|delegat|pass.*through|thin.*function|"
            r"callee.*not.*visible|unknown.*callee",
            re.IGNORECASE,
        ),
        ("Thin wrapper functions that only call one callee without "
        "transforming arguments are clean — do not flag them because "
        "the callee is not visible in context."),
    ),
    (
        "arithmetic_speculation",
        re.compile(
            r"overflow|underflow|truncat|integer.*wrap|"
            r"arithmetic.*on.*kernel|bounded.*value",
            re.IGNORECASE,
        ),
        ("Do not hypothesise integer overflow on kernel-bounded values "
        "(page counts, CPU indices, small enums) without checking the "
        "actual type width and value range."),
    ),
    (
        "crypto_hygiene",
        re.compile(
            r"crypto|timing|constant.*time|side.*channel|"
            r"hash|encrypt|decrypt",
            re.IGNORECASE,
        ),
        ("Do not flag crypto-hygiene issues on functions that do not "
        "handle secret material — verify the data flow reaches a "
        "secret before raising timing or side-channel concerns."),
    ),
]


def extract_fp_patterns(
    results: list[dict[str, Any]],
    min_count: int = 3,
) -> list[dict[str, Any]]:
    """Extract FP patterns from scored corpus results.

    Each result dict must have at least:
      - correct: bool
      - expected: str (ground truth status)
      - actual: str (predicted status)
      - hypothesis: str (LLM hypothesis text)
      - hypotheses: list[dict] (structured hypotheses)

    Returns a list of pattern dicts with category, count, and correction.
    """
    fps = [
        r for r in results
        if not r.get("correct", True)
        and r.get("expected") in ("clean", "dormant")
        and r.get("actual") in ("suspicious", "finding")
    ]

    if not fps:
        return []

    category_counts: Counter = Counter()
    category_examples: dict[str, list[str]] = {}

    for fp in fps:
        hyp_text = fp.get("hypothesis", "")
        hypotheses = fp.get("hypotheses") or []
        full_text = hyp_text
        for h in hypotheses:
            if isinstance(h, dict):
                full_text += " " + h.get("mechanism", "")
                full_text += " " + h.get("counter", "")

        for cat_name, cat_re, _ in _FP_CATEGORY_PATTERNS:
            if cat_re.search(full_text):
                category_counts[cat_name] += 1
                if cat_name not in category_examples:
                    category_examples[cat_name] = []
                func_key = f"{fp.get('file', '?')}:{fp.get('function', '?')}"
                if len(category_examples[cat_name]) < 3:
                    category_examples[cat_name].append(func_key)

    patterns = []
    for cat_name, cat_re, correction in _FP_CATEGORY_PATTERNS:
        count = category_counts.get(cat_name, 0)
        if count >= min_count:
            patterns.append({
                "category": cat_name,
                "count": count,
                "correction": correction,
                "examples": category_examples.get(cat_name, []),
            })

    patterns.sort(key=lambda p: p["count"], reverse=True)
    return patterns


def save_corrections(
    patterns: list[dict[str, Any]],
    out_path: Path,
    *,
    store_to_sage: bool = True,
) -> Path:
    """Save correction rules to JSON and optionally to SAGE.

    JSON is the mechanical store (loadable without SAGE).
    SAGE stores the reasoning and historical context.

    Returns the path to the corrections file.
    """
    corrections_path = out_path / "prompt-corrections.json"
    data = {
        "version": 1,
        "corrections": [
            {
                "category": p["category"],
                "count": p["count"],
                "rule": p["correction"],
                "examples": p["examples"],
            }
            for p in patterns
        ],
    }
    corrections_path.write_text(json.dumps(data, indent=2))
    logger.info(
        "saved %d prompt corrections to %s",
        len(patterns), corrections_path,
    )

    if store_to_sage and patterns:
        _store_corrections_to_sage(patterns, out_path)

    return corrections_path


def _store_corrections_to_sage(
    patterns: list[dict[str, Any]],
    out_path: Path,
) -> None:
    """Store correction metadata to SAGE for cross-run learning."""
    try:
        from core.sage.hooks import sage_remember
    except ImportError:
        logger.debug("SAGE not available for correction storage")
        return

    summary_parts = []
    for p in patterns:
        summary_parts.append(
            f"- {p['category']}: {p['count']} FPs "
            f"(e.g. {', '.join(p['examples'][:2])})"
        )

    memory_text = (
        f"Audit corpus learning: {len(patterns)} FP pattern(s) "
        f"extracted from {out_path.name}.\n"
        + "\n".join(summary_parts)
        + "\n\nCorrections saved to prompt-corrections.json."
    )

    try:
        sage_remember(
            domain="audit-calibration",
            content=memory_text,
            tags=["learning-loop", "fp-patterns", "corrections"],
        )
    except Exception:
        logger.debug("SAGE remember failed for corrections", exc_info=True)


def load_corrections(
    out_dir: Path | None = None,
) -> list[str]:
    """Load correction rules from the most recent corpus run.

    Searches for prompt-corrections.json in:
      1. The given out_dir (for project runs this IS the project's
         run directory — there is no separate active-project lookup)
      2. Repo-level out/audit-corpus-* directories (newest first)

    Returns a list of correction rule strings.
    """
    candidates: list[Path] = []
    if out_dir:
        candidates.append(out_dir / "prompt-corrections.json")

    # RAPTOR_DIR-anchored so the corpus fallback doesn't depend on
    # the process CWD (workers may run with the target as cwd).
    out_root = Path(os.environ["RAPTOR_DIR"]) / "out"
    if out_root.is_dir():
        corpus_dirs = sorted(
            out_root.glob("audit-corpus-*"),
            # OSError-tolerant mtime: a corpus dir can be deleted
            # between glob() and the key call.
            key=_safe_mtime,
            reverse=True,
        )
        for d in corpus_dirs[:5]:
            candidates.append(d / "prompt-corrections.json")

    for path in candidates:
        if path.is_file():
            try:
                data = json.loads(path.read_text())
                rules = [c["rule"] for c in data.get("corrections", [])]
                if rules:
                    logger.info(
                        "loaded %d prompt corrections from %s",
                        len(rules), path,
                    )
                    return rules
            except (json.JSONDecodeError, KeyError, TypeError):
                logger.debug("failed to load corrections from %s", path)
                continue

    return []


def format_corrections_for_prompt(corrections: list[str]) -> str:
    """Format correction rules as a system prompt addendum."""
    if not corrections:
        return ""
    lines = [
        ("\nLEARNED CORRECTIONS (from prior corpus calibration — "
        "these patterns caused false positives):\n")
    ]
    for i, rule in enumerate(corrections, 1):
        lines.append(f"{i}. {rule}")
    return "\n".join(lines)
