"""Dataclasses for CWE-specialized strategies.

Frozen + JSON-friendly so /audit can persist its strategy choices
alongside annotations and so picker tests have predictable equality.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple


@dataclass(frozen=True)
class Signals:
    """Mechanical heuristics for picking a strategy.

    Each list is scored independently and the totals sum into a
    single strategy score. Higher score = stronger pick.

    Signals (best to weakest, generally):

      * ``cwes`` — exact CWE identifiers attached to the target by
        an upstream classifier (``/agentic`` finding, ``/understand``
        sink type). Direct evidence of the bug class.
      * ``function_calls`` — names of functions called by the
        target. The strongest mechanical signal: a function that
        calls ``mutex_lock`` IS concurrency-relevant regardless of
        path, name, or includes.
      * ``includes`` — header file names referenced by the target.
        Strong signal for C/C++ (``linux/skbuff.h`` → input).
      * ``paths`` — substrings of the target file's path. Broad
        but cheap signal; specificity scoring rewards narrow
        declarations like ``fs/splice.c`` over ``fs/``.
      * ``function_keywords`` — tokens that should appear as
        whole identifier components in the function name. Matched
        with token semantics (split on ``_``/``-``), not raw
        substring, so ``parse`` matches ``parse_packet`` but NOT
        ``is_sparse_array``.

    Matching is case-insensitive throughout.
    """

    paths: Tuple[str, ...] = ()  # path substrings (e.g. "net/", "crypto/")
    includes: Tuple[str, ...] = ()  # header file names
    function_keywords: Tuple[str, ...] = ()  # tokens in function name
    function_calls: Tuple[str, ...] = ()  # function names called by target
    cwes: Tuple[str, ...] = ()  # exact CWE ids (e.g. "CWE-78")


@dataclass(frozen=True)
class Exemplar:
    """One worked CVE example illustrating the bug class.

    Per the design doc: include the vulnerable code, what assumption
    was violated, and the consequence. Not the patch, not the CVE
    description — the reasoning that found it.
    """

    cve: str  # canonical id, e.g. "CVE-2023-0179"
    title: str  # short human label
    pattern: str  # the vulnerable structural pattern
    why_buggy: str  # the assumption violation + consequence


@dataclass(frozen=True)
class Strategy:
    """One CWE-specialized review strategy.

    A strategy is data: its prompt addendum + exemplars are baked
    into the YAML; the audit driver renders them into the per-
    function prompt. ``name`` is the canonical identifier
    (``input_handling`` etc.), used by /audit to log which
    strategies fired for a given function.
    """

    name: str
    description: str
    signals: Signals = field(default_factory=Signals)
    key_questions: Tuple[str, ...] = ()
    prompt_addendum: str = ""
    exemplars: Tuple[Exemplar, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "signals": {
                "paths": list(self.signals.paths),
                "includes": list(self.signals.includes),
                "function_keywords": list(self.signals.function_keywords),
                "function_calls": list(self.signals.function_calls),
                "cwes": list(self.signals.cwes),
            },
            "key_questions": list(self.key_questions),
            "prompt_addendum": self.prompt_addendum,
            "exemplars": [
                {
                    "cve": e.cve, "title": e.title,
                    "pattern": e.pattern, "why_buggy": e.why_buggy,
                }
                for e in self.exemplars
            ],
        }
