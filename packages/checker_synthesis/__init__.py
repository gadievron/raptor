"""KNighter-style checker synthesis (SOSP 2025).

Turn a single confirmed bug into a Semgrep or Coccinelle rule, run
it across the codebase, surface variant matches. The thing that
makes ``/audit`` Phase A find more than per-function review alone.

Pipeline:

  1. ``propose``    — LLM gets a confirmed bug (function source +
                      reasoning + CWE) and outputs a candidate rule.
  2. ``validate``   — Run the rule against the seed function's file
                      alone. The rule must match the original bug
                      (positive control). If not, one refinement
                      retry; then give up.
  3. ``run``        — Execute the rule across the repo. Collect
                      matches with line numbers.
  4. ``triage``     — Optional LLM pass per match: variant /
                      false_positive / uncertain. Bounded by
                      ``max_triage_calls``.

Engine choice is automatic from file language:
  * Coccinelle for C source (``.c`` / ``.h``) — the precise tool
    for kernel-style patches and missing-checks bugs.
  * Semgrep for everything else (Python, Java, Go, JavaScript, etc.).

Initial consumers:
  * ``/audit`` Phase A — every confirmed hypothesis triggers
    a checker-synthesis attempt; surfaced variants get re-reviewed.
  * Standalone via ``libexec/raptor-synthesise-checker`` for
    testing rules manually before /audit ships.
"""

from __future__ import annotations

from .languages import detect_engine, supported_engines
from .models import (
    CheckerSynthesisResult,
    Match,
    MatchTriage,
    SeedBug,
    SynthesisedRule,
)
from .synthesise import (
    LLMCallable,
    synthesise_and_run,
    synthesise_with_refinement,
)

__all__ = [
    "CheckerSynthesisResult",
    "LLMCallable",
    "Match",
    "MatchTriage",
    "SeedBug",
    "SynthesisedRule",
    "detect_engine",
    "supported_engines",
    "synthesise_and_run",
    "synthesise_with_refinement",
]
