"""Evaluation harness for the cwe_strategies bug-class lenses.

Two evals, deliberately separate because they answer different questions
and cost wildly different amounts:

  * **selection** (deterministic, no LLM, CI-able) — does the picker route
    the right strategy for a labeled set of signal cases, and refrain from
    firing where it shouldn't? Measures the ROUTING layer only.

  * **efficacy** (offline, live LLM) — does injecting a strategy's guidance
    actually improve the model's findings on labeled code? A/B per sample
    (strategy on vs off). Needs a labeled corpus and an LLM; not CI.

See ``selection.py`` / ``efficacy.py``. Driven by
``libexec/raptor-strategy-eval``.
"""
