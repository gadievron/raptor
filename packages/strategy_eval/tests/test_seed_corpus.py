"""Validate the bundled synthetic seed corpus — no LLM.

Proves the seed is well-formed: it loads, every named strategy resolves
and renders into a treatment prompt, the lens is isolated to treatment,
and every covered strategy has both a vulnerable and a patched variant
(so the A/B is meaningful).
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from packages.strategy_eval.efficacy import build_prompts, load_corpus

_SEED = Path(__file__).resolve().parents[1] / "data" / "seed_corpus"


def test_seed_corpus_loads():
    samples = load_corpus(_SEED)
    assert samples, "seed corpus is empty"
    assert all(s.synthetic for s in samples), "seed samples must be flagged synthetic"


def test_every_seed_strategy_has_both_variants():
    variants = defaultdict(set)
    for s in load_corpus(_SEED):
        variants[s.strategy].add(s.variant)
    for strategy, seen in variants.items():
        assert seen == {"vulnerable", "patched"}, (
            f"{strategy} seed needs both variants, has {sorted(seen)}"
        )


def test_prompts_build_and_isolate_lens_for_every_sample():
    for s in load_corpus(_SEED):
        control, treatment, user = build_prompts(s)
        assert user == s.code
        # Review contract present in both arms.
        assert "VERDICT:" in control and "VERDICT:" in treatment
        # The target lens is named only in the treatment arm's header.
        header = f"## Strategy: {s.strategy}"
        assert header in treatment, f"{s.id}: lens not in treatment"
        if s.strategy != "general":
            assert header not in control, f"{s.id}: lens leaked into control"
