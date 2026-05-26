"""Offline A/B efficacy eval for cwe_strategies.

Question: does injecting a strategy's guidance actually improve the
model's findings? For each labeled sample we run an otherwise-identical
review prompt twice:

  * control   — review instructions + the always-on ``general`` lens
  * treatment — same + the target strategy's lens

so the target lens is the ONLY variable (``general`` is present in both
because it is always pinned in production). On a ``vulnerable`` sample,
a VULNERABLE verdict is a hit; on a ``patched`` sample it is a false
positive. Lift = treatment hit-rate − control hit-rate.

This needs a live LLM and is nondeterministic, so it is an on-demand
tool, never a CI gate. The LLM call is injected (``complete``) so the
harness logic is unit-tested with a fake. Results are only as meaningful
as the corpus: a synthetic seed measures whether the lens helps on the
bug-class *shape*, not on real-world code.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Callable, Dict, List

import yaml

from core.llm.cwe_strategies import load_all, render_strategies

from .models import ABResult, EfficacySample

# complete(system_prompt, user_prompt) -> model reply text
Completer = Callable[[str, str], str]

_REVIEW_INSTRUCTIONS = (
    "You are a security code reviewer. Review the function in the user "
    "message for security vulnerabilities. Reason briefly, then end your "
    "reply with EXACTLY one line:\n"
    "  VERDICT: VULNERABLE   (the function contains a security bug)\n"
    "  VERDICT: SAFE         (it does not)\n"
)

_VERDICT_RE = re.compile(r"VERDICT:\s*VULNERABLE", re.IGNORECASE)


def grade(reply: str) -> bool:
    """True iff the model returned a VULNERABLE verdict."""
    return bool(_VERDICT_RE.search(reply or ""))


def _strategies_by_name() -> Dict[str, object]:
    return {s.name: s for s in load_all()}


def build_prompts(sample: EfficacySample) -> "tuple[str, str, str]":
    """Return (control_system, treatment_system, user_prompt).

    The two system prompts differ ONLY by the target lens, so any verdict
    difference is attributable to it.
    """
    by_name = _strategies_by_name()
    general = by_name.get("general")
    lens = by_name.get(sample.strategy)
    if lens is None:
        raise KeyError(f"unknown strategy {sample.strategy!r} for sample {sample.id}")

    baseline = [general] if general is not None else []
    control_system = _REVIEW_INSTRUCTIONS + "\n\n" + render_strategies(baseline)
    # If the target IS general, treatment == control (no delta).
    treat_lenses = baseline if lens is general else baseline + [lens]
    treatment_system = _REVIEW_INSTRUCTIONS + "\n\n" + render_strategies(treat_lenses)
    return control_system, treatment_system, sample.code


def run_ab(sample: EfficacySample, complete: Completer, runs: int = 3) -> ABResult:
    control_system, treatment_system, user = build_prompts(sample)
    control_flagged = sum(
        1 for _ in range(runs) if grade(complete(control_system, user))
    )
    treatment_flagged = sum(
        1 for _ in range(runs) if grade(complete(treatment_system, user))
    )
    return ABResult(
        sample_id=sample.id,
        strategy=sample.strategy,
        variant=sample.variant,
        runs=runs,
        control_flagged=control_flagged,
        treatment_flagged=treatment_flagged,
    )


def run_efficacy_eval(
    samples: List[EfficacySample], complete: Completer, runs: int = 3,
) -> List[ABResult]:
    return [run_ab(s, complete, runs) for s in samples]


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------


def load_corpus(corpus_dir: Path) -> List[EfficacySample]:
    """Load a labeled corpus: a ``manifest.yml`` listing samples, each with
    ``id``, ``strategy``, ``file`` (relative path to the source), ``variant``
    and optional ``synthetic``. Real samples drop in via the same format.
    """
    corpus_dir = Path(corpus_dir)
    manifest = yaml.safe_load((corpus_dir / "manifest.yml").read_text("utf-8")) or {}
    samples: List[EfficacySample] = []
    for raw in manifest.get("samples", []):
        code = (corpus_dir / raw["file"]).read_text(encoding="utf-8")
        samples.append(
            EfficacySample(
                id=raw["id"],
                strategy=raw["strategy"],
                code=code,
                variant=raw["variant"],
                synthetic=bool(raw.get("synthetic", False)),
            )
        )
    return samples


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def format_report(results: List[ABResult]) -> str:
    # Aggregate per strategy × variant: total runs and flagged counts.
    agg: Dict[tuple, List[int]] = defaultdict(lambda: [0, 0, 0])  # runs, ctrl, treat
    for r in results:
        slot = agg[(r.strategy, r.variant)]
        slot[0] += r.runs
        slot[1] += r.control_flagged
        slot[2] += r.treatment_flagged

    lines = ["Efficacy eval (A/B: baseline vs baseline+lens) — live LLM", ""]
    strategies = sorted({s for (s, _v) in agg})
    for strat in strategies:
        lines.append(f"{strat}:")
        for variant in ("vulnerable", "patched"):
            slot = agg.get((strat, variant))
            if not slot:
                continue
            runs, ctrl, treat = slot
            c_rate = ctrl / runs if runs else 0.0
            t_rate = treat / runs if runs else 0.0
            if variant == "vulnerable":
                lines.append(
                    f"  vulnerable  detection  control {c_rate*100:5.1f}%  "
                    f"treatment {t_rate*100:5.1f}%  lift {(t_rate-c_rate)*100:+5.1f}%"
                )
            else:
                lines.append(
                    f"  patched     false-pos  control {c_rate*100:5.1f}%  "
                    f"treatment {t_rate*100:5.1f}%  delta {(t_rate-c_rate)*100:+5.1f}%"
                )
        lines.append("")
    return "\n".join(lines).rstrip()


# ---------------------------------------------------------------------------
# Default live completer (lazily wires the real LLM client)
# ---------------------------------------------------------------------------


def default_completer() -> Completer:
    """Wire a Completer onto the real LLM client. Imported lazily so the
    harness (and its tests) don't require the client unless a live run is
    actually requested."""
    from core.llm.client import LLMClient

    client = LLMClient()

    def _complete(system_prompt: str, user_prompt: str) -> str:
        resp = client.generate(user_prompt, system_prompt=system_prompt)
        text = getattr(resp, "content", None)
        return text if text is not None else str(resp)

    return _complete
