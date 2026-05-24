"""Dataclasses shared by the selection and efficacy evals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple


@dataclass(frozen=True)
class SelectionCase:
    """A labeled routing case: picker signals in, expected outcome out.

    ``signals`` is a kwargs dict forwarded verbatim to ``pick_strategies``
    (``file_path`` is required; ``function_name`` / ``file_includes`` /
    ``function_calls_made`` / ``candidate_cwes`` / ``max_strategies`` are
    optional). ``expect_selected`` names must appear in the picked set;
    ``expect_not_selected`` names must not (the over-trigger guard).
    """

    name: str
    signals: Dict[str, Any]
    expect_selected: Tuple[str, ...] = ()
    expect_not_selected: Tuple[str, ...] = ()


@dataclass(frozen=True)
class SelectionOutcome:
    """Result of running one SelectionCase through the picker."""

    case: SelectionCase
    picked: Tuple[str, ...]
    missing: Tuple[str, ...]     # expect_selected names absent from picked
    overfired: Tuple[str, ...]   # expect_not_selected names present in picked

    @property
    def passed(self) -> bool:
        return not self.missing and not self.overfired


@dataclass(frozen=True)
class EfficacySample:
    """One labeled code sample for the A/B efficacy eval.

    ``variant`` is ``"vulnerable"`` or ``"patched"``. ``strategy`` is the
    lens whose marginal contribution this sample tests. ``synthetic``
    flags hand-written minimal repros vs. real extracted source.
    """

    id: str
    strategy: str
    code: str
    variant: str
    synthetic: bool = False


@dataclass(frozen=True)
class ABResult:
    """A/B outcome for one sample over ``runs`` repetitions.

    ``*_flagged`` count how many runs the model returned a VULNERABLE
    verdict under each arm (control = baseline lens only; treatment =
    baseline + the target lens).
    """

    sample_id: str
    strategy: str
    variant: str
    runs: int
    control_flagged: int
    treatment_flagged: int
