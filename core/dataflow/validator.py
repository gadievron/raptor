"""Validator protocol — pluggable judgment function for corpus replay.

The corpus runner (``run_corpus``) takes a :class:`Validator` and asks
it to verdict every :class:`~core.dataflow.Finding`. The verdicts are
diffed against the corpus ground truth to produce precision/recall/F1.

The :class:`TrivialValidator` (always says exploitable) is the
producer-only baseline — its precision tells us what fraction of
producer-emitted findings are TPs without any LLM intervention.
Real LLM-backed validators land with PR1; the protocol is the contract
they implement.
"""

from __future__ import annotations

from enum import Enum
from typing import Protocol, runtime_checkable, TYPE_CHECKING


if TYPE_CHECKING:
    from core.dataflow.finding import Finding


class ValidatorVerdict(str, Enum):
    """A validator's per-finding judgement.

    Maps to the corpus's :data:`VERDICT_TRUE_POSITIVE` /
    :data:`VERDICT_FALSE_POSITIVE` via :func:`verdict_to_label`.
    ``UNCERTAIN`` is for validators that decline to commit; the
    corpus runner counts these separately and they don't contribute
    to precision/recall.
    """

    EXPLOITABLE = "exploitable"
    NOT_EXPLOITABLE = "not_exploitable"
    UNCERTAIN = "uncertain"


@runtime_checkable
class Validator(Protocol):
    """Anything that takes a :class:`Finding` and returns a
    :class:`ValidatorVerdict`."""

    def validate(self, finding: Finding) -> ValidatorVerdict: ...


class TrivialValidator:
    """The producer-only baseline: every finding is exploitable.

    Recall is 1.0 when true-positive labels exist, otherwise undefined.
    Precision equals the corpus's TP share for a non-empty corpus and
    is undefined for an empty corpus. This baseline never predicts
    not-exploitable or uncertain.
    """

    def validate(self, finding: Finding) -> ValidatorVerdict:
        return ValidatorVerdict.EXPLOITABLE
