"""UNEXECUTED pure policy/arithmetic controls; no parser or engine invocation."""
from dataclasses import replace

import pytest

from core.audit.conditional_member_policy import Condition, conclusion_signature


def test_closed_conditions_and_unsigned_witness_arithmetic():
    signature = conclusion_signature()
    assert signature.conditions == tuple(item.value for item in Condition)
    assert signature.conclusion_kind == "conditional-size-mismatch"
    assert signature.effect_scope == "conditional-source-model-pre-copy-size-relation"
    n = (1 << 16) + 1
    a = n % (1 << 16)
    assert a == 1 and 0 < a < n < (1 << 32)
    # H is symbolic but positive. No positive H can make H+n <= 65535.
    assert 65535 < n + 1
    assert replace(signature, conclusion_kind="verified-exploit") != signature


@pytest.mark.parametrize("value", [True, "65535", -1, 1 << 128, 0.5])
def test_malformed_numeric_refinement_is_not_an_abi_fact(value):
    with pytest.raises(ValueError):
        conclusion_signature(size_max_refinement=value)


def test_optional_refinement_is_explicitly_a_model_constraint():
    refined = conclusion_signature(size_max_refinement=65535)
    assert refined.conditions[:-1] == conclusion_signature().conditions
    assert refined.conditions[-1] == "model-only-SIZE_MAX:65535"
