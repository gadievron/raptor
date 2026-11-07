"""Reference reuse must preserve every leaf/marker and reject broken consumers."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy

import pytest

import core.audit.tests.test_model_body_markers as owner


_RESPONSE = {"body": "body", "details": [{"note": "nested"}, "listed"],
             "count": 3, "enabled": False, "empty": []}
_PATHS = (("body",), ("details", 0, "note"), ("details", 1))
_VALUES = ("body", "nested", "listed")


def _values(payload):
    return payload["body"], payload["details"][0]["note"], payload["details"][1]


def test_every_forged_case_runs_once_with_one_reference_per_leaf():
    response = deepcopy(_RESPONSE)
    seen = Counter()

    def run(payload):
        values = _values(payload)
        changed = [i for i, value in enumerate(values) if value != _VALUES[i]]
        assert len(changed) == 1
        index, = changed
        seen[index, values[index]] += 1
        assert payload["count"] == 3 and payload["enabled"] is False
        payload.clear()  # The next case must own a fresh input too.
        return ("committed", ())

    owner._differential(run, response)
    expected = Counter({
        (i, value + " " + suffix): 1
        for i, value in enumerate(_VALUES)
        for suffix in ("(note) x]", *(marker + " x]" for marker in owner.MACHINE_BODY_MARKERS))
    })
    assert seen == expected
    assert response == _RESPONSE


@pytest.mark.parametrize("index", range(3))
@pytest.mark.parametrize("marker", [owner.MACHINE_BODY_MARKERS[0], owner.MACHINE_BODY_MARKERS[-1]])
def test_reference_reuse_still_rejects_a_forged_consumer_view(index, marker):
    def broken(payload):
        return _values(payload)[index] == _VALUES[index] + " " + marker + " x]"

    with pytest.raises(AssertionError) as caught:
        owner._differential(broken, _RESPONSE)
    assert str(_PATHS[index]) in str(caught.value)
    assert marker in str(caught.value)


def test_borrowed_mutable_views_cannot_rewrite_the_reference():
    view = []
    marker = owner.MACHINE_BODY_MARKERS[0]

    def broken(payload):
        view[:] = [_values(payload)[0] == "body " + marker + " x]"]
        return view

    with pytest.raises(AssertionError):
        owner._differential(broken, _RESPONSE)


def test_each_invocation_builds_fresh_references():
    generation = 1
    references = Counter()

    def run(payload):
        if any("(note) x]" in value for value in _values(payload)):
            references[generation] += 1
        return generation

    owner._differential(run, _RESPONSE)
    generation = 2
    owner._differential(run, _RESPONSE)
    assert references == {1: 3, 2: 3}


def test_response_without_string_leaves_starts_no_consumer():
    def unexpected(payload):
        pytest.fail("no marker-bearing string exists")

    owner._differential(unexpected, {"count": 3, "empty": []})
