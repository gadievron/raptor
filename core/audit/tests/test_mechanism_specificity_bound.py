"""Scoring saturation must preserve ranking and bound match allocation."""

import pytest

from core.audit import orchestrator as orch


@pytest.mark.parametrize('count', range(9))
def test_long_mechanism_identifier_score_saturates(count):
    mechanism = ('ordinary prose ' * 40) + ('foo_bar ' * count)
    assert orch._mechanism_specificity(mechanism) == 10 + 4 * min(count, 5)


def test_saturation_preserves_other_score_components():
    mechanism = 'é_é call( ' * 100 + 'CWE-123 at line 12'
    assert orch._mechanism_specificity(mechanism) == 35


def test_long_mechanism_stops_after_five_matches(monkeypatch):
    pattern = orch._IDENTIFIER_TOKEN_RE

    class BoundedPattern:
        def finditer(self, text):
            for index, match in enumerate(pattern.finditer(text)):
                assert index < 5, 'Scoring consumed matches beyond saturation'
                yield match

    monkeypatch.setattr(orch, '_IDENTIFIER_TOKEN_RE', BoundedPattern())
    assert orch._mechanism_specificity('foo_bar ' * 10000) == 30
