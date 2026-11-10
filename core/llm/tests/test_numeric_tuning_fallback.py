"""Optional tuning readers retain fallbacks for unrepresentable numbers."""

import json

import pytest

from core.llm import concurrency


@pytest.fixture(params=[
    ('default_max_cost_usd', 'read_default_max_cost_usd', None),
    ('throttle_cooldown_s', 'read_throttle_cooldown_s', 30.0),
], ids=['cost', 'cooldown'])
def tuning_reader(tmp_path, monkeypatch, request):
    key, name, fallback = request.param
    path = tmp_path / 'tuning.json'
    monkeypatch.setattr(concurrency, '_tuning_path', lambda: path)

    def configure(value):
        path.write_text(json.dumps({key: value}), encoding='utf-8')
        return getattr(concurrency, name)()

    return configure, fallback


def test_unrepresentable_integer_uses_reader_fallback(tuning_reader):
    configure, fallback = tuning_reader
    # A 401-digit operator value is cheap to decode as an integer, but
    # cannot be represented by the float consumed by these readers.
    assert configure(10**400) == fallback


def test_finite_setting_is_still_used(tuning_reader):
    configure, _ = tuning_reader
    assert configure(12.5) == 12.5


@pytest.mark.parametrize('value', ['not-a-number', {'invalid': 'shape'}])
def test_existing_conversion_refusals_keep_their_fallback(tuning_reader, value):
    configure, fallback = tuning_reader
    assert configure(value) == fallback
