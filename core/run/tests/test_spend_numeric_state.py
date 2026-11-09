"""Persisted spend stays finite and conservative for oversized JSON integers."""
import json
import math

import pytest

from core.run import resume


@pytest.fixture
def stdlib_reader(monkeypatch):
    monkeypatch.setitem(resume.load_json.__globals__, '_orjson', None)


@pytest.mark.parametrize('value,expected', [
    pytest.param(10**400, resume._MAX_SPEND_EVIDENCE_USD, id='positive'),
    pytest.param(-(10**400), 0.0, id='negative'),
])
def test_oversized_persisted_spend_respects_existing_ceiling(tmp_path, stdlib_reader, value, expected):
    path = tmp_path / resume.SPEND_FLOOR_FILENAME
    path.write_text(json.dumps({'spend_usd': value}))
    before = path.read_bytes()
    parsed = resume.load_json(path, max_bytes=resume._RESUME_JSON_MAX_BYTES)
    assert type(parsed['spend_usd']) is int and parsed['spend_usd'] == value
    booked = resume.spend_floor_usd(tmp_path)
    assert booked == expected and math.isfinite(booked)
    if value > 0:
        assert resume.remaining_budget_usd(1.0, booked) == resume.EXHAUSTED_BUDGET_EPSILON_USD
    resume.persist_spend_floor(tmp_path, 1.0)
    assert resume.spend_floor_usd(tmp_path) == max(1.0, expected)
    if value > 0:
        assert path.read_bytes() == before  # Never lower the original overclaim.
    else:
        assert json.loads(path.read_text())['spend_usd'] == 1.0


@pytest.mark.parametrize('value,expected', [
    pytest.param(10**400, resume._MAX_SPEND_EVIDENCE_USD, id='overflow-positive'),
    pytest.param(-(10**400), 0.0, id='overflow-negative'),
    pytest.param(10**200, resume._MAX_SPEND_EVIDENCE_USD, id='large-representable'),
    pytest.param(0, 0.0, id='zero'),
    pytest.param(0.25, 0.25, id='finite'),
    pytest.param(-1.0, 0.0, id='negative'),
    pytest.param(resume._MAX_SPEND_EVIDENCE_USD, resume._MAX_SPEND_EVIDENCE_USD, id='ceiling'),
    pytest.param(float('inf'), resume._MAX_SPEND_EVIDENCE_USD, id='infinity'),
    pytest.param(float('-inf'), 0.0, id='negative-infinity'),
    pytest.param(float('nan'), 0.0, id='nan'),
    pytest.param(None, None, id='null'),
    pytest.param(True, None, id='boolean'),
    pytest.param('1', None, id='string'),
    pytest.param([], None, id='collection'),
])
def test_spend_scalar_shapes_keep_existing_clamp_contract(value, expected):
    result = resume.spend_value(value)
    assert result == expected
    if result is not None:
        assert math.isfinite(result) and 0.0 <= result <= resume._MAX_SPEND_EVIDENCE_USD


def test_oversized_writer_input_serializes_a_finite_floor(tmp_path):
    resume.persist_spend_floor(tmp_path, 10**400)
    path = tmp_path / resume.SPEND_FLOOR_FILENAME
    stored = json.loads(path.read_text())
    assert stored['spend_usd'] == resume._MAX_SPEND_EVIDENCE_USD
    assert math.isfinite(stored['spend_usd'])
    assert resume.spend_floor_usd(tmp_path) == resume._MAX_SPEND_EVIDENCE_USD
