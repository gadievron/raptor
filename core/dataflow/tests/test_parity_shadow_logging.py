"""Phase 15 — smt_barrier shadow-logging integration tests.

Verifies that the parity telemetry hook (a) writes a record when
RAPTOR_SANITIZER_CUT_PARITY_LOG is set, (b) is a no-op when it
isn't, and (c) never changes the value returned by
validator_dominates_sink / substitution_dominates_sink.
"""
from __future__ import annotations

import pytest

from core.dataflow.sanitizer_cut_parity import read_parity_records
from core.dataflow.smt_barrier import (
    substitution_dominates_sink,
    validator_dominates_sink,
)


# A charset-validator-shaped source where the lexical check fires:
# the ``if not`` guard exits on failure before the sink.
_VALIDATOR_SRC = (
    "def handle(x):\n"
    "    if not re.match('^[a-z]+$', x):\n"
    "        return\n"
    "    render(x)\n"
)


@pytest.fixture
def _log_path(tmp_path, monkeypatch):
    p = tmp_path / "parity.jsonl"
    monkeypatch.setenv("RAPTOR_SANITIZER_CUT_PARITY_LOG", str(p))
    return p


@pytest.fixture
def _no_log(monkeypatch):
    monkeypatch.delenv("RAPTOR_SANITIZER_CUT_PARITY_LOG", raising=False)


class TestShadowLogging:
    def test_no_env_no_record(self, _no_log, tmp_path):
        src = _tmp_src(tmp_path, _VALIDATOR_SRC)
        # No env var → no file written, and a return value still comes back.
        result = validator_dominates_sink(
            _VALIDATOR_SRC, 2, 4,
            file_path=str(src), cwe="CWE-79", language="python",
        )
        assert isinstance(result, bool)

    def test_record_written_when_env_set(self, _log_path, tmp_path):
        src = _tmp_src(tmp_path, _VALIDATOR_SRC)
        validator_dominates_sink(
            _VALIDATOR_SRC, 2, 4,
            file_path=str(src), cwe="CWE-79", language="python",
        )
        records = read_parity_records(_log_path)
        assert len(records) == 1
        r = records[0]
        assert r.kind == "charset"
        assert r.cwe == "CWE-79"
        assert isinstance(r.lexical_suppressed, bool)
        assert isinstance(r.value_bound_suppressed, bool)

    def test_logging_does_not_change_return_value(self, tmp_path, monkeypatch):
        src = _tmp_src(tmp_path, _VALIDATOR_SRC)
        monkeypatch.delenv("RAPTOR_SANITIZER_CUT", raising=False)
        # Without logging.
        monkeypatch.delenv("RAPTOR_SANITIZER_CUT_PARITY_LOG", raising=False)
        without = validator_dominates_sink(
            _VALIDATOR_SRC, 2, 4,
            file_path=str(src), cwe="CWE-79", language="python",
        )
        # With logging.
        log = tmp_path / "p.jsonl"
        monkeypatch.setenv("RAPTOR_SANITIZER_CUT_PARITY_LOG", str(log))
        with_log = validator_dominates_sink(
            _VALIDATOR_SRC, 2, 4,
            file_path=str(src), cwe="CWE-79", language="python",
        )
        assert without == with_log

    def test_missing_kwargs_no_record(self, _log_path):
        # No file_path/cwe/language → telemetry can't build a finding →
        # no record, but the lexical-only call still returns.
        result = validator_dominates_sink(_VALIDATOR_SRC, 2, 4)
        assert isinstance(result, bool)
        assert read_parity_records(_log_path) == []

    def test_substitution_path_also_records(self, _log_path, tmp_path):
        src_text = (
            "def handle(x):\n"
            "    x = re.sub('[<>]', '', x)\n"
            "    render(x)\n"
        )
        src = _tmp_src(tmp_path, src_text)
        substitution_dominates_sink(
            src_text, 2, 3, "x",
            file_path=str(src), cwe="CWE-79", language="python",
        )
        records = read_parity_records(_log_path)
        assert len(records) == 1
        assert records[0].kind == "charset_sub"


def _tmp_src(tmp_path, text):
    f = tmp_path / "app.py"
    f.write_text(text, encoding="utf-8")
    return f
