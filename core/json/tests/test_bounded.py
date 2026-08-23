"""Tests for the bounded JSON entry points (attacker-influenced input)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core.json.bounded import (
    JsonBudgetExceededError,
    load_json_bounded,
    loads_bounded,
)


class TestLoadsBounded:
    def test_under_budget_parses(self) -> None:
        assert loads_bounded('{"a": 1}', max_bytes=1024) == {"a": 1}

    def test_exact_size_parses(self) -> None:
        text = '{"a": 1}'
        assert loads_bounded(text, max_bytes=len(text)) == {"a": 1}

    def test_bytes_input_parses(self) -> None:
        assert loads_bounded(b'[1, 2, 3]', max_bytes=64) == [1, 2, 3]

    def test_over_budget_raises_with_sizes(self) -> None:
        payload = '{"pad": "' + "x" * 100 + '"}'
        with pytest.raises(JsonBudgetExceededError) as exc_info:
            loads_bounded(payload, max_bytes=10)
        msg = str(exc_info.value)
        assert str(len(payload)) in msg
        assert "10" in msg

    def test_over_budget_bytes_raises(self) -> None:
        with pytest.raises(JsonBudgetExceededError):
            loads_bounded(b"[" + b"1," * 100 + b"1]", max_bytes=16)

    def test_budget_error_is_valueerror(self) -> None:
        # Callers with an existing ``except ValueError`` malformed-
        # input path must fail closed without new plumbing.
        assert issubclass(JsonBudgetExceededError, ValueError)

    def test_malformed_raises_valueerror(self) -> None:
        with pytest.raises(ValueError):
            loads_bounded("{not json", max_bytes=1024)

    def test_non_finite_rejected(self) -> None:
        with pytest.raises(ValueError):
            loads_bounded('{"x": NaN}', max_bytes=1024)


class TestLoadJsonBounded:
    def test_under_budget_parses(self, tmp_path: Path) -> None:
        p = tmp_path / "data.json"
        p.write_text('{"key": "value"}')
        assert load_json_bounded(p, max_bytes=1024) == {"key": "value"}

    def test_exact_size_parses(self, tmp_path: Path) -> None:
        p = tmp_path / "data.json"
        p.write_text('{"a": 1}')
        assert load_json_bounded(p, max_bytes=p.stat().st_size) == {"a": 1}

    def test_oversize_valid_json_still_refused(self, tmp_path: Path) -> None:
        # The gate fires on stat alone — a file of perfectly valid
        # JSON over budget is refused even though a read+parse would
        # have succeeded.
        p = tmp_path / "valid-but-big.json"
        p.write_text(json.dumps({"k": "v" * 1000}))
        with pytest.raises(JsonBudgetExceededError) as exc_info:
            load_json_bounded(p, max_bytes=100)
        msg = str(exc_info.value)
        assert str(p.stat().st_size) in msg
        assert "100" in msg

    def test_missing_file_raises_oserror(self, tmp_path: Path) -> None:
        with pytest.raises(OSError):
            load_json_bounded(tmp_path / "absent.json", max_bytes=10)

    def test_non_regular_file_refused(self, tmp_path: Path) -> None:
        fifo = tmp_path / "fifo.json"
        os.mkfifo(fifo)
        # Must raise promptly on the stat, never open (a FIFO open
        # for read blocks until a writer appears).
        with pytest.raises(ValueError, match="not a regular file"):
            load_json_bounded(fifo, max_bytes=1024)

    def test_bom_tolerated(self, tmp_path: Path) -> None:
        p = tmp_path / "bom.json"
        p.write_bytes(b'\xef\xbb\xbf{"a": 1}')
        assert load_json_bounded(p, max_bytes=1024) == {"a": 1}

    def test_malformed_raises_valueerror(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{not json")
        with pytest.raises(ValueError):
            load_json_bounded(p, max_bytes=1024)

    def test_non_finite_rejected(self, tmp_path: Path) -> None:
        p = tmp_path / "nan.json"
        p.write_text('{"x": Infinity}')
        with pytest.raises(ValueError):
            load_json_bounded(p, max_bytes=1024)


def test_lazy_reexport_surface() -> None:
    import core.json as cj

    assert cj.loads_bounded is loads_bounded
    assert cj.load_json_bounded is load_json_bounded
    assert cj.JsonBudgetExceededError is JsonBudgetExceededError
    assert "loads_bounded" in cj.__all__
    assert "load_json_bounded" in cj.__all__
    assert "JsonBudgetExceededError" in cj.__all__
