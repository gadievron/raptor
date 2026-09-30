"""Binary checklist rows in the source-shape hypothesis channels.

Binary rows (``binary:<stem>`` file keys) carry no repo source path,
so the source-reading channels must recognise the row kind up front:
one shared predicate and row-kind-aware inconclusive reasons — never
the meaningless ``.0`` suffix of a versioned shared-object name that
the suffix-based language lookup leaked. Hermetic: no subprocesses,
no LLM.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.ptr_lifecycle import run_ptr_lifecycle_check
from core.audit.release_order import run_release_order_check
from core.audit.resource_bounds import run_resource_bounds_check

BIN_ROW = "binary:libfoo.so.1.0"
HYP = "the loop appends without an upper bound"


class TestIsBinaryRow:
    # Function-level import: per-test attribution when the predicate
    # is absent, instead of one collection error for the whole file.
    def test_binary_row_key(self):
        from core.audit.fail_open_lang import is_binary_row
        assert is_binary_row(BIN_ROW)

    def test_source_path(self):
        from core.audit.fail_open_lang import is_binary_row
        assert not is_binary_row("src/x.c")

    def test_prefix_is_anchored(self):
        from core.audit.fail_open_lang import is_binary_row
        # startswith semantics: a path merely CONTAINING the prefix
        # later is a repo path, not a binary row key.
        assert not is_binary_row("a/binary:x")


class TestChannelGates:
    """Each channel returns inconclusive with a row-kind-aware reason
    BEFORE any suffix-based language lookup can leak ``.0``."""

    def _assert_binary_reason(self, res, reason_const: str) -> None:
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(reason_const)
        assert "binary checklist row" in res.reason
        assert ".0" not in res.reason

    def test_resource_bounds(self):
        from core.audit.resource_bounds import REASON_LANGUAGE_UNSUPPORTED
        res = run_resource_bounds_check(
            Path("/nonexistent"), BIN_ROW, "f", HYP,
        )
        self._assert_binary_reason(res, REASON_LANGUAGE_UNSUPPORTED)

    def test_release_order(self):
        from core.audit.release_order import REASON_LANGUAGE_UNSUPPORTED
        res = run_release_order_check(
            Path("/nonexistent"), BIN_ROW, "f", HYP,
        )
        self._assert_binary_reason(res, REASON_LANGUAGE_UNSUPPORTED)

    def test_ptr_lifecycle(self):
        from core.audit.ptr_lifecycle import REASON_LANGUAGE_UNSUPPORTED
        res = run_ptr_lifecycle_check(
            Path("/nonexistent"), BIN_ROW, "f", HYP,
        )
        self._assert_binary_reason(res, REASON_LANGUAGE_UNSUPPORTED)

    def test_suffix_leak_string_gone(self):
        # The pre-gate reason leaked Path(file_path).suffix — a
        # meaningless ".0" for versioned shared-object stems.
        res = run_resource_bounds_check(
            Path("/nonexistent"), BIN_ROW, "f", HYP,
        )
        assert "analyzer for .0" not in res.reason
