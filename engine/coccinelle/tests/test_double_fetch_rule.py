"""Fixture tests for the double_fetch rule.

A rebound or advanced pointer between the two copy_from_user calls
means the second copy reads a DIFFERENT user region (sequential
chunked consumption), not a re-fetch of validated data.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "double_fetch.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_same_pointer_double_fetch_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int handler(void *dst, char *uptr)
            {
                struct hdr h;
                copy_from_user(&h, uptr, sizeof(h));
                if (h.len > 64)
                    return -1;
                copy_from_user(dst, uptr, h.len);
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "double_fetch"

    @pytest.mark.parametrize("operation", ["uptr += 0;", "uptr -= 0;"])
    def test_zero_offset_keeps_same_pointer_fetch(self, tmp_path, operation):
        results = _run_rule(tmp_path, """\
            int handler(void *dst, char *uptr)
            {
                struct hdr h;
                copy_from_user(&h, uptr, sizeof(h));
                if (h.len > 64)
                    return -1;
                %s
                copy_from_user(dst, uptr, h.len);
                return 0;
            }
        """ % operation)
        assert len(results) == 1
        assert results[0]["rule"] == "double_fetch"


class TestNegatives:
    @pytest.mark.parametrize("operation", ["uptr += 8;", "uptr -= 8;"])
    def test_advanced_pointer_does_not_fire(self, tmp_path, operation):
        results = _run_rule(tmp_path, """\
            int chunked(void *dst, char *uptr)
            {
                copy_from_user(dst, uptr, 8);
                %s
                copy_from_user(dst, uptr, 8);
                return 0;
            }
        """ % operation)
        assert results == []

    def test_reassigned_pointer_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int rebound(void *dst, char *uptr, char *next)
            {
                copy_from_user(dst, uptr, 8);
                uptr = next;
                copy_from_user(dst, uptr, 8);
                return 0;
            }
        """)
        assert results == []
