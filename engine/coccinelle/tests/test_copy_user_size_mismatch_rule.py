"""Fixture tests for the copy_user_size_mismatch rule.

sizeof(*dst) equals sizeof(local) whenever both sides share a type
— the common CORRECT spelling. Only a genuine type mismatch is a
wrong-length copy, enforced via typed metavariables plus a type
comparison in the reporting script.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "copy_user_size_mismatch.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_mismatched_types_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct big { int a[16]; };
            struct small { int a; };
            int leak(struct big *ud)
            {
                struct small local;
                local.a = 1;
                if (copy_to_user(ud, &local, sizeof(*ud)))
                    return -14;
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "copy_user_size_mismatch"

    def test_sizeof_pointer_from_user_still_fires(self, tmp_path):
        # The copy_from_user leg is independent of the type filter.
        results = _run_rule(tmp_path, """\
            struct foo { int a[8]; };
            int get(struct foo *usrc)
            {
                struct foo local;
                if (copy_from_user(&local, usrc, sizeof(usrc)))
                    return -14;
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "copy_from_user_sizeof_ptr"


class TestNegatives:
    def test_same_type_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct foo { int a; int b; };
            int ok(struct foo *ud)
            {
                struct foo local;
                local.a = 1;
                local.b = 2;
                if (copy_to_user(ud, &local, sizeof(*ud)))
                    return -14;
                return 0;
            }
        """)
        assert results == []
