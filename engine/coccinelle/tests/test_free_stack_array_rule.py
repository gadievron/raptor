"""Native local-array origin contracts, including VLAs and shadowing."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "free_stack_array.cocci"
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("spatch") is None, reason="coccinelle not installed"),
]


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_free_of_stack_array_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void scratch(void)
            {
                char buf[64];
                use(buf);
                free(buf);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "free_stack_array"
        assert results[0]["line"] == 5


class TestNegatives:
    def test_free_of_heap_pointer_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void scratch(void)
            {
                char *buf = malloc(64);
                use(buf);
                free(buf);
            }
        """)
        assert results == []


def test_array_storage_forms_and_pointer_controls(tmp_path):
    cases = [
        ("void", "void", "char buf[8]; free(buf);", True),
        ("void", "unsigned long n", "char buf[n]; free(buf);", True),
        ("void", "unsigned long n", "char buf[n + 1]; free(buf);", True),
        ("void", "void", "char buf[2][8]; free(buf);", True),
        ("void", "void", "static char buf[8]; free(buf);", True),
        ("void", "void", "char buf[8] = {0}; free(buf);", True),
        ("void", "void", "char *buf = malloc(8); free(buf);", False),
        ("void", "char buf[8]", "free(buf);", False),
        ("void", "unsigned long n, char buf[n]", "free(buf);", False),
        ("void", "void", "char buf[8]; { char *buf = malloc(8); free(buf); }", False),
        ("void", "void", "char buf[8]; consume(buf);", False),
        ("void", "void", "char buf[8]; consume(sizeof(({ free(buf); 0; })));", False),
    ]
    lines = []
    expected = []
    for index, (result, params, body, positive) in enumerate(cases):
        lines.extend([f"{result} case_{index}({params}) {{", body, "}"])
        if positive:
            expected.append(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert sorted(row["line"] for row in rows) == expected
    assert all(row["rule"] == "free_stack_array" for row in rows)
    assert all(row["line_end"] == row["line"] and row["col_end"] > row["col"] for row in rows)
