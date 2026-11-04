"""Fixture tests for the insecure_temp_file rule.

Verification-role rule (fires mint confirmed CWE-377 verdicts). Group
1 flags the race-prone name-generation APIs themselves; group 2 flags
a mkstemp template reopened BY PATH, which discards the fd's race-free
guarantee. The negatives pin the safe idiom (use the returned fd) and
the reassigned-template shape group 2 must not confirm.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "insecure_temp_file.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_mktemp_call_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            char *make_name(char *tmpl)
            {
                return mktemp(tmpl);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "insecure_temp_file"
        assert results[0]["line"] == 3

    def test_tmpnam_and_tempnam_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void names(void)
            {
                char *a = tmpnam(0);
                char *b = tempnam("/tmp", "pfx");
            }
        """)
        assert len(results) == 2
        assert sorted(r["line"] for r in results) == [3, 4]

    def test_mkstemp_template_reopened_by_path_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int reopen(char *tmpl)
            {
                int fd = mkstemp(tmpl);
                if (fd < 0)
                    return -1;
                return open(tmpl, 2);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "insecure_temp_file"
        assert results[0]["line"] == 6


class TestNegatives:
    def test_mkstemp_with_fd_use_does_not_fire(self, tmp_path):
        # The safe idiom: keep the returned fd, never touch the path.
        results = _run_rule(tmp_path, """\
            void *safe_temp(char *tmpl)
            {
                int fd = mkstemp(tmpl);
                if (fd < 0)
                    return 0;
                return fdopen(fd, "w");
            }
        """)
        assert results == []

    def test_template_reassigned_before_open_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int different_file(char *tmpl, char *other)
            {
                int fd = mkstemp(tmpl);
                if (fd < 0)
                    return -1;
                tmpl = other;
                return open(tmpl, 0);
            }
        """)
        assert results == []

    def test_open_of_unrelated_path_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int unrelated(char *tmpl, const char *cfg)
            {
                int fd = mkstemp(tmpl);
                if (fd < 0)
                    return -1;
                return open(cfg, 0);
            }
        """)
        assert results == []
