"""Fixture tests for the format_string rule.

This is a verification-role rule — a false positive mints a false
"confirmed" CWE-134 verdict — so the negatives pin the safe idioms the
rule used to flag: a gettext-family translation of a string literal,
a const local initialized from a literal, and the file-scope
``static const char *fmt = "..."`` idiom (the shape of the repo's own
negative control, engine/negative_controls/format_string.c).

The reassignment shapes keep the true-positive side honest: a format
variable that WAS constant but got reassigned from a parameter before
the call must still fire, and taking the variable's address voids the
safe marking.

TestDocumentedMisses witnesses the ACCEPTED false negatives the rule
header documents (exists-path reassignment guard, any-scope identifier
binding). They assert current behaviour so a semantics change flips
them consciously — they are misses, not endorsements: if a change
makes these fire without breaking the negatives above, remove them and
the header caveats together.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "format_string.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(rule), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


class TestPositives:
    def test_parameter_as_format_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void log_user(char *user)
            {
                printf(user);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "format_string"
        assert results[0]["line"] == 3

    def test_second_arg_family_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void log_user(void *fp, char *user)
            {
                fprintf(fp, user);
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 3

    def test_third_arg_family_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void log_user(char *buf, char *user)
            {
                snprintf(buf, 64, user);
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 3

    def test_const_local_reassigned_from_parameter_fires(self, tmp_path):
        # The constant initializer must not mark later uses safe once
        # the variable was reassigned from a non-constant.
        results = _run_rule(tmp_path, """\
            void log_user(char *user)
            {
                const char *fmt = "ok %d";
                fmt = user;
                printf(fmt, 1);
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 5

    def test_global_fmt_reassigned_from_parameter_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static const char *fmt = "ok %s";
            void log_user(char *user)
            {
                fmt = user;
                printf(fmt, 1);
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 5

    def test_address_taken_fmt_fires(self, tmp_path):
        # Taking the variable's address voids the safe marking — an
        # alias write cannot be tracked, so the call must stay in the
        # bug set.
        results = _run_rule(tmp_path, """\
            void alias_write(char *user)
            {
                const char *fmt = "ok %d";
                const char **slot = &fmt;
                *slot = user;
                printf(fmt, 1);
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 6


class TestNegatives:
    def test_string_literal_format_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void log_msg(const char *msg)
            {
                printf("%s\\n", msg);
                fprintf((void *)0, "%s\\n", msg);
            }
        """)
        assert results == []

    def test_gettext_of_literal_does_not_fire(self, tmp_path):
        # Translating a string literal does not hand the format to an
        # attacker: the message catalog ships with the installation.
        results = _run_rule(tmp_path, """\
            void greet(int n, void *fp)
            {
                printf(gettext("hello %d\\n"), n);
                printf(_("hi %d\\n"), n);
                fprintf(fp, gettext("bye %d\\n"), n);
                printf(ngettext("%d file", "%d files", n), n);
                printf(dgettext("dom", "%d\\n"), n);
            }
        """)
        assert results == []

    def test_const_local_literal_format_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void log_msg(const char *msg)
            {
                const char *fmt = "%s\\n";
                printf(fmt, msg);
            }
        """)
        assert results == []

    def test_file_scope_const_format_does_not_fire(self, tmp_path):
        # The shape of engine/negative_controls/format_string.c.
        results = _run_rule(tmp_path, """\
            static const char *fmt = "%s\\n";

            void log_msg(const char *msg)
            {
                printf(fmt, msg);
            }
        """)
        assert results == []


class TestDocumentedMisses:
    """Witnesses for the header's accepted false negatives — asserting
    current behaviour, NOT endorsing it (see module docstring)."""

    def test_conditional_reassignment_is_a_documented_miss(self, tmp_path):
        # Exists-path guard semantics: the clean !custom path keeps
        # the position in the safe set even though the custom path
        # carries user data into the format.
        results = _run_rule(tmp_path, """\
            void cond(char *user_fmt, int custom, int n)
            {
                const char *fmt = "default %d";
                if (custom)
                    fmt = user_fmt;
                printf(fmt, n);
            }
        """)
        assert results == []

    def test_parameter_name_collision_is_a_documented_miss(self, tmp_path):
        # Any-scope identifier binding: the const-initialized `fmt`
        # in one function masks a same-named PARAMETER in another.
        results = _run_rule(tmp_path, """\
            void safe_one(int n)
            {
                const char *fmt = "ok %d";
                printf(fmt, n);
            }
            void wrapper(char *fmt)
            {
                printf(fmt);
            }
        """)
        assert results == []

    def test_collision_control_without_constant_decl_fires(self, tmp_path):
        # Control for the collision miss: with no constant-initialized
        # `fmt` declaration in the TU, the parameter call site fires.
        results = _run_rule(tmp_path, """\
            void wrapper(char *fmt)
            {
                printf(fmt);
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 3
