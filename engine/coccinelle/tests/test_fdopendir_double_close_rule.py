"""Fixture tests for the fdopendir_double_close rule.

Verification-role rule (fires mint confirmed CWE-675 verdicts):
closedir() on an fdopendir() stream already closes the underlying
fd, so an explicit close(fd) afterwards is a double close. The
positive pins that close; the negative pins the correct
closedir-only teardown.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "fdopendir_double_close.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_close_after_closedir_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void list_dir(int fd)
            {
                void *dir = fdopendir(fd);
                walk(dir);
                closedir(dir);
                close(fd);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "fdopendir_double_close"
        assert results[0]["line"] == 6


class TestNegatives:
    def test_closedir_only_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void list_dir(int fd)
            {
                void *dir = fdopendir(fd);
                walk(dir);
                closedir(dir);
            }
        """)
        assert results == []


@pytest.mark.parametrize("declaration", [False, True], ids=["assignment", "declaration"])
@pytest.mark.parametrize("close_first", [False, True], ids=["stream-first", "fd-first"])
def test_ownership_changes_and_close_order(tmp_path, declaration, close_first):
    cases = (
        ("", "", True),
        ("walk(dir);", "", True),
        ("", "walk(dir);", True),
        ('dir = opendir("other");', "", False),
        ("replace_dir(&dir);", "", False),
        ("fd = replacement;", "", False),
        ("fd++;", "", False),
        ("++fd;", "", False),
        ("fd--;", "", False),
        ("--fd;", "", False),
        ("fd += 1;", "", False),
        ("fd -= 1;", "", False),
        ("dir++;", "", False),
        ("dir += 1;", "", False),
        ("replace_fd(&fd);", "", False),
        ("", "fd = replacement;", False),
        ("", "fd++;", False),
        ("", "fd += 1;", False),
        ("", "dir++;", not close_first),
        ("", "replace_fd(&fd);", False),
        ("", "dup2(replacement, fd);", False),
        ("", "dup3(replacement, fd, 0);", False),
        # Replacing a stream after closedir cannot undo its fd release.
        ('', 'dir = opendir("other");', not close_first),
        ('', 'replace_dir(&dir);', not close_first),
    )
    lines = []
    expected = set()
    prefix = "void *" if declaration else ""
    for before, between, should_report in cases:
        lines += [f"void case_{len(lines)}(int fd, int replacement) {{"]
        if not declaration:
            lines += ["void *dir;"]
        lines += [f"{prefix}dir = fdopendir(fd);", "if (!dir) return;", before,
                  "close(fd);" if close_first else "closedir(dir);", between,
                  "closedir(dir);" if close_first else "close(fd);", "}"]
        if should_report:
            expected.add(len(lines) - 1)
    # Failure cleanup and mutually exclusive paths cannot form a double close.
    lines += ["void failure_cleanup(int fd) {", "void *dir = fdopendir(fd);",
              "if (!dir) { close(fd); return; }", "closedir(dir);", "}"]
    lines += ["void split_release(int fd, int which) {", "void *dir = fdopendir(fd);",
              "if (!dir) return;", "if (which) { close(fd); return; }",
              "closedir(dir);", "}"]
    lines += ["void unrelated_stream(int fd, void *other) {",
              "void *dir = fdopendir(fd);", "if (!dir) return;",
              "closedir(other);", "close(fd);", "}"]
    lines += ["void unrelated_descriptor(int fd, int other) {",
              "void *dir = fdopendir(fd);", "if (!dir) return;",
              "close(other);", "closedir(dir);", "}"]
    for index in range(120):
        lines += [f"void repeated_{index}(int fd) {{"]
        if not declaration:
            lines += ["void *dir;"]
        lines += [f"{prefix}dir = fdopendir(fd);", "if (!dir) return;",
                  "close(fd);" if close_first else "closedir(dir);",
                  "closedir(dir);" if close_first else "close(fd);", "}"]
        expected.add(len(lines) - 1)
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in results}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(results) == len(expected)
    assert {row["rule"] for row in results} == {"fdopendir_double_close"}


@pytest.mark.integration
def test_directory_ownership_keeps_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        'void forward(int fd) { void *d = fdopendir(fd); if (!d) return; closedir(d); close(fd); }\n'
        'void reverse(int fd) { void *d = fdopendir(fd); if (!d) return; close(fd); closedir(d); }\n'
        'void replaced(int fd) { void *d = fdopendir(fd); d = opendir("x"); closedir(d); close(fd); }\n'
        'void twice(int fd) { close(fd); close(fd); }\n',
    )
    original = runner._confined_default_runner
    invocations = []

    def observe(*args, **kwargs):
        execute = original(*args, **kwargs)

        def invoke(argv, **options):
            invocations.append(tuple(argv))
            return execute(argv, **options)

        return invoke

    monkeypatch.setattr(runner, "_confined_default_runner", observe)
    results = runner.run_rules_batched(
        source, [_RULE, _RULE.with_name("double_close.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"fdopendir_double_close", "double_close"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["fdopendir_double_close"].matches) == 2
    assert len(results["double_close"].matches) == 1
    assert len(invocations) == 1, invocations
