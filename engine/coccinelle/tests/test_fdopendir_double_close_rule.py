"""Native fdopendir ownership candidates, storage and path contracts."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "fdopendir_double_close.cocci"
)

# Every case executes the real tool; engine CI owns the native partition.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("spatch") is None, reason="coccinelle not installed"),
]


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
@pytest.mark.parametrize("phase", ["before", "between", "rebinding", "scale-first", "scale-second"])
def test_ownership_changes_and_close_order(tmp_path, declaration, close_first, phase):
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
        ("fd *= 0;", "", False),
        ("fd /= 2;", "", False),
        ("fd %= 2;", "", False),
        ("fd <<= 1;", "", False),
        ("fd >>= 1;", "", False),
        ("fd &= 1;", "", False),
        ("fd ^= 1;", "", False),
        ("fd |= 1;", "", False),
        ("dir++;", "", False),
        ("dir += 1;", "", False),
        ("replace_fd(&fd);", "", False),
        ("", "fd = replacement;", False),
        ("", "fd++;", False),
        ("", "fd += 1;", False),
        ("", "fd *= 0;", False),
        ("", "fd /= 2;", False),
        ("", "fd %= 2;", False),
        ("", "fd <<= 1;", False),
        ("", "fd >>= 1;", False),
        ("", "fd &= 1;", False),
        ("", "fd ^= 1;", False),
        ("", "fd |= 1;", False),
        ("", "dir++;", not close_first),
        ("", "replace_fd(&fd);", False),
        ("", "dup2(replacement, fd);", False),
        ("", "dup3(replacement, fd, 0);", False),
        ("", "dup2(fd, fd);", True),
        ("", "dup3(fd, fd, 0);", True),
        ("", "dup2((fd), fd);", True),
        ("", "dup2(fd, (fd));", True),
        ("", "dup3((fd), (fd), 0);", True),
        ("", "dup3(fd, replacement, 0);", True),
        ("", "dup3(replacement, other_fd, fd);", True),
        ("", "dup2(replacement, (fd));", False),
        ("", "dup2((replacement), (fd));", False),
        ("", "dup3(replacement, (fd), 0);", False),
        ("", "dup2(get_other_fd(), fd);", False),
        # Replacing a stream after closedir cannot undo its fd release.
        ('', 'dir = opendir("other");', not close_first),
        ('', 'replace_dir(&dir);', not close_first),
    )
    lines = []
    expected = set()
    prefix = "void *" if declaration else ""
    for before, between, should_report in cases:
        category = "rebinding" if "dup2(" in between or "dup3(" in between else (
            "before" if before or not between else "between"
        )
        if category != phase:
            continue
        lines += [f"void case_{len(lines)}(int fd, int replacement, int other_fd) {{"]
        if not declaration:
            lines += ["void *dir;"]
        lines += [f"{prefix}dir = fdopendir(fd);", "if (!dir) return;", before,
                  "close(fd);" if close_first else "closedir(dir);", between,
                  "closedir(dir);" if close_first else "close(fd);", "}"]
        if should_report:
            expected.add(len(lines) - 1)
    if phase.startswith("scale-"):
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
        repetitions = range(16) if phase == "scale-first" else range(16, 32)
        for index in repetitions:
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


def test_directory_ownership_keeps_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        "struct owner { int fd; void *dir; };\n"
        'void forward(int fd) { void *d = fdopendir(fd); if (!d) return; closedir(d); close(fd); }\n'
        'void reverse(int fd) { void *d = fdopendir(fd); if (!d) return; close(fd); closedir(d); }\n'
        'void replaced(int fd) { void *d = fdopendir(fd); d = opendir("x"); closedir(d); close(fd); }\n'
        'void mutated(int fd) { void *d = fdopendir(fd); if (!d) return; fd ^= 1; closedir(d); close(fd); }\n'
        'void self_dup(int fd) { void *d = fdopendir(fd); if (!d) return; closedir(d); dup2(fd, fd); close(fd); }\n'
        'void field_self_dup(struct owner *ctx) { ctx->dir = fdopendir(ctx->fd); closedir(ctx->dir); dup2((ctx->fd), ctx->fd); close(ctx->fd); }\n'
        'void field_rebound(struct owner *ctx, int other) { ctx->dir = fdopendir(ctx->fd); closedir(ctx->dir); dup2(other, ctx->fd); close(ctx->fd); }\n'
        'void moved_receiver(struct owner *ctx, struct owner *next) { ctx->dir = fdopendir(ctx->fd); ctx = next; closedir(ctx->dir); close(ctx->fd); }\n'
        'void computed_handle(void) { void *d = fdopendir(next_fd()); closedir(d); close(next_fd()); }\n'
        'void bypass(int fd, int other, int branch) { void *d = fdopendir(fd); if (branch) fd = other; closedir(d); close(fd); }\n'
        'void pure_fd(int fd) { close(fd); observe(fd); close(fd); }\n'
        'int candidate(void *p) { if (IS_ERR(p)) { int ret = -IS_ERR(p); return ret; } return 0; }\n'
        'int rewritten(void *p) { int ret; if (IS_ERR(p)) { ret = IS_ERR(p); ret *= -EIO; return ret; } return 0; }\n',
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
        source, [_RULE, _RULE.with_name("is_err_not_ptr_err.cocci"), _RULE.with_name("double_close.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"fdopendir_double_close", "is_err_not_ptr_err", "double_close"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["fdopendir_double_close"].matches) == 5
    assert len(results["is_err_not_ptr_err"].matches) == 1
    assert len(results["double_close"].matches) == 1
    assert len(invocations) == 1, invocations


@pytest.mark.parametrize("fd,fd_base,directory,dir_base", [
    ("fd", "fd", "dir", "dir"),
    ("fctx->fd", "fctx", "dir", "dir"),
    ("fitem.fd", "fitem", "dctx->dir", "dctx"),
    ("fds[0]", "fds", "ditem.dir", "ditem"),
    ("fd", "fd", "dirs[0]", "dirs"),
    ("fctx->fd", "fctx", "dirs[0]", "dirs"),
], ids=["locals", "fd-field", "both-fields", "fd-array-dir-field", "dir-array", "fd-field-dir-array"])
@pytest.mark.parametrize("close_first", [False, True], ids=["stream-first", "fd-first"])
@pytest.mark.parametrize("phase", ["before-release", "after-release"])
def test_storage_receivers_and_competing_cleanup_paths(tmp_path, fd, fd_base, directory, dir_base, close_first, phase):
    cases = [
        ("", "", True),
        ("observe(F); observe(D);", "observe(F); observe(D);", True),
        ("F = replacement;", "", False), ("D = other;", "", False),
        (f"replace_base(&{fd_base});", "", False),
        (f"replace_base(&{dir_base});", "", False),
        (f"if (optional) replace_base(&{fd_base}); else D = other;", "", False),
        (f"if (optional) replace_base(&{dir_base});", "", True),
        ("", f"replace_base(&{fd_base});", False),
        ("", f"replace_base(&{dir_base});", not close_first),
        ("", f"if (optional) replace_base(&{fd_base});", True),
        ("", f"if (optional) replace_base(&{fd_base}); else F = replacement;", False),
        ("", "dup2(replacement, F);", False),
        ("", "dup3(F, replacement, 0);", True),
        ("", "dup2((F), (F));", True),
        ("", "dup3((F), F, 0);", True),
    ]
    lines = ["struct owner { int fd; void *dir; };"]
    expected = set()
    parameters = "int fd, int replacement, void *dir, void *other, int *fds, void **dirs, struct owner *fctx, struct owner *dctx, struct owner fitem, struct owner ditem, int optional"
    selected = cases[:8] if phase == "before-release" else cases[8:]
    for number, (before, between, reports) in enumerate(selected):
        lines += [f"void case_{number}({parameters}) {{", f"{directory} = fdopendir({fd});",
                  before.replace("F", fd).replace("D", directory),
                  f"close({fd});" if close_first else f"closedir({directory});",
                  between.replace("F", fd).replace("D", directory),
                  f"closedir({directory});" if close_first else f"close({fd});", "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected)
    assert {row["rule"] for row in rows} == {"fdopendir_double_close"}
    assert all(row["message"].startswith("Candidate:") for row in rows)


@pytest.mark.parametrize("declaration", [False, True], ids=["assignment", "declaration"])
@pytest.mark.parametrize("close_first", [False, True], ids=["stream-first", "fd-first"])
def test_creation_from_field_keeps_receiver_and_bad_path(tmp_path, declaration, close_first):
    lines = ["struct owner { int fd; };"]
    expected = set()
    for number, (before, reports) in enumerate([
        ("", True), ("ctx = next;", False), ("replace(&ctx);", False),
        ("if (optional) ctx = next;", True),
        ("if (optional) ctx = next; else ctx->fd = replacement;", False),
    ]):
        lines += [f"void f_{number}(struct owner *ctx, struct owner *next, int replacement, int optional) {{"]
        if not declaration:
            lines.append("void *dir;")
        prefix = "void *" if declaration else ""
        lines += [f"{prefix}dir = fdopendir(ctx->fd);", "if (!dir) return;", before,
                  "close(ctx->fd);" if close_first else "closedir(dir);",
                  "closedir(dir);" if close_first else "close(ctx->fd);", "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows} == expected
    assert len(rows) == len(expected)


@pytest.mark.parametrize("close_first", [False, True], ids=["stream-first", "fd-first"])
def test_unsupported_expressions_and_numeric_descriptors(tmp_path, close_first):
    lines = []
    expected = set()
    for number, (fd, reports) in enumerate([
        ("next_fd()", False), ("-1", False), ("fds[index + 1]", False),
        ("*slot", False), ("fds[index]", False), ("ctx->child->fd", False),
        ("1", True), ("0x3", True),
    ]):
        lines += [f"void f_{number}(int *fds, int *slot, int index, void *ctx) {{",
                  f"void *dir = fdopendir({fd});",
                  f"close({fd});" if close_first else "closedir(dir);",
                  "closedir(dir);" if close_first else f"close({fd});", "}"]
        if reports:
            expected.add(len(lines) - 1)
    for number, directory in enumerate(("*slot", "dirs[index]", "dirs[index + 1]", "ctx->child->dir")):
        lines += [f"void g_{number}(int fd, void **slot, void **dirs, int index, void *ctx) {{",
                  f"{directory} = fdopendir(fd);",
                  "close(fd);" if close_first else f"closedir({directory});",
                  f"closedir({directory});" if close_first else "close(fd);", "}"]
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows} == expected
    assert len(rows) == len(expected)


@pytest.mark.parametrize("close_first", [False, True], ids=["stream-first", "fd-first"])
def test_exclusive_and_merging_release_paths(tmp_path, close_first):
    first = "close(fd);" if close_first else "closedir(dir);"
    second = "closedir(dir);" if close_first else "close(fd);"
    lines = ["void exclusive(int fd, int branch) {", "void *dir = fdopendir(fd);",
             "if (!dir) { close(fd); return; }",
             f"if (branch) {{ {first} return; }}", second, "}",
             "void merging(int fd, int branch) {", "void *dir = fdopendir(fd);",
             "if (!dir) return;", f"if (branch) {{ {first} }} else {{ {first} }}", second, "}"]
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert [row["line"] for row in rows] == [len(lines) - 1]


@pytest.mark.parametrize("close_first", [False, True], ids=["stream-first", "fd-first"])
def test_shared_receiver_changes_invalidate_both_handles(tmp_path, close_first):
    lines = ["struct owner { int fd; void *dir; };"]
    expected = set()
    for number, (between, reports) in enumerate([
        ("observe(ctx);", True), ("ctx = next;", False),
        ("replace(&ctx);", False), ("ctx++;", False),
        ("if (branch) ctx = next;", True),
        ("if (branch) ctx = next; else ctx->fd = other;", False),
    ]):
        lines += [f"void f_{number}(struct owner *ctx, struct owner *next, int other, int branch) {{",
                  "ctx->dir = fdopendir(ctx->fd);",
                  "close(ctx->fd);" if close_first else "closedir(ctx->dir);", between,
                  "closedir(ctx->dir);" if close_first else "close(ctx->fd);", "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows} == expected
    assert len(rows) == len(expected)
