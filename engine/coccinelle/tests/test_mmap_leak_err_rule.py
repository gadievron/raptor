"""Native mapping-leak candidates and local ownership controls."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "mmap_leak_err.cocci"
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("spatch") is None, reason="coccinelle not installed"),
]


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_error_return_after_successful_mmap_fires_decl(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int process(int fd, unsigned long len)
            {
                void *addr = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                if (addr == MAP_FAILED)
                    return -1;
                if (validate(addr) < 0)
                    return -22;
                munmap(addr, len);
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "mmap_leak_err"
        assert results[0]["line"] == 7

    def test_error_return_after_successful_mmap_fires_assign(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int process(int fd, unsigned long len)
            {
                void *addr;
                addr = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                if (addr == MAP_FAILED)
                    return -1;
                if (validate(addr) < 0)
                    return -22;
                munmap(addr, len);
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 8


class TestNegatives:
    def test_correct_wrapper_does_not_fire(self, tmp_path):
        # The canonical shape of every correct mmap wrapper: the
        # MAP_FAILED return releases nothing (mapping never existed)
        # and `return addr;` transfers ownership to the caller.
        results = _run_rule(tmp_path, """\
            void *map_file(int fd, unsigned long len)
            {
                void *addr = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                if (addr == MAP_FAILED)
                    return 0;
                return addr;
            }
        """)
        assert results == []

    def test_munmap_before_error_return_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int process(int fd, unsigned long len)
            {
                void *addr = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                if (addr == MAP_FAILED)
                    return -1;
                if (validate(addr) < 0) {
                    munmap(addr, len);
                    return -22;
                }
                munmap(addr, len);
                return 0;
            }
        """)
        assert results == []


@pytest.mark.parametrize("api", ["mmap", "mmap64"])
@pytest.mark.parametrize("declaration", [False, True], ids=["assignment", "declaration"])
@pytest.mark.parametrize("cast", ["", "(char *)"], ids=["plain", "cast"])
def test_mapping_cleanup_and_ownership_contracts(tmp_path, api, declaration, cast):
    cases = [
        ("consume(p);", "return -22;", True),
        ("", "return p;", False),
        ("", "return (void *)p;", False),
        ("munmap(p, len);", "return -22;", False),
        ("munmap((void *)p, len);", "return -22;", False),
        ("munmap((int)p, len);", "return -22;", True),
        ("", "return (int)p;", True),
        ("munmap(p, len / 2);", "return -22;", True),
        ("munmap(p + len / 2, len / 2);", "return -22;", True),
        ("munmap(other, len);", "return -22;", True),
        ("if (cond) munmap(p, len);", "return -22;", True),
        ("free(p);", "return -22;", True),
        ("close(fd);", "return -22;", True),
        ("*owner = p;", "return 0;", True),
        ("p = other;", "return -22;", False),
        ("replace(&p);", "return -22;", False),
    ]
    lines = []
    expected = []
    for index, (between, returned, candidate) in enumerate(cases):
        result_type = "void *" if returned in ("return p;", "return (void *)p;") else "long"
        lines.append(f"{result_type} case_{index}(int fd, unsigned long len, char *other, char **owner, int cond) {{")
        if not declaration:
            lines.append("char *p;")
        prefix = "char *" if declaration else ""
        lines.extend([f"{prefix}p = {cast}{api}(0, len, PROT_READ, MAP_PRIVATE, fd, 0);",
                      "if (p == MAP_FAILED) return -1;", between, returned, "}"])
        if candidate:
            expected.append(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert sorted(row["line"] for row in rows) == expected
    assert all(row["rule"] == "mmap_leak_err" for row in rows)
    assert all(row["message"].startswith("Candidate:") and "ownership transfers" in row["message"] for row in rows)
    assert all(row["line_end"] == row["line"] and row["col_end"] > row["col"] for row in rows)


@pytest.mark.parametrize("phase", ["before-check", "after-check"])
def test_rebinding_and_address_escape_end_local_identity_tracking(tmp_path, phase):
    changes = ["p = other;", "p += 1;", "p -= 1;", "p++;", "++p;", "p--;", "--p;", "replace(&p);"]
    lines = []
    for index, change in enumerate(changes):
        lines.extend([f"int case_{index}(int fd, unsigned long len, char *other) {{",
                      "char *p = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);"])
        if phase == "before-check":
            lines.append(change)
        lines.append("if (p == MAP_FAILED) return -1;")
        if phase == "after-check":
            lines.append(change)
        lines.extend(["return -22;", "}"])
    assert _run_rule(tmp_path, "\n".join(lines) + "\n") == []


@pytest.mark.parametrize("condition", ["p == MAP_FAILED", "MAP_FAILED == p", "unlikely(p == MAP_FAILED)", "unlikely(MAP_FAILED == p)"],
                         ids=["direct", "reversed", "hinted", "hinted-reversed"])
def test_failure_branch_returns_are_not_leak_candidates(tmp_path, condition):
    lines = ["void *f(int fd, unsigned long len) {",
             "void *p = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);",
             f"if ({condition}) {{ log_error(); return 0; }}", "return (void *)p;", "}"]
    assert _run_rule(tmp_path, "\n".join(lines) + "\n") == []


def test_same_named_variables_do_not_join_across_functions(tmp_path):
    source = """
        void *create(int fd, unsigned long len) {
            void *p = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
            return p;
        }
        int unrelated(void *p) {
            if (p == MAP_FAILED) return -1;
            return -22;
        }
    """
    assert _run_rule(tmp_path, source) == []


def test_conditional_replacement_keeps_the_unchanged_path(tmp_path):
    lines = ["int f(int fd, unsigned long len, char *other, int cond) {",
             "char *p = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);",
             "if (p == MAP_FAILED) return -1;", "if (cond) p = other;", "return -22;", "}"]
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert len(rows) == 1 and rows[0]["line"] == lines.index("return -22;") + 1


def test_unchecked_and_nonlocal_mapping_storage_need_separate_review(tmp_path):
    source = """
        struct owner { char *p; };
        int unchecked(int fd, unsigned long len) {
            void *p = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
            return -22;
        }
        int nonlocal(struct owner *ctx, int fd, unsigned long len) {
            ctx->p = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
            if (ctx->p == MAP_FAILED) return -1;
            return -22;
        }
    """
    assert _run_rule(tmp_path, source) == []
