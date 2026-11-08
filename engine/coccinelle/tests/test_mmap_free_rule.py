"""Fixture tests for the mmap_free rule.

Verification-role rule (fires mint confirmed CWE-762 verdicts):
mmap'd memory passed to free() corrupts heap allocator metadata —
it must be released with munmap(). The positive pins free on the
mapping; the negative pins the correct munmap release.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "mmap_free.cocci"
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
    def test_free_of_mapping_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void load(int fd, unsigned long len)
            {
                char *map = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                use(map);
                free(map);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "mmap_free"
        assert results[0]["line"] == 5


class TestNegatives:
    def test_munmap_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void load(int fd, unsigned long len)
            {
                char *map = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                use(map);
                munmap(map, len);
            }
        """)
        assert results == []


@pytest.mark.parametrize("declaration", [False, True], ids=["assignment", "declaration"])
@pytest.mark.parametrize("api", ["mmap", "mmap64", "mremap", "mremap-fixed"])
def test_mapping_origins_and_pointer_replacement(tmp_path, api, declaration):
    origins = {
        "mmap": "mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0)",
        "mmap64": "mmap64(0, len, PROT_READ, MAP_PRIVATE, fd, 0)",
        "mremap": "mremap(old, len, 2 * len, MREMAP_MAYMOVE)",
        "mremap-fixed": "mremap(old, len, 2 * len, MREMAP_MAYMOVE | MREMAP_FIXED, dst)",
    }
    cases = (
        ("use(p);", "free(p);", True),
        ("munmap(p, len);", "free(p);", True),
        ("munmap(p, len / 2);", "free(p);", True),
        ("p = malloc(len);", "free(p);", False),
        ("munmap(p, len); p = malloc(len);", "free(p);", False),
        ("replace(&p);", "free(p);", False),
        ("p = other;", "free(p);", False),
        ("p = 0;", "free(p);", False),
        ("munmap(p, len); replace(&p);", "free(p);", False),
        ("use(p);", "munmap(p, len);", False),
        ("", "free(other);", False),
        ("return;", "free(p);", False),
    )
    lines = []
    expected = set()
    prefix = "char *" if declaration else ""
    signature = "int fd, unsigned long len, char *old, char *dst, char *other"
    for between, release, should_report in cases:
        lines += [f"void case_{len(lines)}({signature}) {{"]
        if not declaration:
            lines += ["char *p;"]
        lines += [f"{prefix}p = {origins[api]};", "if (p == MAP_FAILED) return;",
                  between, release, "}"]
        if should_report:
            expected.add(len(lines) - 1)
    for cast_origin, cast_release in ((True, False), (False, True), (True, True)):
        lines += [f"void casted_{len(lines)}({signature}) {{"]
        if not declaration:
            lines += ["char *p;"]
        cast = "(char *)" if cast_origin else ""
        release = "free((void *)p);" if cast_release else "free(p);"
        lines += [f"{prefix}p = {cast}{origins[api]};", "if (p == MAP_FAILED) return;",
                  "munmap(p, len);", release, "}"]
        expected.add(len(lines) - 1)
    lines += [f"void cast_replaced({signature}) {{",
              f"char *p = (char *){origins[api]};", "replace(&p);", "free((void *)p);", "}"]
    for index in range(32):
        lines += [f"void repeated_{index}({signature}) {{"]
        if not declaration:
            lines += ["char *p;"]
        lines += [f"{prefix}p = {origins[api]};", "if (p == MAP_FAILED) return;",
                  "munmap(p, len);", "free(p);", "}"]
        expected.add(len(lines) - 1)
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in results}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(results) == len(expected)
    assert {row["rule"] for row in results} == {"mmap_free"}


@pytest.mark.integration
def test_mapping_release_keeps_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        'void original(int fd) { char *p = mmap(0, 4096, 1, 2, fd, 0); munmap(p, 4096); free(p); }\n'
        'void wide(int fd) { char *p = mmap64(0, 4096, 1, 2, fd, 0); free(p); }\n'
        'void remapped(char *p) { p = mremap(p, 4096, 8192, 1); free(p); }\n'
        'void replaced(int fd) { char *p = mmap(0, 4096, 1, 2, fd, 0); replace(&p); free(p); }\n'
        'void casted(int fd) { char *p = (char *)mmap64(0, 4096, 1, 2, fd, 0); munmap(p, 4096); free((void *)p); }\n'
        'void twice(int fd) { close(fd); close(fd); }\n'
        'int partial(int fd, unsigned long len) { char *p = (char *)mmap64(0, len, 1, 2, fd, 0); if (p == MAP_FAILED) return -1; munmap(p, len / 2); return -22; }\n'
        'int owned(int fd, unsigned long len, void **owner) { void *p = mmap(0, len, 1, 2, fd, 0); if (p == MAP_FAILED) return -1; *owner = p; return 0; }\n'
        'void *wrapped(int fd, unsigned long len) { char *p = (char *)mmap64(0, len, 1, 2, fd, 0); if (p == MAP_FAILED) return 0; return (void *)p; }\n'
        'int branched(int fd, unsigned long len, int cond) { void *p; if (cond) p = mmap(0, len, 1, 2, fd, 0); else p = mmap64(0, len, 1, 2, fd, 0); if (p == MAP_FAILED) return -1; return -22; }\n',
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
        source, [_RULE, _RULE.with_name("double_close.cocci"), _RULE.with_name("mmap_leak_err.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"mmap_free", "double_close", "mmap_leak_err"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["mmap_free"].matches) == 4
    assert len(results["double_close"].matches) == 1
    assert len(results["mmap_leak_err"].matches) == 3
    assert len(invocations) == 1, invocations
