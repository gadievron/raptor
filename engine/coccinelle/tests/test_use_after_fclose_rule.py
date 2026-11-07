"""Fixture tests for the use_after_fclose rule.

Verification-role rule (fires mint confirmed CWE-416 verdicts):
stdio operations on a FILE* after fclose() or pclose() are use-after-free. The
positive pins fprintf on the closed stream; the negative pins the
documented escape — the pointer reassigned (fopen) before reuse.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "use_after_fclose.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_fprintf_after_fclose_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void log_and_close(void *fp)
            {
                fclose(fp);
                fprintf(fp, "done\n");
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "use_after_fclose"
        assert results[0]["line"] == 4


class TestNegatives:
    def test_reassigned_stream_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void reopen(void *fp, const char *path)
            {
                fclose(fp);
                fp = fopen(path, "w");
                fprintf(fp, "fresh\n");
            }
        """)
        assert results == []


@pytest.mark.parametrize("release", ["fclose", "pclose"])
def test_stream_operations_and_lifetime_barriers(tmp_path, release):
    # Split by FILE* argument position, rather than treating every argument
    # mentioning a closed stream as a use of that stream.
    first = ("fprintf(fp, \"done\")", "fscanf(fp, \"%d\", &value)",
             "fflush(fp)", "fgetc(fp)", "fseek(fp, 0, 0)",
             "ftell(fp)", "rewind(fp)")
    last = ("fread(buf, 1, 8, fp)", "fwrite(buf, 1, 8, fp)",
            "fgets(buf, 8, fp)", "fputs(buf, fp)", "fputc(65, fp)")
    lines = ["typedef struct stream FILE;"]
    expected = set()
    for call in first + last:
        for barrier in ("", "fp = fopen(path, \"r\");", "fp = other;",
                        "touch(&fp);"):
            lines += [f"void case_{len(lines)}(FILE *fp, FILE *other, char *path) {{",
                      "char buf[8]; int value;", f"{release}(fp);", barrier,
                      f"{call};", "}"]
            if not barrier:
                expected.add(len(lines) - 1)
        # Closing a different FILE* must not contaminate the live stream.
        lines += [f"void other_{len(lines)}(FILE *fp, FILE *other) {{",
                  "char buf[8]; int value;", f"{release}(other);", f"{call};", "}"]
    for index in range(120):
        lines += [f"void repeated_{index}(FILE *fp) {{", f"{release}(fp);",
                  'fprintf(fp, "done");', "}"]
        expected.add(len(lines) - 1)
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in results}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(results) == len(expected)
    assert {row["rule"] for row in results} == {"use_after_fclose"}


@pytest.mark.integration
def test_closed_stream_rule_keeps_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        "typedef struct stream FILE;\n"
        'void a(FILE *p) { fclose(p); fprintf(p, "bad"); }\n'
        'void b(FILE *p) { pclose(p); fseek(p, 0, 0); }\n'
        'void c(FILE *p) { pclose(p); p = fopen("x", "r"); fgetc(p); }\n'
        "void free(void *);\n"
        "void invalid_stack_free(void) { char a[8]; free(a); }\n",
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
        source, [_RULE, _RULE.with_name("free_stack_array.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"use_after_fclose", "free_stack_array"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["use_after_fclose"].matches) == 2
    assert len(results["free_stack_array"].matches) == 1
    assert len(invocations) == 1, invocations
