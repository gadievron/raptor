"""Fixture tests for the use_after_fclose rule.

Detection-role rule: a stdio use on a closed stream value is a lifetime
candidate, not independent evidence of a reachable heap exploit. Pin
stable storage, receiver changes, operation argument positions and all
modeled uses after the same close.
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
                fprintf(fp, "done\\n");
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
                fprintf(fp, "fresh\\n");
            }
        """)
        assert results == []


@pytest.mark.parametrize("release", ["fclose", "pclose"])
def test_stream_operations_and_lifetime_barriers(tmp_path, release):
    # Split by FILE* argument position, rather than treating every argument
    # mentioning a closed stream as a use of that stream.
    first = ("fprintf(fp, \"done\")", "fscanf(fp, \"%d\", &value)",
             "fflush(fp)", "fgetc(fp)", "fseek(fp, 0, 0)",
             "ftell(fp)", "rewind(fp)", "getc(fp)",
             'vfprintf(fp, "%d", ap)', 'vfscanf(fp, "%d", ap)')
    last = ("fread(buf, 1, 8, fp)", "fwrite(buf, 1, 8, fp)",
            "fgets(buf, 8, fp)", "fputs(buf, fp)", "fputc(65, fp)", "putc(65, fp)")
    lines = ["typedef struct stream FILE;"]
    expected = set()
    for call in first + last:
        for barrier in ("", "fp = fopen(path, \"r\");", "fp = other;",
                        "touch(&fp);"):
            lines += [f"void case_{len(lines)}(FILE *fp, FILE *other, char *path) {{",
                      "char buf[8]; int value; void *ap;", f"{release}(fp);", barrier,
                      f"{call};", "}"]
            if not barrier:
                expected.add(len(lines) - 1)
        # Closing a different FILE* must not contaminate the live stream.
        lines += [f"void other_{len(lines)}(FILE *fp, FILE *other) {{",
                  "char buf[8]; int value; void *ap;", f"{release}(other);", f"{call};", "}"]
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
        'int d(FILE *p) { pclose(p); return getc(p); }\n'
        'int e(FILE *p) { fclose(p); return putc(65, p); }\n'
        'void c(FILE *p) { pclose(p); p = fopen("x", "r"); fgetc(p); }\n'
        "void f(FILE *p) { pclose(p); fclose(p); }\n",
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
    assert set(results) == {"use_after_fclose", "double_close"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["use_after_fclose"].matches) == 4
    assert len(results["double_close"].matches) == 1
    assert len(invocations) == 1, invocations


@pytest.mark.parametrize("release", ["fclose", "pclose"])
@pytest.mark.parametrize("storage,receiver,replacement", [
    ("fp", "fp", "other"), ("ctx->fp", "ctx", "next_ctx"),
    ("item.fp", "item", "next_item"), ("*slot", "slot", "next_slot"),
    ("streams[0]", "streams", "next_slot"),
    ("streams[index]", "streams", "next_slot"),
], ids=["local", "pointer-field", "value-field", "pointer-slot", "array-slot", "indexed-slot"])
@pytest.mark.parametrize("phase", ["value", "receiver"])
def test_stream_observations_and_receiver_identity(tmp_path, release, storage, receiver, replacement, phase):
    cases = {
        "value": [
            ([], True), (["if (B) observe();"], True), (["observe(B);"], True),
            (["B = other;"], False), (["replace(&B);"], False),
            (["B++;"], False), (["B += step;"], False),
            (["if (optional) B = other;"], True),
            (["if (optional) B = other; else B = other;"], False),
            (["fgetc(B);", "fflush(B);"], True),
        ],
        "receiver": [
            ([f"{receiver} = {replacement};"], False),
            ([f"if (optional) {receiver} = {replacement};"], True),
            ([f"if (optional) {receiver} = {replacement}; else B = other;"], False),
            ([f"replace_base(&{receiver});"], False),
            (["unrelated++;"], True),
        ],
    }[phase]
    lines = ["typedef struct stream FILE;", "struct owner { FILE *fp; int tag; };"]
    expected = set()
    parameters = "FILE *fp, FILE *other, FILE **slot, FILE **streams, FILE **next_slot, struct owner *ctx, struct owner *next_ctx, struct owner item, struct owner next_item, int optional, int step, int unrelated, int index"
    for index, (between, reports) in enumerate(cases):
        lines += [f"void case_{index}({parameters}) {{", "char buf[8];", f"{release}({storage});"]
        for statement in between:
            lines.append(statement.replace("B", storage))
            if statement in ("fgetc(B);", "fflush(B);"):
                expected.add(len(lines))
        lines += [f"fread(buf, 1, 8, {storage});", "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected)
    assert all(row["message"].startswith("Candidate:") for row in rows)


@pytest.mark.parametrize("storage", ["fp", "ctx->fp", "item.fp", "*slot", "streams[0]", "streams[index]"], ids=["local", "pointer-field", "value-field", "pointer-slot", "array-slot", "indexed-slot"])
def test_status_queries_are_closed_stream_uses(tmp_path, storage):
    rows = _run_rule(tmp_path, f"""
        typedef struct stream FILE;
        struct owner {{ FILE *fp; }};
        void f(FILE *fp, struct owner *ctx, struct owner item, FILE **slot, FILE **streams, int index) {{
            fclose({storage});
            feof({storage});
            ferror({storage});
            clearerr({storage});
            fileno({storage});
        }}
    """)
    assert len(rows) == 4
    assert {row["rule"] for row in rows} == {"use_after_fclose"}


def test_calculated_receivers_are_outside_local_identity_tracking(tmp_path):
    rows = _run_rule(tmp_path, """
        void f(void **streams, int index) {
            fclose(streams[index + 1]);
            fgetc(streams[index + 1]);
        }
        void g(void) {
            fclose(select_stream());
            fgetc(select_stream());
        }
        void h(void) { fclose(NULL); fflush(NULL); }
    """)
    assert rows == []


def test_index_changes_end_the_closed_slot_relation(tmp_path):
    cases = [
        ("index = next;", False), ("index++;", False),
        ("index += 1;", False), ("replace(&index);", False),
        ("if (optional) index++;", True),
        ("if (optional) index++; else streams[index] = other;", False),
        ("if (index) observe();", True),
    ]
    lines = ["typedef struct stream FILE;"]
    expected = set()
    for number, (between, reports) in enumerate(cases):
        lines += [f"void case_{number}(FILE **streams, FILE *other, int index, int next, int optional) {{",
                  "fclose(streams[index]);", between, "fgetc(streams[index]);", "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows} == expected
    assert len(rows) == len(expected)
