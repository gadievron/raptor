"""Fixture tests for the popen_fclose rule.

Detection-role rule: the popen/pclose ownership contract needs review;
this syntax does not establish a zombie process or a concrete libc leak.
Native controls pin stream identity across writes, receiver changes and
observations, including immediate nested close calls.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "popen_fclose.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_fclose_on_popen_stream_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int run(const char *cmd)
            {
                void *fp = popen(cmd, "r");
                if (!fp)
                    return -1;
                fclose(fp);
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "popen_fclose"
        assert results[0]["line"] == 6


class TestNegatives:
    def test_pclose_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int run(const char *cmd)
            {
                void *fp = popen(cmd, "r");
                if (!fp)
                    return -1;
                pclose(fp);
                return 0;
            }
        """)
        assert results == []


@pytest.mark.parametrize("storage,receiver,replacement", [
    ("fp", "fp", "other"), ("ctx->fp", "ctx", "next_ctx"),
    ("item.fp", "item", "next_item"), ("*slot", "slot", "next_slot"),
    ("streams[0]", "streams", "next_slot"),
    ("streams[index]", "streams", "next_slot"),
], ids=["local", "pointer-field", "value-field", "pointer-slot", "array-slot", "indexed-slot"])
@pytest.mark.parametrize("phase", ["value", "receiver"])
def test_popen_stream_identity_survives_observations(tmp_path, storage, receiver, replacement, phase):
    cases = {
        "value": [
            ("", True), ("if (B) observe();", True), ("fgetc(B);", True),
            ("B = other;", False), ("replace(&B);", False),
            ("B++;", False), ("B += step;", False),
            ("if (optional) B = other;", True),
            ("if (optional) B = other; else B = other;", False),
            ("pclose(B);", False),
        ],
        "receiver": [
            (f"{receiver} = {replacement};", False),
            (f"if (optional) {receiver} = {replacement};", True),
            (f"if (optional) {receiver} = {replacement}; else B = other;", False),
            (f"replace_base(&{receiver});", False),
        ],
    }[phase]
    lines = ["typedef struct stream FILE;", "struct owner { FILE *fp; };"]
    expected = set()
    parameters = "FILE *fp, FILE *other, FILE **slot, FILE **streams, FILE **next_slot, struct owner *ctx, struct owner *next_ctx, struct owner item, struct owner next_item, int optional, int step, int index, char *command"
    for index, (between, reports) in enumerate(cases):
        lines += [f"void case_{index}({parameters}) {{", f'{storage} = popen(command, "r");',
                  between.replace("B", storage), f"fclose({storage});", "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected)
    assert all(row["message"].startswith("Candidate:") for row in rows)


def test_immediate_popen_result_close_is_covered(tmp_path):
    rows = _run_rule(tmp_path, """
        int bad(char *command) { return fclose(popen(command, "r")); }
        int paired(char *command) { return pclose(popen(command, "r")); }
    """)
    assert len(rows) == 1
    assert rows[0]["rule"] == "popen_fclose"


@pytest.mark.integration
def test_stream_rule_pair_keeps_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "stream_pair.c"
    source.write_text(
        "typedef struct stream FILE;\n"
        "struct owner { FILE *fp; };\n"
        'void wrong_close(char *cmd) { FILE *fp = popen(cmd, "r"); fclose(fp); }\n'
        'int nested(char *cmd) { return fclose(popen(cmd, "r")); }\n'
        'void closed(FILE *fp) { char buf[8]; fclose(fp); if (fp) observe(); fflush(fp); fread(buf, 1, 8, fp); }\n'
        'void rebound(struct owner *ctx, struct owner *next) { fclose(ctx->fp); ctx = next; fgetc(ctx->fp); }\n'
        'void mixed(struct owner *ctx, struct owner *next, FILE *other, int flag) { fclose(ctx->fp); if (flag) ctx = next; else ctx->fp = other; fgetc(ctx->fp); }\n'
        'void paired(char *cmd) { FILE *fp = popen(cmd, "r"); pclose(fp); }\n'
        'void twice(FILE *fp) { pclose(fp); fclose(fp); }\n'
        'void indexed(FILE **streams, int index) { fclose(streams[index]); if (index) observe(); fgetc(streams[index]); }\n'
        'void index_changed(FILE **streams, int index) { fclose(streams[index]); index++; fgetc(streams[index]); }\n'
        'void indexed_pipe(FILE **streams, int index, char *command) { streams[index] = popen(command, "r"); fclose(streams[index]); }\n'
        'void pipe_index_changed(FILE **streams, int index, char *command) { streams[index] = popen(command, "r"); index++; fclose(streams[index]); }\n',
        encoding="utf-8",
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
        source, [_RULE, _RULE.with_name("use_after_fclose.cocci"), _RULE.with_name("double_close.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"popen_fclose", "use_after_fclose", "double_close"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["popen_fclose"].matches) == 3
    assert len(results["use_after_fclose"].matches) == 3
    assert len(results["double_close"].matches) == 1
    assert len(invocations) == 1, invocations


def test_index_changes_end_the_popen_slot_relation(tmp_path):
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
        lines += [f"void case_{number}(FILE **streams, FILE *other, int index, int next, int optional, char *command) {{",
                  'streams[index] = popen(command, "r");', between, "fclose(streams[index]);", "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows} == expected
    assert len(rows) == len(expected)
