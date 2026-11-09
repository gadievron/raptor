"""Native descriptor-lifetime candidate contracts; validity needs review."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "double_close.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_close_twice_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void teardown(int fd)
            {
                close(fd);
                close(fd);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "double_close"
        assert results[0]["line"] == 4


class TestNegatives:
    def test_reassigned_fd_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void recycle(int fd, const char *path)
            {
                close(fd);
                fd = open(path, 0);
                close(fd);
            }
        """)
        assert results == []


@pytest.mark.parametrize("first", ["fclose", "pclose"])
@pytest.mark.parametrize("second", ["fclose", "pclose"])
def test_stream_release_pairs_and_lifetime_barriers(tmp_path, first, second):
    lines = ["typedef struct stream FILE;"]
    expected = set()
    cases = (
        ("", "fp", True),
        ('fp = fopen("fresh", "r");', "fp", False),
        ('fp = popen("true", "r");', "fp", False),
        ("fp = other;", "fp", False),
        ("replace(&fp);", "fp", False),
        ("", "other", False),
    )
    for barrier, operand, should_report in cases:
        lines += [f"void case_{len(lines)}(FILE *fp, FILE *other) {{",
                  f"{first}(fp);", barrier, f"{second}({operand});", "}"]
        if should_report:
            expected.add(len(lines) - 1)
    # Similar names are wrappers, not modeled standard-library releases.
    for before, after in ((f"my_{first}", second), (first, f"my_{second}")):
        lines += [f"void wrapper_{len(lines)}(FILE *fp) {{",
                  f"{before}(fp);", f"{after}(fp);", "}"]
    for index in range(120):
        lines += [f"void repeated_{index}(FILE *fp) {{", f"{first}(fp);",
                  f"{second}(fp);", "}"]
        expected.add(len(lines) - 1)
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in results}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(results) == len(expected)
    assert {row["rule"] for row in results} == {"double_fclose"}


@pytest.mark.parametrize("rule_name", ["double_close", "use_after_close"])
@pytest.mark.parametrize("storage,receiver", [
    ("fd", "fd"), ("ctx->fd", "ctx"), ("item.fd", "item"),
    ("*slot", "slot"), ("fds[0]", "fds"), ("fds[index]", "index"),
])
def test_descriptor_storage_and_rebinding(tmp_path, rule_name, storage, receiver):
    cases = [
        ("observe(B);", True), ("if (B >= 0) observe();", True),
        ("B = other;", False), ("B += 1;", False),
        ("replace(&B);", False), ("B++;", False),
        ("dup2(other, B);", False), ("dup3(other, (B), 0);", False),
        ("dup2(B, other);", True), ("dup3(B, other, 0);", True),
        ("dup2(B, B);", True), ("dup3((B), (B), 0);", True),
        ("if (optional) B = other;", True),
        ("if (optional) B = other; else B = other;", False),
        (f"replace_base(&{receiver});", False),
        (f"if (optional) replace_base(&{receiver}); else B = other;", False),
    ]
    lines = ["struct owner { int fd; };"]
    expected = set()
    params = "int fd, int other, int *slot, int *fds, int index, int optional, struct owner *ctx, struct owner item"
    for number, (between, reports) in enumerate(cases):
        lines += [f"void case_{number}({params}) {{", f"close({storage});",
                  between.replace("B", storage)]
        lines.append(f"close({storage});" if rule_name == "double_close"
                     else f"read({storage}, 0, 0);")
        if reports:
            expected.add(len(lines))
        lines.append("}")
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n", _RULE.with_name(f"{rule_name}.cocci"))
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected)
    assert {row["rule"] for row in rows} == {rule_name}
    assert all(row["message"].startswith("Candidate:") for row in rows)


@pytest.mark.parametrize("rule_name", ["double_close", "use_after_close"])
def test_descriptor_expression_limits_and_numeric_handles(tmp_path, rule_name):
    lines = []
    expected = set()
    for number, (value, reports) in enumerate([
        ("-1", False), ("next_fd()", False), ("fds[index + 1]", False),
        ("1", True), ("0x3", True),
    ]):
        lines += [f"void f_{number}(int *fds, int index) {{", f"close({value});"]
        lines.append(f"close({value});" if rule_name == "double_close" else f"read({value}, 0, 0);")
        if reports:
            expected.add(len(lines))
        lines.append("}")
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n", _RULE.with_name(f"{rule_name}.cocci"))
    assert {row["line"] for row in rows} == expected
    assert len(rows) == len(expected)


def test_repeated_releases_report_each_later_call_once(tmp_path):
    lines = ["typedef struct stream FILE;"]
    expected = set()
    for value, release, params in [("fd", "close", "int fd"), ("fp", "fclose", "FILE *fp")]:
        lines += [f"void f_{value}({params}) {{", f"{release}({value});"]
        for _ in range(3):
            lines.append(f"{release}({value});")
            expected.add(len(lines))
        lines.append("}")
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows} == expected
    assert len(rows) == len(expected)


@pytest.mark.integration
def test_descriptor_rules_share_production_invocation(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        "void f(int fd) { close(fd); observe(fd); read(fd, 0, 0); close(fd); }\n"
        "void g(int fd) { close(fd); dup2(fd, fd); read(fd, 0, 0); close(fd); }\n"
        "void h(int fd, int other) { close(fd); dup2(other, fd); read(fd, 0, 0); close(fd); }\n"
        "void i(int fd, int other) { close(fd); dup3(fd, other, 0); read(fd, 0, 0); close(fd); }\n",
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
        source, [_RULE, _RULE.with_name("use_after_close.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"double_close", "use_after_close"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert all(len(result.matches) == 3 for result in results.values())
    assert len(invocations) == 1


@pytest.mark.parametrize("storage,receiver", [
    ("fp", "fp"), ("ctx->fp", "ctx"), ("item.fp", "item"),
    ("*slot", "slot"), ("streams[0]", "streams"), ("streams[index]", "index"),
])
def test_repeated_stream_releases_follow_storage_identity(tmp_path, storage, receiver):
    cases = [
        ("observe(B);", True), ("B = other;", False),
        ("replace(&B);", False), ("B++;", False),
        (f"replace_base(&{receiver});", False),
        (f"if (optional) replace_base(&{receiver});", True),
        (f"if (optional) replace_base(&{receiver}); else B = other;", False),
    ]
    lines = ["typedef struct stream FILE;", "struct owner { FILE *fp; };"]
    expected = set()
    for number, (between, reports) in enumerate(cases):
        lines += [f"void f_{number}(FILE *fp, FILE *other, FILE **slot, FILE **streams, int index, int optional, struct owner *ctx, struct owner item) {{",
                  f"pclose({storage});", between.replace("B", storage), f"fclose({storage});", "}"]
        if reports:
            expected.add(len(lines) - 1)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows} == expected
    assert len(rows) == len(expected)


def test_null_computed_streams_and_merged_origins(tmp_path):
    lines = ["typedef struct stream FILE;",
             "void f(FILE *fp, int branch) {",
             "if (branch) fclose(fp); else pclose(fp);", "fclose(fp);", "}",
             "void g(void) { fclose(NULL); fclose(NULL); }",
             "void h(void) { fclose(select_stream()); fclose(select_stream()); }"]
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert [row["line"] for row in rows] == [lines.index("fclose(fp);") + 1]


@pytest.mark.parametrize("rule_name", ["double_close", "use_after_close"])
def test_parenthesized_self_duplication_is_not_replacement(tmp_path, rule_name):
    lines = []
    expected = set()
    for call in ("dup2", "dup3"):
        for source, destination in (("fd", "fd"), ("(fd)", "fd"), ("fd", "(fd)"), ("(fd)", "(fd)")):
            flags = ", 0" if call == "dup3" else ""
            lines += [f"void f_{len(lines)}(int fd) {{", "close(fd);",
                      f"{call}({source}, {destination}{flags});"]
            lines.append("close(fd);" if rule_name == "double_close" else "read(fd, 0, 0);")
            expected.add(len(lines))
            lines.append("}")
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n", _RULE.with_name(f"{rule_name}.cocci"))
    assert {row["line"] for row in rows} == expected
    assert len(rows) == len(expected)


@pytest.mark.integration
@pytest.mark.parametrize("other_hit", [False, True], ids=["file-empty", "other-function-hit"])
def test_partial_resource_silence_is_inconclusive(tmp_path, other_hit):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    prefix = ''
    source = prefix + 'void partial(int *fds, int index) { close(fds[index + 1]); close(fds[index + 1]); }' + "\n"
    partial_line = 1 + prefix.count("\n")
    if other_hit:
        source += 'void other(int fd) { close(fd); close(fd); }' + "\n"
    (tmp_path / "partial.c").write_text(source)
    result = run_coccinelle_file_sweep(
        target_path=tmp_path, file_path="partial.c", cocci_rule=str(_RULE), language="c",
    )
    assert result.outcome == ("confirmed" if other_hit else "inconclusive"), result.errors
    assert len(result.matches) == int(other_hit)
    if other_hit:
        assert result.matches[0]["rule"] == 'double_close'
    assert result.details["confirm_only"]
    scoped = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="partial",
        line_start=partial_line, line_end=partial_line, language="c",
    )
    assert scoped.outcome == "inconclusive"
    assert scoped.details["confirm_only"]
    assert not scoped.matches
    assert len(result.matches) == int(other_hit)


@pytest.mark.integration
def test_partial_cwe_resource_chain_keeps_silence_uncertain(tmp_path, monkeypatch):
    from core.audit.cwe_dispatch import resolve_cocci_rules_for_cwe
    from core.audit.orchestrator import OrchestratorConfig, _run_tool_chain
    from packages.coccinelle import runner

    source = "void partial(int *fds, int index) { close(fds[index + 1]); close(fds[index + 1]); }\n"
    (tmp_path / "partial.c").write_text(source)
    out = tmp_path / "out"
    out.mkdir()
    config = OrchestratorConfig(
        target_path=tmp_path, out_dir=out,
        inventory={"files": [{"path": "partial.c", "language": "c",
                             "items": [{"name": "partial", "line": 1, "line_end": 1}]}]},
    )
    names = {"double_close", "fdopendir_double_close"}
    rules = [rule for rule in resolve_cocci_rules_for_cwe("CWE-675") if Path(rule).stem in names]
    assert {Path(rule).stem for rule in rules} == names
    chain = [{"type": "coccinelle", "config": {"rule": rule}} for rule in rules]
    original = runner._confined_default_runner
    calls = []

    def observe(*args, **kwargs):
        execute = original(*args, **kwargs)

        def invoke(argv, **options):
            calls.append(tuple(argv))
            return execute(argv, **options)

        return invoke

    monkeypatch.setattr(runner, "_confined_default_runner", observe)
    hypothesis = "a computed descriptor may be released twice"
    for _ in range(2):
        inconclusive, errors, skipped = set(), set(), set()
        result = _run_tool_chain(
            chain, config=config, file_path="partial.c", function_name="partial",
            source=source, hypothesis=hypothesis, cwe="CWE-675", line_start=1,
            inconclusive_types=inconclusive, errored_types=errors, skipped_types=skipped,
        )
        assert result.source_identity is not None
        assert not errors and not skipped
        assert len(result.outcomes) == 2
        assert {Path(probe.rule_id).stem for probe in result.outcomes} == names
        assert result.refutation(file="partial.c", function="partial", line_start=1,
                                 hypothesis=hypothesis) is None, result.outcomes
        assert all(probe.verdict == "inconclusive" for probe in result.outcomes)
        assert inconclusive == {"coccinelle"}
        assert not result
        assert len(calls) == 2, "the second dispatch must reuse both file sweeps"
