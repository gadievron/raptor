"""Fixture tests for the double_sizeof rule.

Pins the two implemented patterns (double sizeof in an allocation
size; explicit sizeof in already-scaled pointer arithmetic) and the
correct single-sizeof and known byte-width calculations staying silent.
Repeated factors are candidates because allocation counts and strides can be
intentional.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "double_sizeof.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_double_sizeof_in_alloc_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(int n)
            {
                char *p = malloc(n * sizeof(int) * sizeof(int));
                use(p);
            }
        """)
        assert [r["rule"] for r in results] == ["double_sizeof"]

    def test_pointer_arith_with_explicit_sizeof_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int *bug(int *p, int n)
            {
                return p + n * sizeof(*p);
            }
        """)
        assert [r["rule"] for r in results] == ["pointer_scaling_double"]


class TestNegatives:
    def test_single_sizeof_alloc_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(int n)
            {
                int *p = malloc(n * sizeof(int));
                use(p);
            }
        """)
        assert results == []

    def test_plain_pointer_arith_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int *ok(int *p, int n)
            {
                return p + n;
            }
        """)
        assert results == []


def test_allocator_size_arguments_and_unit_width_controls(tmp_path):
    scale = "n * sizeof(int) * sizeof(int)"
    cases = [
        (f"malloc({scale})", True),
        (f"vmalloc({scale})", True),
        (f"kmalloc({scale}, 0)", True),
        (f"kzalloc({scale}, 0)", True),
        (f"realloc(old, {scale})", True),
        (f"krealloc(old, {scale}, 0)", True),
        (f"calloc({scale}, 1)", True),
        (f"calloc(1, {scale})", True),
        ("calloc(n * sizeof(int), sizeof(int))", True),
        (f"realloc((void *)({scale}), n)", False),
        (f"krealloc((void *)({scale}), n, 0)", False),
        ("malloc(n * sizeof(char) * sizeof(char))", False),
        ("calloc(n * sizeof(unsigned char), sizeof(unsigned char))", False),
        ("malloc(n * sizeof(int))", False),
        ("realloc(old, n * sizeof(int))", False),
        ("calloc(n, sizeof(int))", False),
    ]
    lines = []
    expected = set()
    for call, candidate in cases:
        lines += [f"void *allocation_{len(lines)}(void *old, unsigned long n) {{", f"  return {call};"]
        if candidate:
            expected.add(len(lines))
        lines.append("}")
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows if row["rule"] == "double_sizeof"} == expected
    assert len(rows) == len(expected)


def test_byte_pointer_scaling_is_not_double_scaling(tmp_path):
    lines = []
    for kind in ("char", "unsigned char", "signed char", "const char", "volatile unsigned char"):
        for operation in ("p + n * sizeof(*p)", "p - n * sizeof(p[0])"):
            lines += [f"{kind} *bytes_{len(lines)}({kind} *p, unsigned long n) {{", f"  return {operation};", "}"]
    assert _run_rule(tmp_path, "\n".join(lines) + "\n") == []


@pytest.mark.integration
def test_scaling_candidates_keep_production_batching(tmp_path, monkeypatch):
    from core.audit.evidence_grade import is_verification_evidence
    from packages.coccinelle import runner

    monkeypatch.setenv("RAPTOR_DIR", str(Path(__file__).resolve().parents[3]))
    source = tmp_path / "batch.c"
    source.write_text(
        "struct inner { int x; }; struct outer { long prefix; struct inner node; };\n"
        "void *alloc(unsigned long n) { return realloc(0, n * sizeof(int) * sizeof(int)); }\n"
        "int *stride(int *p, int n) { return p + n * sizeof(*p); }\n"
        "void container(void) { struct inner *p = kmalloc(sizeof(*p), 0); "
        "consume(container_of(p, struct outer, node)); }\n"
        "void invalid_free(void) { char local[8]; free(local); }\n",
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
        source, [_RULE, _RULE.with_name("sizeof_container_of.cocci"),
                 _RULE.with_name("free_stack_array.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"double_sizeof", "sizeof_container_of", "free_stack_array"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert {hit.rule for hit in results["double_sizeof"].matches} == {
        "double_sizeof", "pointer_scaling_double",
    }
    assert len(results["double_sizeof"].matches) == 2
    assert len(results["sizeof_container_of"].matches) == 1
    assert len(results["free_stack_array"].matches) == 1
    for owner, result in results.items():
        for hit in result.matches:
            assert is_verification_evidence(f"coccinelle:{hit.rule}") is (owner == "free_stack_array")
    assert len(invocations) == 1, invocations


@pytest.mark.integration
@pytest.mark.parametrize("rule_name", ["double_sizeof", "sizeof_container_of"])
@pytest.mark.parametrize("other_hit", [False, True], ids=["file-empty", "other-function-hit"])
def test_scaling_rule_silence_is_inconclusive(tmp_path, rule_name, other_hit):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    lines = ["void safe(void) { char local[8]; consume(sizeof(local)); }"]
    safe_line = len(lines)
    if other_hit:
        lines.append(
            "void *other(int n) { return malloc(n * sizeof(int) * sizeof(int)); }"
            if rule_name == "double_sizeof" else
            "struct inner { int x; }; struct outer { long prefix; struct inner node; }; "
            "void other(void) { struct inner *p = kmalloc(sizeof(*p), 0); "
            "consume(container_of(p, struct outer, node)); }"
        )
    (tmp_path / "safe.c").write_text("\n".join(lines) + "\n")
    result = run_coccinelle_file_sweep(
        target_path=tmp_path, file_path="safe.c",
        cocci_rule=str(_RULE.with_name(f"{rule_name}.cocci")), language="c",
    )
    assert result.outcome == ("confirmed" if other_hit else "inconclusive"), result.errors
    assert len(result.matches) == int(other_hit)
    assert result.details["confirm_only"]
    scoped = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="safe", line_start=safe_line,
        line_end=safe_line, language="c",
    )
    assert scoped.outcome == "inconclusive"
    assert scoped.details["confirm_only"]
    assert not scoped.matches


def test_pointer_sizeof_expression_forms(tmp_path):
    import json

    from core.audit.tests._live_transport import run_pinned_subprocess
    from core.config import RaptorConfig

    lines = []
    for op in ("+", "-"):
        for width in ("sizeof(*p)", "sizeof(p[0])", "sizeof *p", "sizeof p[0]"):
            lines.append(f"int *candidate{len(lines)}(int *p, int n) {{ return p {op} n * {width}; }}")
    expected = {(line, "pointer_scaling_double") for line in range(1, len(lines) + 1)}
    for byte_type in ("char", "signed char", "unsigned char", "const char", "volatile unsigned char"):
        for op in ("+", "-"):
            for width in ("sizeof *p", "sizeof p[0]"):
                lines.append(
                    f"{byte_type} *unit{len(lines)}({byte_type} *p, int n) "
                    f"{{ return p {op} n * {width}; }}"
                )
    lines.append("int *plain(int *p, int n) { return p + n; }")
    source = tmp_path / "strides.c"
    source.write_text("\n".join(lines) + "\n")
    result = run_pinned_subprocess(
        ["spatch", "--sp-file", str(_RULE), str(source), "--no-show-diff"],
        timeout=45, context="Owned pointer sizeof expression forms",
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert result.returncode == 0, result.stderr
    rows = [
        json.loads(line.removeprefix("COCCIRESULT:"))
        for stream in (result.stdout, result.stderr)
        for line in stream.splitlines() if line.startswith("COCCIRESULT:")
    ]
    assert {(int(row["line"]), row["rule"]) for row in rows} == expected
    assert len(rows) == len(expected)
