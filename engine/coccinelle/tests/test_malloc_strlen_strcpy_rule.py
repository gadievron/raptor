"""Native controls for strlen-sized allocation candidates.

Element counts and widths are linked correctly; recognised source/pointer
mutations stop the sizing relationship. Matches still require API and alias
review, and zero matches do not refute arbitrary sizing hypotheses.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "malloc_strlen_strcpy.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_missing_plus_one_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            char *dup_name(const char *name)
            {
                char *copy = malloc(strlen(name));
                strcpy(copy, name);
                return copy;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "malloc_strlen_strcpy"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_strlen_plus_one_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            char *dup_name(const char *name)
            {
                char *copy = malloc(strlen(name) + 1);
                strcpy(copy, name);
                return copy;
            }
        """)
        assert results == []


@pytest.mark.parametrize("declaration", [False, True], ids=["assigned", "declared"])
def test_byte_capacity_allocation_contracts(tmp_path, declaration):
    cases = [
        ("malloc(strlen(src))", True),
        ("calloc(strlen(src), 1)", True),
        ("calloc(1, strlen(src))", True),
        ("calloc(strlen(src), 1U)", True),
        ("calloc(0x01UL, strlen(src))", True),
        ("calloc(strlen(src), (1))", True),
        ("calloc(01, strlen(src))", True),
        ("calloc(strlen(src), sizeof(char))", True),
        ("calloc(sizeof(char), strlen(src))", True),
        ("malloc(strlen(src) + 1)", False),
        ("calloc(strlen(src) + 1, 1)", False),
        ("calloc(1, strlen(src) + 1)", False),
        ("calloc(strlen(src), 2)", False),
        ("calloc(2, strlen(src))", False),
        ("calloc(strlen(src), sizeof(int))", False),
    ]
    lines = []
    expected = set()
    for allocation, candidate in cases:
        lines += [f"void capacity_{len(lines)}(void) {{", '  char src[] = "alpha";']
        if not declaration:
            lines.append("  char *dst;")
        prefix = "char *dst" if declaration else "dst"
        lines.append(f"  {prefix} = {allocation};")
        if candidate:
            expected.add(len(lines))
        lines += ["  if (!dst) return;", "  strcpy(dst, src);", "}"]
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in results} == expected
    assert len(results) == len(expected)
    assert all(row["rule"] == "malloc_strlen_strcpy" for row in results)


@pytest.mark.parametrize("declaration", [False, True], ids=["assigned", "declared"])
def test_mutation_and_escape_break_the_sizing_relationship(tmp_path, declaration):
    changes = [
        'src = other;', 'src += 1;', 'src++;', '++src;',
        'src[0] = 0;', '*src = 0;', 'memset(src, 0, 4);',
        'strcpy(src, "x");', 'replace(&src);',
        'dst = other;', 'dst += 1;', 'dst++;', 'replace(&dst);',
    ]
    lines = []
    for change in changes:
        lines += [f"void changed_{len(lines)}(char *src, char *other) {{"]
        if not declaration:
            lines.append("  char *dst;")
        prefix = "char *dst" if declaration else "dst"
        lines += [f"  {prefix} = malloc(strlen(src));", "  if (!dst) return;", f"  {change}"]
        if not change.startswith("{"):
            lines.append("  strcpy(dst, src);")
        lines.append("}")
    assert _run_rule(tmp_path, "\n".join(lines) + "\n") == []


def test_unrelated_writes_and_surviving_paths_keep_candidates(tmp_path):
    lines = [
        "void f(char *src, int replace) {", "  char *dst = malloc(strlen(src));",
        "  int other = 0;", '  if (replace) src = "x";', "  other++;",
        "  strcpy(dst, src);", "}",
    ]
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in results} == {lines.index("  char *dst = malloc(strlen(src));") + 1}


def test_repeated_strlen_allocations_still_match_independently(tmp_path):
    lines = []
    expected = set()
    for index in range(80):
        lines += [f"void repeated_{index}(char *src) {{", "  char *dst = calloc(1, strlen(src));"]
        expected.add(len(lines))
        lines += ["  if (!dst) return;", "  strcpy(dst, src);", "}"]
    results = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in results} == expected
    assert len(results) == len(expected)


@pytest.mark.parametrize("expression,allocation", [
    ("owner->dst", "malloc(strlen(src))"),
    ("slots[0]", "calloc(1, strlen(src))"),
])
def test_expression_destinations_preserve_candidate_coverage(tmp_path, expression, allocation):
    source = (
        "struct owner { char *dst; };\n"
        "void f(struct owner *owner, char **slots, char *src) {\n"
        f"  {expression} = {allocation};\n"
        f"  strcpy({expression}, src);\n"
        "}\n"
    )
    results = _run_rule(tmp_path, source)
    assert len(results) == 1


class TestDocumentedLimits:
    def test_parenthesized_mutation_is_still_only_a_review_candidate(self, tmp_path):
        source = (
            "void f(char *src) {\n"
            "  char *dst = malloc(strlen(src));\n"
            '  (src) = "x";\n'
            "  strcpy(dst, src);\n"
            "}\n"
        )
        results = _run_rule(tmp_path, source)
        assert len(results) == 1
        assert "Candidate:" in results[0]["message"]


@pytest.mark.integration
def test_sizing_candidates_keep_production_batching(tmp_path, monkeypatch):
    from core.audit.evidence_grade import is_verification_evidence
    from packages.coccinelle import runner

    monkeypatch.setenv("RAPTOR_DIR", str(Path(__file__).resolve().parents[3]))
    source = tmp_path / "batch.c"
    source.write_text(
        "char *copy(char *src) { char *dst = calloc(1, strlen(src)); strcpy(dst, src); return dst; }\n"
        "void sized(int n, char buf[n]) { consume(sizeof(buf)); }\n"
        "void unsized(char buf[]) { consume(sizeof(buf)); }\n"
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
        source, [_RULE, _RULE.with_name("sizeof_array_param.cocci"),
                 _RULE.with_name("free_stack_array.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"malloc_strlen_strcpy", "sizeof_array_param", "free_stack_array"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["malloc_strlen_strcpy"].matches) == 1
    assert {hit.rule for hit in results["sizeof_array_param"].matches} == {
        "sizeof_array_param", "sizeof_array_param_unsized",
    }
    assert len(results["sizeof_array_param"].matches) == 2
    assert len(results["free_stack_array"].matches) == 1
    for owner, result in results.items():
        for hit in result.matches:
            assert is_verification_evidence(f"coccinelle:{hit.rule}") is (owner == "free_stack_array")
    assert len(invocations) == 1, invocations


@pytest.mark.integration
@pytest.mark.parametrize("rule_name", ["malloc_strlen_strcpy", "sizeof_array_param"])
@pytest.mark.parametrize("other_hit", [False, True], ids=["file-empty", "other-function-hit"])
def test_sizing_rule_silence_is_inconclusive(tmp_path, rule_name, other_hit):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    lines = ["void safe(void) { char local[8]; consume(sizeof(local)); }"]
    safe_line = len(lines)
    if other_hit:
        lines.append(
            "void other(char *src) { char *dst = malloc(strlen(src)); strcpy(dst, src); }"
            if rule_name == "malloc_strlen_strcpy" else
            "void other(char buf[32]) { consume(sizeof(buf)); }"
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
        result, target_path=tmp_path, function_name="safe", line_start=safe_line, line_end=safe_line, language="c",
    )
    assert scoped.outcome == "inconclusive"
    assert scoped.details["confirm_only"]
    assert not scoped.matches
