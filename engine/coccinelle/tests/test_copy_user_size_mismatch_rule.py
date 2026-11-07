"""Fixture tests for the copy_user_size_mismatch rule.

Type spelling and pointer-width sizes are review hints, not target-layout
proofs. Equivalent scalar spellings and actual array-size expressions must
stay quiet; unresolved object layouts retain detection candidates.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "copy_user_size_mismatch.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_mismatched_types_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct big { int a[16]; };
            struct small { int a; };
            int leak(struct big *ud)
            {
                struct small local;
                local.a = 1;
                if (copy_to_user(ud, &local, sizeof(*ud)))
                    return -14;
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "copy_user_size_mismatch"

    def test_sizeof_pointer_from_user_still_fires(self, tmp_path):
        # The copy_from_user leg is independent of the type filter.
        results = _run_rule(tmp_path, """\
            struct foo { int a[8]; };
            int get(struct foo *usrc)
            {
                struct foo local;
                if (copy_from_user(&local, usrc, sizeof(usrc)))
                    return -14;
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "copy_from_user_sizeof_ptr"


class TestNegatives:
    def test_same_type_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct foo { int a; int b; };
            int ok(struct foo *ud)
            {
                struct foo local;
                local.a = 1;
                local.b = 2;
                if (copy_to_user(ud, &local, sizeof(*ud)))
                    return -14;
                return 0;
            }
        """)
        assert results == []


@pytest.mark.parametrize("destination,local", [
    ("int", "unsigned int"), ("unsigned", "signed int"),
    ("short", "unsigned short int"), ("long", "unsigned long int"),
    ("long long", "unsigned long long int"), ("char", "unsigned char"),
    ("const int", "int"), ("int", "volatile int"),
], ids=["int", "implicit-int", "short", "long", "long-long", "char", "const", "volatile"])
def test_equivalent_scalar_size_spellings_stay_quiet(tmp_path, destination, local):
    rows = _run_rule(tmp_path, f"""
        int f({destination} *dst) {{
            {local} value = 0;
            return copy_to_user(dst, &value, sizeof(*dst));
        }}
    """)
    assert rows == []


@pytest.mark.parametrize("source,declarations,reports", [
    ("struct item *src", "struct item local;", True),
    ("char *src", "char *local;", False),
    ("struct item *src", "struct item *local;", False),
    ("char *src", "struct item *local;", True),
    ("char *src", "char local[8];", True),
    ("", "char src[8]; char local[8];", False),
    ("", "struct item src[1]; struct item local;", False),
], ids=["struct", "char-pointer", "struct-pointer", "different-pointer-type", "array-destination", "char-array-source", "struct-array-source"])
def test_from_user_requires_pointer_size_and_nonpointer_destination(tmp_path, source, declarations, reports):
    rows = _run_rule(tmp_path, f"""
        struct item {{ int fields[16]; }};
        int f({source or "void"}) {{
            {declarations}
            return copy_from_user(&local, src, sizeof(src));
        }}
    """)
    assert len(rows) == int(reports)
    if reports:
        assert rows[0]["rule"] == "copy_from_user_sizeof_ptr"
        assert rows[0]["message"].startswith("Candidate:")


@pytest.mark.parametrize("source_type", ["struct short_object", "struct same_extent"], ids=["different-extent", "same-extent"])
def test_different_layout_spellings_are_candidates_not_verified_sizes(tmp_path, source_type):
    rows = _run_rule(tmp_path, f"""
        struct large_object {{ int fields[16]; }};
        struct short_object {{ int field; }};
        struct same_extent {{ int fields[16]; }};
        int f(struct large_object *dst) {{
            {source_type} local;
            return copy_to_user(dst, &local, sizeof(*dst));
        }}
    """)
    assert len(rows) == 1
    assert rows[0]["rule"] == "copy_user_size_mismatch"
    assert rows[0]["message"].startswith("Candidate:")
    assert "review target sizes" in rows[0]["message"]


@pytest.mark.integration
def test_usercopy_candidates_keep_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "usercopy.c"
    source.write_text(
        "struct large { int fields[16]; };\n"
        "struct small { int field; };\n"
        "int output(struct large *dst) { struct small local; "
        "return copy_to_user(dst, &local, sizeof(*dst)); }\n"
        "int input(struct large *src) { struct large local; "
        "return copy_from_user(&local, src, sizeof(src)); }\n"
        "int array(void) { char src[8], local[8]; "
        "return copy_from_user(&local, src, sizeof(src)); }\n"
        "void *allocation(size_t a, size_t b) { return malloc(a * b); }\n",
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
        source, [_RULE, _RULE.with_name("integer_overflow_alloc.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"copy_user_size_mismatch", "integer_overflow_alloc"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert {match.rule for match in results["copy_user_size_mismatch"].matches} == {
        "copy_user_size_mismatch", "copy_from_user_sizeof_ptr",
    }
    assert len(results["copy_user_size_mismatch"].matches) == 2
    assert all(match.message.startswith("Candidate:") for match in results["copy_user_size_mismatch"].matches)
    assert len(results["integer_overflow_alloc"].matches) == 1
    assert len(invocations) == 1, invocations


@pytest.mark.parametrize("parameter", ["char src[8]", "char src[]", "char *src[8]"], ids=["bounded", "unbounded", "pointer-elements"])
@pytest.mark.parametrize("pointer_destination", [False, True], ids=["object", "same-pointer-object"])
def test_array_parameter_size_is_pointer_size(tmp_path, parameter, pointer_destination):
    local = ("char **local;" if "*" in parameter else "char *local;") if pointer_destination else "char local[32];"
    rows = _run_rule(tmp_path, f"""
        int f({parameter}) {{
            {local}
            return copy_from_user(&local, src, sizeof(src));
        }}
    """)
    assert len(rows) == int(not pointer_destination)
    if rows:
        assert rows[0]["rule"] == "copy_from_user_sizeof_ptr"


@pytest.mark.parametrize("initializer", ["", " = {0}", ' = "value"'], ids=["uninitialized", "zero-initialized", "string-initialized"])
def test_local_array_shadow_is_not_parameter_pointer_size(tmp_path, initializer):
    source = """
        int f(char src[8]) {
            char local[32];
            {
                char src[32];
                return copy_from_user(&local, src, sizeof(src));
            }
        }
    """
    rows = _run_rule(tmp_path, source.replace("char src[32];", f"char src[32]{initializer};"))
    assert rows == []
