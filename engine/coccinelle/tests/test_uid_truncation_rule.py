"""Fixture tests for the uid_truncation detection-role rule.

The negatives pin the provenance regression: the generic 16-bit casts
((unsigned short) / (__u16)) matched EVERY narrowing cast in a
codebase (ports, lengths, counters) because the operand was an
unconstrained expression metavariable. The operand must now carry
UID/GID provenance — a uid_t/gid_t/kuid_t/kgid_t static type or a
direct accessor call — while the __old_*/__kernel_old_* destination
casts provide UID/GID context themselves. Matches require range and ABI
review; legacy type widths vary by target architecture.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "uid_truncation.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_uid_typed_operand_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct legacy { unsigned short uid16; unsigned short gid16; };

            void store_ids(struct legacy *l, uid_t uid, gid_t gid)
            {
                l->uid16 = (unsigned short)uid;
                l->gid16 = (__u16)gid;
            }
        """)
        assert len(results) == 2
        assert all(r["rule"] == "uid_truncation" for r in results)
        assert sorted(r["line"] for r in results) == [5, 6]

    def test_accessor_call_operand_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct legacy { unsigned short uid16; };

            void store_current(struct legacy *l)
            {
                l->uid16 = (unsigned short)getuid();
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 5

    def test_old_kernel_type_cast_fires(self, tmp_path):
        # Casting to the legacy 16-bit uid types is UID context by the
        # destination type alone — no operand constraint needed.
        results = _run_rule(tmp_path, """\
            struct oldcred { __kernel_old_uid_t uid; };

            void store_old(struct oldcred *c, unsigned int wide)
            {
                c->uid = (__kernel_old_uid_t)wide;
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 5


class TestNegatives:
    def test_benign_narrowing_casts_do_not_fire(self, tmp_path):
        # Ports, lengths, counters: narrowing casts with no UID/GID
        # provenance are the overwhelmingly common benign shape.
        results = _run_rule(tmp_path, """\
            struct pkt { unsigned short len16; };

            void store_port(unsigned short *out, int port)
            {
                *out = (unsigned short)port;
            }

            void store_len(struct pkt *p, unsigned long len)
            {
                p->len16 = (unsigned short)len;
            }
        """)
        assert results == []


@pytest.mark.parametrize("destination", [
    "__old_uid_t", "__old_gid_t", "__kernel_old_uid_t", "__kernel_old_gid_t",
    "unsigned short", "__u16",
], ids=["old-uid", "old-gid", "kernel-old-uid", "kernel-old-gid", "short", "u16"])
@pytest.mark.parametrize("context", ["assignment", "declaration", "argument", "return"])
def test_cast_contexts_keep_provenance_and_range_controls(tmp_path, destination, context):
    legacy = destination not in ("unsigned short", "__u16")
    cases = [
        ("uid", True), ("gid", True), ("kuid", True), ("kgid", True),
        ("getuid()", True), ("geteuid()", True),
        ("getgid()", True), ("getegid()", True),
        ("from_kuid(ns, kuid)", True), ("from_kgid(ns, kgid)", True),
        ("__kuid_val(kuid)", True), ("__kgid_val(kgid)", True),
        ("plain", legacy), ("old", destination != "__kernel_old_uid_t"),
        ("narrow", False), ("small", False),
        ("0", False), ("65535U", False), ("0xffffUL", False), ("0177777U", False),
        ("65536UL", legacy), ("0x10000ULL", legacy),
    ]
    lines = []
    expected = set()
    parameters = "uid_t uid, gid_t gid, kuid_t kuid, kgid_t kgid, unsigned int plain, __u16 narrow, unsigned short small, __kernel_old_uid_t old, void *ns"
    for index, (value, reports) in enumerate(cases):
        lines.append(f"{destination if context == 'return' else 'void'} case_{index}({parameters}) {{")
        cast = f"({destination}){value}"
        if context == "assignment":
            lines += [f"{destination} out;", f"out = {cast};"]
        elif context == "declaration":
            lines.append(f"{destination} out = {cast};")
        elif context == "argument":
            lines.append(f"consume({cast});")
        else:
            lines.append(f"return {cast};")
        if reports:
            expected.add(len(lines))
        lines.append("}")
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected)
    assert all(row["rule"] == "uid_truncation" and row["message"].startswith("Candidate:") for row in rows)


@pytest.mark.parametrize("declarations,destination", [
    ("typedef unsigned int __kernel_old_uid_t;", "__kernel_old_uid_t"),
    ("typedef unsigned short __kernel_old_uid_t;", "unsigned short"),
], ids=["generic-old-uid-width", "x86-old-uid-width"])
def test_target_type_identity_is_not_narrowing(tmp_path, declarations, destination):
    rows = _run_rule(tmp_path, f"""
        {declarations}
        {destination} f(__kernel_old_uid_t value) {{
            return ({destination})value;
        }}
    """)
    assert rows == []


@pytest.mark.integration
def test_uid_casts_keep_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "identity.c"
    source.write_text(
        "void assignment(uid_t uid) { unsigned short out; out = (unsigned short)uid; }\n"
        "unsigned short current(void) { return (unsigned short)getuid(); }\n"
        "__kernel_old_uid_t legacy(unsigned int wide) { return (__kernel_old_uid_t)wide; }\n"
        "unsigned short port(unsigned int value) { return (unsigned short)value; }\n"
        "__kernel_old_uid_t constant(void) { return (__kernel_old_uid_t)0xffffUL; }\n"
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
    assert set(results) == {"uid_truncation", "integer_overflow_alloc"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["uid_truncation"].matches) == 3
    assert all(match.rule == "uid_truncation" and match.message.startswith("Candidate:") for match in results["uid_truncation"].matches)
    assert len(results["integer_overflow_alloc"].matches) == 1
    assert len(invocations) == 1, invocations


@pytest.mark.integration
@pytest.mark.parametrize("other_hit", [False, True], ids=["file-empty", "other-function-hit"])
def test_partial_integer_rule_silence_is_inconclusive(tmp_path, other_hit):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    source = ("typedef unsigned int uid_t;\n"
              "unsigned short partial(uid_t uid) { return uid; }\n")
    if other_hit:
        source += "unsigned short other(uid_t uid) { return (unsigned short)uid; }\n"
    (tmp_path / "partial.c").write_text(source)
    result = run_coccinelle_file_sweep(
        target_path=tmp_path, file_path="partial.c", cocci_rule=str(_RULE), language="c",
    )
    assert result.outcome == ("confirmed" if other_hit else "inconclusive"), result.errors
    assert len(result.matches) == int(other_hit)
    assert result.details["confirm_only"]
    scoped = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="partial",
        line_start=2, line_end=2, language="c",
    )
    assert scoped.outcome == "inconclusive"
    assert scoped.details["confirm_only"]
    assert not scoped.matches
