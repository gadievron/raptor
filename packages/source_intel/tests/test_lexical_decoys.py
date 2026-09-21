"""Comment/string decoys must not steer the lexical axis helpers.

source_intel scans the HOSTILE repo, and five helpers minted or
withheld verdict-relevant facts from RAW file text: a planted comment
could mark a function static (dead-code / privilege back-walk
completeness gate), fabricate an interprocedural NULL check, upgrade
a bounded capability to root-equivalent, fabricate a downstream size
guard, or satisfy the fixed-size-stack-buffer gate — each one a
NOT_EXPLOITABLE (or support-withholding) steer from prose. All five
now read through the shared comment/string-blanked view
(core.audit.source_view idiom); each axis gets a decoy fixture and a
real-code control.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from core.dataflow.finding import Finding, Step
from packages.source_intel.adapter import (
    _downstream_check_suppresses_finding,
    _fortified_dest_is_variable_size,
    _function_is_static,
    _has_interprocedural_check,
    _line_uses_privileged_cap,
    _stack_protector_suppresses_finding,
)


def _write(tmp_path: Path, code: str, name: str = "t.c") -> str:
    f = tmp_path / name
    f.write_text(code)
    return str(f)


def _finding_at(path: str, line: int, rule_id: str,
                snippet: str = "int size = nex * 8;") -> Finding:
    return Finding(
        finding_id="t",
        producer="codeql",
        rule_id=rule_id,
        message="m",
        source=Step(file_path=path, line=line, column=1,
                    snippet=snippet, label="source"),
        sink=Step(file_path=path, line=line, column=1,
                  snippet=snippet, label="sink"),
        intermediate_steps=(),
        raw={},
    )


class TestStaticDecoy:
    def test_comment_static_decl_does_not_mark_static(self, tmp_path):
        # The regex anchors at line start, so the hostile shape is a
        # block-comment line that BEGINS with the static declaration.
        path = _write(tmp_path, (
            "/* removed legacy prototype:\n"
            "static vuln_fn(struct s *p)\n"
            "*/\n"
            "int vuln_fn(struct s *p) { return use(p); }\n"
        ))
        assert _function_is_static(path, "vuln_fn") is False

    def test_string_static_decl_does_not_mark_static(self, tmp_path):
        path = _write(tmp_path, (
            'const char *doc = "static vuln_fn(void)";\n'
            "int vuln_fn(struct s *p) { return use(p); }\n"
        ))
        assert _function_is_static(path, "vuln_fn") is False

    def test_real_static_decl_control(self, tmp_path):
        path = _write(tmp_path, (
            "static int vuln_fn(struct s *p) { return use(p); }\n"
        ))
        assert _function_is_static(path, "vuln_fn") is True


class TestInterproceduralCheckDecoy:
    def test_comment_check_does_not_withhold_support(self, tmp_path):
        path = _write(tmp_path, (
            "int f(void) {\n"
            "    char *p = kstrdup(s, GFP_KERNEL);\n"   # line 2 alloc
            "    // if (p) goto out;\n"                  # line 3 decoy
            "    use(p);\n"                              # line 4 sink
            "}\n"
        ))
        assert _has_interprocedural_check(path, 2, 4, "p") is False

    def test_real_check_control(self, tmp_path):
        path = _write(tmp_path, (
            "int f(void) {\n"
            "    char *p = kstrdup(s, GFP_KERNEL);\n"
            "    if (validate(p) < 0)\n"
            "        return -EINVAL;\n"
            "    use(p);\n"
            "}\n"
        ))
        assert _has_interprocedural_check(path, 2, 5, "p") is True


class TestPrivilegedCapDecoy:
    def test_comment_cap_constant_does_not_upgrade(self, tmp_path):
        path = _write(tmp_path, (
            "int f(int mask) {\n"
            "    if (!capable(mask)) /* CAP_SYS_ADMIN */\n"  # line 2
            "        return -EPERM;\n"
            "}\n"
        ))
        assert _line_uses_privileged_cap(path, 2) is False

    def test_real_cap_constant_control(self, tmp_path):
        path = _write(tmp_path, (
            "int f(void) {\n"
            "    if (!capable(CAP_SYS_ADMIN))\n"             # line 2
            "        return -EPERM;\n"
            "}\n"
        ))
        assert _line_uses_privileged_cap(path, 2) is True


class TestDownstreamCheckDecoy:
    RULE = "cpp/uncontrolled-allocation-size"

    def test_block_comment_guard_does_not_suppress(self, tmp_path):
        path = _write(tmp_path, (
            "int f(int nex) {\n"
            "    int size = nex * 8;\n"        # line 2 sink
            "    /*\n"
            "    if (size < 0)\n"
            "        return -EINVAL;\n"
            "    */\n"
            "    do_alloc(size);\n"
            "    return 0;\n"
            "}\n"
        ))
        assert _downstream_check_suppresses_finding(
            _finding_at(path, 2, self.RULE),
        ) is False

    def test_real_guard_control(self, tmp_path):
        path = _write(tmp_path, (
            "int f(int nex) {\n"
            "    int size = nex * 8;\n"        # line 2 sink
            "    if (size < 0)\n"
            "        return -EINVAL;\n"
            "    do_alloc(size);\n"
            "    return 0;\n"
            "}\n"
        ))
        assert _downstream_check_suppresses_finding(
            _finding_at(path, 2, self.RULE),
        ) is True


class TestStackProtectorDecoy:
    RULE = "cpp/unbounded-write"

    @pytest.fixture(autouse=True)
    def _grant_build_trust(self, monkeypatch):
        # The trust-marker gate is a separate control (pinned in
        # test_build_flags_consumer); grant it so these tests pin the
        # lexical-decoy axis in isolation.
        import packages.source_intel.adapter as adapter
        monkeypatch.setattr(adapter, "_build_flags_trusted",
                            lambda *_a, **_k: True)

    def test_stack_protector_never_suppresses_without_trust(
        self, tmp_path, monkeypatch,
    ):
        import packages.source_intel.adapter as adapter
        monkeypatch.setattr(adapter, "_build_flags_trusted",
                            lambda *_a, **_k: False)
        path = _write(tmp_path, (
            "int f(const char *s) {\n"
            "    char buf[64];\n"
            "    strcpy(buf, s);\n"
            "}\n"
        ))
        assert _stack_protector_suppresses_finding(
            _finding_at(path, 3, self.RULE, snippet="strcpy(buf, s);"),
            self._result(),
        ) is False

    def _result(self):
        return SimpleNamespace(
            build_flags=SimpleNamespace(stack_protector_level="strong"),
        )

    def test_comment_array_decl_does_not_suppress(self, tmp_path):
        path = _write(tmp_path, (
            "int f(const char *s) {\n"
            "    /* char buf[64] legacy */\n"
            "    char *buf = get_buf();\n"
            "    strcpy(buf, s);\n"            # line 4 sink
            "}\n"
        ))
        assert _stack_protector_suppresses_finding(
            _finding_at(path, 4, self.RULE, snippet="strcpy(buf, s);"),
            self._result(),
        ) is False

    def test_real_array_decl_control(self, tmp_path):
        path = _write(tmp_path, (
            "int f(const char *s) {\n"
            "    char buf[64];\n"
            "    strcpy(buf, s);\n"            # line 3 sink
            "}\n"
        ))
        assert _stack_protector_suppresses_finding(
            _finding_at(path, 3, self.RULE, snippet="strcpy(buf, s);"),
            self._result(),
        ) is True


class TestPreprocessorDeadDecoys:
    """Preprocessor-dead text has the same one-planted-line attacker
    capability as a comment: #if 0 regions and backslash-continued //
    comments are prose to the compiler and must not steer the axis
    helpers (blanked by the shared view)."""

    RULE = "cpp/uncontrolled-allocation-size"

    def test_if0_guard_does_not_suppress(self, tmp_path):
        path = _write(tmp_path, (
            "int f(int nex) {\n"
            "    int size = nex * 8;\n"       # line 2 sink
            "#if 0\n"
            "    if (size < 0)\n"
            "        return -EINVAL;\n"
            "#endif\n"
            "    do_alloc(size);\n"
            "    return 0;\n"
            "}\n"
        ))
        assert _downstream_check_suppresses_finding(
            _finding_at(path, 2, self.RULE),
        ) is False

    def test_line_continued_comment_guard_does_not_suppress(
        self, tmp_path,
    ):
        path = _write(tmp_path, (
            "int f(int nex) {\n"
            "    int size = nex * 8;\n"       # line 2 sink
            "    // dead: \\\n"
            "    if (size < 0) return -EINVAL;\n"
            "    do_alloc(size);\n"
            "    return 0;\n"
            "}\n"
        ))
        assert _downstream_check_suppresses_finding(
            _finding_at(path, 2, self.RULE),
        ) is False

    def test_if0_static_decl_does_not_mark_static(self, tmp_path):
        path = _write(tmp_path, (
            "#if 0\n"
            "static vuln_fn(struct s *p)\n"
            "#endif\n"
            "int vuln_fn(struct s *p) { return use(p); }\n"
        ))
        assert _function_is_static(path, "vuln_fn") is False

    def test_if0_else_arm_is_live_control(self, tmp_path):
        # The #else arm of an #if 0 IS compiled — a real guard there
        # must keep suppressing (two-direction bound on the blanking).
        path = _write(tmp_path, (
            "int f(int nex) {\n"
            "    int size = nex * 8;\n"       # line 2 sink
            "#if 0\n"
            "    log(size);\n"
            "#else\n"
            "    if (size < 0)\n"
            "        return -EINVAL;\n"
            "#endif\n"
            "    do_alloc(size);\n"
            "    return 0;\n"
            "}\n"
        ))
        assert _downstream_check_suppresses_finding(
            _finding_at(path, 2, self.RULE),
        ) is True

    def test_paren_zero_guard_does_not_suppress(self, tmp_path):
        # Spelling-swap of the #if 0 decoy: `#if (0)` is dead in
        # every build and must blank identically.
        path = _write(tmp_path, (
            "int f(int nex) {\n"
            "    int size = nex * 8;\n"       # line 2 sink
            "#if (0)\n"
            "    if (size < 0)\n"
            "        return -EINVAL;\n"
            "#endif\n"
            "    do_alloc(size);\n"
            "    return 0;\n"
            "}\n"
        ))
        assert _downstream_check_suppresses_finding(
            _finding_at(path, 2, self.RULE),
        ) is False


class TestFortifiedDestDecoy:
    """_fortified_dest_is_variable_size scans backwards for
    `dest = <allocator>(` — over raw lines a planted comment forged
    True, withholding the fortify NOT_EXPLOITABLE suppression from
    prose (the False direction was never forgeable: a comment cannot
    erase real code)."""

    def test_comment_alloc_does_not_forge_heap_dest(self, tmp_path):
        path = _write(tmp_path, (
            "void f(const char *src) {\n"                  # 1
            "    char buf[64];\n"                           # 2
            "    /* buf = malloc(64) legacy */\n"           # 3 decoy
            "    strcpy(buf, src);\n"                       # 4 sink
            "}\n"
        ))
        finding = _finding_at(path, 4, "cpp/fortified",
                              snippet="strcpy(buf, src);")
        assert _fortified_dest_is_variable_size(finding) is False

    def test_string_alloc_does_not_forge_heap_dest(self, tmp_path):
        path = _write(tmp_path, (
            "void f(const char *src) {\n"
            "    char buf[64];\n"
            '    log("buf = malloc(64)");\n'
            "    strcpy(buf, src);\n"
            "}\n"
        ))
        finding = _finding_at(path, 4, "cpp/fortified",
                              snippet="strcpy(buf, src);")
        assert _fortified_dest_is_variable_size(finding) is False

    def test_real_alloc_control(self, tmp_path):
        path = _write(tmp_path, (
            "void f(const char *src) {\n"
            "    char *buf;\n"
            "    buf = malloc(64);\n"
            "    strcpy(buf, src);\n"
            "}\n"
        ))
        finding = _finding_at(path, 4, "cpp/fortified",
                              snippet="strcpy(buf, src);")
        assert _fortified_dest_is_variable_size(finding) is True
