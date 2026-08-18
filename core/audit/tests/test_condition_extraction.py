"""Tests for core.audit.condition_extraction — multi-language guard extraction."""

from __future__ import annotations

import pytest
try:
    import tree_sitter  # noqa: F401
    _HAS_TS = True
except ImportError:
    _HAS_TS = False
pytestmark = pytest.mark.skipif(not _HAS_TS, reason="tree-sitter not installed")

from core.audit.condition_extraction import (  # noqa: E402
    GuardCondition,
    SinkGuard,
    extract_guards_for_files,
    extract_sink_guards,
    language_for_file,
)


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


class TestLanguageForFile:
    def test_python(self):
        assert language_for_file("src/main.py") == "python"

    def test_c(self):
        assert language_for_file("src/auth.c") == "c"
        assert language_for_file("include/auth.h") == "c"

    def test_cpp(self):
        assert language_for_file("src/main.cpp") == "cpp"
        assert language_for_file("src/main.cc") == "cpp"

    def test_go(self):
        assert language_for_file("cmd/server.go") == "go"

    def test_rust(self):
        assert language_for_file("src/main.rs") == "rust"

    def test_java(self):
        assert language_for_file("src/Main.java") == "java"

    def test_javascript(self):
        assert language_for_file("src/app.js") == "javascript"

    def test_typescript(self):
        assert language_for_file("src/app.ts") == "typescript"
        assert language_for_file("src/App.tsx") == "tsx"

    def test_ruby(self):
        assert language_for_file("app/models/user.rb") == "ruby"

    def test_php(self):
        assert language_for_file("src/Controller.php") == "php"

    def test_unknown(self):
        assert language_for_file("Makefile") is None
        assert language_for_file("data.json") is None


# ---------------------------------------------------------------------------
# Python extraction via tree-sitter
# ---------------------------------------------------------------------------


class TestPythonExtraction:
    """Python guard extraction via tree-sitter layer."""

    SINKS = frozenset({"system", "eval", "exec", "open"})

    def test_unconditional_sink(self):
        source = """\
def run_command(cmd):
    os.system(cmd)
"""
        guards = extract_sink_guards(source, "cmd.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert sg.unconditional is True
        assert sg.sink_function == "run_command"
        assert sg.sink_api == "system"
        assert sg.guards == []
        assert sg.priority_score == 1.0

    def test_single_if_guard(self):
        source = """\
def run_command(cmd, user):
    if user.is_admin:
        os.system(cmd)
"""
        guards = extract_sink_guards(source, "cmd.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert sg.unconditional is False
        assert len(sg.guards) == 1
        g = sg.guards[0]
        assert "is_admin" in g.text
        assert g.polarity == "required"
        assert g.category == "auth"

    def test_nested_guards(self):
        source = """\
def run_command(cmd, user, config):
    if user.is_authenticated:
        if config.allow_exec:
            os.system(cmd)
"""
        guards = extract_sink_guards(source, "cmd.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert len(sg.guards) == 2
        categories = {g.category for g in sg.guards}
        assert "auth" in categories
        assert "config" in categories

    def test_early_return_guard(self):
        source = """\
def run_command(cmd, user):
    if not user.is_admin:
        return
    os.system(cmd)
"""
        guards = extract_sink_guards(source, "cmd.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert len(sg.guards) == 1
        g = sg.guards[0]
        assert g.polarity == "excluded"

    def test_else_branch(self):
        source = """\
def process(data, flag):
    if flag:
        safe_process(data)
    else:
        eval(data)
"""
        guards = extract_sink_guards(source, "proc.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert len(sg.guards) == 1
        assert sg.guards[0].polarity == "excluded"

    def test_bounds_guard(self):
        source = """\
def copy_data(buf, src, n):
    if len(src) < MAX_SIZE:
        open(buf)
"""
        guards = extract_sink_guards(source, "buf.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert len(sg.guards) == 1
        assert sg.guards[0].category == "bounds"

    def test_multiple_sinks_same_function(self):
        source = """\
def dangerous(cmd, data):
    os.system(cmd)
    eval(data)
"""
        guards = extract_sink_guards(source, "multi.py", sink_names=self.SINKS)
        assert len(guards) == 2
        apis = {sg.sink_api for sg in guards}
        assert "system" in apis
        assert "eval" in apis

    def test_sink_lines_mode(self):
        source = """\
def process(cmd):
    if check_auth():
        result = os.system(cmd)
    return result
"""
        guards = extract_sink_guards(
            source, "cmd.py", sink_lines=[3],
        )
        assert len(guards) == 1
        sg = guards[0]
        assert sg.sink_line == 3

    def test_no_sinks_found(self):
        source = """\
def safe_function(x):
    return x + 1
"""
        guards = extract_sink_guards(source, "safe.py", sink_names=self.SINKS)
        assert guards == []


# ---------------------------------------------------------------------------
# C extraction via tree-sitter
# ---------------------------------------------------------------------------


class TestCExtraction:
    """C guard extraction via tree-sitter layer."""

    SINKS = frozenset({"system", "execve", "memcpy", "strcpy", "sprintf"})

    def test_unconditional_c_sink(self):
        source = """\
void run(char *cmd) {
    system(cmd);
}
"""
        guards = extract_sink_guards(source, "cmd.c", sink_names=self.SINKS)
        assert len(guards) == 1
        assert guards[0].unconditional is True
        assert guards[0].sink_function == "run"

    def test_null_guard_c(self):
        source = """\
void copy(char *dst, char *src) {
    if (src != NULL) {
        strcpy(dst, src);
    }
}
"""
        guards = extract_sink_guards(source, "str.c", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert len(sg.guards) == 1
        assert sg.guards[0].category == "null"
        assert sg.guards[0].polarity == "required"

    def test_bounds_guard_c(self):
        source = """\
void safe_copy(char *dst, const char *src, size_t n) {
    if (n < sizeof(dst)) {
        memcpy(dst, src, n);
    }
}
"""
        guards = extract_sink_guards(source, "mem.c", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert len(sg.guards) == 1
        assert sg.guards[0].category == "bounds"

    def test_early_return_guard_c(self):
        source = """\
int exec_cmd(const char *cmd, int privileged) {
    if (!privileged)
        return -1;
    return system(cmd);
}
"""
        guards = extract_sink_guards(source, "exec.c", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert len(sg.guards) == 1
        assert sg.guards[0].polarity == "excluded"

    def test_nested_c_guards(self):
        source = """\
void process(request_t *req) {
    if (req->authenticated) {
        if (req->payload_len < MAX_PAYLOAD) {
            memcpy(buffer, req->payload, req->payload_len);
        }
    }
}
"""
        guards = extract_sink_guards(source, "proc.c", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert len(sg.guards) == 2


# ---------------------------------------------------------------------------
# Go extraction via tree-sitter
# ---------------------------------------------------------------------------


class TestGoExtraction:
    """Go guard extraction via tree-sitter layer."""

    SINKS = frozenset({"Command", "exec.Command"})

    def test_go_error_guard(self):
        source = """\
package main

import "os/exec"  # noqa: E402

func runCmd(cmd string, authorized bool) error {
    if !authorized {
        return fmt.Errorf("not authorized")
    }
    exec.Command("sh", "-c", cmd).Run()
    return nil
}
"""
        guards = extract_sink_guards(source, "cmd.go", sink_names=self.SINKS)
        assert len(guards) >= 1
        sg = guards[0]
        assert sg.sink_function == "runCmd"
        assert len(sg.guards) >= 1


# ---------------------------------------------------------------------------
# Classifier integration
# ---------------------------------------------------------------------------


class TestGuardClassification:
    """Verify the classifier is properly wired into extraction."""

    SINKS = frozenset({"system", "eval"})

    def test_auth_classification(self):
        source = """\
def run(cmd, user):
    if user.is_authenticated:
        os.system(cmd)
"""
        guards = extract_sink_guards(source, "a.py", sink_names=self.SINKS)
        assert guards[0].guards[0].category == "auth"

    def test_config_classification(self):
        source = """\
def run(cmd, config):
    if config.debug:
        os.system(cmd)
"""
        guards = extract_sink_guards(source, "a.py", sink_names=self.SINKS)
        assert guards[0].guards[0].category == "config"

    def test_null_classification(self):
        source = """\
def run(cmd, obj):
    if obj is not None:
        os.system(cmd)
"""
        guards = extract_sink_guards(source, "a.py", sink_names=self.SINKS)
        assert guards[0].guards[0].category == "null"


# ---------------------------------------------------------------------------
# Priority scoring
# ---------------------------------------------------------------------------


class TestPriorityScoring:
    def test_unconditional_highest(self):
        sg = SinkGuard(
            sink_file="x.py", sink_line=1,
            sink_function="f", sink_api="eval",
            unconditional=True,
        )
        assert sg.priority_score == 1.0

    def test_auth_guard_reduces_priority(self):
        sg = SinkGuard(
            sink_file="x.py", sink_line=1,
            sink_function="f", sink_api="eval",
            guards=[
                GuardCondition(
                    text="user.is_admin", category="auth",
                    polarity="required", line=5,
                ),
            ],
        )
        assert sg.priority_score < 0.8
        assert sg.has_auth_guard is True

    def test_multiple_guards_lower_priority(self):
        sg = SinkGuard(
            sink_file="x.py", sink_line=1,
            sink_function="f", sink_api="eval",
            guards=[
                GuardCondition(
                    text="user.is_admin", category="auth",
                    polarity="required", line=5,
                ),
                GuardCondition(
                    text="len(data) < limit", category="bounds",
                    polarity="required", line=6,
                ),
            ],
        )
        assert sg.priority_score < 0.5
        assert sg.has_auth_guard is True
        assert sg.has_bounds_guard is True

    def test_priority_never_negative(self):
        sg = SinkGuard(
            sink_file="x.py", sink_line=1,
            sink_function="f", sink_api="eval",
            guards=[
                GuardCondition(text="a", category="auth", polarity="required", line=1),
                GuardCondition(text="b", category="auth", polarity="required", line=2),
                GuardCondition(text="c", category="auth", polarity="required", line=3),
                GuardCondition(text="d", category="config", polarity="required", line=4),
                GuardCondition(text="e", category="bounds", polarity="required", line=5),
            ],
        )
        assert sg.priority_score >= 0.0


# ---------------------------------------------------------------------------
# Batch API
# ---------------------------------------------------------------------------


class TestBatchExtraction:
    SINKS = frozenset({"system", "eval", "exec", "strcpy"})

    def test_multiple_files(self):
        sources = {
            "a.py": "def f(cmd):\n    os.system(cmd)\n",
            "b.c": "void g(char *s) {\n    strcpy(buf, s);\n}\n",
        }
        results = extract_guards_for_files(sources, self.SINKS)
        assert "a.py" in results
        assert "b.c" in results
        assert results["a.py"][0].sink_api == "system"
        assert results["b.c"][0].sink_api == "strcpy"

    def test_skips_unsupported_language(self):
        sources = {
            "Makefile": "all:\n\tgcc main.c\n",
            "a.py": "def f():\n    eval('x')\n",
        }
        results = extract_guards_for_files(sources, self.SINKS)
        assert "Makefile" not in results
        assert "a.py" in results

    def test_empty_input(self):
        results = extract_guards_for_files({}, self.SINKS)
        assert results == {}


# ---------------------------------------------------------------------------
# SinkGuard serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_to_dict(self):
        sg = SinkGuard(
            sink_file="x.py", sink_line=10,
            sink_function="dangerous", sink_api="eval",
            guards=[
                GuardCondition(
                    text="user.is_admin", category="auth",
                    polarity="required", line=8,
                ),
            ],
            unconditional=False,
        )
        d = sg.to_dict()
        assert d["sink_file"] == "x.py"
        assert d["sink_line"] == 10
        assert d["sink_function"] == "dangerous"
        assert d["sink_api"] == "eval"
        assert d["unconditional"] is False
        assert len(d["guards"]) == 1
        assert d["guards"][0]["category"] == "auth"

    def test_to_dict_with_concrete_values(self):
        g = GuardCondition(
            text="MAX_SIZE > n", category="bounds",
            polarity="required", line=5,
            resolvable=True,
            concrete_values={"MAX_SIZE": "1024"},
        )
        d = g.to_dict()
        assert d["resolvable"] is True
        assert d["concrete_values"] == {"MAX_SIZE": "1024"}
