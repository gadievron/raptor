"""Tests for core.audit.condition_extraction_python — deep Python AST layer."""

from __future__ import annotations

from core.audit.condition_extraction_python import extract_sink_guards_python


class TestBasicExtraction:
    """Core extraction functionality."""

    SINKS = frozenset({"eval", "exec", "system"})

    def test_unconditional(self):
        source = """\
def run(cmd):
    eval(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert sg.unconditional is True
        assert sg.sink_api == "eval"
        assert sg.sink_function == "run"
        assert sg.sink_line == 2

    def test_guarded_by_if(self):
        source = """\
def run(cmd, user):
    if user.is_admin:
        eval(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert sg.unconditional is False
        assert len(sg.guards) == 1
        g = sg.guards[0]
        assert "is_admin" in g.text
        assert g.category == "auth"
        assert g.polarity == "required"

    def test_nested_ifs(self):
        source = """\
def run(cmd, user, config):
    if user.is_authenticated:
        if config.allow_eval:
            eval(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert len(sg.guards) == 2
        categories = {g.category for g in sg.guards}
        assert "auth" in categories
        assert "config" in categories

    def test_module_level_call(self):
        source = """\
eval("import os")
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        assert guards[0].sink_function == "<module>"
        assert guards[0].unconditional is True


class TestEarlyReturnGuard:
    """Early-return patterns produce 'excluded' polarity."""

    SINKS = frozenset({"eval", "exec", "system"})

    def test_if_not_return(self):
        source = """\
def run(cmd, user):
    if not user.is_admin:
        return
    eval(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert len(sg.guards) == 1
        assert sg.guards[0].polarity == "excluded"

    def test_if_not_raise(self):
        source = """\
def run(cmd, user):
    if not user.is_admin:
        raise PermissionError("denied")
    eval(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert sg.guards[0].polarity == "excluded"

    def test_else_branch(self):
        source = """\
def process(data, safe):
    if safe:
        print("ok")
    else:
        eval(data)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert sg.guards[0].polarity == "excluded"


class TestDecoratorGuards:
    """Decorator-based auth guards detected as conditions."""

    SINKS = frozenset({"eval", "exec", "system"})

    def test_login_required(self):
        source = """\
@login_required
def admin_panel(cmd):
    eval(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        # Should have a decorator guard
        decorator_guards = [g for g in sg.guards if g.text.startswith("@")]
        assert len(decorator_guards) == 1
        assert decorator_guards[0].category == "auth"
        assert decorator_guards[0].polarity == "required"

    def test_permission_required_call(self):
        source = """\
@permission_required('admin')
def danger(cmd):
    exec(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        decorator_guards = [g for g in sg.guards if "@" in g.text]
        assert len(decorator_guards) == 1
        assert decorator_guards[0].category == "auth"

    def test_non_auth_decorator_ignored(self):
        source = """\
@staticmethod
def run(cmd):
    eval(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        # staticmethod is not classified as auth
        auth_guards = [g for g in sg.guards if g.category == "auth"]
        assert len(auth_guards) == 0


class TestConstantResolution:
    """Module-level constants resolved in condition text."""

    SINKS = frozenset({"eval", "exec", "system"})

    def test_resolves_max_size(self):
        source = """\
MAX_SIZE = 1024

def process(data, n):
    if n < MAX_SIZE:
        eval(data)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert len(sg.guards) == 1
        g = sg.guards[0]
        assert g.resolvable is True
        assert g.concrete_values.get("MAX_SIZE") == "1024"

    def test_resolves_bool_const(self):
        source = """\
DEBUG = False

def run(cmd):
    if DEBUG:
        eval(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert len(sg.guards) == 1
        g = sg.guards[0]
        assert g.resolvable is True
        assert g.concrete_values.get("DEBUG") == "False"

    def test_non_constant_not_resolved(self):
        source = """\
dynamic_value = get_config()

def run(cmd):
    if dynamic_value:
        eval(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert len(sg.guards) == 1
        g = sg.guards[0]
        assert g.resolvable is False


class TestContextManagerGuards:
    """with statements detected as resource guards."""

    SINKS = frozenset({"eval", "exec", "system"})

    def test_with_open(self):
        source = """\
def process(path, cmd):
    with open(path) as f:
        eval(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        with_guards = [g for g in sg.guards if g.text.startswith("with ")]
        assert len(with_guards) == 1
        assert with_guards[0].polarity == "required"

    def test_with_lock(self):
        source = """\
import threading

def run(cmd, lock):
    with lock:
        exec(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        with_guards = [g for g in sg.guards if "with " in g.text]
        assert len(with_guards) == 1


class TestDottedSinkMatching:
    """Dotted sink names like os.system, subprocess.call."""

    def test_os_system(self):
        source = """\
import os
def run(cmd):
    os.system(cmd)
"""
        sinks = frozenset({"os.system"})
        guards = extract_sink_guards_python(source, "x.py", sink_names=sinks)
        assert len(guards) == 1
        assert guards[0].sink_api == "os.system"

    def test_subprocess_call(self):
        source = """\
import subprocess
def run(cmd):
    subprocess.call(cmd, shell=True)
"""
        sinks = frozenset({"subprocess.call"})
        guards = extract_sink_guards_python(source, "x.py", sink_names=sinks)
        assert len(guards) == 1
        assert guards[0].sink_api == "subprocess.call"

    def test_partial_match_last_component(self):
        source = """\
def run(cmd):
    exec(cmd)
"""
        sinks = frozenset({"exec"})
        guards = extract_sink_guards_python(source, "x.py", sink_names=sinks)
        assert len(guards) == 1
        assert guards[0].sink_api == "exec"


class TestSinkLinesMode:
    """Specify exact lines instead of names."""

    def test_specific_line(self):
        source = """\
def process(data):
    x = 1
    eval(data)
    y = 2
"""
        guards = extract_sink_guards_python(source, "x.py", sink_lines=[3])
        assert len(guards) == 1
        assert guards[0].sink_line == 3

    def test_multiple_lines(self):
        source = """\
def process(data, cmd):
    eval(data)
    exec(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_lines=[2, 3])
        assert len(guards) == 2

    def test_line_not_a_call(self):
        source = """\
def process(data):
    x = 1
    y = 2
"""
        guards = extract_sink_guards_python(source, "x.py", sink_lines=[2])
        # No call on line 2 — no results
        assert guards == []


class TestAsyncFunctions:
    """Async function definitions handled correctly."""

    SINKS = frozenset({"eval", "exec"})

    def test_async_def(self):
        source = """\
async def handler(cmd, user):
    if user.is_admin:
        eval(cmd)
"""
        guards = extract_sink_guards_python(source, "x.py", sink_names=self.SINKS)
        assert len(guards) == 1
        sg = guards[0]
        assert sg.sink_function == "handler"
        assert len(sg.guards) == 1
        assert sg.guards[0].category == "auth"


class TestSyntaxErrors:
    """Graceful handling of invalid Python."""

    def test_syntax_error_returns_empty(self):
        source = "def broken(\n"
        guards = extract_sink_guards_python(source, "x.py", sink_names=frozenset({"eval"}))
        assert guards == []


class TestDefaultSinks:
    """Using the built-in _PY_SINKS set."""

    def test_default_sinks_detect_eval(self):
        source = """\
def run(x):
    eval(x)
"""
        guards = extract_sink_guards_python(source, "x.py")
        assert len(guards) == 1
        assert guards[0].sink_api == "eval"

    def test_default_sinks_detect_subprocess(self):
        source = """\
import subprocess
def run(cmd):
    subprocess.call(cmd, shell=True)
"""
        guards = extract_sink_guards_python(source, "x.py")
        assert len(guards) == 1
