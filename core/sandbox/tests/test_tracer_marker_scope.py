"""Review tracer marker scope without importing or collecting tracer tests."""

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest


_HERE = Path(__file__).parent
_NATIVE = {
    "test_tracer.py::TestSeizeAndDetachLifecycle." + name for name in (
        "test_seize_interrupt_detach_against_sleeping_child",
        "test_seize_nonexistent_pid_returns_false", "test_trace_returns_3_on_seize_failure",
    )
} | {
    "test_tracer.py::TestPathDereference." + name for name in (
        "test_reads_self_string", "test_reads_path_like_string",
        "test_reads_long_string_truncates_at_max", "test_handles_non_utf8_bytes",
    )
}
_PURE = {
    "test_tracer.py::TestLibcCacheSentinel.test_failure_sentinel_is_distinct_from_unprobed",
    "test_tracer.py::TestPathDereference.test_null_pointer_returns_none",
    "test_tracer_event_loop.py::TestExitedTracees.test_exited_tracee_removed_from_traced",
}


class _Mark:
    def __init__(self, name, args=(), kwargs=None):
        self.name, self.args, self.kwargs = name, args, kwargs or {}

    def __call__(self, *args, **kwargs):
        return _Mark(self.name, args, kwargs)


class _Marks:
    def __getattr__(self, name):
        return _Mark(name)


class _Item:
    def __init__(self, name, marks):
        self.name, self.marks = name, list(marks)

    def get_closest_marker(self, name):
        return next((mark for mark in self.marks if mark.name == name), None)

    def add_marker(self, mark):
        self.marks.append(mark)

    def skipped(self):
        return any(mark.name == "skip" or (mark.name == "skipif" and mark.args[0])
                   for mark in self.marks)


def _evaluate(expression, namespace):
    # Only marker metadata is evaluated: no test body or import statement.
    return eval(compile(ast.Expression(expression), "<owned-marker>", "eval"), namespace)


def _items(platform, supported):
    items = []
    for filename in ("test_tracer.py", "test_tracer_event_loop.py"):
        tree = ast.parse((_HERE / filename).read_text())
        namespace = {"__builtins__": {}, "pytest": SimpleNamespace(mark=_Marks()),
                     "sys": SimpleNamespace(platform=platform),
                     "platform": SimpleNamespace(machine=lambda: "owned-architecture"),
                     "tracer": SimpleNamespace(_is_supported_arch=lambda: supported)}
        module_marks = []
        for node in tree.body:
            if isinstance(node, ast.Assign):
                names = [target.id for target in node.targets if isinstance(target, ast.Name)]
                if "pytestmark" in names:
                    module_marks = [_evaluate(node.value, namespace)]
                if "_requires_linux_tracer" in names:
                    namespace["_requires_linux_tracer"] = _evaluate(node.value, namespace)
            if not isinstance(node, ast.ClassDef):
                continue
            class_marks = [_evaluate(mark, namespace) for mark in node.decorator_list]
            for function in node.body:
                if not isinstance(function, ast.FunctionDef):
                    continue
                name = filename + "::" + node.name + "." + function.name
                if name not in _NATIVE | _PURE:
                    continue
                marks = [_evaluate(mark, namespace) for mark in function.decorator_list]
                items.append(_Item(name, module_marks + class_marks + marks))
    return items


def test_marker_inventory_and_architecture_contract():
    for filename in ("test_tracer.py", "test_tracer_event_loop.py"):
        tree = ast.parse((_HERE / filename).read_text())
        assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "pytestmark"
                               for target in node.targets)]
        assert len(assignments) == 1
        predicate = assignments[0].value.args[0]
        assert ast.dump(predicate) == ast.dump(ast.parse("not tracer._is_supported_arch()", mode="eval").body)
    items = _items("linux", True)
    all_native = set()
    for filename in ("test_tracer.py", "test_tracer_event_loop.py"):
        tree = ast.parse((_HERE / filename).read_text())
        for cls in (node for node in tree.body if isinstance(node, ast.ClassDef)):
            inherited = any(ast.unparse(mark) == "pytest.mark.linux_native" for mark in cls.decorator_list)
            for function in (node for node in cls.body if isinstance(node, ast.FunctionDef)):
                native = inherited or any(ast.unparse(mark) == "pytest.mark.linux_native"
                                          for mark in function.decorator_list)
                if native and function.name.startswith("test_"):
                    all_native.add(filename + "::" + cls.name + "." + function.name)
    assert all_native == _NATIVE
    assert {item.name for item in items if item.get_closest_marker("linux_native")} == _NATIVE
    assert {item.name for item in items} == _NATIVE | _PURE
    sleeper = next(item for item in items if item.name.endswith("against_sleeping_child"))
    assert sleeper.get_closest_marker("slow") is not None


def _apply_native_policy(items, real_platform, emulated):
    tree = ast.parse((_HERE.parents[2] / "conftest.py").read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "pytest_collection_modifyitems")
    branch = next(node for node in function.body if isinstance(node, ast.If)
                  and ast.unparse(node.test) == "_EMULATED_PLATFORM is not None")
    marker_map = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "_NATIVE_MARKERS"
                              for target in node.targets))
    deselected = []
    namespace = {"__builtins__": {"any": any, "sorted": sorted}, "items": items,
                 "_EMULATED_PLATFORM": emulated, "_REAL_PLATFORM": real_platform,
                 "_NATIVE_MARKERS": ast.literal_eval(marker_map),
                 "pytest": SimpleNamespace(mark=_Marks()),
                 "config": SimpleNamespace(hook=SimpleNamespace(
                     pytest_deselected=lambda **kwargs: deselected.extend(kwargs["items"])))}
    # Execute only the existing native-marker branch against owned fake items.
    exec(compile(ast.Module(body=[branch], type_ignores=[]), "<owned-native-policy>", "exec"), namespace)
    return namespace["items"], deselected


@pytest.mark.parametrize("platform,real_platform,emulated", [
    ("linux", "linux", None), ("darwin", "darwin", None), ("darwin", "linux", "darwin"),
])
@pytest.mark.parametrize("supported", [True, False])
def test_owned_items_preserve_platform_and_emulation_boundary(platform, real_platform, emulated, supported):
    items, deselected = _apply_native_policy(_items(platform, supported), real_platform, emulated)
    eligible = {item.name for item in items if not item.skipped()}
    assert eligible & _PURE == (_PURE if supported else set())
    assert eligible & _NATIVE == (_NATIVE if supported and platform == "linux" else set())
    assert {item.name for item in deselected} == (_NATIVE if emulated else set())
