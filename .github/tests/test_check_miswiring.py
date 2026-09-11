"""Tests for .github/scripts/check_miswiring.py — the missing_method
detector and its self_attr_callable suppression."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from check_miswiring import RepoIndex, check_calls


def _index(tmp_path: Path, files: dict[str, str]) -> RepoIndex:
    for name, src in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
    idx = RepoIndex(tmp_path)
    idx.build()
    return idx


def _missing_method_findings(idx: RepoIndex) -> list[dict]:
    findings, _sup = check_calls(idx)
    return [f for f in findings if f["kind"] == "missing_method"]


class TestMissingMethodDetector:
    def test_self_call_to_missing_method_fires(self, tmp_path):
        # The dominant detector shape: a self-call to a method that
        # exists nowhere. The suppression used to search for the
        # substring f"self.{attr}" in the module source — the call
        # site itself contains it, so this could NEVER fire.
        idx = _index(tmp_path, {"foo.py": (
            "class Foo:\n"
            "    def bar(self):\n"
            "        return self.definitely_missing_method()\n"
        )})
        found = _missing_method_findings(idx)
        assert len(found) == 1
        assert found[0]["sym"] == "Foo.definitely_missing_method"

    def test_assigned_instance_attr_suppresses(self, tmp_path):
        # Other direction: an attribute assigned somewhere may hold
        # a callable — no finding.
        idx = _index(tmp_path, {"foo.py": (
            "class Foo:\n"
            "    def __init__(self):\n"
            "        self.handler = print\n"
            "    def bar(self):\n"
            "        return self.handler()\n"
        )})
        assert _missing_method_findings(idx) == []

    def test_attr_assigned_in_other_module_suppresses(self, tmp_path):
        # Instance attributes are routinely attached from factory /
        # setup code in OTHER modules; the assignment scan is
        # repo-wide on purpose.
        idx = _index(tmp_path, {
            "foo.py": (
                "class Foo:\n"
                "    def bar(self):\n"
                "        return self.hook()\n"
            ),
            "wire.py": (
                "def wire(obj):\n"
                "    obj.hook = print\n"
            ),
        })
        assert _missing_method_findings(idx) == []

    def test_setattr_literal_suppresses(self, tmp_path):
        idx = _index(tmp_path, {"foo.py": (
            "class Foo:\n"
            "    def bar(self):\n"
            "        return self.plugin()\n"
            "def install(obj, fn):\n"
            "    setattr(obj, 'plugin', fn)\n"
        )})
        assert _missing_method_findings(idx) == []

    def test_nested_class_attribute_suppresses(self, tmp_path):
        # `class _Session:` in the class body is a class attribute
        # holding a callable — self._Session(self) is valid.
        idx = _index(tmp_path, {"foo.py": (
            "class Foo:\n"
            "    class _Session:\n"
            "        def __init__(self, outer):\n"
            "            self.outer = outer\n"
            "    def bar(self):\n"
            "        return self._Session(self)\n"
        )})
        assert _missing_method_findings(idx) == []

    def test_getattr_hook_suppresses(self, tmp_path):
        idx = _index(tmp_path, {"foo.py": (
            "class Foo:\n"
            "    def __getattr__(self, name):\n"
            "        return print\n"
            "    def bar(self):\n"
            "        return self.anything_at_all()\n"
        )})
        assert _missing_method_findings(idx) == []

    def test_nested_def_with_own_self_not_attributed(self, tmp_path):
        # `def do_post(self)` nested inside a method binds its OWN
        # `self` parameter — its self-calls must not be resolved
        # against the lexically-enclosing class.
        idx = _index(tmp_path, {"foo.py": (
            "class Foo:\n"
            "    def make_handler(self):\n"
            "        def do_post(self):\n"
            "            self.send_response(200)\n"
            "        return do_post\n"
        )})
        assert _missing_method_findings(idx) == []

    def test_method_call_still_resolved(self, tmp_path):
        # Sanity: a self-call to a REAL method neither fires nor
        # needs the suppression.
        idx = _index(tmp_path, {"foo.py": (
            "class Foo:\n"
            "    def helper(self):\n"
            "        return 1\n"
            "    def bar(self):\n"
            "        return self.helper()\n"
        )})
        assert _missing_method_findings(idx) == []
