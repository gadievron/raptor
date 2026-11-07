"""Generated audit scratch must not survive failed preparation."""

from pathlib import Path
import pytest
from core.audit import orchestrator, hypothesis_mapping, sweep
import tempfile


from core.testing.module_bindings import patch_module_attribute

import core.run.scratch as _storage_fault_consumer


@pytest.mark.parametrize("error", [OSError("disk full"), KeyboardInterrupt()])
def test_decompilation_write_failure_removes_directory(tmp_path, monkeypatch, error):
    allocated = tmp_path / "decomp"
    allocated.mkdir()
    patch_module_attribute(monkeypatch, orchestrator, 'tempfile', "mkdtemp", lambda **kw: str(allocated))

    def fail(*args, **kw):
        raise error

    monkeypatch.setattr(Path, "write_text", fail)
    if isinstance(error, OSError):
        assert orchestrator._write_decompilation_tmpfile("int f() {}", "f") is None
    else:
        with pytest.raises(type(error)):
            orchestrator._write_decompilation_tmpfile("int f() {}", "f")
    assert not allocated.exists()


@pytest.mark.parametrize("kind", ["pattern", "hypothesis", "relanguage"])
@pytest.mark.parametrize("error", [OSError("disk full"), KeyboardInterrupt()])
def test_rule_write_failure_removes_partial_file(tmp_path, monkeypatch, kind, error):
    original = tempfile.NamedTemporaryFile
    allocated = []

    class Broken:
        def __init__(self, *args, **kw):
            kw["dir"] = tmp_path
            self.file = original(*args, **kw)
            self.name = self.file.name
            allocated.append(Path(self.name))

        def __enter__(self):
            return self

        def write(self, text):
            self.file.write(text[:2])
            raise error

        def __exit__(self, *exc):
            self.file.close()

    rule = tmp_path / "input.txt"
    rule.write_text("languages: [c]")
    patch_module_attribute(monkeypatch, _storage_fault_consumer, 'tempfile', 'NamedTemporaryFile', Broken)

    def generate():
        if kind == "pattern":
            return orchestrator._pattern_rule_file("malloc(...)", "test.c")
        if kind == "hypothesis":
            return hypothesis_mapping.hypothesis_to_semgrep_rule_keyed(
                "buffer overflow", "test.c"
            )
        return sweep._relanguage_rule_config(str(rule), "c", "python")

    if kind == "relanguage" or not isinstance(error, OSError):
        with pytest.raises(type(error)):
            generate()
    else:
        assert generate() is None
    assert allocated and all(not path.exists() for path in allocated)
