"""Editor-policy fixtures keep the native runner outside their import view."""

from contextlib import contextmanager, nullcontext
import subprocess

import pytest

from core.project.tests import test_cli
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_editor_fixture_preserves_borrowed_runner(failure, monkeypatch, tmp_path):
    owner = test_cli._os_fault_consumer
    original_main, imported_main = owner.main, test_cli.main
    original_run, original_temp = subprocess.run, owner.temporary_text
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    patch_module_attribute(monkeypatch, owner, "os", "isatty", owner.os.isatty)
    seen = []

    @contextmanager
    def inspect_transport(*args, **kwargs):
        assert owner.main is not original_main
        assert test_cli.main is imported_main
        assert subprocess.run is original_run
        with original_temp(*args, **kwargs) as path:
            seen.append(path)
            if failure:
                raise failure("owned notes setup failure")
            yield path

    monkeypatch.setattr(owner, "temporary_text", inspect_transport)
    if failure is KeyboardInterrupt:
        expected = pytest.raises(SystemExit)
    elif failure:
        expected = pytest.raises(failure, match="owned notes setup failure")
    else:
        expected = nullcontext()
    with expected as caught:
        _, runner = test_cli.TestEditorGuard()._run_notes_edit("vim")
        runner.assert_called_once()
    if failure is KeyboardInterrupt:
        assert caught.value.code == 130
    assert len(seen) == 1
    assert all(not path.exists() for path in seen)
    assert owner.main is original_main
    assert test_cli.main is imported_main
    assert subprocess.run is original_run
