"""Real tempfile factories respect a private cache, including class constructors."""
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import shutil
import tempfile

import pytest

from core.testing.module_views import module_function_view
from core.testing.tempdirs import private_tempfile_module


@pytest.mark.parametrize("borrowed", ["canonical", "shallow", "function-view"])
@pytest.mark.parametrize("factory", ["mkdtemp", "mkstemp", "TemporaryDirectory", "NamedTemporaryFile", "TemporaryFile"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_real_factory_obeys_private_root_and_releases_resources(tmp_path, borrowed, factory, exit_mode):
    original = tempfile
    if borrowed == "shallow":
        from types import ModuleType
        original = ModuleType(tempfile.__name__)
        vars(original).update(vars(tempfile))
    elif borrowed == "function-view":
        original = module_function_view(tempfile)
    before = dict(vars(original))
    standard = dict(vars(tempfile))
    view = private_tempfile_module(original)
    view.tempdir = str(tmp_path)
    descriptor = None
    path = None
    failure = RuntimeError("allocated scope") if exit_mode == "error" else KeyboardInterrupt("allocated scope")
    try:
        with ExitStack() as cleanup:
            if factory == "mkdtemp":
                path = Path(view.mkdtemp(prefix="private-"))
                cleanup.callback(shutil.rmtree, path)
            elif factory == "mkstemp":
                descriptor, name = view.mkstemp(prefix="private-")
                path = Path(name)
                cleanup.callback(path.unlink)
                cleanup.callback(os.close, descriptor)
            else:
                resource = cleanup.enter_context(getattr(view, factory)(prefix="private-"))
                if factory == "TemporaryDirectory":
                    assert isinstance(resource, str)
                    path = Path(resource)
                else:
                    descriptor = resource.fileno()
                    if factory == "NamedTemporaryFile":
                        path = Path(resource.name)
                    resource.write(b"owned")
                    resource.flush()
            if path is not None:
                assert path.parent == tmp_path
                assert path.exists()
            assert all(vars(original)[name] is value for name, value in before.items())
            assert all(vars(tempfile)[name] is value for name, value in standard.items())
            assert view._once_lock is not original._once_lock
            if exit_mode != "normal":
                raise failure
    except BaseException as error:
        assert exit_mode != "normal" and error is failure
    assert not list(tmp_path.iterdir())
    if descriptor is not None:
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == errno.EBADF
    assert vars(original).keys() == before.keys()
    assert all(vars(original)[name] is value for name, value in before.items())
    assert all(vars(tempfile)[name] is value for name, value in standard.items())


@pytest.mark.parametrize("borrowed", [False, True])
def test_directory_preserves_real_type_signature_and_explicit_parent(tmp_path, borrowed):
    original = module_function_view(tempfile) if borrowed else tempfile
    view = private_tempfile_module(original)
    selected = tmp_path / "selected"
    explicit = tmp_path / "explicit"
    selected.mkdir()
    explicit.mkdir()
    view.tempdir = str(selected)
    directory = view.TemporaryDirectory("-suffix", "prefix-", str(explicit), ignore_cleanup_errors=True)
    assert isinstance(directory, tempfile.TemporaryDirectory)
    assert directory.__init__.__code__ is tempfile.TemporaryDirectory.__init__.__code__
    assert Path(directory.name).parent == explicit
    with directory as name:
        assert Path(name).name.startswith("prefix-") and name.endswith("-suffix")
    assert not Path(name).exists()
    assert not list(selected.iterdir())


def test_nested_view_preserves_inherited_overrides(tmp_path):
    inherited = private_tempfile_module()
    inherited.tempdir = str(tmp_path)
    calls = []
    def allocate(*args, **kwargs):
        calls.append((args, kwargs))
        return "inherited-fault"
    inherited.mkdtemp = allocate
    nested = private_tempfile_module(inherited)
    assert nested.mkdtemp is allocate
    assert nested.mkdtemp(prefix="test-") == "inherited-fault"
    assert calls == [((), {"prefix": "test-"})]
    assert nested.tempdir == str(tmp_path)
    assert inherited.mkdtemp is allocate
