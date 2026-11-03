"""Real nested dependency import inside the shared symbolic sandbox."""
import tempfile

import pytest


pytestmark = [pytest.mark.integration, pytest.mark.slow]


def _nested_probe():
    from core.symbolic._availability import angr_available
    from core.symbolic._types import SymbolicResult
    return SymbolicResult(succeeded=angr_available(), reason='nested dependency probe',
                          wall_seconds=0, metadata={'scratch': tempfile.gettempdir()})


@pytest.mark.usefixtures('require_worker_sandbox')
def test_angr_probe_inherits_private_worker_scratch():
    from core.symbolic._availability import angr_available
    from core.symbolic._isolate import run_isolated
    if not angr_available():
        pytest.skip('Angr required for the real nested import')
    result = run_isolated(__name__, '_nested_probe', {}, timeout=150)
    assert result.succeeded, result.reason
    assert 'raptor-symex-' in result.metadata['scratch']


@pytest.mark.usefixtures('require_worker_sandbox')
def test_shared_worker_delivers_required_tier(tmp_path):
    from core.symbolic import _isolate
    from core.symbolic.tests.test_isolate import _benign_result
    reader, writer = _isolate.mp.Pipe(duplex=False)
    try:
        result = _isolate._run_confined(writer, 'core.symbolic.tests.test_isolate',
                                        '_benign_result', {}, str(tmp_path), 30)
        assert result.returncode == 0, result.stderr
        assert result.sandbox_info['restrict_reads'] is True
        import sys
        assert result.sandbox_info['containment_tier'] == ('mount-ns' if sys.platform == 'linux' else 'seatbelt')
        assert _isolate._loads_result(reader.recv_bytes()) == _benign_result()
    finally:
        reader.close()
        writer.close()


def _read_target(binary_path, sibling):
    from pathlib import Path
    from core.symbolic._types import SymbolicResult
    assert Path(binary_path).read_bytes() == b'owned target'
    try:
        Path(sibling).read_bytes()
    except OSError:
        return SymbolicResult(succeeded=True, reason='sibling read denied', wall_seconds=0)
    return SymbolicResult(succeeded=False, reason='sibling exposed', wall_seconds=0)


@pytest.mark.usefixtures('require_worker_sandbox')
def test_only_selected_binary_is_readable(tmp_path):
    from core.symbolic import _isolate
    target = tmp_path / 'source'
    target.mkdir()
    binary, sibling = target / 'binary', target / 'secret'
    binary.write_bytes(b'owned target')
    sibling.write_bytes(b'owned secret')
    result = _isolate.run_isolated(__name__, '_read_target',
        {'binary_path': binary, 'sibling': str(sibling)}, timeout=30)
    assert result.succeeded, result.reason


def _nested_user_probe():
    import importlib
    from core.symbolic import _availability
    from core.symbolic._types import SymbolicResult
    name = 'raptor_owned_symbolic_dep'
    module = importlib.import_module(name)
    _availability._ALLOWED_PROBE_MODULES |= {name}
    return SymbolicResult(succeeded=(_availability._import_probe_child(name, name)
                                    and module.SCRATCH == tempfile.gettempdir()),
                          reason='explicit user dependency and nested import', wall_seconds=0)


@pytest.mark.usefixtures('require_worker_sandbox')
def test_user_installed_dependency_and_nested_probe_keep_private_scratch(tmp_path, monkeypatch):
    import site
    from core.symbolic import _isolate
    packages = tmp_path / 'user-packages'
    packages.mkdir()
    (packages / 'raptor_owned_symbolic_dep.py').write_text(
        'import tempfile\nSCRATCH = tempfile.gettempdir()\n'
        'with tempfile.NamedTemporaryFile() as stream: stream.write(b"owned cache")\n')
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    monkeypatch.setattr(site, 'getusersitepackages', lambda: str(packages))
    reader, writer = _isolate.mp.Pipe(duplex=False)
    try:
        status = _isolate._run_confined(writer, __name__, '_nested_user_probe', {}, str(scratch), 60)
        assert status.returncode == 0, status.stderr
        result = _isolate._loads_result(reader.recv_bytes())
        assert result.succeeded, result.reason
    finally:
        reader.close()
        writer.close()
