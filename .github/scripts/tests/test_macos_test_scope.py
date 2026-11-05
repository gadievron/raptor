"""Linux scope computation must skip only provably unused macOS test work."""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'macos_test_scope.py'


@pytest.fixture(scope='module')
def scope():
    spec = importlib.util.spec_from_file_location('macos_scope', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _module(tmp_path, text):
    path = tmp_path / 'test_platform.py'
    path.write_text(text)
    return path


@pytest.mark.parametrize('condition,skipped', [
    ('sys.platform != "linux"', True),
    ('sys.platform == "linux"', False),
    ('sys.platform != "darwin"', False),
    ('not sys.platform.startswith("linux")', True),
    ('not sys.platform.startswith(("linux", "darwin"))', False),
    ('sys.platform != "linux" or host_probe()', True),
    ('sys.platform != "linux" and host_probe()', False),
    ('sys.platform == "linux" or host_probe()', False),
    ('host_probe()', False),
    ('host_probe() or sys.platform != "linux"', False),
    ('True', True),
    ('False', False),
], ids=['linux-only', 'mac-only', 'darwin-only', 'linux-prefix', 'posix-prefixes',
        'or-unknown', 'and-unknown', 'unknown-or', 'unknown-probe', 'probe-before-platform', 'always', 'never'])
def test_conditions_are_proved_without_executing_tests(scope, tmp_path, condition, skipped):
    path = _module(tmp_path, f'import sys, pytest\npytestmark = pytest.mark.skipif({condition}, reason="owned")\n')
    assert scope.skipped_on_macos(path) is skipped


@pytest.mark.parametrize('text', [
    'import sys as _sys, pytest as _pytest\npytestmark = _pytest.mark.skipif(_sys.platform != "linux", reason="owned")',
    'from sys import platform as host\nimport pytest\npytestmark = pytest.mark.skipif(host != "linux", reason="owned")',
    'import sys, pytest\nlinux = pytest.mark.skipif(sys.platform != "linux", reason="owned")\npytestmark = [linux]',
    'import sys, pytest\npytestmark = pytest.mark.skipif(sys.platform != "linux", reason="owned")\npytestmark = [pytestmark, other_mark]',
], ids=['module-aliases', 'platform-import', 'marker-alias', 'marker-list'])
def test_aliases_and_marker_lists(scope, tmp_path, text):
    assert scope.skipped_on_macos(_module(tmp_path, text))


@pytest.mark.parametrize('suffix', [
    'pytestmark = []',
    'if unknown:\n    pytestmark = []',
    'pytestmark.clear()',
    'adjust(pytestmark)',
    'def adjust(mark=pytestmark):\n    mark.clear()\nadjust()',
    'pytestmark[0] = other',
    'alias = pytestmark\nalias.clear()',
    'del pytestmark',
    'globals()["pytestmark"] = []',
    'sys.platform = "linux"',
    'sys = other',
    'pytest.mark = other',
    'setattr(pytest, "mark", other)',
    'import other as sys',
    'from other import sys',
    'from other import *',
    'def sys():\n    pass',
    'if unknown:\n    import other as sys',
], ids=['replace-marker', 'conditional-marker', 'clear-marker', 'unknown-consumer', 'default-argument', 'element-write', 'marker-alias', 'delete-marker', 'dynamic-globals', 'platform-write', 'module-rebinding', 'factory-write', 'dynamic-setattr', 'import-rebinding', 'from-rebinding', 'star-import', 'function-rebinding', 'conditional-import'])
def test_reassignment_or_unknown_mutation_keeps_real_runner(scope, tmp_path, suffix):
    path = _module(tmp_path, 'import sys, pytest\npytestmark = pytest.mark.skipif(sys.platform != "linux", reason="owned")\n' + suffix)
    assert not scope.skipped_on_macos(path)


@pytest.mark.parametrize('text', [
    'import pytest\n@pytest.mark.skipif(True, reason="owned")\ndef test_one(): pass',
    'pytestmark = custom_mark()',
    'pytestmark =',
], ids=['individual-mark', 'computed-marker', 'invalid-source'])
def test_unknown_or_per_test_marks_cannot_skip_a_whole_file(scope, tmp_path, text):
    assert not scope.skipped_on_macos(_module(tmp_path, text))


def test_selection_omits_linux_files_and_keeps_shared_mac_and_unknown(scope, tmp_path):
    linux = _module(tmp_path, 'import sys, pytest\npytestmark = pytest.mark.skipif(sys.platform != "linux", reason="owned")')
    shared = tmp_path / 'shared.py'
    shared.write_text('def test_shared(): pass')
    audit = tmp_path / scope.AUDIT_FILE
    audit.parent.mkdir(parents=True)
    audit.write_text('def test_native(): pass')
    assert scope.selection(tmp_path, [linux.name]) == {'run': False, 'files': [], 'native_audit': False}
    result = scope.selection(tmp_path, [linux.name, shared.name, str(scope.AUDIT_FILE), 'unknown.py'])
    assert result == {'run': True, 'files': sorted([shared.name, str(scope.AUDIT_FILE), 'unknown.py']), 'native_audit': True}
    assert scope.selection(tmp_path, [shared.name])['native_audit'] is False
    assert scope.selection(tmp_path, ['core/sandbox/tests'])['native_audit'] is True


def test_empty_selection_and_cli_outputs(scope, tmp_path, monkeypatch):
    assert scope.selection(tmp_path, []) == {'run': False, 'files': [], 'native_audit': False}
    path = _module(tmp_path, 'import sys, pytest\npytestmark = pytest.mark.skipif(sys.platform != "linux", reason="owned")')
    output = tmp_path / 'outputs'
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('SANDBOX_FILES', path.name)
    monkeypatch.setenv('SCOPE_MODE', 'scoped')
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    scope.main()
    assert output.read_text() == 'run=false\nfiles=\nnative_audit=false\n'


@pytest.mark.parametrize('mutation', ['linux.clear()', 'linux[0] = other', 'alias = linux\nalias.clear()'],
                         ids=['method-call', 'element-write', 'escaped-alias'])
def test_mutated_marker_aliases_keep_runner(scope, tmp_path, mutation):
    text = ('import sys, pytest\n'
            'linux = [pytest.mark.skipif(sys.platform != "linux", reason="owned")]\n'
            'pytestmark = linux\n' + mutation)
    assert not scope.skipped_on_macos(_module(tmp_path, text))


def test_relative_platform_import_is_not_treated_as_stdlib_sys(scope, tmp_path):
    path = _module(tmp_path, 'from .sys import platform as host\nimport pytest\npytestmark = pytest.mark.skipif(host != "linux", reason="owned")')
    assert not scope.skipped_on_macos(path)


def test_conditionally_rebound_marker_alias_keeps_runner(scope, tmp_path):
    path = _module(tmp_path, 'import sys, pytest\nlinux = pytest.mark.skipif(sys.platform != "linux", reason="owned")\nif unknown:\n    linux = other\npytestmark = linux')
    assert not scope.skipped_on_macos(path)


@pytest.mark.parametrize('mode', [None, '', 'full', 'unknown'], ids=['missing', 'empty', 'forced', 'unexpected'])
def test_forced_or_unknown_scope_keeps_full_macos_backstop(scope, tmp_path, monkeypatch, mode):
    path = _module(tmp_path, 'import sys, pytest\npytestmark = pytest.mark.skipif(sys.platform != "linux", reason="owned")')
    output = tmp_path / 'outputs'
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('SANDBOX_FILES', path.name)
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    if mode is None:
        monkeypatch.delenv('SCOPE_MODE', raising=False)
    else:
        monkeypatch.setenv('SCOPE_MODE', mode)
    scope.main()
    assert output.read_text() == f'run=true\nfiles={path.name}\nnative_audit=true\n'
