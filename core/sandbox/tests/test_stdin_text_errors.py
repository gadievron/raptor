"""Explicit subprocess text error handlers survive Linux stdin spooling."""
import sys
import subprocess
from pathlib import Path

from core.testing.processes import run_in_process_group
from core.testing.standalone_cli import standalone_cli_env

import pytest

from core.sandbox import sandbox
from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns

pytestmark = [
    pytest.mark.slow, pytest.mark.linux_native,
    pytest.mark.skipif(sys.platform != "linux", reason="Linux stdin spool"),
    requires_landlock, requires_mount, requires_userns,
]

@pytest.mark.parametrize("errors,expected", [
    ("replace", "owned ?"), ("ignore", "owned "),
    ("backslashreplace", "owned \\u03bb"),
], ids=["replace", "ignore", "backslashreplace"])
def test_explicit_error_handler_preserves_subprocess_input_contract(tmp_path, errors, expected):
    target, output = tmp_path / "target", tmp_path / "output"
    target.mkdir()
    output.mkdir()
    with sandbox(profile="strict", target=str(target), output=str(output)) as run:
        actual = run(["/bin/cat"], input="owned \u03bb", encoding="ascii", errors=errors,
                     capture_output=True, check=True, timeout=15)
    assert actual.returncode == 0, actual.stderr
    assert actual.stdout == expected
    assert actual.sandbox_info["mount_ns_active"] is True


def test_default_error_handler_still_refuses_unencodable_input(tmp_path):
    target, output = tmp_path / "target", tmp_path / "output"
    target.mkdir()
    output.mkdir()
    with sandbox(profile="strict", target=str(target), output=str(output)) as run:
        with pytest.raises(UnicodeEncodeError):
            run(["/bin/cat"], input="owned \u03bb", encoding="ascii",
                capture_output=True, timeout=15)


@pytest.mark.parametrize("errors,expected", [
    ("replace", "\ufffd\n"), ("ignore", "\n"),
    ("backslashreplace", "\\xff\n"),
], ids=["replace", "ignore", "backslashreplace"])
def test_explicit_output_codec_preserves_bytes_and_normalizes_newlines(tmp_path, errors, expected):
    target, output = tmp_path / "target", tmp_path / "output"
    target.mkdir()
    output.mkdir()
    with sandbox(profile="strict", target=str(target), output=str(output)) as run:
        actual = run(["/bin/sh", "-c", "printf '\\377\\r\\n'; printf '\\377\\r\\n' >&2"],
                     encoding="ascii", errors=errors, capture_output=True, check=True, timeout=15)
    assert actual.returncode == 0
    assert actual.stdout == actual.stderr == expected
    assert actual.sandbox_info["mount_ns_active"] is True


def test_explicit_output_codec_default_remains_strict(tmp_path):
    target, output = tmp_path / "target", tmp_path / "output"
    target.mkdir()
    output.mkdir()
    with sandbox(profile="strict", target=str(target), output=str(output)) as run:
        with pytest.raises(UnicodeDecodeError):
            run(["/bin/sh", "-c", "printf '\\377'"], encoding="ascii",
                capture_output=True, timeout=15)


def test_errors_only_uses_the_parent_locale_for_input_and_output(tmp_path):
    code = r"""
import locale,sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from core.sandbox import sandbox
assert not sys.flags.utf8_mode
assert locale.getpreferredencoding(False).lower() in ('ascii', 'ansi_x3.4-1968')
target, output = Path(sys.argv[2]), Path(sys.argv[3])
target.mkdir(); output.mkdir()
with sandbox(profile='strict', target=str(target), output=str(output)) as run:
    result = run(['/bin/cat'], input='owned \u03bb', errors='replace',
                 capture_output=True, check=True, timeout=15)
assert result.stdout == 'owned ?', repr(result.stdout)
assert result.sandbox_info['mount_ns_active'] is True
"""
    root = Path(__file__).resolve().parents[3]
    with standalone_cli_env(data_home=tmp_path / 'keys') as environment:
        environment.update(LC_ALL='C', PYTHONUTF8='0', PYTHONCOERCECLOCALE='0')
        result = run_in_process_group(
            [sys.executable, '-X', 'utf8=0', '-c', code, str(root),
             str(tmp_path / 'target'), str(tmp_path / 'output')],
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=25, start_new_session=True)
    assert result.returncode == 0, result.stderr
