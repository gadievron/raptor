"""Compare literal argv recognition with an actual POSIX shell, never eval input."""
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import pytest

from core.config import RaptorConfig
from core.run.literal_command import literal_invocation_argv


def quote_word(text, style):
    if style == 'single':
        return shlex.quote(text)
    if style == 'double':
        return '"' + ''.join('\\' + c if c in '\\"$`' else c for c in text) + '"'
    return ''.join(c if c.isalnum() or c in '/._-' else '\\' + c for c in text)


@pytest.mark.skipif(shutil.which('sh') is None, reason='POSIX shell oracle')
@pytest.mark.parametrize('style', ['single', 'double', 'escaped'])
@pytest.mark.parametrize('word', [
    'app/[slug]/page.tsx', 'has space.c', 'cost$price.c', 'star*.c', 'has?.c',
    'hash#tag.c', 'tick`name.c', "single'quote.c", 'double"quote.c',
    r'back\slash.c', '$(touch should-not-exist)', '; touch should-not-exist',
    'brace{a,b}.c', 'tilde~name.c', 'bang!name.c', '',
])
def test_recognized_argv_matches_actual_shell(tmp_path, style, word):
    helper = tmp_path / 'capture'
    helper.write_text('#!' + sys.executable + '\nimport json,sys\nprint(json.dumps(sys.argv))\n')
    helper.chmod(0o700)
    command = shlex.quote(str(helper)) + ' ' + quote_word(word, style)
    expected = literal_invocation_argv(command, helper, cwd=tmp_path)
    # An empty unquoted argument has no shell word. Quoted empty args survive.
    assert expected == [str(helper), *([] if not word and style == 'escaped' else [word])]
    result = subprocess.run(['sh', '-c', command], cwd=tmp_path,
                            env=RaptorConfig.get_safe_env(), capture_output=True,
                            text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == expected
    assert not (tmp_path / 'should-not-exist').exists()


@pytest.mark.parametrize('suffix', [
    '/target/[slug]/page.tsx', '/target/*.c', '/target/?.c', '$SOURCE', '"$SOURCE"',
    '$(cat path)', '"$(cat path)"', '`cat path`', '"`cat path`"',
    '/target > out', '/target 2>&1', '/target | cat', '/target; true',
    '/target && true', '/target || true', '/target &', '/target # comment',
    '/target\ntrue', '/target\rtrue', '/target\0.c', '~user/source.c',
    '/target/{one,two}.c', '<(cat /target)', '$\'ansi\'', '"unterminated', "'unterminated", '\\',
])
def test_active_syntax_and_malformed_commands_are_unknown(suffix):
    root = Path('/installed')
    assert literal_invocation_argv('libexec/raptor-read ' + suffix,
        root / 'libexec/raptor-read', cwd=root) is None


@pytest.mark.parametrize('prefix', ['exec ', 'env ', 'VAR=value ', 'command ', 'echo '])
def test_wrappers_are_unknown(prefix):
    root = Path('/installed')
    assert literal_invocation_argv(prefix + 'libexec/raptor-read /target',
        root / 'libexec/raptor-read', cwd=root) is None


def test_adjacent_quotes_and_literal_shell_operators_are_data():
    root = Path('/installed')
    command = 'libexec/raptor-read app/"["\'slug\'"]/"page.tsx ";" "#" "*" "?" "$(x)"'
    # Active substitution in double quotes rejects the whole invocation.
    assert literal_invocation_argv(command, root / 'libexec/raptor-read', cwd=root) is None
    command = command.removesuffix(' "$(x)"')
    assert literal_invocation_argv(command, root / 'libexec/raptor-read', cwd=root) == [
        str(root / 'libexec/raptor-read'), 'app/[slug]/page.tsx', ';', '#', '*', '?']


@pytest.mark.parametrize('value', [None, {}, [], 1, '', ' ' * 16001])
def test_invalid_types_and_budget_are_unknown(value):
    root = Path('/installed')
    assert literal_invocation_argv(value, root / 'libexec/raptor-read', cwd=root) is None
