"""Shell/socket taint must reach the command/payload argument itself."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from core.audit.tests._live_transport import run_pinned_subprocess

_RULES = Path(__file__).resolve().parents[1] / 'rules/php'
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which('semgrep') is None, reason='semgrep not installed')]


def test_command_and_protocol_payload_positions(tmp_path, monkeypatch):
    cases = {
        'argument-injection': [
            ('exec($v);', True),
            ('\\exec($v);', True),
            ('EXEC($v);', True),
            ('\\Exec($v);', True),
            ('system($v);', True),
            ('\\system($v);', True),
            ('SYSTEM($v);', True),
            ('\\System($v);', True),
            ('passthru($v);', True),
            ('\\passthru($v);', True),
            ('PASSTHRU($v);', True),
            ('\\Passthru($v);', True),
            ('shell_exec($v);', True),
            ('\\shell_exec($v);', True),
            ('SHELL_EXEC($v);', True),
            ('\\Shell_Exec($v);', True),
            ("popen($v, 'r');", True),
            ("\\popen($v, 'r');", True),
            ("POPEN($v, 'r');", True),
            ("\\Popen($v, 'r');", True),
            ('proc_open($v, [], $pipes);', True),
            ('\\proc_open($v, [], $pipes);', True),
            ('PROC_OPEN($v, [], $pipes);', True),
            ('\\Proc_Open($v, [], $pipes);', True),
            ("$out=[$v]; $status=$v; exec('/usr/bin/true', $out, $status);", False),
            ("$status=$v; system('/usr/bin/true', $status);", False),
            ("$status=$v; passthru('/usr/bin/true', $status);", False),
            ("popen('/usr/bin/true', $v);", False),
            ("$spec=[1=>['file', $v, 'w']]; proc_open('/usr/bin/true', $spec, $pipes);", False),
            ("proc_open('/usr/bin/true', [], $pipes, $v);", False),
            ("proc_open('/usr/bin/true', [], $pipes, null, ['APP_VALUE'=>$v]);", False),
            ("proc_open(['/usr/bin/printf', $v], [], $pipes);", False),
            ("\\PROC_OPEN(array('/usr/bin/printf', $v), [], $pipes);", False),
            ('$obj->exec($v);', False),
            ('Vendor\\exec($v);', False),
            ("exec('tool ' . escapeshellcmd($v));", True),
            ("exec('tool ' . \\ESCAPESHELLCMD($v));", True),
            ("$q=escapeshellarg($v); exec('tool ' . $q . ' ' . $_GET['other']);", True),
            ('escapeshellarg(system($v));', True),
            ('$q=\\ESCAPESHELLARG(\\SYSTEM($v));', True),
            ('exec($obj->escapeshellarg($v));', True),
            ('exec("tool " . escapeshellarg($v));', False),
            ('$safe=escapeshellarg($v); $copy=$safe; system("tool " . $copy);', False),
            ('exec("tool " . \\ESCAPESHELLARG($v));', False),
            ('$safe=\\ESCAPESHELLARG($v); $copy=$safe; system("tool " . $copy);', False),
            ('exec("tool " . intval($v));', False),
            ('$safe=intval($v); $copy=$safe; system("tool " . $copy);', False),
            ('exec("tool " . \\INTVAL($v));', False),
            ('$safe=\\INTVAL($v); $copy=$safe; system("tool " . $copy);', False),
            ('exec("tool " . floatval($v));', False),
            ('$safe=floatval($v); $copy=$safe; system("tool " . $copy);', False),
            ('exec("tool " . \\FLOATVAL($v));', False),
            ('$safe=\\FLOATVAL($v); $copy=$safe; system("tool " . $copy);', False),
            ('exec("tool " . count($v));', False),
            ('$safe=count($v); $copy=$safe; system("tool " . $copy);', False),
            ('exec("tool " . \\COUNT($v));', False),
            ('$safe=\\COUNT($v); $copy=$safe; system("tool " . $copy);', False),
            ('exec("tool " . sizeof($v));', False),
            ('$safe=sizeof($v); $copy=$safe; system("tool " . $copy);', False),
            ('exec("tool " . \\SIZEOF($v));', False),
            ('$safe=\\SIZEOF($v); $copy=$safe; system("tool " . $copy);', False),
            ('exec("tool " . strlen($v));', False),
            ('$safe=strlen($v); $copy=$safe; system("tool " . $copy);', False),
            ('exec("tool " . \\STRLEN($v));', False),
            ('$safe=\\STRLEN($v); $copy=$safe; system("tool " . $copy);', False),
            ('exec("tool " . (int)$v);', False),
            ('$safe=(int)$v; exec("tool " . $safe);', False),
            ('exec("tool " . (float)$v);', False),
            ('$safe=(float)$v; exec("tool " . $safe);', False),
            ('exec("tool " . (bool)$v);', False),
            ('$safe=(bool)$v; exec("tool " . $safe);', False),
            ('escapeshellarg($v); exec($v);', True),
            ('intval($v); exec($v);', True),
            ('floatval($v); exec($v);', True),
            ('strlen($v); exec($v);', True),
            ('$safe=(float)$v; exec($v);', True),
        ],
        'crlf-injection': [
            ("$s=fsockopen('localhost', 25); fwrite($s, $v);", True),
            ("$s=\\fsockopen('localhost', 25); \\fwrite($s, $v);", True),
            ("$s=FSOCKOPEN('localhost', 25); FWRITE($s, $v);", True),
            ("$s=\\Fsockopen('localhost', 25); \\Fwrite($s, $v);", True),
            ("$s=fsockopen('localhost', 25); fputs($s, $v);", True),
            ("$s=\\fsockopen('localhost', 25); \\fputs($s, $v);", True),
            ("$s=FSOCKOPEN('localhost', 25); FPUTS($s, $v);", True),
            ("$s=\\Fsockopen('localhost', 25); \\Fputs($s, $v);", True),
            ("$s=stream_socket_client('tcp://localhost:25'); fwrite($s, $v);", True),
            ("$s=\\stream_socket_client('tcp://localhost:25'); \\fwrite($s, $v);", True),
            ("$s=STREAM_SOCKET_CLIENT('tcp://localhost:25'); FWRITE($s, $v);", True),
            ("$s=\\Stream_Socket_Client('tcp://localhost:25'); \\Fwrite($s, $v);", True),
            ("$s=stream_socket_client('tcp://localhost:25'); fputs($s, $v);", True),
            ("$s=\\stream_socket_client('tcp://localhost:25'); \\fputs($s, $v);", True),
            ("$s=STREAM_SOCKET_CLIENT('tcp://localhost:25'); FPUTS($s, $v);", True),
            ("$s=\\Stream_Socket_Client('tcp://localhost:25'); \\Fputs($s, $v);", True),
            ('socket_write($socket, $v);', True),
            ('\\socket_write($socket, $v);', True),
            ('SOCKET_WRITE($socket, $v);', True),
            ('\\Socket_Write($socket, $v);', True),
            ('socket_send($socket, $v, strlen($v), 0);', True),
            ('\\socket_send($socket, $v, strlen($v), 0);', True),
            ('SOCKET_SEND($socket, $v, strlen($v), 0);', True),
            ('\\Socket_Send($socket, $v, strlen($v), 0);', True),
            ("$s=fsockopen($v, 25); fwrite($s, 'PING');", False),
            ("$s=stream_socket_client($v); fputs($s, 'PING');", False),
            ("$s=fsockopen('localhost', 25); fwrite($s, 'PING', $v);", False),
            ("$s=fsockopen('localhost', 25); fputs($s, 'PING', $v);", False),
            ("socket_write($socket, 'PING', $v);", False),
            ("socket_send($socket, 'PING', $v, 0);", False),
            ("socket_send($socket, 'PING', 4, $v);", False),
            ("$s=fopen('local.txt', 'w'); fwrite($s, $v);", False),
            ('fwrite($socket, $v);', False),
            ("$s=$obj->fsockopen('localhost',25); fwrite($s, $v);", False),
            ("$s=Vendor\\fsockopen('localhost',25); fwrite($s, $v);", False),
            ("$s=fsockopen('localhost',25); $obj->fwrite($s, $v);", False),
            ('Vendor\\socket_write($socket, $v);', False),
            ('$s=fsockopen($v,25); $safe=str_replace(["\\r", "\\n"], \'\', $v); fwrite($s, $safe);', False),
            ('$s=fsockopen(\'localhost\',25); $safe=str_replace(["\\r", "\\n"], \'\', $v); fwrite($s, $v);', True),
            ("$s=fsockopen('localhost',25); rawurlencode(fwrite($s, $v));", True),
            ("$s=fsockopen('localhost',25); $safe=rawurlencode(fwrite($s, $v));", True),
        ],
    }
    suffixes = {'argument-injection': 'exec-family', 'crlf-injection': 'socket-write'}
    expected = set()
    targets = []
    for family, matrix in cases.items():
        for index, (body, finding) in enumerate(matrix):
            target = tmp_path / f'{family}_{index}.php'
            target.write_text('<?php\nfunction f($socket, $obj) {\n  $v=$_GET["x"];\n  ' + body + '\n}\n')
            targets.append(target)
            if finding:
                expected.add((target.name, f'raptor.php.{family}.{suffixes[family]}'))
    many = (
        ('argument-injection', '\\SYSTEM($_GET["x"]);'),
        ('crlf-injection', '\\SOCKET_WRITE($socket, $_GET["x"]);'),
        ('crlf-stream', '$s=\\FSOCKOPEN("localhost",25); \\FWRITE($s,$_GET["x"]);'),
    )
    for name, statement in many:
        family = 'argument-injection' if name == 'argument-injection' else 'crlf-injection'
        target = tmp_path / f'{name}_many.php'
        target.write_text('<?php\n' + '\n'.join(
            f'function case_{i}($socket) {{ {statement} }}' for i in range(120)) + '\n')
        targets.append(target)
        expected.add((target.name, f'raptor.php.{family}.{suffixes[family]}'))
    for args in (['git', 'init', '-q'], ['git', 'add', '--', *[p.name for p in targets]]):
        subprocess.run(args, cwd=tmp_path, capture_output=True, check=True, timeout=20)
    configs = [arg for family in cases for arg in ('--config', str(_RULES / f'{family}.yaml'))]
    monkeypatch.chdir(tmp_path)
    proc = run_pinned_subprocess(
        ['semgrep', 'scan', *configs, '--metrics', 'off', '--disable-version-check',
         '--jobs', '1', '--json', *map(str, targets)],
        timeout=180, context='PHP call-argument precision', skip_signals=(9,),
        env={**os.environ, 'SEMGREP_SETTINGS_FILE': str(tmp_path / 'settings.yml'),
             'SEMGREP_LOG_FILE': str(tmp_path / 'semgrep.log')},
    )
    data = json.loads(proc.stdout)
    assert proc.returncode == 0, proc.stderr
    assert not data.get('errors'), data.get('errors')
    assert {Path(p).name for p in data['paths']['scanned']} == {p.name for p in targets}
    actual = {(Path(row['path']).name, row['check_id'][row['check_id'].index('raptor.php.'):])
              for row in data['results']}
    assert actual == expected, {'missing': sorted(expected - actual),
                                'unexpected': sorted(actual - expected)}
    assert len(data['results']) == sum(hit for matrix in cases.values() for _, hit in matrix) + 360
    for name, _ in many:
        assert sum(Path(row['path']).name == f'{name}_many.php' for row in data['results']) == 120
