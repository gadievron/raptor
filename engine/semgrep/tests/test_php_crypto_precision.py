"""Crypto name anchors must identify data/destinations, not unrelated text."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

_RULES = Path(__file__).resolve().parents[1] / 'rules/php'
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which('semgrep') is None, reason='semgrep not installed')]


def test_crypto_names_builtin_spellings_and_destination_shapes(tmp_path):
    cases = {
        'weak-password-hash': [
            ('return md5($password);', ('arg',)),
            ('return \\MD5($password);', ('arg',)),
            ('return SHA1($password);', ('arg',)),
            ('return \\sha1($user_password);', ('arg',)),
            ("return hash('MD5', $user_password, false);", ('arg',)),
            ("return \\HASH('sHa1', $pwd);", ('arg',)),
            ('return md5($password . $salt);', ('arg',)),
            ('return md5(trim($user_password));', ('arg',)),
            ('return md5("{$password}");', ('arg',)),
            ("return md5($_POST['password']);", ('arg',)),
            ('return md5($user->password);', ('arg',)),
            ("return md5($config['auth_password']);", ('arg',)),
            ('return md5($password_store->cache);', ()),
            ("return md5($password_store['cache']);", ()),
            ('return md5($map[$password_key]);', ()),
            ('return md5("password_reset_template");', ()),
            ("return md5('$password');", ()),
            ('return md5(password_status($input));', ()),
            ('$password = md5($value);', ('store',)),
            ('$obj->passwd = \\SHA1($value);', ('store',)),
            ("$row['password_hash'] = \\HASH('mD5', $value);", ('store',)),
            ("$passphrase_digest = hash('SHA1', $value);", ('store',)),
            ('$password_store->etag = md5($value);', ()),
            ("$password_store['cache'] = md5($value);", ()),
            ('$row[$password_key] = md5($value);', ()),
            ('$obj->$password_field = md5($value);', ()),
            ("$row[lookup('password')] = md5($value);", ()),
            ("$password = hash('sha256', $value);", ()),
            ('$password = password_hash(md5($value), PASSWORD_DEFAULT);', ()),
            ('$password = custom_md5($value);', ()),
            ('return $obj->md5($password);', ()),
            ('return Vendor\\md5($password);', ()),
            ('return hash($algo, $password);', ()),
            ('return md5($passthrough);', ()),
            ('$password = md5($password);', ('arg', 'store')),
        ],
        'weak-prng-token': [
            ('$csrf_token = mt_rand();', ('var',)),
            ('$token = \\MT_RAND();', ('var',)),
            ("$obj->api_key = \\STR_SHUFFLE('abc');", ('property',)),
            ("$_SESSION['csrf_token'] = \\RAND();", ('array-store',)),
            ('$row["session_id"] = md5(\\UNIQID());', ('array-store',)),
            ('$obj->reset_token = md5(mt_rand());', ('property',)),
            ('$row[$csrf_key] = rand();', ()),
            ("$row[lookup('csrf_token')] = rand();", ()),
            ('$obj->$token_field = rand();', ()),
            ('$token_store->cache = rand();', ()),
            ('$frame->pad = rand();', ()),
            ('$pad = rand();', ('var',)),
            ("$_SESSION['pad'] = rand();", ()),
            ('$token = random_int(1, 99);', ()),
            ('$token = bin2hex(random_bytes(32));', ()),
            ('$nonce = $obj->rand();', ()),
            ('$nonce = Vendor\\rand();', ()),
            ("$notepad = str_shuffle('ab');", ()),
            ("$csrf_token = hash('sha256', uniqid());", ('var',)),
            ('$r = rand(); $csrf_token = $r;', ()),
            ('$token = array_rand($entries);', ('var',)),
            ('$token = $obj->array_rand($entries);', ()),
            ('$token = $rand_fn();', ()),
            ("$row['csrf_token'] = array_rand($entries);", ('array-store',)),
            ("$row['csrf_token'] = custom_rand();", ()),
        ],
    }
    cases['weak-password-hash'] += [
        ('Foo::$password_hash = md5($value);', ('store',)),
        ('Foo::$password_hash = hash("md5", $value);', ('store',)),
        ('return md5(Foo::$password);', ('arg',)),
        ('return md5($obj->$password_field);', ()),
        ('Foo::${$password_field} = md5($value);', ()),
        ("$obj->{'password'} = md5($value);", ('store',)),
        ("return md5($obj->{'password'});", ('arg',)),
        ("return md5($request['login-password']);", ('arg',)),
        ("$row['auth.password'] = hash('sha1', $value);", ('store',)),
    ]
    cases['weak-prng-token'] += [
        ('Foo::$csrf_token = rand();', ('property',)),
        ('Foo::${$token_field} = rand();', ()),
        ("$obj->{'csrf_token'} = rand();", ('property',)),
        ("$row['csrf-token'] = rand();", ('array-store',)),
        ("$row['auth.reset_token'] = rand();", ('array-store',)),
    ]
    cases['weak-password-hash'] += [
        ("$algo='MD5'; return hash($algo, $password);", ('arg',)),
        ("$algo='sha1'; $password_hash=hash($algo, $value);", ('store',)),
        ("$algo='sha256'; return hash($algo, $password);", ()),
        ("$algo='md5'; $algo=$input; return hash($algo, $password);", ()),
        ("$algo='sha1'; $algo='sha256'; return hash($algo, $password);", ()),
        ("$key='password'; $row[$key]=md5($value);", ('store',)),
        ("$key='password'; return md5($row[$key]);", ('arg',)),
        ("$password_key='cache'; $row[$password_key]=md5($value);", ()),
    ]
    cases['weak-prng-token'] += [
        ("$key='csrf_token'; $row[$key]=rand();", ('array-store',)),
        ("$token_key='cache'; $row[$token_key]=rand();", ()),
    ]
    cases['weak-password-hash'] += [
        ("$key='password'; return hash('MD5', $row[$key]);", ('arg',)),
        ("$key='password'; $row[$key]=hash('sha1', $value);", ('store',)),
        ("$key='password'; $key='cache'; $row[$key]=md5($value);", ()),
        ("$key='password'; $row[$key]=password_hash($value, PASSWORD_DEFAULT);", ()),
        ("$algo='md5'; $password=Vendor\\hash($algo, $value);", ()),
        ("$algo='md5'; $password=$obj->hash($algo, $value);", ()),
    ]
    cases['weak-prng-token'] += [
        ("$key='csrf_token'; $key='cache'; $row[$key]=rand();", ()),
        ("$key='csrf_token'; $row[$key]=random_int(1, 9);", ()),
    ]
    expected = set()
    targets = []
    for family, matrix in cases.items():
        for index, (body, suffixes) in enumerate(matrix):
            target = tmp_path / f'{family}_{index}.php'
            target.write_text('<?php\nfunction f() {\n  ' + body + '\n}\n')
            targets.append(target)
            expected.update((target.name, f'raptor.php.{family}.{suffix}') for suffix in suffixes)
    for family, statement, suffix in (
        ('weak-password-hash', 'return \\MD5($password);', 'arg'),
        ('weak-prng-token', '$_SESSION["csrf_token"] = \\MT_RAND();', 'array-store'),
    ):
        target = tmp_path / f'{family}_many.php'
        target.write_text('<?php\n' + '\n'.join(
            f'function case_{i}($password) {{ {statement} }}' for i in range(120)) + '\n')
        targets.append(target)
        expected.add((target.name, f'raptor.php.{family}.{suffix}'))
    for args in (['git', 'init', '-q'], ['git', 'add', '--', *[p.name for p in targets]]):
        subprocess.run(args, cwd=tmp_path, capture_output=True, check=True, timeout=20)
    configs = [arg for family in cases for arg in ('--config', str(_RULES / f'{family}.yaml'))]
    proc = subprocess.run(
        ['semgrep', 'scan', *configs, '--metrics', 'off', '--disable-version-check',
         '--jobs', '1', '--json', *map(str, targets)],
        cwd=tmp_path, capture_output=True, text=True, timeout=180, check=False,
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
    assert len(data['results']) == sum(len(ids) for matrix in cases.values() for _, ids in matrix) + 240
    for family in cases:
        assert sum(Path(row['path']).name == f'{family}_many.php'
                   for row in data['results']) == 120
