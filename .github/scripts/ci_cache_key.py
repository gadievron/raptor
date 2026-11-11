#!/usr/bin/env python3
"""Compute cache identities from the runtime and the inputs actually restored."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys
import sysconfig


VENV_INPUTS = ('uv.lock', 'pyproject.toml', 'uv.toml', '.github/actions/setup-venv/action.yml')


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def host_identity() -> dict:
    system = platform.system()
    if system == 'Linux':
        release = platform.freedesktop_os_release()
        release = {key: release.get(key, '') for key in ('ID', 'VERSION_ID')}
    elif system == 'Darwin':
        release = {'macos': platform.mac_ver()[0]}
    else:
        release = {'windows': platform.win32_ver()}
    return dict(system=system, machine=platform.machine(), release=release,
                libc=platform.libc_ver(), image_os=os.environ.get('ImageOS', ''),
                image_version=os.environ.get('ImageVersion', ''))


def interpreter_identity() -> dict:
    return dict(implementation=sys.implementation.name, version=sys.version,
                cache_tag=sys.implementation.cache_tag, abi=sysconfig.get_config_var('SOABI'),
                base_prefix=sys.base_prefix,
                base_executable=str(Path(getattr(sys, "_base_executable", sys.executable)).resolve()))


def requirements_identity(repo: Path, name: str) -> dict:
    """Fingerprint one self-contained manifest of exact package pins.

    Includes, indexes and remote requirements introduce inputs this identity
    cannot cover. Refuse them before restoring an executable environment.
    """
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts or '\\' in name:
        raise ValueError('requirements file must be relative to the checkout')
    path = repo / relative
    if not path.resolve().is_relative_to(repo.resolve()):
        raise ValueError('requirements file escapes the checkout')
    raw = path.read_bytes()
    pins = []
    for line in raw.decode('utf-8').splitlines():
        pin = line.split('#', 1)[0].strip()
        if not pin:
            continue
        if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,.-]+\])?'
                        r'==[A-Za-z0-9][A-Za-z0-9.!+_-]*', pin) is None:
            raise ValueError('requirements file must contain only exact package pins')
        pins.append(pin)
    if not pins:
        raise ValueError('requirements file contains no package pins')
    return dict(path=relative.as_posix(), sha256=hashlib.sha256(raw).hexdigest())


def venv_key(repo: Path, host: dict, interpreter: dict, *, prefix: str = 'venv',
             export_args: str = '', venv_path: str = '.venv',
             install_method: str = 'export', requirements_file: str = '') -> str:
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', prefix):
        raise ValueError('invalid venv cache prefix')
    if install_method not in {'export', 'sync'}:
        raise ValueError('invalid venv install method')
    files = {}
    for name in VENV_INPUTS:
        path = repo / name
        if name in ('uv.lock', 'pyproject.toml') or path.exists():
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            files[name] = None
    material = dict(schema=3, host=host, interpreter=interpreter, files=files,
                    export_args=export_args, install_method=install_method,
                    path=str((repo / venv_path).resolve()))
    if requirements_file:
        material['requirements'] = requirements_identity(repo, requirements_file)
    return prefix + '-v3-' + digest(material)


def codeql_metadata(repo: Path, host: dict) -> dict:
    if host['system'] != 'Linux' or host['machine'].lower() not in ('x86_64', 'amd64'):
        raise ValueError('the pinned CodeQL archive requires Linux x64')
    metadata = json.loads((repo / '.github/scripts/codeql-cli.json').read_text())
    for name, pattern in (('version', r'[0-9]+\.[0-9]+\.[0-9]+'), ('sha256', r'[0-9a-f]{64}'),
                          ('libraries_ref', r'[0-9a-f]{40}')):
        if not isinstance(metadata.get(name), str) or not re.fullmatch(pattern, metadata[name]):
            raise ValueError('invalid CodeQL ' + name)
    key = 'codeql-cli-v2-' + digest(dict(system=host['system'], machine=host['machine'],
                                       version=metadata['version'], sha256=metadata['sha256']))
    return dict(key=key, **{name: metadata[name] for name in ('version', 'sha256', 'libraries_ref')})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', choices=('venv', 'platform', 'codeql'), default='venv')
    args = parser.parse_args(argv)
    repo = Path.cwd()
    host = host_identity()
    year, week, _ = datetime.now(timezone.utc).isocalendar()
    result = dict(platform_key='platform-v1-' + digest(host)[:24], week=f'{year}-W{week:02d}')
    if args.kind == 'venv':
        result['key'] = venv_key(repo, host, interpreter_identity(),
                                 prefix=os.environ.get('VENV_CACHE_PREFIX', 'venv'),
                                 export_args=os.environ.get('VENV_CACHE_EXPORT_ARGS', ''),
                                 venv_path=os.environ.get('VENV_PATH', '.venv'),
                                 install_method=os.environ.get('VENV_CACHE_INSTALL_METHOD', 'export'),
                                 requirements_file=os.environ.get('VENV_CACHE_REQUIREMENTS_FILE', ''))
    elif args.kind == 'codeql':
        result.update(codeql_metadata(repo, host))
    if os.environ.get('GITHUB_OUTPUT'):
        with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
            for name, value in result.items():
                output.write(name + '=' + value + '\n')
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
