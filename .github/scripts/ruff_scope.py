#!/usr/bin/env python3
"""Scope Ruff without installing it; uncertainty retains full-tree linting."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tomllib

from ci_change_scope import changed_paths

# A discovery compatibility guard, not an installation pin. Unknown releases
# keep full linting until their defaults have been reviewed against the scoper.
REVIEWED_PINS = {'ruff==0.15.12'}

CONFIG_NAMES = {'pyproject.toml', 'ruff.toml', '.ruff.toml', '.gitignore', '.ignore', '.gitmodules', '.gitattributes'}
HARNESS = {'.github/workflows/lint.yml', '.github/scripts/ruff_scope.py',
           '.github/scripts/ci_change_scope.py', 'uv.lock'}


def full(reason: str) -> dict:
    return dict(mode='full', files=['.'], reason=reason)


def plan(repo: Path, changed: list[str] | None, configs: list[str] | None) -> dict:
    if changed is None:
        return full('change history unavailable or deliberate full run')
    if any(Path(path).name in CONFIG_NAMES or path in HARNESS for path in changed):
        return full('lint configuration, discovery or harness changed')
    if configs is None or 'pyproject.toml' not in configs:
        return full('configuration inventory unavailable')
    try:
        for name in configs:
            path = Path(name)
            if path.name in {'ruff.toml', '.ruff.toml'}:
                return full('alternate Ruff configuration needs full discovery')
            if path.name != 'pyproject.toml':
                continue
            data = tomllib.loads((repo / path).read_text(encoding='utf-8'))
            tool = data.get('tool', {})
            if not isinstance(tool, dict):
                return full('unknown configuration shape')
            ruff = tool.get('ruff')
            if name != 'pyproject.toml' and ruff is not None:
                return full('nested Ruff configuration needs full discovery')
            if name == 'pyproject.toml':
                pins = [value for value in data.get('dependency-groups', {}).get('lint', [])
                        if isinstance(value, str) and value.startswith('ruff')]
                if len(pins) != 1 or pins[0] not in REVIEWED_PINS:
                    return full('unreviewed Ruff release needs full discovery')
                if (not isinstance(ruff, dict)
                        or {'include', 'extend-include', 'extend', 'extension'} & ruff.keys()
                        or ruff.get('preview') or ruff.get('lint', {}).get('preview')
                        or 'extension' in ruff.get('lint', {})):
                    return full('custom or unknown file discovery needs full linting')
    except (OSError, ValueError, UnicodeError, TypeError, AttributeError):
        return full('configuration could not be analysed')
    files = []
    for name in changed:
        path = repo / name
        if path.is_symlink() or not path.is_file():
            return full('deleted or indirect input needs full linting')
        if name.endswith(('.py', '.pyi', '.ipynb')):
            files.append(name)
    files = sorted(set(files))
    return dict(mode='files' if files else 'skip', files=files,
                reason='changed Python inputs' if files else 'no Ruff inputs changed')


def tracked_configs(repo: Path) -> list[str] | None:
    try:
        result = subprocess.run(['git', 'ls-files', '-z', '--', '*.toml'], cwd=repo,
                                capture_output=True, check=True, timeout=10)
        return [os.fsdecode(path) for path in result.stdout.split(b'\0') if path]
    except (OSError, subprocess.SubprocessError):
        return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--files-out', type=Path, help='write NUL-delimited Ruff arguments for xargs')
    args = parser.parse_args(argv)
    repo = Path.cwd()
    event = os.environ.get('EVENT', '')
    changed = (changed_paths(repo, os.environ.get('BASE_SHA', ''))
               if event in {'push', 'pull_request', 'merge_group'} else None)
    result = plan(repo, changed, tracked_configs(repo))
    if args.files_out:
        # Prefix ./ also protects names beginning with '-' or Ruff's '@' argfile
        # marker. NUL delimiters preserve spaces/newlines; xargs bounds argv size.
        args.files_out.write_bytes(b''.join(os.fsencode('./' + path) + b'\0' for path in result['files']))
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
        output.write('ruff_run=' + str(result['mode'] != 'skip').lower() + '\n')
    print(json.dumps(dict(mode=result['mode'], count=len(result['files']), reason=result['reason'])))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
