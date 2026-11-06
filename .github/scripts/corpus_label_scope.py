"""Dispatch corpus pin lint from the event's complete, immutable Git range."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from ci_change_scope import changed_paths

LABELS = 'core/audit/corpus/labels'
FULL = [LABELS]
INFRASTRUCTURE = {
    '.github/workflows/corpus-labels.yml', '.github/scripts/corpus_label_scope.py',
    '.github/scripts/ci_change_scope.py', 'pyproject.toml', 'uv.lock', 'uv.toml',
    '.python-version', 'core/__init__.py', 'core/audit/__init__.py',
}
# Keep ample exec/environment headroom. Small selections stay granular;
# oversized selections broaden to the tree instead of risking E2BIG.
_MAX_SCOPED_ARG_BYTES = 32 * 1024


def select(repo: Path, changed: list[str] | None) -> list[str]:
    if changed is None:
        return FULL.copy()
    labels = set()
    for name in changed:
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or name != path.as_posix():
            return FULL.copy()
        corpus_input = path.is_relative_to('core/audit/corpus')
        if not corpus_input and name not in INFRASTRUCTURE:
            continue  # Complete history also proves unrelated deletions irrelevant.
        try:
            if not (repo / path).is_file():
                return FULL.copy()
        except OSError:
            return FULL.copy()
        if path.is_relative_to(LABELS) and name.endswith('.label.json'):
            labels.add(name)
        else:
            return FULL.copy()
    selected = sorted(labels)
    if sum(len(os.fsencode(name)) + 1 for name in selected) > _MAX_SCOPED_ARG_BYTES:
        return FULL.copy()
    return selected


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lint', action='store_true')
    parser.add_argument('--cache-dir', default='.corpus-lint-cache')
    args = parser.parse_args(argv)
    repo = Path.cwd()
    changed = (changed_paths(repo, os.environ.get('BASE_SHA', ''))
               if os.environ.get('EVENT') in {'pull_request', 'merge_group'} else None)
    files = select(repo, changed)
    if os.environ.get('GITHUB_OUTPUT'):
        with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
            output.write(f"pins_run={str(bool(files)).lower()}\n")
    print(json.dumps({'changes_known': changed is not None, 'pin_paths': files}),
          file=sys.stderr if args.lint else sys.stdout, flush=True)
    if not args.lint or not files:
        return 0
    return subprocess.run([
        sys.executable, '-m', 'core.audit.corpus.lint', '--mode', 'pins',
        '--fetch-missing', '--cache-dir', args.cache_dir, *files,
    ], cwd=repo, check=False).returncode


if __name__ == '__main__':
    raise SystemExit(main())
