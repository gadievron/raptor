"""Execute the workflows' retention scripts against a fake GitHub API."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from textwrap import dedent

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('workflow', ['ci-deps-image', 'sandbox-matrix-image'])
@pytest.mark.parametrize('count,failure', [(0, ''), (3, ''), (8, ''), (8, 'list'), (8, 'delete')])
def test_untagged_retention_keeps_floor_and_tagged_anchors(tmp_path, workflow, count, failure):
    if not shutil.which('jq'):
        pytest.skip('jq is needed by the fake API')
    text = (ROOT / f'.github/workflows/{workflow}.yml').read_text()
    block = text.split('      - name: Prune superseded (untagged) image versions\n', 1)[1]
    block = block.split('      # Tagged-anchor retention:', 1)[0]
    script = dedent(block.split('        run: |\n', 1)[1])
    for name in ('untagged-versions.tsv', 'prune-untagged.tsv'):
        script = script.replace(f'/tmp/{name}', str(tmp_path / name))
    versions = [{'id': i, 'created_at': f'2026-01-{i:02}T00:00:00Z',
                 'metadata': {'container': {'tags': []}}} for i in range(1, count + 1)]
    versions.append({'id': 999, 'created_at': '2025-01-01T00:00:00Z',
                     'metadata': {'container': {'tags': ['main', 'req-anchor']}}})
    fixture = tmp_path / 'versions.json'
    fixture.write_text(json.dumps(versions))
    deleted = tmp_path / 'deleted'
    fake = tmp_path / 'gh'
    fake.write_text('''#!/usr/bin/env python3
import os, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
if '-X' in args:
    if os.environ['FAILURE'] == 'delete': sys.exit(1)
    with open(os.environ['DELETED'], 'a') as f: f.write(args[-1] + '\\n')
    sys.exit(0)  # Successful DELETE has no JSON response body.
if '--paginate' in args:
    if os.environ['FAILURE'] == 'list': sys.exit(1)
    result = subprocess.run(['jq', '-r', args[args.index('--jq') + 1]],
        input=Path(os.environ['VERSIONS']).read_text(), text=True)
    sys.exit(result.returncode)
sys.exit(1 if args[-1].startswith('orgs/') else 0)
''')
    fake.chmod(0o755)
    result = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                            env=dict(os.environ, PATH=f'{tmp_path}{os.pathsep}{os.environ["PATH"]}',
                                     OWNER='owner', PKG='package', VERSIONS=str(fixture),
                                     DELETED=str(deleted), FAILURE=failure))
    assert (result.returncode != 0) == bool(failure), result.stderr
    ids = [int(line.rsplit('/', 1)[-1]) for line in deleted.read_text().splitlines()] if deleted.exists() else []
    assert ids == ([] if failure else list(range(max(0, count - 5), 0, -1)))
