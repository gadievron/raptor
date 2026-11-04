"""Exercise the real workflow comment script against a paginated fake API."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from textwrap import dedent

import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('bot_comment,fail_api', [(True, False), (False, False), (True, True)])
def test_comment_uses_bot_author_and_all_pages(tmp_path, bot_comment, fail_api):
    if not shutil.which('jq'):
        pytest.skip('jq is required by the fake GitHub API')
    workflow = (REPO / '.github/workflows/sca-pr-gate.yml').read_text()
    block = workflow.split('      - name: Post PR comment\n', 1)[1].split(
        '      - name: Upload debug logs\n', 1,
    )[0]
    # ci-lint installs only pytest; extracting this block needs no YAML package.
    script = dedent(block.split('        run: |\n', 1)[1])
    # Keep the test's files isolated while exercising the actual workflow body.
    body_file = tmp_path / 'diff.md'
    body_file.write_text('SCA results')
    script = script.replace('/tmp/sca-diff.md', str(body_file))
    marker = '<!-- raptor-sca-pr-gate -->'
    pages = [[{'id': 1, 'user': {'login': 'contributor'}, 'body': marker}]]
    pages.append([{'id': 42, 'user': {'login': 'github-actions[bot]' if bot_comment else 'reviewer'}, 'body': marker}])
    fixture = tmp_path / 'pages.json'
    fixture.write_text(json.dumps(pages))
    calls = tmp_path / 'calls.jsonl'
    output = tmp_path / 'output'
    fake = tmp_path / 'gh'
    fake.write_text('''#!/usr/bin/env python3
import json, os, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as f:
    f.write(json.dumps(args) + '\\n')
if '--paginate' in args:
    assert '--slurp' in args
    assert 'per_page=100' in args[args.index('--slurp') + 1]
    if os.environ['FAIL_API'] == '1':
        sys.exit(1)
    result = subprocess.run(['jq', '-r', args[args.index('--jq') + 1]],
        input=Path(os.environ['PAGES']).read_text(), text=True)
    sys.exit(result.returncode)
''')
    fake.chmod(0o755)
    result = subprocess.run(['bash', '-c', script], env=dict(
        os.environ, PATH=f'{tmp_path}{os.pathsep}{os.environ["PATH"]}',
        REPO='owner/repo', PR='12', GITHUB_OUTPUT=str(output),
        CALLS=str(calls), PAGES=str(fixture), FAIL_API=str(int(fail_api)),
    ), capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    actions = [json.loads(line) for line in calls.read_text().splitlines()]
    if fail_api:
        assert len(actions) == 1
        assert output.read_text() == 'posted=false\n'
    else:
        assert output.read_text() == 'posted=true\n'
        if bot_comment:
            assert actions[1][:3] == ['api', '-X', 'PATCH']
            assert actions[1][3] == '/repos/owner/repo/issues/comments/42'
        else:
            assert actions[1][:3] == ['pr', 'comment', '12']
