"""Browser provisioning and failure artifacts follow the tested runner contract."""
import ast
import json
from pathlib import Path
import re

import pytest


def test_browser_job_uses_supported_linux_runner():
    # The lint tier installs pytest only; keep this source contract stdlib-only.
    workflow = (Path(__file__).resolve().parents[2] / '.github/workflows/sandbox-wrappers.yml').read_text()
    lines = {line.strip() for line in workflow.splitlines()}
    assert 'matrix: ${{ fromJSON(needs.scope.outputs.matrix) }}' in lines
    scope = (Path(__file__).resolve().parents[2] / '.github/scripts/sandbox_wrapper_scope.py').read_text()
    assert "'linux': 'ubuntu-24.04', 'darwin': 'macos-latest'" in scope
    assert 'id: contracts' in lines
    assert 'id: native' in lines
    _, separator, upload = workflow.partition('      - name: Retain coverage and native exclusions\n')
    assert separator, 'wrapper report upload step is missing'
    upload_lines = {line.strip() for line in upload.splitlines()}
    assert "if: always() && (steps.contracts.outcome != 'skipped' || steps.native.outcome != 'skipped')" in upload_lines
    assert 'if-no-files-found: error' in upload_lines


def _trigger_matcher(pattern):
    # Only the workflow's current pattern forms. GitHub '*' stops at '/',
    # unlike fnmatch; new forms need review rather than an optimistic match.
    if pattern.endswith('/**'):
        prefix = pattern[:-2]
        assert not set('*?+[]!') & set(prefix), pattern
        return lambda path: path.startswith(prefix)
    if pattern == '*.py':
        return lambda path: '/' not in path and path.endswith('.py')
    assert not set('*?+[]!') & set(pattern), pattern
    return lambda path: path == pattern


@pytest.mark.parametrize('path,pattern,expected', [
    ('entry.py', '*.py', True), ('acceptance/cases.py', '*.py', False),
    ('core/nested/file.py', 'core/**', True), ('core-other/file.py', 'core/**', False),
    ('pytest.ini', 'pytest.ini', True), ('nested/pytest.ini', 'pytest.ini', False),
])
def test_trigger_guard_respects_path_boundaries(path, pattern, expected):
    assert _trigger_matcher(pattern)(path) == expected


@pytest.mark.parametrize('pattern', ['!core/**', '**/*.py', 'core/*', 'docs/[x].py'])
def test_trigger_guard_requires_review_of_new_pattern_forms(pattern):
    with pytest.raises(AssertionError):
        _trigger_matcher(pattern)


def test_registered_automated_cases_and_fixtures_are_covered_by_workflow_triggers():
    root = Path(__file__).resolve().parents[2]
    registry = json.loads((root / '.github/sandbox-wrapper-tests.json').read_text())
    sources = {row['source'] for row in registry['wrappers']}
    collected = {selector.split('::', 1)[0] for row in registry['wrappers']
                 for platform in ('linux', 'darwin')
                 for selector in row.get('contract_platforms', {}).get(platform, row['contracts'])}
    collected.update(selector.split('::', 1)[0] for family in registry['native']
                     for cell in family['platforms'].values() if not cell.get('manual')
                     for selector in (cell.get('tests') or ()))
    required = sources | collected
    for path in collected:
        required.update((parent / 'conftest.py').as_posix() for parent in Path(path).parents)
    workflow = (root / '.github/workflows/sandbox-wrappers.yml').read_text()
    filters = re.findall(r'(?m)^    paths: (\[[^\n]*\])$', workflow)
    assert len(filters) == 2, 'review PR and push path filters with this guard'
    for source in filters:
        patterns = ast.literal_eval(source)
        # Validate every pattern before matching; an earlier positive match
        # must never hide a later, unsupported exclusion.
        matches = [_trigger_matcher(pattern) for pattern in patterns]
        missing = sorted(path for path in required if not any(match(path) for match in matches))
        assert missing == [], 'registered wrapper inputs cannot trigger acceptance: ' + ', '.join(missing)
