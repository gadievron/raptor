"""Browser provisioning and failure artifacts follow the tested runner contract."""
from pathlib import Path


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
