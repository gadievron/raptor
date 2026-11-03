"""Browser provisioning and failure artifacts follow the tested runner contract."""
from pathlib import Path

import yaml


def test_browser_job_uses_supported_linux_runner():
    workflow = yaml.safe_load((Path(__file__).resolve().parents[2] / '.github/workflows/sandbox-wrappers.yml').read_text())
    job = workflow['jobs']['acceptance']
    assert job['strategy']['matrix']['os'] == ['ubuntu-24.04', 'macos-latest']
    steps = job['steps']
    assert any(step.get('id') == 'contracts' for step in steps)
    assert any(step.get('id') == 'native' for step in steps)
    upload = next(step for step in steps if step.get('name') == 'Retain coverage and native exclusions')
    assert upload['if'] == "always() && (steps.contracts.outcome != 'skipped' || steps.native.outcome != 'skipped')"
    assert upload['with']['if-no-files-found'] == 'error'
