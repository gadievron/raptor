"""Generate the maintenance PR body from inert, owned phase artifacts."""
from pathlib import Path
import re
import runpy
from textwrap import dedent

import pytest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/sca-self-bump.yml'


def step(name):
    matches = [body for body in re.split(r'^      - name: ', WORKFLOW.read_text(), flags=re.M)[1:]
               if body.splitlines()[0] == name]
    assert len(matches) == 1, name
    return matches[0]


def report_python():
    body = step('Assemble self-bump PR report')
    match = re.search(r"          python3 - <<'PYTHON'\n(.*?)          PYTHON\n", body, re.S)
    assert match is not None
    return dedent(match[1])


def generate(tmp_path, monkeypatch, *, applied=True, patch=None, excluded=''):
    hardening = tmp_path / 'hardening report.md'
    hardening.write_text('## Promoted (applied)\n- python:capstone 5.0.6 -> 5.0.8\n')
    (tmp_path / 'bump-proposals.md').write_text(
        '### Phase 2: 5 block-tier proposals across 4 rows\n'
        '| docker | old | new | Block | not applied |\n'
        'Skipped: registry lookup unavailable\n'
    )
    if patch is None:
        patch = ('diff --git a/requirements-sandbox-wrappers.txt b/requirements-sandbox-wrappers.txt\n'
                 '-capstone==5.0.6\n+capstone==5.0.8\n')
    (tmp_path / 'sca-applied.patch').write_text(patch)
    (tmp_path / 'excluded-workflows.txt').write_text(excluded)
    monkeypatch.setenv('RUNNER_TEMP', str(tmp_path))
    monkeypatch.setenv('HARDEN_REPORT', str(hardening))
    monkeypatch.setenv('HARDEN_PATCH_APPLIED', str(applied).lower())
    # Execute only the literal stdlib report body, never the shell/Git/SCA steps.
    script = tmp_path / 'owned-pr-report.py'
    script.write_text(report_python())
    runpy.run_path(str(script))
    return (tmp_path / 'pr-body.md').read_text()


def test_applied_hardening_is_distinct_from_blocked_proposals(tmp_path, monkeypatch):
    text = generate(tmp_path, monkeypatch)
    assert 'The Phase 1 hardening patch was applied' in text
    assert 'capstone==5.0.6\n+capstone==5.0.8' in text
    assert text.index('## Manifest hardening (Phase 1)') < text.index('## Non-manifest proposals (Phase 2)')
    assert 'Review and Block proposals are not applied' in text
    assert '5 block-tier proposals across 4 rows' in text
    assert 'not a list of changes in this PR' in text
    assert 'does not establish functional or native compatibility' in text
    assert 'nor prove that every SCA signal was available or passed' in text
    assert 'does not attest the status of PR checks' in text
    assert 'pass the separate required CI checks' in text


def test_report_does_not_reinterpret_a_range_in_the_actual_diff(tmp_path, monkeypatch):
    # Historical PR1064 shape: report literal edits, even when posture was wrong.
    patch = '-capstone==5.0.6\n+capstone>=5.0.8\n'
    text = generate(tmp_path, monkeypatch, patch=patch)
    assert patch.rstrip() in text
    assert '+capstone==5.0.8' not in text


def test_no_applied_patch_is_not_reported_as_an_upgrade(tmp_path, monkeypatch):
    text = generate(tmp_path, monkeypatch, applied=False, patch='')
    assert 'No Phase 1 hardening patch was applied' in text
    assert 'following is analysis only' in text
    assert 'No changes remain after exclusions.' in text
    assert 'The Phase 1 hardening patch was applied' not in text


def test_workflow_exclusions_and_lookup_gaps_stay_visible(tmp_path, monkeypatch):
    text = generate(tmp_path, monkeypatch, excluded='.github/workflows/example.yml\n')
    assert 'Workflow-file edits reverted before publication' in text
    assert '.github/workflows/example.yml' in text
    assert 'registry lookup unavailable' in text
    for pattern in ('**/tests/**', '**/test/**', '**/fixtures/**', '**/testdata/**',
                    'core/sandbox/scripts/feature-matrix/images/**'):
        assert pattern in text
    assert 'Skipped/excluded surfaces remain unverified' in text


def test_diff_backticks_cannot_close_the_literal_patch_block(tmp_path, monkeypatch):
    patch = '--- a/owned\n+++ b/owned\n+```\n+<details>not a report section</details>\n'
    text = generate(tmp_path, monkeypatch, patch=patch)
    assert '````\n' + patch.rstrip() + '\n````' in text


@pytest.mark.parametrize('missing', ['hardening report.md', 'bump-proposals.md',
                                   'sca-applied.patch', 'excluded-workflows.txt'])
def test_missing_phase_artifact_refuses_to_publish_partial_report(tmp_path, monkeypatch, missing):
    generate(tmp_path, monkeypatch)
    (tmp_path / 'pr-body.md').unlink()
    (tmp_path / missing).unlink()
    with pytest.raises(FileNotFoundError):
        runpy.run_path(str(tmp_path / 'owned-pr-report.py'))
    assert not (tmp_path / 'pr-body.md').exists()


def test_workflow_owns_report_order_posture_and_token_separation():
    source = WORKFLOW.read_text()
    harden = step('Phase 1 — harden Python / Debian / npm manifests')
    assert '--self-test \\' in harden and '--no-llm \\' in harden
    bump = step('Phase 2 — bump non-manifest surfaces')
    assert '--apply \\' in bump and '--pr-comment \\' in bump
    assert '> "$RUNNER_TEMP/bump-proposals.md"' in bump
    assert source.index('name: Apply harden patch') < source.index('name: Phase 2')
    assert source.index('name: Exclude workflow-file changes') < source.index('name: Assemble self-bump PR report')
    assert source.index('name: Assemble self-bump PR report') < source.index('name: Detect changes')
    assembly = step('Assemble self-bump PR report')
    assert 'git diff --no-ext-diff --binary > "$RUNNER_TEMP/sca-applied.patch"' in assembly
    for body in (harden, bump, assembly):
        assert 'GH_TOKEN:' not in body and 'GITHUB_TOKEN:' not in body
    assert 'persist-credentials: false' in step('Checkout')
    commit = step('Commit + push branch')
    assert 'Every change passed the full' not in commit
    assert 'not functional or native compatibility' in commit
    assert 'gh auth setup-git' in commit and 'git push --force-with-lease' in commit
    assert 'GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}' in commit
