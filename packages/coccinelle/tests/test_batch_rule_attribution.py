"""Inert-only rule attribution controls; no live-tool prerequisites."""

import json
import subprocess

import pytest

from packages.coccinelle import runner
from packages.coccinelle.models import SpatchMatch, SpatchResult


@pytest.mark.parametrize('unknown', [False, True])
def test_batch_rule_attribution_preserves_evidence_or_retries(tmp_path, monkeypatch, unknown):
    target = tmp_path / 'owned.c'
    target.write_text('/* inert owned fixture, never compiled */\n')
    rules = []
    for stem in ('owned_a', 'owned_b'):
        rule = tmp_path / (stem + '.cocci')
        rule.write_text('@r@\nposition p;\n@@\nidentifier@p\n\n@script:python@\np << r.p;\n@@\n'
                        'import json\nprint("COCCIRESULT:" + json.dumps({"rule": "' + stem + '", "file": "owned.c", "line": 1}))\n')
        rules.append(rule)
    nonce = 'owned_inert_nonce'
    retries = []

    def execute(command, **kwargs):
        ids = ['owned_a', 'owned_b'] + (['owned_unknown'] if unknown else [])
        output = '\n'.join(runner._nonced_prefix(nonce) + json.dumps(
            {'rule': identity, 'file': str(target), 'line': 1},
        ) for identity in ids)
        return subprocess.CompletedProcess(command, 0, '', output)

    def individual(target, rule, **kwargs):
        retries.append(rule.stem)
        return SpatchResult(rule=rule.stem, matches=[SpatchMatch(
            file=str(target), line=2, rule=rule.stem, message='owned isolated evidence',
        )], files_examined=[str(target)])

    def forbidden(*args, **kwargs):
        raise AssertionError('native/version probe entered')

    monkeypatch.setattr(runner, 'is_available', lambda: True)
    monkeypatch.setattr(runner, '_spatch_path', lambda: 'owned-inert-spatch')
    monkeypatch.setattr(runner, '_make_nonce', lambda: nonce)
    monkeypatch.setattr(runner, '_confined_default_runner', lambda *args: execute)
    monkeypatch.setattr(runner, 'run_rule', individual)
    results = runner.run_rules_batched(
        target, rules, allow_scripting=True, subprocess_runner=execute,
        env={'TMPDIR': str(tmp_path)}, _installed_version=forbidden,
    )
    assert retries == (['owned_a', 'owned_b'] if unknown else [])
    assert all(result.ok and len(result.matches) == 1 for result in results.values())
    assert {result.matches[0].line for result in results.values()} == ({2} if unknown else {1})
