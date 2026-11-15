"""Conditional mathematical diagnostics cannot become bridge certificates."""

import json

import pytest

from core.dataflow import cvefix_bridge as bridge
from core.dataflow import cvefix_walk as walk
from core.dataflow import smt_barrier as sb
from core.dataflow import tier1_llm as t1
from core.dataflow.barrier_synth import SynthResult
from core.dataflow.cvefix_loader import CveFixPair


@pytest.mark.parametrize('tier', [0, 1])
@pytest.mark.parametrize('cwe,sink_class', [
    ('CWE-79', 'xss'), ('CWE-78', 'cmdi'), ('CWE-89', 'sqli'),
])
def test_bridge_keeps_character_diagnostics_non_authoritative(
    tmp_path, monkeypatch, tier, cwe, sink_class,
):
    guard = '    if not re.fullmatch(r"[a-z]+", raw): return'
    source = 'import re\ndef run(raw, sink):\n' + guard + '\n    sink(raw)\n'
    builds = []
    observed = []

    def fetch(repo_url, fix_hash, repo, timeout):
        repo.mkdir(parents=True)
        (repo / 'app.py').write_text(source)
        return True

    def build(repo, commit, *args, **kwargs):
        builds.append(commit)
        return True

    def tier0(**kwargs):
        result = sb.try_tier0(**kwargs)
        observed.append(result)
        return result

    def tier1(**kwargs):
        result = t1.try_tier1b(**kwargs)
        observed.append(result)
        return result

    monkeypatch.setattr(walk, '_fetch_pair', fetch)
    monkeypatch.setattr(walk, '_build_db', build)
    monkeypatch.setattr(bridge, '_run_query', lambda *args, **kwargs: True)
    proposal = bridge.BarrierProposal(sink_class, 'finding', 'sink(raw)', source, 'python')
    monkeypatch.setattr(bridge, '_extract_proposal',
                        lambda *args, **kwargs: (proposal, 'app.py', 4))
    monkeypatch.setattr(bridge, '_git_diff', lambda *args: '+' + guard + '\n')
    monkeypatch.setattr(bridge, '_TIER0_AVAILABLE', True)
    monkeypatch.setattr(bridge, '_TIER1B_AVAILABLE', True)
    if tier == 0:
        monkeypatch.setattr(bridge, 'try_tier0', tier0)
    else:
        monkeypatch.setattr(bridge, 'try_tier0', lambda **kwargs: sb.Tier0Result(
            sb.Tier0Status.NOT_APPLICABLE, 'exercise Tier1 source adjudication'))
    monkeypatch.setattr(bridge, 'try_tier1b', tier1)
    monkeypatch.setattr(bridge, 'run_synthesis_loop', lambda *args, **kwargs: SynthResult(
        query_ql='MOCK_LATER_QUERY', after_count=0, before_count=1))
    reply = json.dumps(dict(kind='charset', validator_source_line=guard.strip(),
                            variable_name='raw', charset='a-z', forbidden='', library_call=''))
    pair = CveFixPair('CVE-X', cwe, 'https://example.invalid/repo', 'Python', 'after', 'before')
    status, finding, backend, artifact, _ = bridge.synthesize_one(
        pair, work_dir=tmp_path / 'work', proposer=lambda *args: '',
        tier1b_complete=(lambda *args: reply) if tier else None,
    )
    assert len(observed) == 1
    diagnostic = observed[0]
    assert diagnostic.status is sb.Tier0Status.NOT_APPLICABLE
    assert diagnostic.artifact is None
    assert diagnostic.extras['smt_character_model']['sound'] is True
    assert diagnostic.extras['smt_character_model']['source_bound'] is False
    assert (status, finding, backend, artifact) == (
        'sound', 'finding', 'codeql', 'MOCK_LATER_QUERY',
    )
    assert builds == ['after', 'before']
