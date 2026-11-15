import json
import os
import shlex

import pytest

from core.dataflow import tier1_llm as t1
from core.dataflow import smt_barrier as sb


@pytest.mark.parametrize("tier", [0, 1])
def test_character_guard_does_not_restrict_command_name(tmp_path, monkeypatch, tier):
    guard = '    if not re.fullmatch(r"[a-z]+", raw): return'
    source = 'import os, re\ndef run(raw):\n' + guard + '\n    os.system(raw)\n'
    namespace = {}
    exec(compile(source, 'owned-command-context.py', 'exec'), namespace)
    calls = []
    with monkeypatch.context() as patch:
        patch.setattr(os, 'system', calls.append)
        namespace['run']('id')
        namespace['run']('whoami')
    assert calls == ['id', 'whoami']
    assert [shlex.split(call) for call in calls] == [['id'], ['whoami']]
    (tmp_path / 'app.py').write_text(source)
    kwargs = dict(fix_diff='+' + guard + '\n', repo_root=tmp_path,
                  sink_uri='app.py', sink_line=4, sink_class='cmdi', language='python')
    if tier == 0:
        result = sb.try_tier0(**kwargs)
    else:
        reply = json.dumps(dict(kind='charset', validator_source_line=guard.strip(),
                                variable_name='raw', charset='a-z', forbidden='',
                                library_call=''))
        result = t1.try_tier1b(**kwargs, complete=lambda *_: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras['smt_character_model']['sound'] is True
    assert result.extras['smt_character_model']['source_bound'] is False
    assert sb.prove_neutralizes(result.spec, 'cmdi').sound
