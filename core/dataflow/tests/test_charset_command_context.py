import json
import re
import shlex
from types import SimpleNamespace

import pytest

from core.dataflow import tier1_llm as t1
from core.dataflow import smt_barrier as sb


@pytest.mark.parametrize("tier", [0, 1])
def test_character_guard_does_not_restrict_command_name(tmp_path, tier):
    guard = '    if not re.fullmatch(r"[a-z]+", raw): return'
    source = 'import os, re\ndef run(raw):\n' + guard + '\n    os.system(raw)\n'
    calls = []
    owned_os = SimpleNamespace(system=calls.append)

    def owned_import(name, *args, **kwargs):
        assert name in {'os', 're'}
        return owned_os if name == 'os' else re

    namespace = {'__builtins__': {'__import__': owned_import}}
    exec(compile(source, 'owned-command-context.py', 'exec'), namespace)
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


@pytest.mark.parametrize("tier", [0, 1])
def test_tokenizer_guard_does_not_fix_executable_identity(tmp_path, tier):
    guard = '    if (!raw.matches("[a-z]+")) return;'
    source = ('class App {\n  void run(String raw) throws Exception {\n'
              '    Runtime runtime = Runtime.getRuntime();\n' + guard + '\n'
              '    runtime.exec(raw);\n  }\n}\n')
    assert re.fullmatch('[a-z]+', 'id') and re.fullmatch('[a-z]+', 'whoami')
    (tmp_path/'App.java').write_text(source)
    kwargs = dict(fix_diff='+'+guard+'\n', repo_root=tmp_path,
                  sink_uri='App.java', sink_line=5, sink_class='cmdi_argv', language='java')
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
    assert sb.prove_neutralizes(result.spec, 'cmdi_argv').sound
