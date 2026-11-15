import json
from types import SimpleNamespace

import pytest

from core.dataflow import tier1_llm as t1
from core.dataflow import smt_barrier as sb


@pytest.mark.parametrize("tier", [0, 1])
def test_character_guard_does_not_establish_sql_value_context(tmp_path, tier):
    guard = '    if not re.fullmatch(r"[A-Z]+", raw): return'
    source = 'import re\ndef run(raw, cursor):\n'+guard+'\n    cursor.execute(raw)\n'
    namespace = {}
    exec(compile(source, 'owned-sql-context.py', 'exec'), namespace)
    statements = []
    cursor = SimpleNamespace(execute=statements.append)
    namespace['run']('COMMIT', cursor)
    namespace['run']('ROLLBACK', cursor)
    assert statements == ['COMMIT', 'ROLLBACK']
    (tmp_path/'app.py').write_text(source)
    kwargs = dict(fix_diff='+'+guard+'\n', repo_root=tmp_path,
                  sink_uri='app.py', sink_line=4, sink_class='sqli', language='python')
    if tier == 0:
        result = sb.try_tier0(**kwargs)
    else:
        reply = json.dumps(dict(kind='charset', validator_source_line=guard.strip(),
                                variable_name='raw', charset='A-Z', forbidden='',
                                library_call=''))
        result = t1.try_tier1b(**kwargs, complete=lambda *_: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras['smt_character_model']['sound'] is True
    assert result.extras['smt_character_model']['source_bound'] is False
    assert sb.prove_neutralizes(result.spec, 'sqli').sound
