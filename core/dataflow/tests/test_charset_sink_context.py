import io
from html.parser import HTMLParser
import json

import pytest

from core.dataflow import smt_barrier as sb
from core.dataflow import tier1_llm as t1


@pytest.mark.parametrize("tier", [0, 1])
def test_character_guard_does_not_validate_url_scheme(tmp_path, tier):
    guard = '    if not re.fullmatch(r"[a-z]+", raw): return'
    source = ('import re\ndef render(raw, out):\n'
              '    out.write(\'<a href="\')\n' + guard + '\n'
              '    out.write(raw)\n    out.write(\':alert(1)">link</a>\')\n')
    namespace = {}
    exec(compile(source, 'owned-context.py', 'exec'), namespace)
    output = io.StringIO()
    namespace['render']('javascript', output)
    class Observe(HTMLParser):
        def handle_starttag(self, tag, attrs):
            self.attrs = dict(attrs)
    parsed = Observe()
    parsed.feed(output.getvalue())
    assert parsed.attrs['href'] == 'javascript:alert(1)'
    (tmp_path/'app.py').write_bytes(source.encode())
    kwargs = dict(fix_diff='+'+guard+'\n', repo_root=tmp_path,
                  sink_uri='app.py', sink_line=5, sink_class='xss', language='python')
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
    assert sb.prove_neutralizes(result.spec, 'xss').sound
