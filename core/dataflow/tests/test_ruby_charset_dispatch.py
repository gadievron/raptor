"""Ruby match syntax does not establish the receiver's dispatch target."""
import json
import re

import pytest

from core.dataflow import smt_barrier as sb
from core.dataflow import tier1_llm as t1


@pytest.mark.parametrize('tier', [0, 1], ids=['tier0', 'tier1'])
@pytest.mark.parametrize('visible_override', [False, True], ids=['external', 'visible'])
@pytest.mark.parametrize('guard', [
    r'  raise ArgumentError unless name =~ /\A[a-z]+\z/',
    r'  return if name !~ /\A[a-z]+\z/',
], ids=['unless', 'if-not'])
def test_ruby_match_dispatch_needs_a_receiver_contract(
    tmp_path, tier, visible_override, guard,
):
    prefix = ('class Unchecked < String\n  def =~(pattern)\n    0\n  end\nend\n'
              if visible_override else '')
    source = prefix + 'def read_config(name)\n' + guard + '\n  File.open(name)\nend\n'
    if visible_override:
        source += 'read_config(Unchecked.new("../secret"))\n'
    assert re.fullmatch('[a-z]+', '../secret') is None
    (tmp_path / 'app.rb').write_text(source)
    kwargs = dict(fix_diff='+' + guard + '\n', repo_root=tmp_path,
                  sink_uri='app.rb', sink_line=prefix.count('\n') + 3,
                  sink_class='pathtrav', language='ruby')
    if tier == 0:
        result = sb.try_tier0(**kwargs)
    else:
        reply = json.dumps(dict(kind='charset', validator_source_line=guard.strip(),
                                variable_name='name', charset='a-z', forbidden='',
                                library_call='', receiver_dispatch='verified'))
        result = t1.try_tier1b(**kwargs, complete=lambda *_: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras['unverified_source_contracts'] == [sb.RUBY_CHARSET_DISPATCH_CONTRACT]
    assert result.extras['smt_character_model']['sound'] is True
    assert result.extras['smt_character_model']['source_bound'] is False
    assert sb.prove_neutralizes(result.spec, 'pathtrav').sound
