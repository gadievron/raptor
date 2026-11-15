"""A line-only value certificate cannot skip later sink evaluation rows."""
import json

import pytest

from core.dataflow.tests._epoch_character_contract import assert_epoch_character_model

from core.dataflow import smt_barrier as sb, tier1_llm


@pytest.mark.parametrize("consumer", ("tier0", "tier1"))
@pytest.mark.parametrize("local", (False, True), ids=("shared-slot", "local-slot"))
@pytest.mark.parametrize("descriptor", (False, True), ids=("direct", "descriptor"))
@pytest.mark.parametrize("multiline", (False, True), ids=("one-row", "multiple-rows"))
def test_sink_statement_requires_complete_row(tmp_path, consumer, local, descriptor, multiline):
    pytest.importorskip("z3")
    guard = '    if not re.fullmatch(r"[a-z]+", value): return'
    prefix = ('import re\nvalue = "abc"\nseen = []\n'
              'class Carrier:\n    @property\n    def consume(self):\n'
              '        global value\n        value = "<raw marker>"\n'
              '        return seen.append\ncarrier = Carrier()\nconsume = seen.append\n')
    callee = "carrier.consume" if descriptor else "consume"
    sink = ('    (\n        ' + callee + '\n    )(value)\n' if multiline
            else '    ' + callee + '(value)\n')
    header = prefix + ('def process(value):\n' if local else 'def process():\n') + guard + '\n'
    source = header + sink
    namespace = {}
    exec(compile(source, "owned-sink-rows.py", "exec"), namespace)
    namespace["process"](*(["abc"] if local else []))
    assert namespace["seen"] == (["<raw marker>"] if descriptor and not local else ["abc"])
    (tmp_path / "app.py").write_bytes(source.encode())
    arguments = dict(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                     sink_uri="app.py", sink_line=len(header.splitlines()) + 1,
                     sink_class="xss", language="python")
    if consumer == "tier0":
        result = sb.try_tier0(**arguments)
    else:
        reply = json.dumps({"kind": "charset", "validator_source_line": guard,
                            "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
        result = tier1_llm.try_tier1b(**arguments, complete=lambda *_: reply)
    refused = multiline or (descriptor and not local)
    assert_epoch_character_model(result, (sb.Tier0Status.NOT_APPLICABLE if refused else sb.Tier0Status.SOUND) is sb.Tier0Status.SOUND)
    if refused:
        assert result.artifact is None
