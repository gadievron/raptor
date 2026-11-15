"""Exiting failure-arm effects do not run on the certified sink path."""
import json

import pytest

from core.dataflow.tests._epoch_character_contract import assert_epoch_character_model

from core.dataflow import smt_barrier as sb, tier1_llm


@pytest.mark.parametrize("consumer", ("tier0", "tier1"))
@pytest.mark.parametrize("action", ("mutate()", "probe.item", "probe and None"))
def test_exiting_failure_arm_keeps_successful_guard_eligible(tmp_path, consumer, action):
    pytest.importorskip("z3")
    guard = '    if not re.fullmatch(r"[a-z]+", value): ' + action + '; return'
    source = ('import re\nvalue = "abc"\n'
              'def mutate():\n    global value\n    value = "<raw marker>"\n'
              'class Probe:\n    @property\n    def item(self):\n        mutate()\n        return None\n'
              '    def __bool__(self):\n        mutate()\n        return True\nprobe = Probe()\n'
              'def process():\n' + guard + '\n    sink(value)\n')
    seen = []
    namespace = {"sink": seen.append}
    exec(compile(source, "owned-failure-arm.py", "exec"), namespace)
    namespace["process"]()
    namespace["value"] = "<unsafe>"
    namespace["process"]()
    assert seen == ["abc"]
    assert namespace["value"] == "<raw marker>"
    (tmp_path / "app.py").write_bytes(source.encode())
    arguments = dict(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                     sink_uri="app.py", sink_line=len(source.splitlines()), sink_class="xss", language="python")
    if consumer == "tier0":
        result = sb.try_tier0(**arguments)
    else:
        reply = json.dumps({"kind": "charset", "validator_source_line": guard,
                            "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
        result = tier1_llm.try_tier1b(**arguments, complete=lambda *_: reply)
    assert_epoch_character_model(result, (sb.Tier0Status.SOUND) is sb.Tier0Status.SOUND)
