"""A successful same-row guard body cannot freeze a shared value slot."""
import json

import pytest

from core.dataflow import smt_barrier as sb, tier1_llm


@pytest.mark.parametrize("consumer", ("tier0", "tier1"))
@pytest.mark.parametrize("local", (False, True), ids=("shared", "parameter"))
@pytest.mark.parametrize("effect", ("pass", "call", "descriptor", "operator"))
@pytest.mark.parametrize("inline", (False, True), ids=("next-row", "same-row"))
def test_positive_guard_success_body_preserves_only_owned_slots(tmp_path, consumer, local, effect, inline):
    pytest.importorskip("z3")
    prefix = ('import re\nvalue = "abc"\n'
              'def mutate():\n    global value\n    value = "<raw marker>"\n'
              'class Probe:\n    @property\n    def item(self):\n        mutate()\n        return None\n'
              '    def __bool__(self):\n        mutate()\n        return True\nprobe = Probe()\n')
    action = {"pass": "pass", "call": "mutate()", "descriptor": "probe.item", "operator": "probe and None"}[effect]
    guard = '    if re.fullmatch(r"[a-z]+", value):' + (' ' + action if inline else '')
    header = prefix + ('def process(value):\n' if local else 'def process():\n')
    source = header + guard + '\n' + ('' if inline else '        ' + action + '\n')
    source += '    else: return\n    sink(value)\n'
    seen = []
    namespace = {"sink": seen.append}
    exec(compile(source, "owned-positive-guard.py", "exec"), namespace)
    namespace["process"](*(["abc"] if local else []))
    unsafe = effect != "pass" and not local
    assert seen == (["<raw marker>"] if unsafe else ["abc"])
    (tmp_path / "app.py").write_bytes(source.encode())
    arguments = dict(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                     sink_uri="app.py", sink_line=len(source.splitlines()), sink_class="xss", language="python")
    if consumer == "tier0":
        result = sb.try_tier0(**arguments)
    else:
        reply = json.dumps({"kind": "charset", "validator_source_line": guard,
                            "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
        result = tier1_llm.try_tier1b(**arguments, complete=lambda *_: reply)
    assert result.status is (sb.Tier0Status.NOT_APPLICABLE if unsafe else sb.Tier0Status.SOUND), result.reasoning
    if unsafe:
        assert result.artifact is None
