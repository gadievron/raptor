"""Exception-group dispatch can replace externally owned value slots."""
import ast
import json

import pytest

from core.dataflow import smt_barrier as sb, tier1_llm


@pytest.mark.parametrize("consumer", ("tier0", "tier1"))
@pytest.mark.parametrize("slot", ("shared", "parameter", "snapshot"))
@pytest.mark.parametrize("group_handler", (False, True), ids=("ordinary", "except-star"))
def test_exception_group_dispatch_requires_current_value(tmp_path, consumer, slot, group_handler):
    pytest.importorskip("z3")
    guard = '    if not re.fullmatch(r"[a-z]+", value): return'
    source = ('import re\nvalue = "abc"\n'
              'class Group(ExceptionGroup):\n    def derive(self, exceptions):\n'
              '        global value\n        value = "<raw marker>"\n'
              '        return ExceptionGroup(self.message, exceptions)\n'
              + ('def process(value):\n' if slot == "parameter" else 'def process():\n')
              + guard + '\n' + ('    alias = value\n' if slot == "snapshot" else '')
              + '    try:\n        raise\n')
    source += ('    except* ValueError:\n        pass\n    except* TypeError:\n        pass\n'
               if group_handler else '    except ExceptionGroup:\n        pass\n')
    source += ('    sink(alias)\n' if slot == "snapshot" else '    sink(value)\n')
    sink_line = len(source.splitlines())
    source += ('try:\n    raise Group("owned", [ValueError(), TypeError()])\n'
               'except Group:\n    process(' + ('"abc"' if slot == "parameter" else '') + ')\n')
    seen = []
    exec(compile(source, "owned-exception-group.py", "exec"), {"sink": seen.append})
    unsafe = group_handler and slot == "shared"
    assert seen == (["<raw marker>"] if unsafe else ["abc"])
    (tmp_path / "app.py").write_bytes(source.encode())
    arguments = dict(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                     sink_uri="app.py", sink_line=sink_line, sink_class="xss", language="python")
    if consumer == "tier0":
        result = sb.try_tier0(**arguments)
    else:
        reply = json.dumps({"kind": "charset", "validator_source_line": guard,
                            "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
        result = tier1_llm.try_tier1b(**arguments, complete=lambda *_: reply)
    assert result.status is (sb.Tier0Status.NOT_APPLICABLE if unsafe else sb.Tier0Status.SOUND), result.reasoning
    if unsafe:
        assert result.artifact is None


@pytest.mark.parametrize("star", (False, True))
def test_unnamed_handler_effect_is_bound_to_its_scope(star):
    keyword = "except* ValueError" if star else "except ValueError"
    tree = ast.parse('def process():\n    try:\n        raise\n    ' + keyword + ':\n        pass\n')
    function = tree.body[0]
    handler = function.body[0].handlers[0]
    assert sb._python_scope_possible_calls(function)(handler) is star
