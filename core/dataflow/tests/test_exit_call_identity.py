"""Written exit-call spellings do not establish that a guard terminates."""

import json

import pytest

from core.dataflow import injection_prescreen, smt_barrier as sb, tier1_llm


@pytest.fixture(autouse=True)
def native():
    pytest.importorskip("z3")


def source(call, parameter=""):
    guard = ' if not re.fullmatch(r"[a-z]+", value): ' + call
    text = "import re\nimport sys\ndef handle(value" + parameter + "):\n" + guard + "\n consume(value)\n"
    return guard, text


@pytest.mark.parametrize("call,parameter", [
    ("exit()", ", exit"), ("quit()", ", quit"), ("sys.exit()", ", sys"),
])
def test_shadowed_exit_call_cannot_establish_guard_dominance(tmp_path, call, parameter):
    guard, text = source(call, parameter)
    (tmp_path / "app.py").write_text(text)
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                         sink_uri="app.py", sink_line=5, sink_class="xss", language="python")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert result.artifact is None


@pytest.mark.parametrize("call", ["exit()", "quit()", "sys.exit()"])
def test_unshadowed_existing_exit_profiles_remain_eligible(tmp_path, call):
    guard, text = source(call)
    # A separate function's callback parameter does not shadow this guard.
    text += "\ndef unrelated(exit):\n return exit()\n"
    (tmp_path / "app.py").write_text(text)
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                         sink_uri="app.py", sink_line=5, sink_class="xss", language="python")
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_shadowed_handler_exit_cannot_hide_a_validation_failure(tmp_path):
    guard = '  if not re.fullmatch(r"[a-z]+", value): raise ValueError()'
    text = ("import re\ndef handle(value, exit):\n try:\n" + guard
            + "\n except ValueError:\n  exit()\n consume(value)\n")
    (tmp_path / "app.py").write_text(text)
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                         sink_uri="app.py", sink_line=7, sink_class="xss", language="python")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


def test_mutated_sys_exit_member_is_not_trusted(tmp_path):
    guard, text = source("sys.exit()")
    text = text.replace("def handle", "sys.exit = lambda: None\ndef handle")
    (tmp_path / "app.py").write_text(text)
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                         sink_uri="app.py", sink_line=6, sink_class="xss", language="python")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


def test_closure_callback_named_exit_is_not_a_builtin(tmp_path):
    guard = '  if not re.fullmatch(r"[a-z]+", value): exit()'
    text = ("import re\ndef factory(exit):\n def handle(value):\n" + guard
            + "\n  consume(value)\n return handle\n")
    (tmp_path / "app.py").write_text(text)
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                         sink_uri="app.py", sink_line=5, sink_class="xss", language="python")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


def test_substitution_handler_exit_needs_the_same_identity_check():
    text = ("import re\ndef handle(value, exit):\n try:\n"
            "  value = re.sub(r'[ ]+', '', value)\n except Exception:\n  exit()\n consume(value)\n")
    assert sb.substitution_dominates_sink(text, 4, 7, "value") is False
    assert sb.substitution_dominates_sink(text.replace("  exit()", "  return"), 4, 7, "value") is True


def test_exit_identity_refusal_reaches_tier1_and_prescreen(tmp_path):
    guard, text = source("exit()", ", exit")
    (tmp_path / "app.py").write_text(text)
    reply = json.dumps({"kind": "charset", "validator_source_line": guard.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                                 sink_uri="app.py", sink_line=5, sink_class="xss", language="python",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    spec = sb.extract_validator_from_line(guard, "python")
    assert spec is not None
    refuted, _, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.py", step_line=4, sink_file="app.py", sink_line=5,
        source_text=text, language="python", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False
