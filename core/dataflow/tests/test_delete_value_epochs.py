"""Deleting a global can expose a different builtin value under the same name."""

import builtins
import json

import pytest

from core.dataflow import injection_prescreen, smt_barrier as sb, tier1_llm

GUARD = ' if not re.fullmatch(r"[a-z]+", __doc__): return'


@pytest.fixture(autouse=True)
def native():
    pytest.importorskip("z3")


def source(change, sink="__doc__"):
    lines = ["import re", '__doc__ = "abc"', "def handle():", " global __doc__", GUARD]
    lines += change.splitlines()
    lines.append(" consume(" + sink + ")")
    return "\n".join(lines) + "\n", len(lines)


@pytest.mark.parametrize("change", [
    " del __doc__",
    " def remove():\n  global __doc__\n  del __doc__\n remove()",
    " class Remove:\n  global __doc__\n  del __doc__",
], ids=["global-delete", "nested-global-delete", "class-global-delete"])
def test_global_deletion_cannot_reuse_the_old_charset(tmp_path, change):
    assert type(builtins.__doc__) is str and " " in builtins.__doc__
    text, sink_line = source(change)
    (tmp_path / "app.py").write_text(text)
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="app.py", sink_line=sink_line, sink_class="xss", language="python")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert result.artifact is None


@pytest.mark.parametrize("change,sink", [
    (" alias = __doc__\n del __doc__", "alias"),
    (' other = "abc"\n del other', "__doc__"),
], ids=["preserved-alias", "unrelated-delete"])
def test_deletion_does_not_remove_other_value_epochs(tmp_path, change, sink):
    text, sink_line = source(change, sink)
    (tmp_path / "app.py").write_text(text)
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="app.py", sink_line=sink_line, sink_class="xss", language="python")
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_substitution_epoch_also_ends_at_global_deletion():
    text = ("import re\ndef handle():\n global __doc__\n"
            " __doc__ = re.sub(r'[ ]+', '', __doc__)\n del __doc__\n consume(__doc__)\n")
    assert not sb.substitution_dominates_sink(text, 4, 6, "__doc__")
    assert sb.substitution_dominates_sink(text.replace(" del __doc__", " pass"), 4, 6, "__doc__")


def test_deletion_refusal_reaches_tier1_and_prescreen(tmp_path):
    text, sink_line = source(" del __doc__")
    (tmp_path / "app.py").write_text(text)
    reply = json.dumps({"kind": "charset", "validator_source_line": GUARD.strip(),
                        "variable_name": "__doc__", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                                 sink_uri="app.py", sink_line=sink_line, sink_class="xss", language="python",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    spec = sb.extract_validator_from_line(GUARD, "python")
    assert spec is not None
    refuted, _, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.py", step_line=5, sink_file="app.py", sink_line=sink_line,
        source_text=text, language="python", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False


def test_curated_transform_epoch_ends_at_deletion(tmp_path):
    line = " __doc__ = html.escape(raw)"
    text = ("import html\ndef handle(raw):\n global __doc__\n"
            " if type(raw) is not str: return\n" + line + "\n del __doc__\n render(__doc__)\n")
    (tmp_path / "app.py").write_text(text)
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line.strip(),
                        "variable_name": "raw", "charset": "", "forbidden": "", "library_call": "html.escape"})

    def check():
        return tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                   sink_uri="app.py", sink_line=7, sink_class="xss", language="python",
                                   complete=lambda *_args: reply)

    result = check()
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    (tmp_path / "app.py").write_text(text.replace(" del __doc__", " pass"))
    control = check()
    assert control.status is sb.Tier0Status.SOUND, control.reasoning
