"""Suppressed validation exceptions cannot certify code after a with body."""

import json

import pytest

from core.dataflow import injection_prescreen, smt_barrier as sb, tier1_llm

GUARD = '  if not re.fullmatch(r"[a-z]+", value): raise ValueError()'


@pytest.fixture(autouse=True)
def native():
    pytest.importorskip("z3")


def source(*, asynchronous=False, inside=False):
    return ("import re\nfrom contextlib import suppress\n"
            + ("async " if asynchronous else "") + "def handle(value, manager):\n "
            + ("async with manager:" if asynchronous else "with suppress(ValueError):")
            + "\n" + GUARD + "\n" + ("  " if inside else " ") + "consume(value)\n")


@pytest.mark.parametrize("asynchronous", [False, True], ids=["with", "async-with"])
@pytest.mark.parametrize("inside", [False, True], ids=["outside-body", "inside-body"])
def test_guard_exception_ownership_controls_certification(tmp_path, asynchronous, inside):
    (tmp_path / "app.py").write_text(source(asynchronous=asynchronous, inside=inside))
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="app.py", sink_line=6, sink_class="xss", language="python")
    expected = sb.Tier0Status.SOUND if inside else sb.Tier0Status.NOT_APPLICABLE
    assert result.status is expected, result.reasoning
    if not inside:
        assert result.artifact is None


@pytest.mark.parametrize("inside", [False, True], ids=["outside-body", "inside-body"])
def test_substitution_uses_the_same_protected_body_boundary(inside):
    text = ("import re\ndef handle(value, manager):\n with manager:\n"
            "  value = re.sub(r'[ ]+', '', value)\n"
            + ("  " if inside else " ") + "consume(value)\n")
    assert sb.substitution_dominates_sink(text, 4, 5, "value") is inside


def test_guard_refusal_reaches_tier1_and_prescreen(tmp_path):
    text = source()
    (tmp_path / "app.py").write_text(text)
    reply = json.dumps({"kind": "charset", "validator_source_line": GUARD.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                                 sink_uri="app.py", sink_line=6, sink_class="xss", language="python",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    spec = sb.extract_validator_from_line(GUARD, "python")
    assert spec is not None
    refuted, _, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.py", step_line=5, sink_file="app.py", sink_line=6,
        source_text=text, language="python", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False


def test_curated_call_also_refuses_a_sink_after_the_context_body(tmp_path):
    line = "  safe = html.escape(raw)"
    text = "import html\ndef handle(raw, manager):\n safe = raw\n with manager:\n" + line + "\n return render(safe)\n"
    (tmp_path / "app.py").write_text(text)
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line.strip(),
                        "variable_name": "raw", "charset": "", "forbidden": "", "library_call": "html.escape"})
    result = tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                 sink_uri="app.py", sink_line=6, sink_class="xss", language="python",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "caught" in result.reasoning
