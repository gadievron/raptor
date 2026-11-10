"""Whole-source proof admission must preserve reader completeness."""
import pytest

from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available

GUARD = "    if not re.fullmatch(r'[a-z]+', value): return"
PREFIX = "import re\ndef handle(value):\n" + GUARD + "\n    consume(value)\n"


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
def test_tier0_rejects_truncated_source_even_when_sink_is_visible(tmp_path, monkeypatch):
    path = tmp_path / "app.py"
    path.write_text(PREFIX + "# padding\n" * 40 + "re = supplied_validator\n")
    arguments = dict(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                     sink_uri="app.py", sink_line=4, sink_class="xss", language="python")
    complete = sb.try_tier0(**arguments)
    assert complete.status is sb.Tier0Status.NOT_APPLICABLE
    real = sb.read_text_capped

    def capped(path, **kwargs):
        result = real(path, len(PREFIX), **kwargs)
        assert result == (PREFIX, True)
        return result

    monkeypatch.setattr(sb, "read_text_capped", capped)
    result = sb.try_tier0(**arguments)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "truncated" in result.reasoning


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
def test_complete_source_remains_eligible(tmp_path):
    (tmp_path / "app.py").write_text(PREFIX)
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="app.py", sink_line=4, sink_class="xss", language="python")
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_tier1_rejects_truncated_source_with_visible_sink(tmp_path, monkeypatch):
    import json
    from core.dataflow import tier1_llm as tier1

    (tmp_path / "app.py").write_text(PREFIX + "# padding\n" * 40 + "re = supplied_validator\n")
    real = tier1.read_text_capped
    monkeypatch.setattr(tier1, "read_text_capped", lambda path, **kw: real(path, len(PREFIX), **kw))
    reply = json.dumps({"kind": "charset", "validator_source_line": GUARD.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1.try_tier1b(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                             sink_uri="app.py", sink_line=4, sink_class="xss", language="python",
                             complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.extras["unverified_source_profile"] == "truncated_source"


def test_prescreen_requires_complete_exact_source(tmp_path, monkeypatch):
    from core.dataflow import injection_prescreen as prescreen

    path = tmp_path / "app.py"
    path.write_bytes(PREFIX.encode() + b"# padding\n" * 40)
    real = prescreen.read_contained_bytes
    with monkeypatch.context() as patch:
        patch.setattr(prescreen, "read_contained_bytes", lambda root, rel, cap: real(root, rel, len(PREFIX)))
        assert prescreen._read_source(tmp_path, "app.py") is None
    exact = b"# carriage\rreturn\n" + PREFIX.encode()
    path.write_bytes(exact)
    assert prescreen._read_source(tmp_path, "app.py") == exact.decode()
    path.write_bytes(b"# invalid UTF-8: \xff\n" + PREFIX.encode())
    assert prescreen._read_source(tmp_path, "app.py") is None
