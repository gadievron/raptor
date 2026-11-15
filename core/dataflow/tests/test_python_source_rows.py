"""Raw proof rows must agree with Python AST rows before certification."""
import json

import pytest

from core.dataflow import injection_prescreen, smt_barrier as sb, tier1_llm
from core.dataflow.source_identity import known_python_identity_conflict


PROFILES = ("lf", "crlf", "bare-cr", "unicode-comment")
GUARD = '    if not re.fullmatch(r"[a-z]+", value): return'


def source_text(profile, body):
    prefix = "# pad\r# pad\r# pad\n" if profile == "bare-cr" else "# pad\n"
    if profile == "unicode-comment":
        prefix = "# pad\u2028\u2029\u0085\v\fstill-comment\n"
    text = prefix + body
    return text.replace("\n", "\r\n") if profile == "crlf" else text


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("overwritten", (False, True))
def test_reported_sink_row_cannot_borrow_an_earlier_sink(tmp_path, profile, overwritten):
    pytest.importorskip("z3")
    body = "import re\ndef process(value):\n" + (GUARD + "\n") * 3
    if overwritten:
        body += "    sink(value)\n    value = '<raw marker>'\n"
    source = source_text(profile, body + "    sink(value)\n")
    seen = []
    namespace = {"sink": seen.append}
    exec(compile(source, "owned-source-rows.py", "exec"), namespace)
    namespace["process"]("abc")
    assert seen == (["abc", "<raw marker>"] if overwritten else ["abc"])
    (tmp_path / "app.py").write_bytes(source.encode())
    sink_line = len(source.split("\n")) - 1
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                          sink_uri="app.py", sink_line=sink_line, sink_class="xss")
    expected = sb.Tier0Status.NOT_APPLICABLE if overwritten or profile == "bare-cr" else sb.Tier0Status.SOUND
    assert result.status is expected, result.reasoning
    if expected is sb.Tier0Status.NOT_APPLICABLE:
        assert result.artifact is None


@pytest.mark.parametrize("profile", PROFILES)
def test_curated_call_requires_verified_source_rows(tmp_path, profile):
    line = "    safe = html.escape('abc')"
    source = source_text(profile, "import html\ndef process():\n    pass\n    pass\n" + line + "\n    sink(safe)\n")
    (tmp_path / "app.py").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "safe", "charset": "", "forbidden": "",
                        "library_call": "html.escape", "exact_type": "str"})
    result = tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                 sink_uri="app.py", sink_line=len(source.split("\n")) - 1,
                                 sink_class="xss", language="python", complete=lambda *_: reply)
    if profile == "bare-cr":
        assert result.status is sb.Tier0Status.NOT_APPLICABLE
        assert "bare carriage returns" in result.reasoning
        assert result.artifact is None
    else:
        assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize("profile", PROFILES)
def test_prescreen_uses_the_same_row_profile(profile):
    pytest.importorskip("z3")
    source = source_text(profile, "import re\ndef process(value):\n" + (GUARD + "\n") * 3 + "    sink(value)\n")
    spec = sb.extract_validator_from_line(GUARD, "python")
    assert spec is not None
    refuted, _, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.py", step_line=6, sink_file="app.py", sink_line=7,
        source_text=source, language="python", sink_classes=frozenset({"xss"}),
    )
    assert refuted is (profile != "bare-cr")


@pytest.mark.parametrize("tail", ("\r", "\r\r\n", "\r\n\r"))
def test_unpaired_carriage_returns_never_establish_source_identity(tail):
    source = "import html\ndef process():\n    safe = html.escape('abc')\n" + "# tail" + tail
    conflict = known_python_identity_conflict(source, 3, ("html.escape",))
    assert conflict is not None and "bare carriage returns" in conflict
