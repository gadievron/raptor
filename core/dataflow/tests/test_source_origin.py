"""Repository import shadows cannot supply canonical library certificates."""
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from core.dataflow import smt_barrier as sb
from core.dataflow import injection_prescreen as ip
from core.dataflow import tier1_llm as t1
from core.smt_solver import z3_available


@pytest.fixture(autouse=True)
def isolated_prescreen_stats(monkeypatch):
    monkeypatch.setattr(ip, "_STATS", ip.PrescreenStats())


@pytest.mark.skipif(not z3_available(), reason="z3-solver not installed")
@pytest.mark.parametrize("shadow", ["re.py", "re/__init__.py", "app/re.py", "app/re/__init__.py"])
def test_regex_import_origin_reaches_all_consumers(tmp_path: Path, shadow):
    line = '    if not re.fullmatch(r"[a-z]+", name):'
    source = "import re\ndef handle(name):\n" + line + "\n        return\n    return open(name)\n"
    subject = tmp_path / "app/handler.py"
    subject.parent.mkdir()
    subject.write_text(source)
    shadow_path = tmp_path / shadow
    shadow_path.parent.mkdir(parents=True, exist_ok=True)
    shadow_path.write_text("def fullmatch(*args): return True\n")

    def adjudicate():
        mechanical = sb.try_tier0(
            fix_diff="+" + line + "\n", repo_root=tmp_path,
            sink_uri="app/handler.py", sink_line=5, sink_class="pathtrav",
        )
        reply = json.dumps({"kind": "charset", "validator_source_line": line,
                            "variable_name": "name", "charset": "a-z",
                            "forbidden": "", "library_call": ""})
        pointed = t1.try_tier1b(
            fix_diff="+" + line + "\n", repo_root=tmp_path,
            sink_uri="app/handler.py", sink_line=5, sink_class="pathtrav",
            language="python", complete=lambda _system, _user: reply,
        )
        def step(n):
            return SimpleNamespace(file_path="app/handler.py", line=n, column=1,
                                   snippet="", label="step")
        path = SimpleNamespace(source=step(2), sink=step(5), intermediate_steps=[step(3)])
        prescreen = ip.prescreen_finding(paths=[path], repo_root=tmp_path,
                                        rule_id="py/path-injection")
        return mechanical, pointed, prescreen

    mechanical, pointed, prescreen = adjudicate()
    assert mechanical.status is sb.Tier0Status.NOT_APPLICABLE
    assert "origin" in mechanical.reasoning
    assert pointed.status is sb.Tier0Status.NOT_APPLICABLE
    assert "origin" in pointed.reasoning
    assert prescreen is None or not prescreen.refuted
    shadow_path.unlink()
    mechanical, pointed, prescreen = adjudicate()
    assert mechanical.status is sb.Tier0Status.SOUND
    assert pointed.status is sb.Tier0Status.SOUND
    assert prescreen is not None and prescreen.refuted


@pytest.mark.skipif(not z3_available(), reason="z3-solver not installed")
@pytest.mark.parametrize("shadow", ["html.py", "app/html/__init__.py"])
def test_curated_import_origin_cannot_certify_source(tmp_path: Path, shadow):
    line = "    safe = html.escape(raw)"
    subject = tmp_path / "app/handler.py"
    subject.parent.mkdir()
    subject.write_text(
        "import html\ndef handle(raw):\n    if type(raw) is not str: return\n"
        + line + "\n    return render(safe)\n"
    )
    shadow_path = tmp_path / shadow
    shadow_path.parent.mkdir(parents=True, exist_ok=True)
    shadow_path.write_text("def escape(value): return value\n")
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": "html.escape"})
    def adjudicate():
        return t1.try_tier1b(
            fix_diff="+" + line + "\n", repo_root=tmp_path,
            sink_uri="app/handler.py", sink_line=5, sink_class="xss",
            language="python", complete=lambda _system, _user: reply,
        )
    result = adjudicate()
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "origin" in result.reasoning
    shadow_path.unlink()
    assert adjudicate().status is sb.Tier0Status.SOUND


def test_unrelated_sibling_module_is_not_a_known_origin_conflict(tmp_path: Path):
    from core.dataflow.source_identity import known_python_origin_conflict

    sibling = tmp_path / "unrelated/re.py"
    sibling.parent.mkdir()
    sibling.write_text("# an unrelated import-search directory\n")
    assert known_python_origin_conflict(tmp_path, tmp_path / "app/handler.py", "re") is None
    assert known_python_origin_conflict(tmp_path, tmp_path.parent / "outside.py", "re")


@pytest.mark.skipif(not z3_available(), reason="z3-solver not installed")
def test_substitution_import_origin_is_checked_before_certificate(tmp_path: Path):
    line = r'    name = re.sub(r"[/\\.]+", "", name)'
    (tmp_path / "app.py").write_text("import re\ndef handle(name):\n" + line + "\n    return open(name)\n")
    shadow = tmp_path / "re.py"
    shadow.write_text("def sub(pattern, replacement, value): return value\n")
    def adjudicate():
        return sb.try_tier0(fix_diff="+" + line + "\n", repo_root=tmp_path,
                            sink_uri="app.py", sink_line=4, sink_class="pathtrav")
    result = adjudicate()
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "origin" in result.reasoning
    shadow.unlink()
    assert adjudicate().status is sb.Tier0Status.SOUND
