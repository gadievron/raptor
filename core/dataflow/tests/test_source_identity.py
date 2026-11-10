"""Source namespace conflicts must invalidate a written library identity."""
from pathlib import Path

import pytest

from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available


@pytest.mark.skipif(not z3_available(), reason="z3-solver not installed")
def test_rebound_regex_root_cannot_certify_source(tmp_path: Path):
    source = (
        "import re\n"
        "re = replacement\n"
        "def handle(name):\n"
        '    if not re.fullmatch(r"[a-z]+", name):\n'
        "        return\n"
        "    return open(name)\n"
    )
    (tmp_path / "app.py").write_text(source)
    result = sb.try_tier0(
        fix_diff='+    if not re.fullmatch(r"[a-z]+", name):\n',
        repo_root=tmp_path, sink_uri="app.py", sink_line=6, sink_class="pathtrav",
    )
    assert result.status is sb.Tier0Status.NOT_APPLICABLE

    (tmp_path / "app.py").write_text(source.replace("re = replacement", "# canonical import"))
    control = sb.try_tier0(
        fix_diff='+    if not re.fullmatch(r"[a-z]+", name):\n',
        repo_root=tmp_path, sink_uri="app.py", sink_line=6, sink_class="pathtrav",
    )
    assert control.status is sb.Tier0Status.SOUND


@pytest.mark.skipif(not z3_available(), reason="z3-solver not installed")
@pytest.mark.parametrize("prefix,parameters", [
    ("import re\nre = replacement\n", "name"),
    ("import other as re\n", "name"),
    ("import re\n", "name, re"),
    ("import re\nre.fullmatch = lambda pattern, value: True\n", "name"),
    ("import re\nproxy = re\nproxy.fullmatch = lambda pattern, value: True\n", "name"),
    ("import re\nre.__dict__['fullmatch'] = lambda pattern, value: True\n", "name"),
    ("import re\nsetattr(re, 'fullmatch', lambda pattern, value: True)\n", "name"),
    ("import re\nexec('re.fullmatch = lambda pattern, value: True')\n", "name"),
    ("import re\ndef poison():\n    proxy = re\n    proxy.fullmatch = replacement\npoison()\n", "name"),
    ("import re\ndef poison():\n    vars(re)['fullmatch'] = replacement\npoison()\n", "name"),
    ("import re\ndef poison():\n    import re as rx\n    rx.fullmatch = replacement\npoison()\n", "name"),
    ("import re\ndef poison():\n    global re\n    proxy = re\n    proxy.fullmatch = replacement\npoison()\n", "name"),
    ("import re\ndef poison():\n    exec('re.fullmatch = replacement')\npoison()\n", "name"),
    ("import re\ndef poison():\n    eval('setattr(re, \"fullmatch\", replacement)')\npoison()\n", "name"),
    ("import re\ndef poison():\n    run = exec\n    run('re.fullmatch = replacement')\npoison()\n", "name"),
    ("import re\ndef poison():\n    from builtins import exec as run\n    run('re.fullmatch = replacement')\npoison()\n", "name"),
], ids=["root-rebind", "wrong-import", "parameter", "member-write", "alias-write",
        "namespace-dict", "setattr", "dynamic-namespace", "helper-alias", "helper-vars",
        "helper-import-alias", "helper-global", "helper-exec", "helper-eval",
        "helper-exec-alias", "helper-imported-exec"])
def test_regex_namespace_conflicts_reach_all_consumers(tmp_path: Path, prefix, parameters):
    import json
    from core.dataflow import injection_prescreen as ip
    from core.dataflow import tier1_llm as t1
    from core.dataflow.source_identity import known_python_identity_conflict

    line = '    if not re.fullmatch(r"[a-z]+", name):'
    source = prefix + "def handle(" + parameters + "):\n" + line + "\n        return\n    return open(name)\n"
    guard_line = len(prefix.splitlines()) + 2
    sink_line = len(source.splitlines())
    (tmp_path / "app.py").write_text(source)
    assert known_python_identity_conflict(source, guard_line, ("re.fullmatch",))
    spec = sb.extract_validator("+" + line + "\n")
    assert spec is not None
    refuted, _, _ = ip._step_refutes_path(
        spec=spec, step_file="app.py", step_line=guard_line,
        sink_file="app.py", sink_line=sink_line, source_text=source,
        language="python", sink_classes=frozenset({"pathtrav"}),
    )
    assert not refuted
    result = sb.try_tier0(
        fix_diff="+" + line + "\n", repo_root=tmp_path,
        sink_uri="app.py", sink_line=sink_line, sink_class="pathtrav",
    )
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    reply = json.dumps({
        "kind": "charset", "validator_source_line": line,
        "variable_name": "name", "charset": "a-z", "forbidden": "", "library_call": "",
    })
    pointed = t1.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path,
        sink_uri="app.py", sink_line=sink_line, sink_class="pathtrav",
        language="python", complete=lambda _system, _user: reply,
    )
    assert pointed.status is sb.Tier0Status.NOT_APPLICABLE


@pytest.mark.skipif(not z3_available(), reason="z3-solver not installed")
@pytest.mark.parametrize("body", ["return re", "re.fullmatch = replacement"])
def test_unrelated_parameter_does_not_shadow_regex_namespace(tmp_path: Path, body):
    from core.dataflow.source_identity import known_python_identity_conflict

    source = (
        "import re\ndef unrelated(re):\n    " + body + "\n"
        "def handle(name):\n"
        '    if not re.fullmatch(r"[a-z]+", name):\n'
        "        return\n    return open(name)\n"
    )
    assert known_python_identity_conflict(source, 5, ("re.fullmatch",)) is None
    (tmp_path / "app.py").write_text(source)
    control = sb.try_tier0(
        fix_diff='+    if not re.fullmatch(r"[a-z]+", name):\n', repo_root=tmp_path,
        sink_uri="app.py", sink_line=7, sink_class="pathtrav",
    )
    assert control.status is sb.Tier0Status.SOUND


@pytest.mark.skipif(not z3_available(), reason="z3-solver not installed")
def test_substitution_root_conflict_cannot_certify_source(tmp_path: Path):
    line = r'    name = re.sub(r"[/\\.]+", "", name)'
    source = "import other as re\ndef handle(name):\n" + line + "\n    return open(name)\n"
    (tmp_path / "app.py").write_text(source)
    result = sb.try_tier0(
        fix_diff="+" + line + "\n", repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="pathtrav",
    )
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    (tmp_path / "app.py").write_text(source.replace("import other as re", "import re"))
    control = sb.try_tier0(
        fix_diff="+" + line + "\n", repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="pathtrav",
    )
    assert control.status is sb.Tier0Status.SOUND


@pytest.mark.skipif(not z3_available(), reason="z3-solver not installed")
@pytest.mark.parametrize("prefix", [
    "import html\nhtml = replacement\n",
    "import other as html\n",
    "import html\nhtml.escape = lambda raw: raw\n",
], ids=["root-rebind", "wrong-import", "member-write"])
def test_curated_library_identity_conflict_retains_finding(tmp_path: Path, prefix):
    import json
    from core.dataflow import tier1_llm as t1

    line = "    safe = html.escape(raw)"
    source = prefix + "def handle(raw):\n" + line + "\n    return render(safe)\n"
    sink_line = len(source.splitlines())
    (tmp_path / "app.py").write_text(source)
    reply = json.dumps({
        "kind": "known_safe_call", "validator_source_line": line,
        "variable_name": "raw", "charset": "", "forbidden": "", "library_call": "html.escape",
    })
    result = t1.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path,
        sink_uri="app.py", sink_line=sink_line, sink_class="xss",
        language="python", complete=lambda _system, _user: reply,
    )
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "source" in result.reasoning
    control_source = "import html\ndef handle(raw):\n" + line + "\n    return render(safe)\n"
    (tmp_path / "app.py").write_text(control_source)
    control = t1.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=lambda _system, _user: reply,
    )
    assert control.status is sb.Tier0Status.SOUND


def test_identity_conflict_is_not_overridden_by_dominance(monkeypatch):
    def unexpected_dominance(**_kwargs):
        raise AssertionError("a separate dominance answer cannot establish callable identity")

    monkeypatch.setattr(sb, "_value_bound_dominates", unexpected_dominance)
    source = (
        "import other as re\ndef handle(name):\n"
        '    if not re.fullmatch(r"[a-z]+", name):\n'
        "        return\n    return open(name)\n"
    )
    assert not sb.validator_dominates_sink(source, 3, 5)


@pytest.mark.skipif(not z3_available(), reason="z3-solver not installed")
def test_unrelated_local_exec_parameter_is_not_dynamic_builtin(tmp_path: Path):
    source = (
        "import re\ndef unrelated(exec):\n    return exec('literal')\n"
        "def handle(name):\n"
        '    if not re.fullmatch(r"[a-z]+", name):\n'
        "        return\n    return open(name)\n"
    )
    (tmp_path / "app.py").write_text(source)
    result = sb.try_tier0(
        fix_diff='+    if not re.fullmatch(r"[a-z]+", name):\n', repo_root=tmp_path,
        sink_uri="app.py", sink_line=7, sink_class="pathtrav",
    )
    assert result.status is sb.Tier0Status.SOUND
