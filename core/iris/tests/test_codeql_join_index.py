"""Inert CodeQL result joins: no tool discovery or native execution."""

from types import SimpleNamespace

from core.iris import codeql_runner as module
from core.iris import specs as spec_module
from core.iris.specs import TaintSpec, spec_message_token
from core.iris.store import _spec_key


def test_result_round_builds_spec_index_once(tmp_path, monkeypatch):
    import packages.codeql as package
    from packages.codeql import query_runner

    specs = [TaintSpec(file=f"f{i}.c", function="read", role="source") for i in range(16)]
    message = f"[src={spec_message_token(specs[0])} sink={spec_message_token(specs[1])}]"
    calls = []
    original = spec_module.spec_message_token

    def counted(spec):
        calls.append(spec.file)
        return original(spec)

    monkeypatch.setattr(spec_module, "spec_message_token", counted)
    monkeypatch.setattr(package, "is_available", lambda: True)
    result = SimpleNamespace(success=True, sarif_path=tmp_path / "inert.sarif", errors=[])
    fake_runner = SimpleNamespace(run_local_pack=lambda *args, **kwargs: result)
    monkeypatch.setattr(query_runner, "QueryRunner", lambda: fake_runner)
    monkeypatch.setattr(query_runner, "vendored_stdlib_roots", lambda *args: [])
    monkeypatch.setattr(module, "compile_codeql_config", lambda *args, **kwargs: "select 1")
    monkeypatch.setattr(module, "_parse_sarif_matches", lambda *args: [{"message": message}] * 3)
    runner = module.make_codeql_tool_runner(tmp_path, tmp_path, language="cpp")
    assert runner is not None
    feedback = runner(specs)
    assert feedback.n_successes == 1
    assert feedback.confirmed_keys == [_spec_key(specs[0]), _spec_key(specs[1])]
    assert len(calls) == len(specs)
