"""Owned native-parser receiver identity probe; no JS evaluation or provider call."""
import json

import pytest

from core.dataflow import tier1_llm as t1
from core.analysis.validator_control_scope import _native_source_tree
from core.analysis.validator_call_binding import javascript_local_object_receiver_conflict


def test_local_js_validator_object_cannot_earn_library_certificate(tmp_path):
    call = "    name = validator.escape(name);"
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": call,
                        "variable_name": "name", "charset": "", "forbidden": "",
                        "library_call": "validator.escape"})
    def check(source):
        assert _native_source_tree(source, "javascript") is not None
        (tmp_path / "app.js").write_text(source)
        return t1.try_tier1b(
            fix_diff="+" + call + "\n", repo_root=tmp_path, sink_uri="app.js",
            sink_line=len(source.splitlines()) - 1, sink_class="xss", language="javascript",
            complete=lambda _system, _user: reply,
        )
    ordinary = ("function serve(req, res) {\n    let name = req.query.name;\n"
                + call + "\n    res.send(name);\n}\n")
    control = check(ordinary)
    assert control.status is t1.Tier0Status.NOT_APPLICABLE
    assert control.extras["unverified_source_contracts"] == ["html_text_or_quoted_attribute_sink_context_and_policy"]
    shadowed = ordinary.replace("    let name", "    const validator = {escape: value => value};\n    let name")
    result = check(shadowed)
    assert result.status is t1.Tier0Status.NOT_APPLICABLE
    assert "receiver" in result.reasoning
    assert "unverified_source_contracts" not in result.extras


@pytest.mark.parametrize('source,conflict', [
    ('function serve(name) {\n const validator = {escape: value => value};\n name = validator.escape(name);\n}', True),
    ('function serve(name) {\n { const validator = {escape: value => value};\n name = validator.escape(name); }\n}', True),
    ('function serve(name) {\n const validator = ({escape: value => value});\n name = validator.escape(name);\n}', True),
    ('function other() { const validator = {escape: value => value}; }\nfunction serve(name) {\n name = validator.escape(name);\n}', False),
    ('function serve(name) {\n { const validator = {escape: value => value}; }\n name = validator.escape(name);\n}', False),
    ('function serve(name) {\n function unused() { const validator = {escape: value => value}; }\n name = validator.escape(name);\n}', False),
    ('function serve(name) {\n name = validator.escape(name);\n const validator = {escape: value => value};\n}', False),
    ('function serve(name) {\n const other = {escape: value => value};\n name = validator.escape(name);\n}', False),
    ('function serve(name) {\n const validator = factory();\n name = validator.escape(name);\n}', False),
    ('function serve(name) {\n const validator = {escape: value => value};\n name = escape(name);\n}', False),
], ids=['local-object', 'containing-block', 'parenthesised-object', 'sibling-function',
        'sibling-block', 'unused-nested', 'later-binding', 'other-root', 'opaque-initializer', 'suffix-only'])
def test_bounded_local_receiver_refusal_scope(source, conflict):
    assert _native_source_tree(source, 'javascript') is not None
    line = next(index for index, text in enumerate(source.splitlines(), 1)
                if 'name = ' in text)
    assert javascript_local_object_receiver_conflict(source, line, 'validator.escape') is conflict


def test_parser_unavailable_does_not_earn_curated_certificate(tmp_path, monkeypatch):
    from core.analysis import validator_control_scope

    monkeypatch.setattr(validator_control_scope, '_native_source_tree', lambda *_args: None)
    call = '    name = validator.escape(name);'
    source = 'function serve(name) {\n' + call + '\n    res.send(name);\n}\n'
    (tmp_path / 'app.js').write_text(source)
    reply = json.dumps({'kind': 'known_safe_call', 'validator_source_line': call,
                        'variable_name': 'name', 'library_call': 'validator.escape'})
    result = t1.try_tier1b(fix_diff='+' + call + '\n', repo_root=tmp_path,
                          sink_uri='app.js', sink_line=3, sink_class='xss', language='javascript',
                          complete=lambda _system, _user: reply)
    assert result.status is not t1.Tier0Status.SOUND
    assert result.artifact is None


def test_parser_error_supplies_no_receiver_identity_match():
    assert not javascript_local_object_receiver_conflict('function {', 1, 'validator.escape')
