"""Config-value resolver contract tests (wave b22)."""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.config_resolve_java import (  # noqa: E402
    ConfigResolver,
    _parser,
    parse_properties_strict,
)
from core.analysis.const_fold_java import REFUSE  # noqa: E402

_SRC = """\
import java.util.Properties;
public class T {
    public void handle() throws Exception {
        Properties props = new Properties();
        props.load(getClass().getClassLoader()
            .getResourceAsStream("@RES@"));
        String alg = props.getProperty(@ARGS@);
        use(alg);
    }
}
"""

def _src(res: str, args: str, template: str = _SRC) -> str:
    return template.replace("@RES@", res).replace("@ARGS@", args)


def _get_call(src: str):
    tree = _parser().parse(src.encode())
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type == "method_invocation":
            name = n.child_by_field_name("name")
            if name is not None and name.text == b"getProperty":
                return n
        stack.extend(n.children)
    raise AssertionError("no getProperty call in fixture")


def _resolver(tmp_path, src: str) -> ConfigResolver:
    java = tmp_path / "T.java"
    java.write_text(src, encoding="utf-8")
    return ConfigResolver(src, str(java), str(tmp_path))


class TestStrictGrammar:
    def test_plain_pairs_comments_blanks(self):
        e = parse_properties_strict(
            "# c\n! c2\n\nalg=SHA-256\nother = x \n")
        assert not e.unsupported
        assert e.entries["alg"] == ["SHA-256"]
        assert e.entries["other"] == ["x"]

    def test_backslash_anywhere_refuses_file(self):
        assert parse_properties_strict("alg=SHA\\\n256\n").unsupported

    def test_missing_equals_refuses_file(self):
        assert parse_properties_strict("alg SHA-256\n").unsupported

    def test_duplicate_key_recorded(self):
        e = parse_properties_strict("alg=A\nalg=B\n")
        assert e.entries["alg"] == ["A", "B"]


class TestResolveCall:
    def test_resolves_single_file_single_key(self, tmp_path):
        (tmp_path / "app.properties").write_text("alg=SHA-256\n")
        src = _src("app.properties", '"alg"')
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.resolved and res.value == "SHA-256"

    def test_default_refused_without_allow(self, tmp_path):
        (tmp_path / "app.properties").write_text("alg=SHA-256\n")
        src = _src("app.properties", '"alg", "MD5"')
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.refusal == "default_present"

    def test_default_allowed_records_default(self, tmp_path):
        (tmp_path / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg", "SHA-512"')
        res = _resolver(tmp_path, src).resolve_call(
            _get_call(src), allow_default=True)
        assert res.resolved and res.value == "MD5"
        assert res.default == "SHA-512"

    def test_two_files_with_key_ambiguous(self, tmp_path):
        (tmp_path / "app.properties").write_text("alg=SHA-256\n")
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg"')
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.refusal == "file_ambiguous"

    def test_key_missing(self, tmp_path):
        (tmp_path / "app.properties").write_text("other=x\n")
        src = _src("app.properties", '"alg"')
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.refusal == "key_missing"

    def test_unsupported_grammar_beats_missing(self, tmp_path):
        (tmp_path / "app.properties").write_text("alg=A\\\nB\n")
        src = _src("app.properties", '"alg"')
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.refusal == "grammar_unsupported"

    def test_dynamic_key_refuses(self, tmp_path):
        (tmp_path / "app.properties").write_text("alg=A\n")
        src = _src("app.properties", "someVar")
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.refusal == "dynamic_key"

    def test_receiver_escape_refuses(self, tmp_path):
        (tmp_path / "app.properties").write_text("alg=A\n")
        src = _src("app.properties", '"alg"').replace(
            "use(alg);", "use(alg);\n        share(props);")
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.refusal == "receiver_escapes"

    def test_system_receiver_refuses(self, tmp_path):
        src = ("public class T { void m() { "
               'String a = System.getProperty("alg"); } }')
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.refusal == "receiver_not_local"

    def test_duplicate_key_in_one_file_refuses(self, tmp_path):
        (tmp_path / "app.properties").write_text("alg=A\nalg=B\n")
        src = _src("app.properties", '"alg"')
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.refusal == "key_duplicated"

    def test_non_properties_resource_refuses(self, tmp_path):
        (tmp_path / "app.xml").write_text("<x/>")
        src = _src("app.xml", '"alg"')
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.refusal == "not_properties_file"

    def test_skip_dirs_excluded_from_search(self, tmp_path):
        (tmp_path / "app.properties").write_text("alg=SHA-256\n")
        (tmp_path / "target").mkdir()
        (tmp_path / "target" / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg"')
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.resolved and res.value == "SHA-256"


class TestFoldHook:
    def test_hook_none_for_foreign_calls(self, tmp_path):
        src = "public class T { void m() { int x = foo(); } }"
        r = _resolver(tmp_path, src)
        call = None
        tree = _parser().parse(src.encode())
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type == "method_invocation":
                call = n
            stack.extend(n.children)
        assert r.fold_hook(call, 1) is None

    def test_hook_value_and_refuse(self, tmp_path):
        (tmp_path / "app.properties").write_text("alg=SHA-256\n")
        src = _src("app.properties", '"alg"')
        r = _resolver(tmp_path, src)
        assert r.fold_hook(_get_call(src), 1) == "SHA-256"
        src2 = _src("app.properties", '"alg", "MD5"')
        r2 = _resolver(tmp_path, src2)
        assert r2.fold_hook(_get_call(src2), 1) is REFUSE
        assert r2.stats["default_present"] == 1
