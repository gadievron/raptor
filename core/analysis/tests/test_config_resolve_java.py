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

    def test_root_under_skip_named_dir_still_searched(self, tmp_path):
        # Skip names apply BELOW the search root only: a checkout
        # under a parent dir named out/ (or build/, dist/, ...) must
        # still find its own properties files — the absolute-path
        # check refused every candidate (file_not_found) for such
        # repos.
        repo = tmp_path / "out" / "checkout"
        repo.mkdir(parents=True)
        (repo / "app.properties").write_text("alg=SHA-256\n")
        (repo / "target").mkdir()
        (repo / "target" / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg"')
        java = repo / "T.java"
        java.write_text(src, encoding="utf-8")
        res = ConfigResolver(src, str(java), str(repo)).resolve_call(
            _get_call(src))
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


_SRC_COND = """\
import java.util.Properties;
public class T {
    public void handle() throws Exception {
        Properties props = new Properties();
        if (cond()) {
            props.load(getClass().getClassLoader()
                .getResourceAsStream("@RES@"));
        }
        String alg = props.getProperty(@ARGS@);
        use(alg);
    }
}
"""

_SRC_TRY = """\
import java.util.Properties;
public class T {
    public void handle() {
        Properties props = new Properties();
        try {
            props.load(getClass().getClassLoader()
                .getResourceAsStream("@RES@"));
        } catch (Exception e) { }
        String alg = props.getProperty(@ARGS@);
        use(alg);
    }
}
"""

_SRC_SAME_ROW = """\
import java.util.Properties;
public class T {
    public void handle() throws Exception {
        Properties props = new Properties();
        String alg = props.getProperty(@ARGS@); props.load(getClass().getClassLoader().getResourceAsStream("@RES@"));
        use(alg);
    }
}
"""


class TestLoadMustExecuteDiscipline:
    """'Load precedes read' was textual: a load under an if (or a
    try whose failure a catch swallows) still resolved the FILE
    value, while at runtime the get returns null on the not-loaded
    path — downstream 'v == null' then folds False and the live
    null-handling branch is pruned as dead."""

    def test_conditional_load_refuses(self, tmp_path):
        (tmp_path / "app.properties").write_text("alg=SHA-256\n")
        src = _src("app.properties", '"alg"', template=_SRC_COND)
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert not res.resolved
        assert res.refusal == "conditional_load"

    def test_try_guarded_load_refuses(self, tmp_path):
        (tmp_path / "app.properties").write_text("alg=SHA-256\n")
        src = _src("app.properties", '"alg"', template=_SRC_TRY)
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert not res.resolved
        assert res.refusal == "conditional_load"

    def test_same_row_get_before_load_refuses(self, tmp_path):
        # 'load_rows[0] > get_row' passed when the get textually
        # precedes the load on ONE line — at runtime the get ran
        # before the load.
        (tmp_path / "app.properties").write_text("alg=SHA-256\n")
        src = _src("app.properties", '"alg"', template=_SRC_SAME_ROW)
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert not res.resolved
        assert res.refusal == "load_after_get"

    def test_unconditional_load_still_resolves(self, tmp_path):
        # Control: the straight-line template keeps resolving.
        (tmp_path / "app.properties").write_text("alg=SHA-256\n")
        src = _src("app.properties", '"alg"')
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.resolved and res.value == "SHA-256"


_SRC_SAME_TRY = """\
import java.util.Properties;
public class T {
    public void handle(Out o) {
        try {
            Properties props = new Properties();
            props.load(getClass().getClassLoader()
                .getResourceAsStream("@RES@"));
            String alg = props.getProperty(@ARGS@);
            use(alg);
        } catch (Exception e) { }
    }
}
"""

_SRC_ARM_SPLIT = """\
import java.util.Properties;
public class T {
    public void handle(boolean c) throws Exception {
        Properties props = new Properties();
        if (c) {
            props.load(getClass().getClassLoader()
                .getResourceAsStream("@RES@"));
        } else {
            String alg = props.getProperty(@ARGS@);
            use(alg);
        }
    }
}
"""

_SRC_SHARED_LOOP = """\
import java.util.Properties;
public class T {
    public void handle(int n) throws Exception {
        Properties props = new Properties();
        while (n-- > 0) {
            props.load(getClass().getClassLoader()
                .getResourceAsStream("@RES@"));
            String alg = props.getProperty(@ARGS@);
            use(alg);
        }
    }
}
"""

_SRC_LAMBDA_LOAD = """\
import java.util.Properties;
public class T {
    public void handle() throws Exception {
        Properties props = new Properties();
        Runnable r = () -> {
            props.load(getClass().getClassLoader()
                .getResourceAsStream("@RES@"));
        };
        r.run();
        String alg = props.getProperty(@ARGS@);
        use(alg);
    }
}
"""

_SRC_LAMBDA_PAIR = """\
import java.util.Properties;
public class T {
    public void handle() throws Exception {
        Properties props = new Properties();
        Runnable r = () -> {
            props.load(getClass().getClassLoader()
                .getResourceAsStream("@RES@"));
            String alg = props.getProperty(@ARGS@);
            use(alg);
        };
        r.run();
    }
}
"""

_SRC_GET_IN_TRY = """\
import java.util.Properties;
public class T {
    public void handle() throws Exception {
        Properties props = new Properties();
        props.load(getClass().getClassLoader()
            .getResourceAsStream("@RES@"));
        try {
            String alg = props.getProperty(@ARGS@);
            use(alg);
        } catch (Exception e) { }
    }
}
"""

_SRC_LOCAL_CLASS_INIT = """\
import java.util.Properties;
public class T {
    public void handle() throws Exception {
        Properties props = new Properties();
        class Helper {
            { props.load(getClass().getClassLoader()
                .getResourceAsStream("@RES@")); }
        }
        String alg = props.getProperty(@ARGS@);
        use(alg);
    }
}
"""

_SRC_SHORT_CIRCUIT_INIT = """\
import java.util.Properties;
public class T {
    public void handle(boolean c) throws Exception {
        Properties props = new Properties();
        boolean b = c && (new Object() {
            { props.load(getClass().getClassLoader()
                .getResourceAsStream("@RES@")); }
        }) != null;
        String alg = props.getProperty(@ARGS@);
        use(alg);
    }
}
"""

_SRC_ASSERT_INIT = """\
import java.util.Properties;
public class T {
    public void handle() throws Exception {
        Properties props = new Properties();
        assert (new Object() {
            { props.load(getClass().getClassLoader()
                .getResourceAsStream("@RES@")); }
        }) != null;
        String alg = props.getProperty(@ARGS@);
        use(alg);
    }
}
"""

_SRC_EAGER_ANON_INIT = """\
import java.util.Properties;
public class T {
    public void handle() throws Exception {
        Properties props = new Properties();
        Object o = new Object() {
            { props.load(getClass().getClassLoader()
                .getResourceAsStream("@RES@")); }
        };
        String alg = props.getProperty(@ARGS@);
        use(alg);
    }
}
"""


class TestLoadDominance:
    """conditional_load is a DOMINANCE refusal, not an any-ancestor
    veto: a load and get in the same region resolve (a throwing load
    exits past the get — no path reads an unloaded receiver), while a
    swallowed-failure load, an arm-split, or a deferred load still
    refuse."""

    def test_same_try_block_resolves(self, tmp_path):
        # Load and get inside ONE try block: if the load throws,
        # control leaves the block past the get. The common
        # real-world spelling (and the previous rule's biggest
        # measured refusal class).
        (tmp_path / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg"', template=_SRC_SAME_TRY)
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.resolved and res.value == "MD5"

    def test_arm_split_refuses(self, tmp_path):
        # Load in the then-arm, get in the else-arm: mutually
        # exclusive paths share the if_statement but never a block.
        (tmp_path / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg"', template=_SRC_ARM_SPLIT)
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert not res.resolved
        assert res.refusal == "conditional_load"

    def test_shared_loop_body_resolves(self, tmp_path):
        # Both in one loop body, load first: every iteration that
        # reaches the get ran the load.
        (tmp_path / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg"', template=_SRC_SHARED_LOOP)
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.resolved and res.value == "MD5"

    def test_lambda_load_refuses(self, tmp_path):
        # A deferred load never dominates a later get.
        (tmp_path / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg"', template=_SRC_LAMBDA_LOAD)
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert not res.resolved
        assert res.refusal == "conditional_load"

    def test_same_lambda_body_pair_resolves(self, tmp_path):
        # Load and get PAIRED inside one lambda body: every invocation
        # that reaches the get ran the load first. The walk meets the
        # shared (lambda body) block before the lambda node, so the
        # deferral of the pair as a whole is irrelevant.
        (tmp_path / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg"', template=_SRC_LAMBDA_PAIR)
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.resolved and res.value == "MD5"

    def test_get_nested_in_try_resolves(self, tmp_path):
        # Unconditional load in the method body, get nested DEEPER
        # inside a try: the get-side chain must contribute every
        # enclosing block, not just the innermost one — the load meets
        # the method body block, not the try's.
        (tmp_path / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg"', template=_SRC_GET_IN_TRY)
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert res.resolved and res.value == "MD5"

    def test_local_class_initializer_refuses(self, tmp_path):
        # Instance initializer of a local class that is NEVER
        # instantiated: the load never executes, the runtime get
        # returns null. class bodies are not execution-transparent.
        (tmp_path / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg"',
                   template=_SRC_LOCAL_CLASS_INIT)
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert not res.resolved
        assert res.refusal == "conditional_load"

    def test_short_circuit_operand_refuses(self, tmp_path):
        # Anonymous-class initializer as a && operand: with the left
        # side false the operand — and the load — never evaluates.
        (tmp_path / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg"',
                   template=_SRC_SHORT_CIRCUIT_INIT)
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert not res.resolved
        assert res.refusal == "conditional_load"

    def test_assert_vehicle_refuses(self, tmp_path):
        # Load inside an assert operand: assertions are disabled by
        # default at runtime, so the load is conditional evaluation.
        (tmp_path / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg"', template=_SRC_ASSERT_INIT)
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert not res.resolved
        assert res.refusal == "conditional_load"

    def test_eager_anon_initializer_refuses(self, tmp_path):
        # Eager `Object o = new Object() { { load } };` DOES execute
        # the load in this spelling, but class bodies stay off the
        # transparent allowlist wholesale — accepting them is exactly
        # how the deferred local-class/short-circuit/assert vehicles
        # slipped through. Conservative refusal, fail-closed.
        (tmp_path / "app.properties").write_text("alg=MD5\n")
        src = _src("app.properties", '"alg"',
                   template=_SRC_EAGER_ANON_INIT)
        res = _resolver(tmp_path, src).resolve_call(_get_call(src))
        assert not res.resolved
        assert res.refusal == "conditional_load"
