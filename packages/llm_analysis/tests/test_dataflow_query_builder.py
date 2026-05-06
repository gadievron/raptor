"""Tests for the mechanical CodeQL query builder (Tier 1 + Tier 2)."""

import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis import dataflow_query_builder as _dqb
from packages.llm_analysis.dataflow_query_builder import (
    TEMPLATE_PREDICATE_SCHEMA,
    build_template_query,
    discover_prebuilt_queries,
    discover_prebuilt_query,
    infer_cwe_from_rule_id,
    supported_languages_for_template,
)


# Tier 1 — discovery ---------------------------------------------------------


def _write_query(path: Path, *, kind: str, cwe_tag: str, qid: str = "raptor/test") -> None:
    """Materialise a minimally-valid QLDoc-tagged .ql stub for discovery to find.

    Discovery only reads the header; it never compiles the file. We just need
    the @kind / @id / @tags external/cwe/cwe-NNN bits in the leading 4KB.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    body = textwrap.dedent(
        f"""\
        /**
         * @name Test query
         * @kind {kind}
         * @id {qid}
         * @tags security
         *       {cwe_tag}
         */
        import python
        """
    )
    path.write_text(body)


def _build_pack_tree(root: Path, *, language: str, version: str = "1.0.0") -> Path:
    """Mimic the on-disk layout of an installed CodeQL queries pack:
    <root>/<lang>-queries/<version>/Security/CWE-NNN/*.ql
    where <root> is the configured pack root.
    """
    sec = root / f"{language}-queries" / version / "Security"
    sec.mkdir(parents=True, exist_ok=True)
    return sec


class TestDiscovery:
    """`discover_prebuilt_queries` walks installed packs to map (lang, CWE) → path.

    Tests build a fake pack tree under tmp_path, monkeypatch the module's
    `_DEFAULT_PACK_ROOT` to point at it, AND clear
    RaptorConfig.EXTRA_CODEQL_PACK_ROOTS so the in-repo
    raptor-python-queries pack (a real production extras root) doesn't
    leak into the test's view. Avoiding env vars per project convention.
    """

    def setup_method(self):
        discover_prebuilt_queries.cache_clear()

    def teardown_method(self):
        discover_prebuilt_queries.cache_clear()

    def _isolate_default_root(self, monkeypatch, tmp_path):
        """Point discovery at tmp_path only — no in-repo extras leak."""
        from core.config import RaptorConfig
        monkeypatch.setattr(_dqb, "_DEFAULT_PACK_ROOT", tmp_path)
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [])

    def test_finds_path_problem_query(self, tmp_path, monkeypatch):
        sec = _build_pack_tree(tmp_path, language="python")
        ql = sec / "CWE-078" / "CommandInjection.ql"
        _write_query(ql, kind="path-problem",
                     cwe_tag="external/cwe/cwe-78", qid="py/cmd-injection")

        self._isolate_default_root(monkeypatch, tmp_path)
        out = discover_prebuilt_queries()
        assert ("python", "CWE-78") in out
        assert out[("python", "CWE-78")] == ql

    def test_skips_non_path_problem_queries(self, tmp_path, monkeypatch):
        sec = _build_pack_tree(tmp_path, language="python")
        ql = sec / "CWE-079" / "CookieFlag.ql"
        # @kind problem (not path-problem) — useful as a static check, but
        # dataflow validation isn't what it does.
        _write_query(ql, kind="problem", cwe_tag="external/cwe/cwe-79")

        self._isolate_default_root(monkeypatch, tmp_path)
        out = discover_prebuilt_queries()
        assert ("python", "CWE-79") not in out

    def test_lookup_normalises_inputs(self, tmp_path, monkeypatch):
        sec = _build_pack_tree(tmp_path, language="python")
        _write_query(
            sec / "CWE-089" / "SqlInjection.ql",
            kind="path-problem",
            cwe_tag="external/cwe/cwe-89",
        )

        self._isolate_default_root(monkeypatch, tmp_path)
        # Case-insensitive language and CWE; trims whitespace.
        assert discover_prebuilt_query("Python", "cwe-89") is not None
        assert discover_prebuilt_query("PYTHON", " CWE-89 ") is not None
        assert discover_prebuilt_query("python", "CWE-89") is not None

    def test_lookup_returns_none_for_unknown(self, tmp_path, monkeypatch):
        # Empty pack tree.
        self._isolate_default_root(monkeypatch, tmp_path)
        assert discover_prebuilt_query("python", "CWE-9999") is None
        assert discover_prebuilt_query("cobol", "CWE-78") is None

    def test_lookup_empty_inputs(self, tmp_path, monkeypatch):
        self._isolate_default_root(monkeypatch, tmp_path)
        assert discover_prebuilt_query("", "CWE-78") is None
        assert discover_prebuilt_query("python", "") is None
        assert discover_prebuilt_query(None, None) is None

    def test_finds_queries_across_languages(self, tmp_path, monkeypatch):
        py_sec = _build_pack_tree(tmp_path, language="python")
        java_sec = _build_pack_tree(tmp_path, language="java")
        cpp_sec = _build_pack_tree(tmp_path, language="cpp")

        _write_query(
            py_sec / "CWE-078" / "CommandInjection.ql",
            kind="path-problem", cwe_tag="external/cwe/cwe-78",
        )
        _write_query(
            java_sec / "CWE-078" / "ExecTainted.ql",
            kind="path-problem", cwe_tag="external/cwe/cwe-78",
        )
        _write_query(
            cpp_sec / "CWE-078" / "ExecTainted.ql",
            kind="path-problem", cwe_tag="external/cwe/cwe-78",
        )

        self._isolate_default_root(monkeypatch, tmp_path)
        assert discover_prebuilt_query("python", "CWE-78") is not None
        assert discover_prebuilt_query("java", "CWE-78") is not None
        assert discover_prebuilt_query("cpp", "CWE-78") is not None

    def test_first_seen_wins_on_collision(self, tmp_path, monkeypatch):
        sec = _build_pack_tree(tmp_path, language="python")
        # Two queries both tagged CWE-78. discover walks alphabetically so
        # the lexicographically-first file wins, deterministically.
        a = sec / "CWE-078" / "Aaa.ql"
        b = sec / "CWE-078" / "Bbb.ql"
        _write_query(a, kind="path-problem", cwe_tag="external/cwe/cwe-78")
        _write_query(b, kind="path-problem", cwe_tag="external/cwe/cwe-78")

        self._isolate_default_root(monkeypatch, tmp_path)
        assert discover_prebuilt_query("python", "CWE-78") == a

    def test_skips_non_queries_packs(self, tmp_path, monkeypatch):
        # `python-all` is a library pack, not a queries pack. Discovery
        # only looks at <lang>-queries dirs.
        not_a_queries = tmp_path / "python-all" / "1.0.0" / "Security"
        not_a_queries.mkdir(parents=True)
        _write_query(
            not_a_queries / "CWE-078" / "CommandInjection.ql",
            kind="path-problem", cwe_tag="external/cwe/cwe-78",
        )

        self._isolate_default_root(monkeypatch, tmp_path)
        assert discover_prebuilt_query("python", "CWE-78") is None

    def test_missing_pack_root_is_handled(self, tmp_path, monkeypatch):
        # Pack root points at a non-existent dir → empty result, no crash.
        from core.config import RaptorConfig
        monkeypatch.setattr(_dqb, "_DEFAULT_PACK_ROOT", tmp_path / "does-not-exist")
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [])
        out = discover_prebuilt_queries()
        assert out == {}

    def test_zero_padded_cwe_tags_are_normalised(self, tmp_path, monkeypatch):
        """Real CodeQL packs use zero-padded tags (`cwe-022`); RAPTOR
        findings carry canonical CWE strings (`CWE-22`). Discovery must
        strip leading zeros so the dict keys match what callers pass."""
        sec = _build_pack_tree(tmp_path, language="python")
        # Tag uses zero-padded form, as real packs do
        ql = sec / "CWE-022" / "PathInjection.ql"
        _write_query(ql, kind="path-problem",
                     cwe_tag="external/cwe/cwe-022")

        self._isolate_default_root(monkeypatch, tmp_path)
        # Lookup with canonical (unpadded) form must hit the entry.
        assert discover_prebuilt_query("python", "CWE-22") == ql
        # The dict key itself is also canonical.
        assert ("python", "CWE-22") in discover_prebuilt_queries()
        assert ("python", "CWE-022") not in discover_prebuilt_queries()

    def test_multiple_cwes_per_query(self, tmp_path, monkeypatch):
        # Some queries tag multiple CWEs. Discovery indexes the query
        # under each one — both lookups should find it.
        sec = _build_pack_tree(tmp_path, language="python")
        ql = sec / "CWE-078" / "MultiTagged.ql"
        ql.parent.mkdir(parents=True, exist_ok=True)
        ql.write_text(textwrap.dedent(
            """\
            /**
             * @name Multi-tagged
             * @kind path-problem
             * @id raptor/multi
             * @tags security
             *       external/cwe/cwe-78
             *       external/cwe/cwe-77
             */
            import python
            """
        ))

        self._isolate_default_root(monkeypatch, tmp_path)
        assert discover_prebuilt_query("python", "CWE-78") == ql
        assert discover_prebuilt_query("python", "CWE-77") == ql


class TestMultiRoot:
    """Discovery walks RaptorConfig.EXTRA_CODEQL_PACK_ROOTS before the
    default. Extras win on (lang, CWE) collisions so RAPTOR-shipped
    packs (LocalFlowSource etc.) override the bundled stdlib queries."""

    def setup_method(self):
        discover_prebuilt_queries.cache_clear()

    def teardown_method(self):
        discover_prebuilt_queries.cache_clear()

    def test_extras_override_default_on_collision(self, tmp_path, monkeypatch):
        """Same (lang, CWE) in both extras and default → extras wins."""
        from core.config import RaptorConfig

        # Default root: stdlib-shaped query for CWE-78
        default_root = tmp_path / "default"
        default_sec = default_root / "python-queries" / "1.0.0" / "Security"
        default_sec.mkdir(parents=True)
        default_ql = default_sec / "CWE-078" / "FromDefault.ql"
        _write_query(default_ql, kind="path-problem",
                     cwe_tag="external/cwe/cwe-78", qid="default/cwe-78")

        # Extras root: same CWE, flat layout (in-repo packs ship flat).
        extras_root = tmp_path / "extras"
        extras_sec = extras_root / "python-queries" / "Security"
        extras_sec.mkdir(parents=True)
        extras_ql = extras_sec / "CWE-078" / "FromExtras.ql"
        _write_query(extras_ql, kind="path-problem",
                     cwe_tag="external/cwe/cwe-78", qid="extras/cwe-78")

        monkeypatch.setattr(_dqb, "_DEFAULT_PACK_ROOT", default_root)
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [extras_root])

        assert discover_prebuilt_query("python", "CWE-78") == extras_ql

    def test_extras_and_default_merge_distinct_cwes(self, tmp_path, monkeypatch):
        """Extras and default contribute different CWEs — both surface."""
        from core.config import RaptorConfig

        default_root = tmp_path / "default"
        default_sec = default_root / "python-queries" / "1.0.0" / "Security"
        default_sec.mkdir(parents=True)
        _write_query(default_sec / "CWE-022" / "PathInjection.ql",
                     kind="path-problem", cwe_tag="external/cwe/cwe-22")

        extras_root = tmp_path / "extras"
        extras_sec = extras_root / "python-queries" / "Security"
        extras_sec.mkdir(parents=True)
        _write_query(extras_sec / "CWE-094" / "CodeInjection.ql",
                     kind="path-problem", cwe_tag="external/cwe/cwe-94")

        monkeypatch.setattr(_dqb, "_DEFAULT_PACK_ROOT", default_root)
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [extras_root])

        assert discover_prebuilt_query("python", "CWE-22") is not None
        assert discover_prebuilt_query("python", "CWE-94") is not None

    def test_missing_extras_root_tolerated(self, tmp_path, monkeypatch):
        """A non-existent extras root must not crash discovery."""
        from core.config import RaptorConfig

        default_root = tmp_path / "default"
        default_sec = default_root / "python-queries" / "1.0.0" / "Security"
        default_sec.mkdir(parents=True)
        _write_query(default_sec / "CWE-078" / "X.ql",
                     kind="path-problem", cwe_tag="external/cwe/cwe-78")

        monkeypatch.setattr(_dqb, "_DEFAULT_PACK_ROOT", default_root)
        monkeypatch.setattr(
            RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS",
            [tmp_path / "does-not-exist"],
        )

        # Default root still resolves; missing extras silently skipped.
        assert discover_prebuilt_query("python", "CWE-78") is not None

    def test_flat_pack_layout_recognised(self, tmp_path, monkeypatch):
        """In-repo packs use flat layout (<pack>/Security/...) without a
        version dir. Discovery must recognise both layouts."""
        from core.config import RaptorConfig

        # Flat layout — used by raptor-python-queries
        extras_root = tmp_path / "extras"
        flat_sec = extras_root / "python-queries" / "Security"
        flat_sec.mkdir(parents=True)
        ql = flat_sec / "CWE-502" / "Deser.ql"
        _write_query(ql, kind="path-problem",
                     cwe_tag="external/cwe/cwe-502")

        monkeypatch.setattr(_dqb, "_DEFAULT_PACK_ROOT", tmp_path / "no-default")
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [extras_root])

        assert discover_prebuilt_query("python", "CWE-502") == ql

    def test_in_repo_pack_discoverable_in_default_config(self):
        """Smoke-test the production default: discovery actually picks up
        the RAPTOR-shipped raptor-python-queries pack via the default
        EXTRA_CODEQL_PACK_ROOTS without any monkeypatching."""
        # No monkeypatch — use real RaptorConfig defaults
        out = discover_prebuilt_queries()
        # CWE-78 must resolve to the in-repo LocalFlowSource query
        # (extras win over the stdlib CommandInjection.ql on collision).
        path = discover_prebuilt_query("python", "CWE-78")
        assert path is not None
        assert "raptor-python-queries" in str(path) or \
               "codeql_packs/python-queries" in str(path), \
               f"expected in-repo pack to win, got {path}"


# Tier 2 ---------------------------------------------------------------------

class TestBuildTemplateQuery:
    def test_python_template(self):
        q = build_template_query(
            language="python",
            source_predicate_body="n instanceof RemoteFlowSource",
            sink_predicate_body="exists(Call c | n.asExpr() = c.getArg(0))",
        )
        assert q is not None
        assert "import python" in q
        assert "n instanceof RemoteFlowSource" in q
        assert "exists(Call c | n.asExpr() = c.getArg(0))" in q
        assert "module IrisConfig implements DataFlow::ConfigSig" in q
        assert "module IrisFlow = TaintTracking::Global<IrisConfig>" in q
        assert "import IrisFlow::PathGraph" in q

    def test_java_template(self):
        q = build_template_query(
            language="java",
            source_predicate_body="n instanceof RemoteFlowSource",
            sink_predicate_body="exists(MethodAccess m)",
        )
        assert q is not None
        assert "import java" in q
        assert "import semmle.code.java.dataflow.TaintTracking" in q

    def test_cpp_template(self):
        q = build_template_query(
            language="cpp",
            source_predicate_body="exists(FunctionCall fc)",
            sink_predicate_body="exists(FunctionCall fc | fc.getTarget().getName() = \"strcpy\")",
        )
        assert q is not None
        assert "import cpp" in q

    def test_unsupported_language_returns_none(self):
        q = build_template_query(
            language="cobol",
            source_predicate_body="x",
            sink_predicate_body="y",
        )
        assert q is None

    def test_empty_source_returns_none(self):
        q = build_template_query(
            language="python",
            source_predicate_body="",
            sink_predicate_body="x",
        )
        assert q is None

    def test_empty_sink_returns_none(self):
        q = build_template_query(
            language="python",
            source_predicate_body="x",
            sink_predicate_body="   ",
        )
        assert q is None

    def test_query_id_in_metadata(self):
        q = build_template_query(
            language="python",
            source_predicate_body="x",
            sink_predicate_body="y",
            query_id="raptor/iris/test",
        )
        assert "raptor/iris/test" in q

    def test_predicates_stripped(self):
        """Leading/trailing whitespace in predicates is stripped, so
        callers don't need to be careful about indentation."""
        q = build_template_query(
            language="python",
            source_predicate_body="   n instanceof X   \n",
            sink_predicate_body="\n  n instanceof Y  ",
        )
        # Stripped values appear in the output
        assert "n instanceof X" in q
        assert "n instanceof Y" in q

    def test_supported_languages(self):
        langs = supported_languages_for_template()
        assert "python" in langs
        assert "java" in langs
        assert "cpp" in langs
        assert "javascript" in langs
        assert "go" in langs


class TestSchemas:
    def test_template_predicate_schema_has_required_fields(self):
        assert "source_predicate_body" in TEMPLATE_PREDICATE_SCHEMA
        assert "sink_predicate_body" in TEMPLATE_PREDICATE_SCHEMA

    def test_schema_descriptions_mention_examples(self):
        # Schema descriptions should help the LLM produce well-shaped predicates
        s = TEMPLATE_PREDICATE_SCHEMA["source_predicate_body"]
        assert "Example" in s or "example" in s


class TestCweInference:
    """infer_cwe_from_rule_id maps Semgrep rule names to CWE strings."""

    def test_command_injection_patterns(self):
        for rule in (
            "raptor.injection.command-shell",
            "python.lang.security.audit.subprocess-shell-true",
            "OS_COMMAND_INJECTION",
            "command_injection",
        ):
            assert infer_cwe_from_rule_id(rule) == "CWE-78", rule

    def test_sql_injection_patterns(self):
        for rule in (
            "raptor.sqli",
            "SQL_INJECTION",
            "python.django.sql-injection",
            "raptor.sql-injection.tainted",
        ):
            assert infer_cwe_from_rule_id(rule) == "CWE-89", rule

    def test_path_traversal(self):
        for rule in (
            "python.path-traversal.tainted-path",
            "raptor.injection.directory-traversal",
        ):
            assert infer_cwe_from_rule_id(rule) == "CWE-22", rule

    def test_xss_patterns(self):
        assert infer_cwe_from_rule_id("python.django.xss") == "CWE-79"
        assert infer_cwe_from_rule_id("dom-based-xss") == "CWE-79"
        assert infer_cwe_from_rule_id("cross-site-scripting") == "CWE-79"

    def test_xxe(self):
        assert infer_cwe_from_rule_id("xxe") == "CWE-611"
        assert infer_cwe_from_rule_id("xml-external-entity") == "CWE-611"

    def test_ssrf(self):
        assert infer_cwe_from_rule_id("ssrf") == "CWE-918"
        assert infer_cwe_from_rule_id("server-side-request-forgery") == "CWE-918"

    def test_deserialization(self):
        assert infer_cwe_from_rule_id("unsafe-deserialization") == "CWE-502"
        assert infer_cwe_from_rule_id("pickle.deserialization") == "CWE-502"

    def test_log_injection(self):
        assert infer_cwe_from_rule_id("log-injection") == "CWE-117"
        assert infer_cwe_from_rule_id("log-forging") == "CWE-117"

    def test_hardcoded_credentials(self):
        for rule in (
            "raptor.crypto.hardcoded-secret",
            "hardcoded-password",
            "hardcoded-token",
        ):
            assert infer_cwe_from_rule_id(rule) == "CWE-798", rule

    def test_weak_crypto(self):
        for rule in (
            "weak-hash",
            "weak-crypto.python",
            "broken-crypto",
        ):
            assert infer_cwe_from_rule_id(rule) == "CWE-327", rule

    def test_redos(self):
        assert infer_cwe_from_rule_id("redos") == "CWE-1333"
        assert infer_cwe_from_rule_id("polynomial-redos") == "CWE-1333"

    def test_returns_none_for_unknown(self):
        assert infer_cwe_from_rule_id("raptor.lint.style.indentation") is None
        assert infer_cwe_from_rule_id("raptor.crypto.maybe-weak-thing") is None
        assert infer_cwe_from_rule_id("") is None
        assert infer_cwe_from_rule_id(None) is None

    def test_specific_pattern_wins_over_general(self):
        # "subprocess-shell-true" should hit the command-injection
        # pattern, not be vaguely classified as something generic.
        assert infer_cwe_from_rule_id("subprocess-shell-true") == "CWE-78"
