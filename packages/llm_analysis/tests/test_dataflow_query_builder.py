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
        """Point discovery at tmp_path only — no in-repo extras leak,
        no real `codeql resolve qlpacks` output leaks either."""
        from core.config import RaptorConfig
        monkeypatch.setattr(_dqb, "_DEFAULT_PACK_ROOT", tmp_path)
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [])
        monkeypatch.setattr(_dqb, "_resolved_pack_pointers", lambda: {})

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
        monkeypatch.setattr(_dqb, "_resolved_pack_pointers", lambda: {})
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
        monkeypatch.setattr(_dqb, "_resolved_pack_pointers", lambda: {})
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
        monkeypatch.setattr(_dqb, "_resolved_pack_pointers", lambda: {})
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
        monkeypatch.setattr(_dqb, "_resolved_pack_pointers", lambda: {})
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
        monkeypatch.setattr(_dqb, "_resolved_pack_pointers", lambda: {})
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

    def test_shipped_query_files_present_on_disk(self):
        """Lock the on-disk file inventory of the in-repo packs.

        Asserts on file paths rather than `discover_prebuilt_query`
        resolution because:

          - Tag-driven discovery hides accidental drift — a query
            that loses its `@kind path-problem` line or canonical CWE
            tag would silently disappear from `discover_*` lookups
            but still be on disk.
          - File-path assertions surface that drift instead of giving
            a confusing "no query for X" indirection.

        Pairs with `test_shipped_cwe_breadth_resolves_via_discovery`
        below, which checks the discovery layer reads the same files
        with the right metadata.
        """
        from packages.llm_analysis.dataflow_query_builder import _DEFAULT_PACK_ROOT  # noqa: F401
        from core.config import RaptorConfig

        repo_packs = (RaptorConfig.EXTRA_CODEQL_PACK_ROOTS or [None])[0]
        assert repo_packs is not None and repo_packs.is_dir(), \
            f"EXTRA_CODEQL_PACK_ROOTS missing or non-existent: {repo_packs}"

        # Each entry: (language pack dir name, list of expected query
        # files relative to Security/). The .ql files MUST exist for
        # the workstream's documented coverage to hold; if you add or
        # rename one, update this list and the discovery test below.
        expected = {
            "python-queries": [
                "CWE-022/PathTraversalLocal.ql",
                "CWE-078/CommandInjectionLocal.ql",
                "CWE-079/ReflectedXssLocal.ql",
                "CWE-089/SqlInjectionLocal.ql",
                "CWE-094/CodeInjectionLocal.ql",
                "CWE-502/UnsafeDeserializationLocal.ql",
                "CWE-611/XxeLocal.ql",
                "CWE-918/SsrfLocal.ql",
            ],
            "java-queries": [
                "CWE-022/PathTraversalLocal.ql",
                "CWE-078/CommandInjectionLocal.ql",
                "CWE-079/XssLocal.ql",
                "CWE-089/SqlInjectionLocal.ql",
                # CWE-94 Java has no unified CodeInjection sink — split
                # across Groovy + JEXL engines, hence two narrow queries.
                "CWE-094/GroovyInjectionLocal.ql",
                "CWE-094/JexlInjectionLocal.ql",
                "CWE-502/UnsafeDeserializationLocal.ql",
                "CWE-611/XxeLocal.ql",
                "CWE-918/SsrfLocal.ql",
            ],
            "javascript-queries": [
                "CWE-022/PathTraversalLocal.ql",
                "CWE-078/CommandInjectionLocal.ql",
                "CWE-079/ReflectedXssLocal.ql",
                "CWE-089/SqlInjectionLocal.ql",
                "CWE-094/CodeInjectionLocal.ql",
                "CWE-502/UnsafeDeserializationLocal.ql",
                "CWE-918/SsrfLocal.ql",
            ],
            "go-queries": [
                "CWE-022/PathTraversalLocal.ql",
                "CWE-078/CommandInjectionLocal.ql",
                "CWE-079/ReflectedXssLocal.ql",
                "CWE-089/SqlInjectionLocal.ql",
                "CWE-918/SsrfLocal.ql",
            ],
        }
        for pack_dirname, query_paths in expected.items():
            pack_dir = repo_packs / pack_dirname
            assert pack_dir.is_dir(), f"missing pack: {pack_dir}"
            for rel in query_paths:
                ql = pack_dir / "Security" / rel
                assert ql.is_file(), f"missing query: {ql}"

    def test_shipped_cwe_breadth_resolves_via_discovery(self):
        """Discovery resolves the canonical CWE for each shipped query
        to the in-repo pack (not the stdlib).

        Skipped when the test environment has no real CodeQL packs —
        a fresh CI runner without `~/.codeql/packages/` populated
        would otherwise generate a misleading failure. The on-disk
        inventory test above runs unconditionally.
        """
        import pytest as _pytest
        from packages.llm_analysis.dataflow_query_builder import _DEFAULT_PACK_ROOT
        if not _DEFAULT_PACK_ROOT.is_dir():
            _pytest.skip(
                f"no real CodeQL packs at {_DEFAULT_PACK_ROOT}; "
                "the on-disk inventory test covers file presence "
                "without needing them."
            )
        # Canonical-CWE coverage shipped per language. Multi-tagged
        # queries (e.g. CommandInjectionLocal.ql tags both cwe-78 and
        # cwe-88) only need the canonical CWE asserted here.
        expected = {
            "python": ["CWE-78", "CWE-89", "CWE-22", "CWE-94", "CWE-502",
                       "CWE-79", "CWE-918", "CWE-611"],
            "java":   ["CWE-78", "CWE-89", "CWE-22", "CWE-94", "CWE-502",
                       "CWE-79", "CWE-611", "CWE-918"],
            "javascript": ["CWE-78", "CWE-22", "CWE-94",
                           "CWE-79", "CWE-89", "CWE-918", "CWE-502"],
            "go":     ["CWE-78", "CWE-22", "CWE-89",
                       "CWE-79", "CWE-918"],
        }
        for lang, cwes in expected.items():
            for cwe in cwes:
                path = discover_prebuilt_query(lang, cwe)
                assert path is not None, \
                    f"{lang}/{cwe}: no query discovered"
                assert "codeql_packs" in str(path), \
                    f"{lang}/{cwe}: stdlib won the collision (expected in-repo): {path}"


class TestResolvedPackPointers:
    """`_resolved_pack_pointers()` shells out to `codeql resolve qlpacks`
    so operators with non-default install layouts (e.g. the upstream
    queries-checkout at `~/.local/codeql-queries/`) get IRIS Tier 1
    coverage. Discovery merges these pointers with the default-root
    walk."""

    def setup_method(self):
        discover_prebuilt_queries.cache_clear()

    def teardown_method(self):
        discover_prebuilt_queries.cache_clear()

    def test_resolved_pointers_picked_up_by_discovery(self, tmp_path, monkeypatch):
        """A pack at a non-default location is found via the resolved-
        pointers fallback. Layout: `<pack_dir>/Security/CWE-NNN/*.ql`
        (no `<lang>-queries/<version>/` wrapper)."""
        from core.config import RaptorConfig

        pack_dir = tmp_path / "alt-install" / "go" / "ql" / "src"
        sec = pack_dir / "Security" / "CWE-078"
        sec.mkdir(parents=True)
        _write_query(sec / "CommandInjection.ql",
                     kind="path-problem", cwe_tag="external/cwe/cwe-78")

        # Default root and extras both empty; only the resolved pointer
        # provides this pack.
        monkeypatch.setattr(_dqb, "_DEFAULT_PACK_ROOT", tmp_path / "no-default")
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [])
        monkeypatch.setattr(_dqb, "_resolved_pack_pointers",
                            lambda: {"go": pack_dir})

        assert discover_prebuilt_query("go", "CWE-78") is not None

    def test_resolved_pointers_handle_nested_cwe_layout(self, tmp_path, monkeypatch):
        """Upstream codeql-queries checkout uses
        `Security/CWE/CWE-NNN/*.ql` — an extra `CWE/` intermediate dir.
        rglob inside the walk handles this transparently."""
        from core.config import RaptorConfig

        pack_dir = tmp_path / "queries" / "cpp" / "ql" / "src"
        nested = pack_dir / "Security" / "CWE" / "CWE-078"
        nested.mkdir(parents=True)
        _write_query(nested / "ExecTainted.ql",
                     kind="path-problem", cwe_tag="external/cwe/cwe-78")

        monkeypatch.setattr(_dqb, "_DEFAULT_PACK_ROOT", tmp_path / "no-default")
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [])
        monkeypatch.setattr(_dqb, "_resolved_pack_pointers",
                            lambda: {"cpp": pack_dir})

        assert discover_prebuilt_query("cpp", "CWE-78") is not None

    def test_extras_still_win_over_resolved(self, tmp_path, monkeypatch):
        """Extras (RaptorConfig) take priority over both resolved
        pointers and the default — RAPTOR-shipped LocalFlowSource packs
        must override stdlib queries on collisions."""
        from core.config import RaptorConfig

        # Extras: in-repo override
        extras_root = tmp_path / "extras"
        extras_pack = extras_root / "python-queries" / "Security" / "CWE-078"
        extras_pack.mkdir(parents=True)
        extras_ql = extras_pack / "FromExtras.ql"
        _write_query(extras_ql, kind="path-problem",
                     cwe_tag="external/cwe/cwe-78")

        # Resolved pointer: stdlib version
        resolved_pack = tmp_path / "alt-install" / "python" / "ql" / "src"
        resolved_sec = resolved_pack / "Security" / "CWE-078"
        resolved_sec.mkdir(parents=True)
        _write_query(resolved_sec / "FromResolved.ql",
                     kind="path-problem", cwe_tag="external/cwe/cwe-78")

        monkeypatch.setattr(_dqb, "_DEFAULT_PACK_ROOT", tmp_path / "no-default")
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [extras_root])
        monkeypatch.setattr(_dqb, "_resolved_pack_pointers",
                            lambda: {"python": resolved_pack})

        assert discover_prebuilt_query("python", "CWE-78") == extras_ql

    def test_codeql_unavailable_falls_back_silently(self, tmp_path, monkeypatch):
        """When `codeql` isn't on PATH, _resolved_pack_pointers returns
        {} and discovery proceeds with whatever the default + extras
        walks find. No crash."""
        from core.config import RaptorConfig
        # Empty default, no extras, no resolved pointers — empty dict.
        monkeypatch.setattr(_dqb, "_DEFAULT_PACK_ROOT", tmp_path / "no-default")
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [])
        monkeypatch.setattr(_dqb, "_resolved_pack_pointers", lambda: {})
        out = discover_prebuilt_queries()
        assert out == {}

    def test_dedup_when_resolved_overlaps_default(self, tmp_path, monkeypatch):
        """If resolve-qlpacks returns a path that's also under
        _DEFAULT_PACK_ROOT, the walk dedupes by resolved absolute
        path so we don't scan the same files twice."""
        from core.config import RaptorConfig

        # Default root contains a python-queries pack
        default_root = tmp_path / "default"
        pack_dir = default_root / "python-queries"
        sec = pack_dir / "Security" / "CWE-078"
        sec.mkdir(parents=True)
        ql = sec / "X.ql"
        _write_query(ql, kind="path-problem", cwe_tag="external/cwe/cwe-78")

        monkeypatch.setattr(_dqb, "_DEFAULT_PACK_ROOT", default_root)
        monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [])
        # Resolved pointer points at the same pack
        monkeypatch.setattr(_dqb, "_resolved_pack_pointers",
                            lambda: {"python": pack_dir})

        # Should still find exactly one entry, not crash on duplicate
        # walk into the same Security tree.
        out = discover_prebuilt_queries()
        assert out.get(("python", "CWE-78")) == ql


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

    def test_cpp_template_aliases_flowsources_to_avoid_dataflow_ambiguity(self):
        """The cpp template MUST alias FlowSources to FS — otherwise its
        transitive `semmle.code.cpp.ir.dataflow.DataFlow` collides with
        the explicit `semmle.code.cpp.dataflow.new.DataFlow` (both
        export module `DataFlow`) and codeql refuses to compile with
        'module DataFlow is ambiguous between: DataFlow::DataFlow,
        DataFlow::DataFlow'. Real failure observed on a /agentic run
        2026-05-10 against /tmp/smt-tier4-test; fix matches canonical
        pattern in shipped CWE-120 query."""
        q = build_template_query(
            language="cpp",
            source_predicate_body="x",
            sink_predicate_body="y",
        )
        assert q is not None
        # The alias MUST be present — without it Tier 2/3 compile
        # fails on every cpp finding.
        assert "FlowSources as FS" in q, (
            "cpp template lost its `FlowSources as FS` alias — "
            "compile will fail with 'module DataFlow is ambiguous'"
        )
        # The redundant explicit DataFlow import should be absent —
        # TaintTracking pulls it in. Keeping both worked fine
        # historically (same module), but the canonical CWE-120 query
        # omits it for cleanliness; assert here so a future drive-by
        # re-add doesn't go unnoticed.
        assert "import semmle.code.cpp.dataflow.new.DataFlow\n" not in q, (
            "cpp template re-added the redundant explicit DataFlow "
            "import; TaintTracking already pulls it in transitively"
        )

    def test_javascript_template_uses_iris_flow_pathgraph(self):
        """The JS template must `import IrisFlow::PathGraph` (the local
        TaintTracking::Global<IrisConfig> path graph), NOT the
        deprecated language-wide `DataFlow::PathGraph`. Pre-fix the
        template imported the deprecated one, which produced
        "PathNode is incompatible with PathNode (the type of the edge
        relation)" warnings AND deprecation notices on compile —
        meaning the path graph types mismatched and the query
        couldn't actually find paths. Verified by `codeql query
        compile` 2026-05-11."""
        q = build_template_query(
            language="javascript",
            source_predicate_body="x",
            sink_predicate_body="y",
        )
        assert q is not None
        # Must import the local path graph from the IrisFlow module.
        assert "import IrisFlow::PathGraph" in q, (
            "javascript template lost its `import IrisFlow::PathGraph` "
            "line — query will compile with PathNode type-mismatch "
            "warnings and produce wrong/empty results"
        )
        # And must NOT import the deprecated language-wide one.
        assert "import DataFlow::PathGraph" not in q, (
            "javascript template re-added the deprecated "
            "`DataFlow::PathGraph` import; codeql warns on this and "
            "the resulting PathNode type doesn't match the local "
            "edge relation"
        )

    def test_all_templates_compile_shape(self):
        """Smoke-test that each language template produces a query
        with the structural pieces needed to compile: imports,
        IrisConfig module, IrisFlow alias, PathGraph import, select
        clause. Doesn't actually invoke codeql (too slow for unit
        tests); just pins the textual contract. Real compile checks
        were run 2026-05-11 for python/java/javascript/go — all
        passed after the javascript fix."""
        for lang in ("python", "java", "cpp", "javascript", "go"):
            q = build_template_query(
                language=lang,
                source_predicate_body="x",
                sink_predicate_body="y",
            )
            assert q is not None, f"{lang} template missing"
            assert f"import {lang}" in q, f"{lang} template missing top-level import"
            assert "module IrisConfig implements DataFlow::ConfigSig" in q, (
                f"{lang} template missing IrisConfig module")
            assert "module IrisFlow = TaintTracking::Global<IrisConfig>" in q, (
                f"{lang} template missing IrisFlow alias")
            assert "import IrisFlow::PathGraph" in q, (
                f"{lang} template missing IrisFlow::PathGraph import — "
                f"PathNode types won't match the edge relation")
            assert "from IrisFlow::PathNode source, IrisFlow::PathNode sink" in q, (
                f"{lang} template missing path-problem select preamble")

    def test_cpp_prompt_instructs_FS_prefix(self):
        """Companion to the template change: the LLM prompt for cpp
        predicates must mention the `FS::` prefix so the LLM doesn't
        emit an unqualified `n instanceof FlowSource` that won't
        resolve."""
        # Inspect the prompt-building helper directly — this is the
        # source of truth for what the LLM sees. Pass a dummy hypothesis
        # and check the cpp branch fires.
        from packages.llm_analysis.dataflow_validation import (
            _ask_llm_for_predicates,
        )
        from packages.hypothesis_validation.hypothesis import Hypothesis
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        h = Hypothesis(
            claim="dummy",
            target=Path("/x.c"),
        )
        captured = {}

        def fake_generate_structured(prompt, schema, system_prompt, task_type):
            captured["prompt"] = prompt
            return None  # short-circuit; we only care about the prompt

        client = MagicMock()
        client.generate_structured.side_effect = fake_generate_structured
        _ask_llm_for_predicates(h, client, "cpp")
        prompt = captured.get("prompt", "")
        # The cpp-specific instruction MUST appear so the LLM uses the
        # `FS::` prefix when referencing FlowSources types.
        assert "FS::" in prompt, (
            f"cpp prompt missing FS:: prefix instruction; LLM may emit "
            f"unqualified FlowSource references that won't compile. "
            f"Prompt: {prompt[:500]}"
        )

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
