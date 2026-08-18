"""Tests for core.concepts.compiler — invariant-to-rule compilation."""

from __future__ import annotations

import json
from unittest.mock import patch

from core.concepts.compiler import (
    CompilationResult,
    _fixture_ext,
    _fixture_language,
    _infer_engine,
    _make_rule_id,
    build_invariant_prompt,
    compile_invariant,
    compile_model,
)
from core.concepts.model import DomainModel, Invariant

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

def _make_invariant(**overrides) -> Invariant:
    defaults = {
        "id": "inv-page-lock",
        "concept": "page-cache-ownership",
        "statement": "All callers of copy_page must hold page_lock",
        "negation": "A caller of copy_page that does not hold page_lock",
        "description": "Page cache ownership invariant",
        "evidence": ["mm/filemap.c:1234 - copy_page with lock held"],
        "relevant_cwes": ["CWE-362"],
        "confidence": "traced",
    }
    defaults.update(overrides)
    return Invariant(**defaults)


def _stub_llm(response: dict | None = None):
    """LLM stub returning a fixed response dict."""
    default = {
        "rule_body": "rules:\n  - id: test\n    pattern: copy_page(...)\n    languages: [c]\n    message: violation\n    severity: WARNING\n",
        "rationale": "Matches calls to copy_page without page_lock",
        "test_positive": "void bad(void) { copy_page(a, b); }",
        "test_negative": "void good(void) { lock(page_lock); copy_page(a, b); unlock(page_lock); }",
    }
    data = response if response is not None else default

    def llm(prompt, schema, system_prompt):
        return data

    return llm


# ------------------------------------------------------------------
# Prompt construction
# ------------------------------------------------------------------

class TestBuildInvariantPrompt:
    # build_invariant_prompt returns the enveloped (user, system)
    # pair: invariant text / evidence / snippets in untrusted blocks
    # (user), CWEs and id in slots (user), task instructions in the
    # system text.
    def test_includes_statement_and_negation(self):
        inv = _make_invariant()
        user, _system = build_invariant_prompt(inv, "semgrep")
        assert "All callers of copy_page must hold page_lock" in user
        assert "does not hold page_lock" in user

    def test_includes_engine(self):
        inv = _make_invariant()
        _user, system = build_invariant_prompt(inv, "coccinelle")
        assert "coccinelle" in system

    def test_includes_cwes(self):
        inv = _make_invariant(relevant_cwes=["CWE-362", "CWE-416"])
        user, _system = build_invariant_prompt(inv, "semgrep")
        assert "CWE-362" in user
        assert "CWE-416" in user

    def test_includes_evidence(self):
        inv = _make_invariant(
            evidence=["mm/filemap.c:1234 - with lock", "mm/swap.c:56 - also locked"],
        )
        user, _system = build_invariant_prompt(inv, "semgrep")
        assert "mm/filemap.c:1234" in user
        assert "mm/swap.c:56" in user

    def test_caps_evidence_at_5(self):
        inv = _make_invariant(evidence=[f"file{i}.c:1 - ev" for i in range(10)])
        user, _system = build_invariant_prompt(inv, "semgrep")
        assert "file4.c" in user
        assert "file5.c" not in user
        assert "5 more" in user

    def test_retry_feedback(self):
        inv = _make_invariant()
        user, system = build_invariant_prompt(
            inv, "semgrep", retry_feedback="rule too broad",
        )
        assert "RETRY" in system
        assert "rule too broad" in user

    def test_no_description(self):
        inv = _make_invariant(description="")
        user, _system = build_invariant_prompt(inv, "semgrep")
        assert "invariant-context" not in user

    def test_no_cwes(self):
        inv = _make_invariant(relevant_cwes=[])
        user, _system = build_invariant_prompt(inv, "semgrep")
        assert "relevant_cwes" not in user


class TestFixtureLanguageInPrompt:
    """The fixture-language instruction tracks _fixture_ext.

    The synthesis prompt must ask for test fixtures in the SAME
    language the dual-control oracle will execute them as
    (_fixture_ext resolves the extension from the invariant's
    evidence); a prompt that unconditionally demands "parseable C
    code" gets non-C targets C fixtures executed under the wrong
    extension, and valid rules are rejected."""

    def test_python_evidence_asks_for_python_fixtures(self):
        inv = _make_invariant(evidence=["src/auth.py:42 - check"])
        _user, system = build_invariant_prompt(inv, "semgrep")
        assert "parseable Python code" in system
        assert "parseable C code" not in system
        assert "#include" not in system

    def test_coccinelle_asks_for_c_fixtures(self):
        inv = _make_invariant(evidence=["src/auth.py:42 - check"])
        _user, system = build_invariant_prompt(inv, "coccinelle")
        # Coccinelle always executes fixtures as .c regardless of
        # evidence extension.
        assert "parseable C code" in system
        assert "no #include headers" in system

    def test_c_evidence_with_semgrep_asks_for_c(self):
        inv = _make_invariant(evidence=["mm/filemap.c:1234 - lock held"])
        _user, system = build_invariant_prompt(inv, "semgrep")
        assert "parseable C code" in system
        assert "no #include headers" in system

    def test_cpp_evidence_asks_for_cpp(self):
        inv = _make_invariant(evidence=["src/engine.cpp:7 - guarded"])
        _user, system = build_invariant_prompt(inv, "semgrep")
        assert "parseable C++ code" in system
        assert "no #include headers" in system

    def test_go_evidence_asks_for_go(self):
        inv = _make_invariant(evidence=["pkg/server.go:88 - checked"])
        _user, system = build_invariant_prompt(inv, "semgrep")
        assert "parseable Go code" in system
        assert "#include" not in system

    def test_no_evidence_defaults_to_python(self):
        # _fixture_ext falls back to .py, so the prompt must too.
        inv = _make_invariant(evidence=[])
        _user, system = build_invariant_prompt(inv, "semgrep")
        assert "parseable Python code" in system
        assert "parseable C code" not in system

    def test_unknown_extension_names_the_extension(self):
        inv = _make_invariant(evidence=["src/thing.weird:3 - site"])
        _user, system = build_invariant_prompt(inv, "semgrep")
        assert ".weird source file" in system
        assert "parseable C code" not in system

    def test_prompt_language_matches_oracle_extension(self):
        # The instruction and the executed extension must agree for
        # every evidence shape the compiler encounters.
        cases = [
            (["a.py:1 - x"], "semgrep", "Python"),
            (["a.rs:1 - x"], "semgrep", "Rust"),
            (["a.java:1 - x"], "semgrep", "Java"),
            (["a.c:1 - x"], "coccinelle", "C"),
        ]
        for evidence, engine, lang in cases:
            inv = _make_invariant(evidence=evidence)
            ext = _fixture_ext(inv, engine)
            assert _fixture_language(ext) == lang
            _user, system = build_invariant_prompt(inv, engine)
            assert f"parseable {lang} code" in system


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

class TestHelpers:
    def test_make_rule_id(self):
        inv = _make_invariant(id="page-lock-hold")
        rid = _make_rule_id(inv, "semgrep", 0)
        assert rid.startswith("inv.")
        assert "page-lock-hold" in rid
        assert rid.endswith(".0")

    def test_make_rule_id_sanitises(self):
        inv = _make_invariant(id="bad/chars here!")
        rid = _make_rule_id(inv, "coccinelle", 1)
        assert "/" not in rid
        assert "!" not in rid

    def test_fixture_ext_coccinelle(self):
        inv = _make_invariant()
        assert _fixture_ext(inv, "coccinelle") == ".c"

    def test_fixture_ext_from_evidence(self):
        inv = _make_invariant(evidence=["auth.py:42 - check"])
        assert _fixture_ext(inv, "semgrep") == ".py"

    def test_fixture_ext_default(self):
        inv = _make_invariant(evidence=[])
        assert _fixture_ext(inv, "semgrep") == ".py"

    def test_fixture_language_known_extensions(self):
        assert _fixture_language(".c") == "C"
        assert _fixture_language(".hpp") == "C++"
        assert _fixture_language(".py") == "Python"
        assert _fixture_language(".ts") == "TypeScript"
        assert _fixture_language(".rb") == "Ruby"

    def test_fixture_language_case_insensitive(self):
        assert _fixture_language(".PY") == "Python"

    def test_fixture_language_unknown_extension_returns_none(self):
        assert _fixture_language(".weird") is None
        assert _fixture_language("") is None

    def test_infer_engine_c(self):
        inv = _make_invariant(evidence=["mm/filemap.c:1234 - with lock"])
        assert _infer_engine(inv) == "coccinelle"

    def test_infer_engine_python(self):
        inv = _make_invariant(evidence=["auth/login.py:10 - validated"])
        assert _infer_engine(inv) == "semgrep"

    def test_infer_engine_default(self):
        inv = _make_invariant(evidence=[])
        assert _infer_engine(inv) == "semgrep"


# ------------------------------------------------------------------
# CompilationResult
# ------------------------------------------------------------------

class TestCompilationResult:
    def test_success_requires_body_and_dual_control(self):
        r = CompilationResult(invariant_id="x")
        assert not r.success

        r.rule_body = "rules: ..."
        assert not r.success

        r.dual_control = True
        assert r.success

    def test_to_dict_roundtrip(self):
        r = CompilationResult(
            invariant_id="inv-1",
            engine="semgrep",
            rule_id="inv.inv-1.semgrep.0",
            rule_body="rules: ...",
            dual_control=True,
            matches=[{"file": "a.py", "line": 10, "snippet": ""}],
            errors=["attempt 0: retry"],
        )
        d = r.to_dict()
        assert d["invariant_id"] == "inv-1"
        assert d["dual_control"] is True
        assert len(d["matches"]) == 1


# ------------------------------------------------------------------
# compile_invariant
# ------------------------------------------------------------------

class TestCompileInvariant:
    def test_rejects_missing_statement(self, tmp_path):
        inv = _make_invariant(statement="")
        r = compile_invariant(inv, "semgrep", _stub_llm(), tmp_path)
        assert not r.success
        assert "statement" in r.errors[0]

    def test_rejects_missing_negation(self, tmp_path):
        inv = _make_invariant(negation="")
        r = compile_invariant(inv, "semgrep", _stub_llm(), tmp_path)
        assert not r.success
        assert "negation" in r.errors[0]

    def test_handles_llm_exception(self, tmp_path):
        def bad_llm(prompt, schema, system_prompt):
            raise RuntimeError("model down")

        inv = _make_invariant()
        r = compile_invariant(inv, "semgrep", bad_llm, tmp_path, max_retries=0)
        assert not r.success
        assert any("LLM error" in e for e in r.errors)

    def test_handles_llm_non_dict(self, tmp_path):
        inv = _make_invariant()
        r = compile_invariant(inv, "semgrep", _stub_llm(response="garbage"), tmp_path, max_retries=0)
        assert not r.success
        assert any("non-dict" in e for e in r.errors)

    def test_handles_missing_rule_body(self, tmp_path):
        inv = _make_invariant()
        r = compile_invariant(
            inv, "semgrep",
            _stub_llm(response={"rationale": "no rule"}),
            tmp_path,
            max_retries=0,
        )
        assert not r.success
        assert any("rule_body" in e for e in r.errors)

    @patch("packages.checker_synthesis.synthesise._dual_control")
    @patch("packages.checker_synthesis.synthesise._write_rule")
    def test_success_with_dual_control(self, mock_write, mock_dc, tmp_path):
        mock_write.return_value = tmp_path / "checkers" / "test.yml"
        mock_dc.return_value = (True, [])

        inv = _make_invariant()
        r = compile_invariant(inv, "semgrep", _stub_llm(), tmp_path)
        assert r.success
        assert r.rule_id is not None
        assert r.dual_control is True
        mock_dc.assert_called_once()

    @patch("packages.checker_synthesis.synthesise._dual_control")
    @patch("packages.checker_synthesis.synthesise._write_rule")
    def test_dual_control_failure_retries(self, mock_write, mock_dc, tmp_path):
        mock_write.return_value = tmp_path / "checkers" / "test.yml"
        mock_dc.side_effect = [
            (False, ["dual control: positive fixture not matched"]),
            (True, []),
        ]

        inv = _make_invariant()
        r = compile_invariant(inv, "semgrep", _stub_llm(), tmp_path, max_retries=1)
        assert r.success
        assert mock_dc.call_count == 2

    @patch("packages.checker_synthesis.synthesise._dual_control")
    @patch("packages.checker_synthesis.synthesise._write_rule")
    def test_no_fixtures_still_saves_rule(self, mock_write, mock_dc, tmp_path):
        mock_write.return_value = tmp_path / "checkers" / "test.yml"

        inv = _make_invariant()
        llm = _stub_llm(response={
            "rule_body": "rules: ...",
            "rationale": "test",
            "test_positive": "",
            "test_negative": "",
        })
        r = compile_invariant(inv, "semgrep", llm, tmp_path, max_retries=0)
        assert r.rule_body == "rules: ..."
        assert not r.dual_control
        mock_dc.assert_not_called()

    @patch("packages.checker_synthesis.synthesise._run_engine")
    @patch("packages.checker_synthesis.synthesise._dual_control")
    @patch("packages.checker_synthesis.synthesise._write_rule")
    def test_sweep_with_repo_root(self, mock_write, mock_dc, mock_run, tmp_path):
        mock_write.return_value = tmp_path / "checkers" / "test.yml"
        mock_dc.return_value = (True, [])

        from packages.checker_synthesis.models import Match
        mock_run.return_value = (
            [Match(file="src/bad.c", line=42), Match(file="src/worse.c", line=99)],
            [],
        )

        repo = tmp_path / "repo"
        repo.mkdir()

        inv = _make_invariant()
        r = compile_invariant(inv, "semgrep", _stub_llm(), tmp_path, repo_root=repo)
        assert r.success
        assert len(r.matches) == 2
        assert r.matches[0]["file"] == "src/bad.c"

    @patch("packages.checker_synthesis.synthesise._run_engine")
    @patch("packages.checker_synthesis.synthesise._dual_control")
    @patch("packages.checker_synthesis.synthesise._write_rule")
    def test_no_sweep_on_dual_control_failure(
        self, mock_write, mock_dc, mock_run, tmp_path,
    ):
        # rule_body is populated even when dual control fails (the
        # last attempt's evidence) — the codebase sweep must still be
        # gated on dual control passing, so an unvalidated rule never
        # produces matches.
        mock_write.return_value = tmp_path / "checkers" / "test.yml"
        mock_dc.return_value = (
            False, ["dual control: positive fixture not matched"],
        )

        repo = tmp_path / "repo"
        repo.mkdir()

        inv = _make_invariant()
        r = compile_invariant(
            inv, "semgrep", _stub_llm(), tmp_path,
            repo_root=repo, max_retries=0,
        )
        assert r.rule_body  # evidence carried the body
        assert not r.dual_control
        mock_run.assert_not_called()
        assert r.matches == []

    @patch("packages.checker_synthesis.synthesise._run_engine")
    @patch("packages.checker_synthesis.synthesise._dual_control")
    @patch("packages.checker_synthesis.synthesise._write_rule")
    def test_sweep_caps_matches(self, mock_write, mock_dc, mock_run, tmp_path):
        mock_write.return_value = tmp_path / "checkers" / "test.yml"
        mock_dc.return_value = (True, [])

        from packages.checker_synthesis.models import Match
        mock_run.return_value = (
            [Match(file=f"f{i}.c", line=i) for i in range(100)],
            [],
        )

        repo = tmp_path / "repo"
        repo.mkdir()

        inv = _make_invariant()
        r = compile_invariant(
            inv, "semgrep", _stub_llm(), tmp_path,
            repo_root=repo, max_sweep_matches=10,
        )
        assert len(r.matches) == 10
        assert any("capped" in e for e in r.errors)


# ------------------------------------------------------------------
# compile_model
# ------------------------------------------------------------------

class TestCompileModel:
    @patch("core.concepts.compiler.compile_invariant")
    def test_filters_by_confidence(self, mock_compile, tmp_path):
        mock_compile.side_effect = lambda inv, *a, **kw: CompilationResult(
            invariant_id=inv.id, dual_control=True, rule_body="r",
            rule_id=f"inv.{inv.id}.semgrep.0",
        )
        model = DomainModel(invariants=[
            _make_invariant(id="low", confidence="inferred"),
            _make_invariant(id="high", confidence="traced"),
        ])
        results = compile_model(model, tmp_path, _stub_llm(), min_confidence="traced")
        assert len(results) == 1
        compiled_ids = [r.invariant_id for r in results]
        assert "high" in compiled_ids

    @patch("core.concepts.compiler.compile_invariant")
    def test_skips_already_compiled(self, mock_compile, tmp_path):
        mock_compile.side_effect = lambda inv, *a, **kw: CompilationResult(
            invariant_id=inv.id, dual_control=True, rule_body="r",
            rule_id=f"inv.{inv.id}.semgrep.0",
        )
        model = DomainModel(invariants=[
            _make_invariant(id="done", mechanical_rule="existing-rule"),
            _make_invariant(id="todo"),
        ])
        results = compile_model(model, tmp_path, _stub_llm(), min_confidence="inferred")
        compiled_ids = [r.invariant_id for r in results]
        assert "done" not in compiled_ids
        assert "todo" in compiled_ids

    @patch("core.concepts.compiler.compile_invariant")
    def test_skips_incomplete_invariants(self, mock_compile, tmp_path):
        mock_compile.side_effect = lambda inv, *a, **kw: CompilationResult(
            invariant_id=inv.id, dual_control=True, rule_body="r",
            rule_id=f"inv.{inv.id}.semgrep.0",
        )
        model = DomainModel(invariants=[
            _make_invariant(id="no-neg", negation=""),
            _make_invariant(id="ok"),
        ])
        results = compile_model(model, tmp_path, _stub_llm(), min_confidence="inferred")
        compiled_ids = [r.invariant_id for r in results]
        assert "no-neg" not in compiled_ids
        assert "ok" in compiled_ids

    @patch("core.concepts.compiler.compile_invariant")
    def test_respects_max_compilations(self, mock_compile, tmp_path):
        mock_compile.return_value = CompilationResult(
            invariant_id="x", dual_control=True, rule_body="r",
        )
        model = DomainModel(invariants=[
            _make_invariant(id=f"inv-{i}") for i in range(20)
        ])
        results = compile_model(
            model, tmp_path, _stub_llm(),
            min_confidence="inferred", max_compilations=5,
        )
        assert len(results) == 5

    @patch("core.concepts.compiler.compile_invariant")
    def test_updates_mechanical_rule_on_success(self, mock_compile, tmp_path):
        mock_compile.return_value = CompilationResult(
            invariant_id="inv-1",
            rule_id="inv.inv-1.semgrep.0",
            rule_body="rules: ...",
            dual_control=True,
        )
        inv = _make_invariant(id="inv-1")
        model = DomainModel(invariants=[inv])
        compile_model(model, tmp_path, _stub_llm(), min_confidence="inferred")
        assert inv.mechanical_rule == "inv.inv-1.semgrep.0"

    @patch("core.concepts.compiler.compile_invariant")
    def test_writes_manifest(self, mock_compile, tmp_path):
        mock_compile.return_value = CompilationResult(
            invariant_id="inv-1", rule_body="r", dual_control=True,
        )
        model = DomainModel(invariants=[_make_invariant(id="inv-1")])
        compile_model(model, tmp_path, _stub_llm(), min_confidence="inferred")
        manifest = tmp_path / "compiled-invariants.json"
        assert manifest.exists()
        data = json.loads(manifest.read_text())
        assert len(data) == 1
        assert data[0]["invariant_id"] == "inv-1"

    @patch("core.concepts.compiler.compile_invariant")
    def test_infers_engine_from_evidence(self, mock_compile, tmp_path):
        mock_compile.return_value = CompilationResult(invariant_id="x")
        model = DomainModel(invariants=[
            _make_invariant(evidence=["mm/filemap.c:1234 - lock held"]),
        ])
        compile_model(model, tmp_path, _stub_llm(), min_confidence="inferred")
        # First call uses inferred engine; fallback tries the other.
        first_call = mock_compile.call_args_list[0]
        assert first_call[0][1] == "coccinelle"

    @patch("core.concepts.compiler.compile_invariant")
    def test_engine_fallback_on_failure(self, mock_compile, tmp_path):
        mock_compile.return_value = CompilationResult(invariant_id="x")
        model = DomainModel(invariants=[
            _make_invariant(evidence=["mm/filemap.c:1234 - lock held"]),
        ])
        compile_model(model, tmp_path, _stub_llm(), min_confidence="inferred")
        assert mock_compile.call_count == 2
        assert mock_compile.call_args_list[0][0][1] == "coccinelle"
        assert mock_compile.call_args_list[1][0][1] == "semgrep"

    @patch("core.concepts.compiler.compile_invariant")
    def test_no_fallback_when_primary_succeeds(self, mock_compile, tmp_path):
        mock_compile.return_value = CompilationResult(
            invariant_id="x", rule_body="rule", dual_control=True,
        )
        model = DomainModel(invariants=[
            _make_invariant(evidence=["mm/filemap.c:1234 - lock held"]),
        ])
        compile_model(model, tmp_path, _stub_llm(), min_confidence="inferred")
        assert mock_compile.call_count == 1

    @patch("core.concepts.compiler.compile_invariant")
    def test_explicit_engine_skips_fallback(self, mock_compile, tmp_path):
        mock_compile.return_value = CompilationResult(invariant_id="x")
        model = DomainModel(invariants=[
            _make_invariant(evidence=["mm/filemap.c:1234 - lock held"]),
        ])
        compile_model(
            model, tmp_path, _stub_llm(),
            min_confidence="inferred", engine="semgrep",
        )
        # Explicit engine: no fallback even on failure.
        assert mock_compile.call_count == 1
        assert mock_compile.call_args[0][1] == "semgrep"


# ------------------------------------------------------------------
# CopyFail ground truth (CVE-2026-31431)
# ------------------------------------------------------------------

def _copyfail_invariant() -> Invariant:
    """The invariant that CopyFail violates: page-cache pages are read-only."""
    return Invariant(
        id="page_cache_readonly",
        concept="page_ownership",
        statement="Page-cache pages must not be written to",
        negation="Writing through a shared page corrupts the page cache",
        description="Splice path uses get_page (borrow) not alloc_page (copy)",
        evidence=[
            "crypto/af_alg.c:1142 - extract_iter_to_sg borrows page-cache pages",
            "crypto/af_alg.c:1198 - _aead_recvmsg writes into borrowed pages",
            "include/linux/scatterlist.h:142 - sg_chain aliases, no copy",
        ],
        relevant_cwes=["CWE-416", "CWE-787"],
        confidence="traced",
    )


def _copyfail_coccinelle_response() -> dict:
    """Stub LLM response: Coccinelle rule for page-cache write violation."""
    return {
        "rule_body": (
            "@@\n"
            "expression E;\n"
            "@@\n"
            "- memcpy(sg_virt(...), E, ...)\n"
            "+ /* potential page-cache corruption: writing to borrowed page */\n"
        ),
        "rationale": (
            "Matches memcpy into sg_virt() destinations — scatterlist "
            "entries that may reference page-cache pages.  The invariant "
            "violation is writing through a borrowed page reference."
        ),
        "test_positive": (
            "void bad(struct scatterlist *sg, void *src, int len) {\n"
            "    memcpy(sg_virt(sg), src, len);\n"
            "}\n"
        ),
        "test_negative": (
            "void good(struct scatterlist *sg, void *src, int len) {\n"
            "    void *dst = kmalloc(len, GFP_KERNEL);\n"
            "    memcpy(dst, src, len);\n"
            "    sg_set_buf(sg, dst, len);\n"
            "}\n"
        ),
    }


class TestCopyFail:
    """Verify the compiler handles the CopyFail invariant correctly."""

    def test_prompt_captures_ownership_semantics(self):
        inv = _copyfail_invariant()
        user, system = build_invariant_prompt(inv, "coccinelle")
        assert "Page-cache pages must not be written to" in user
        assert "Writing through a shared page" in user
        assert "CWE-416" in user
        assert "crypto/af_alg.c" in user
        assert "coccinelle" in system

    def test_infers_coccinelle_from_evidence(self):
        inv = _copyfail_invariant()
        assert _infer_engine(inv) == "coccinelle"

    def test_fixture_ext_is_c(self):
        inv = _copyfail_invariant()
        assert _fixture_ext(inv, "coccinelle") == ".c"

    @patch("packages.checker_synthesis.synthesise._dual_control")
    @patch("packages.checker_synthesis.synthesise._write_rule")
    def test_compiles_to_coccinelle_rule(self, mock_write, mock_dc, tmp_path):
        mock_write.return_value = tmp_path / "checkers" / "test.cocci"
        mock_dc.return_value = (True, [])

        inv = _copyfail_invariant()
        llm = _stub_llm(response=_copyfail_coccinelle_response())
        r = compile_invariant(inv, "coccinelle", llm, tmp_path)

        assert r.success
        assert r.engine == "coccinelle"
        assert "memcpy" in r.rule_body
        assert "sg_virt" in r.rule_body
        assert "page-cache" in r.rationale.lower()

    @patch("packages.checker_synthesis.synthesise._dual_control")
    @patch("packages.checker_synthesis.synthesise._write_rule")
    def test_compile_model_picks_coccinelle(self, mock_write, mock_dc, tmp_path):
        mock_write.return_value = tmp_path / "checkers" / "test.cocci"
        mock_dc.return_value = (True, [])

        from core.concepts.model import Concept, Contract
        model = DomainModel(
            target="crypto/",
            source_root="/data/linux/",
            concepts=[Concept(
                id="page_ownership",
                description="Pages have ownership semantics",
                confidence="traced",
            )],
            invariants=[_copyfail_invariant()],
            contracts=[Contract(
                function="extract_iter_to_sg",
                file="crypto/af_alg.c",
                when="MSG_SPLICE_PAGES set",
                ownership_transfer="none — borrowed",
            )],
        )

        llm = _stub_llm(response=_copyfail_coccinelle_response())
        results = compile_model(
            model, tmp_path, llm,
            min_confidence="traced",
        )

        assert len(results) == 1
        r = results[0]
        assert r.success
        assert r.engine == "coccinelle"
        assert model.invariants[0].mechanical_rule is not None
