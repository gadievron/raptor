"""Prior finding-grade claims: /agentic per-finding analyses reach the
audit review prompt as claims-to-verify, never as coverage or verdicts.

The kind-aware gap fold excludes these entries from suppression; this
is the other half — they surface in review context, sourced from the
project index and from ``--prior-journal`` run dirs whose journals are
not yet merged into the index (the /agentic post-pass case).
"""

from __future__ import annotations

from pathlib import Path

from core.audit.context import format_context_for_prompt
from core.audit.orchestrator import (
    OrchestratorConfig,
    _build_context,
    _build_prior_finding_analyses,
)
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    merge_into_index,
    now_iso,
)


def _entry(*, producer="agentic", verdict="suspicious", function="f",
           body="scanner said so", run_id="agentic_1", ts=None):
    return ReviewJournalEntry(
        ts=ts or now_iso(),
        run_id=run_id,
        file="src/a.c",
        function=function,
        verdict=verdict,
        source_hash="",
        cwe="CWE-89",
        model="test-model",
        body=body,
        producer=producer,
    )


def _config(tmp_path, **kw) -> OrchestratorConfig:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return OrchestratorConfig(target_path=target, out_dir=out, **kw)


class TestBuildPriorFindingAnalyses:
    def test_reads_prior_journal_dirs(self, tmp_path):
        run = tmp_path / "agentic_run"
        run.mkdir()
        append_entry(run, _entry())
        config = _config(tmp_path, prior_journal_dirs=[run])

        claims = _build_prior_finding_analyses(config, None)
        assert claims is not None
        assert list(claims) == ["src/a.c:f"]
        claim = claims["src/a.c:f"][0]
        assert claim["verdict"] == "suspicious"
        assert claim["cwe"] == "CWE-89"
        assert claim["body"] == "scanner said so"

    def test_reads_project_index(self, tmp_path):
        project = tmp_path / "project"
        run = project / "agentic_1"
        run.mkdir(parents=True)
        append_entry(run, _entry())
        merge_into_index(project, run)
        config = _config(tmp_path)

        claims = _build_prior_finding_analyses(config, project)
        assert claims and "src/a.c:f" in claims

    def test_function_grade_and_error_entries_excluded(self, tmp_path):
        run = tmp_path / "agentic_run"
        run.mkdir()
        append_entry(run, _entry(producer="audit", function="g"))
        append_entry(run, _entry(verdict="error", function="h"))
        config = _config(tmp_path, prior_journal_dirs=[run])

        assert _build_prior_finding_analyses(config, None) is None

    def test_newest_first_and_capped(self, tmp_path):
        run = tmp_path / "agentic_run"
        run.mkdir()
        for i in range(5):
            append_entry(run, _entry(body=f"claim {i}"))
        config = _config(tmp_path, prior_journal_dirs=[run])

        claims = _build_prior_finding_analyses(config, None)
        group = claims["src/a.c:f"]
        assert len(group) == 3
        assert group[0]["body"] == "claim 4"

    def test_missing_dir_is_tolerated(self, tmp_path):
        config = _config(
            tmp_path, prior_journal_dirs=[Path("/nonexistent/run")],
        )
        assert _build_prior_finding_analyses(config, None) is None


class TestContextInjection:
    def _gap(self):
        return {"file": "src/a.c", "name": "f", "line_start": 1,
                "line_end": 3, "strategies": []}

    def _checklist(self, config):
        return {
            "target_path": str(config.target_path),
            "files": [{
                "path": "src/a.c",
                "items": [{"name": "f", "kind": "function",
                           "line_start": 1, "line_end": 3}],
            }],
        }

    def _config_with_claims(self, tmp_path):
        config = _config(tmp_path)
        (config.target_path / "src").mkdir()
        (config.target_path / "src" / "a.c").write_text(
            "int f(void) {\n    return 0;\n}\n", encoding="utf-8",
        )
        config.prior_finding_analyses = {
            "src/a.c:f": [{
                "verdict": "suspicious", "cwe": "CWE-89",
                "model": "test-model", "run_id": "agentic_1",
                "ts": now_iso(), "body": "scanner said so",
            }],
        }
        return config

    def test_claims_reach_ctx(self, tmp_path):
        config = self._config_with_claims(tmp_path)
        ctx = _build_context(
            config, self._gap(), self._checklist(config), None,
        )
        assert ctx.get("prior_finding_analyses")

    def test_blind_mode_withholds_claims(self, tmp_path):
        config = self._config_with_claims(tmp_path)
        ctx = _build_context(
            config, self._gap(), self._checklist(config), None, blind=True,
        )
        assert "prior_finding_analyses" not in ctx


class TestPromptRendering:
    def _ctx(self):
        return {
            "file": "src/a.c",
            "function": "f",
            "line_start": 1,
            "source": "int f(void) { return 0; }",
            "prior_finding_analyses": [{
                "verdict": "suspicious", "cwe": "CWE-89",
                "model": "test-model", "run_id": "agentic_1",
                "ts": now_iso(), "body": "scanner said so",
            }],
        }

    def test_section_rendered_as_claims(self):
        text = format_context_for_prompt(self._ctx())
        assert "Prior finding-grade analyses" in text
        assert "suspicious" in text
        assert "CWE-89" in text
        assert "never" in text and "inherit a verdict" in text

    def test_body_is_enveloped(self):
        """Bodies can embed scanner messages quoting the target repo —
        they must ride inside the untrusted envelope, not verbatim."""
        text = format_context_for_prompt(self._ctx())
        assert 'kind="prior_finding_analysis"' in text
        assert "scanner said so" in text

    def test_absent_without_claims(self):
        ctx = self._ctx()
        del ctx["prior_finding_analyses"]
        text = format_context_for_prompt(ctx)
        assert "Prior finding-grade analyses" not in text


class TestTunables:
    def test_cap_zero_disables_injection(self, tmp_path):
        run = tmp_path / "agentic_run"
        run.mkdir()
        append_entry(run, _entry())
        config = _config(
            tmp_path, prior_journal_dirs=[run],
            prior_claims_per_function=0,
        )
        assert _build_prior_finding_analyses(config, None) is None

    def test_cap_honoured(self, tmp_path):
        run = tmp_path / "agentic_run"
        run.mkdir()
        for i in range(4):
            append_entry(run, _entry(body=f"claim {i}"))
        config = _config(
            tmp_path, prior_journal_dirs=[run],
            prior_claims_per_function=2,
        )
        claims = _build_prior_finding_analyses(config, None)
        group = claims["src/a.c:f"]
        assert len(group) == 2
        assert group[0]["body"] == "claim 3"

    def test_bodies_excerpted_at_collection(self, tmp_path):
        run = tmp_path / "agentic_run"
        run.mkdir()
        append_entry(run, _entry(body="x" * 2000))
        config = _config(
            tmp_path, prior_journal_dirs=[run],
            prior_claim_excerpt_chars=100,
        )
        claims = _build_prior_finding_analyses(config, None)
        assert len(claims["src/a.c:f"][0]["body"]) == 100
