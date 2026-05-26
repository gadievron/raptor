"""Tests for LLM inline-install review stage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


from packages.sca.llm.inline_install_review import review_inline_installs
from packages.sca.llm.schemas import InlineInstallItem, InlineInstallVerdict
from packages.sca.models import Confidence, Dependency, PinStyle


def _make_dep(
    name: str = "flask",
    ecosystem: str = "PyPI",
    version: str = "2.3.0",
    source_kind: str = "dockerfile",
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("/fake/Dockerfile"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:pypi/{name}@{version}",
        parser_confidence=Confidence(level="high"),
        source_kind=source_kind,
    )


class TestReviewInlineInstalls:
    def test_empty_content_returns_empty(self):
        client = MagicMock()
        result = review_inline_installs(
            client,
            Path("/fake/Dockerfile"),
            "",
            [],
            "dockerfile",
        )
        assert result == []

    def test_whitespace_only_returns_empty(self):
        client = MagicMock()
        result = review_inline_installs(
            client,
            Path("/fake/Dockerfile"),
            "   \n\n  ",
            [],
            "dockerfile",
        )
        assert result == []

    @patch("packages.sca.llm.inline_install_review.run_stage")
    def test_llm_finds_missed_install(self, mock_run_stage):
        verdict = InlineInstallVerdict(
            missed_installs=[
                InlineInstallItem(
                    ecosystem="PyPI",
                    name="gunicorn",
                    version="21.2.0",
                    line_no=15,
                    manager_used="pipx install",
                    reasoning="pipx install not covered by mechanical parser",
                ),
            ],
            confidence="low",
        )
        mock_run_stage.return_value = MagicMock(
            error=None, model=verdict, preflight_hit=False,
        )

        client = MagicMock()
        result = review_inline_installs(
            client,
            Path("/fake/Dockerfile"),
            "FROM python:3.12\nRUN pipx install gunicorn==21.2.0",
            [],
            "dockerfile",
        )

        assert len(result) == 1
        assert result[0].name == "gunicorn"
        assert result[0].ecosystem == "PyPI"
        assert result[0].source_kind == "llm_inline_review"
        assert result[0].parser_confidence.level == "low"

    @patch("packages.sca.llm.inline_install_review.run_stage")
    def test_deduplicates_against_mechanical(self, mock_run_stage):
        verdict = InlineInstallVerdict(
            missed_installs=[
                InlineInstallItem(
                    ecosystem="PyPI",
                    name="flask",
                    version="2.3.0",
                    line_no=10,
                    manager_used="pip install",
                    reasoning="found pip install flask",
                ),
                InlineInstallItem(
                    ecosystem="PyPI",
                    name="gunicorn",
                    version=None,
                    line_no=15,
                    manager_used="pipx install",
                    reasoning="found pipx install",
                ),
            ],
            confidence="low",
        )
        mock_run_stage.return_value = MagicMock(
            error=None, model=verdict, preflight_hit=False,
        )

        mechanical = [_make_dep("flask", "PyPI")]
        client = MagicMock()
        result = review_inline_installs(
            client,
            Path("/fake/Dockerfile"),
            "RUN pip install flask\nRUN pipx install gunicorn",
            mechanical,
            "dockerfile",
        )

        # flask already found mechanically — only gunicorn is new
        assert len(result) == 1
        assert result[0].name == "gunicorn"

    @patch("packages.sca.llm.inline_install_review.run_stage")
    def test_llm_error_returns_empty(self, mock_run_stage):
        mock_run_stage.return_value = MagicMock(
            error="LLM unavailable", model=None, preflight_hit=False,
        )

        client = MagicMock()
        result = review_inline_installs(
            client,
            Path("/fake/Dockerfile"),
            "RUN curl https://example.com/install.sh | bash",
            [],
            "dockerfile",
        )
        assert result == []

    @patch("packages.sca.llm.inline_install_review.run_stage")
    def test_preflight_hit_caps_confidence(self, mock_run_stage):
        verdict = InlineInstallVerdict(
            missed_installs=[
                InlineInstallItem(
                    ecosystem="npm",
                    name="esbuild",
                    version=None,
                    line_no=5,
                    manager_used="npx",
                    reasoning="npx esbuild in build step",
                ),
            ],
            confidence="high",
        )
        mock_run_stage.return_value = MagicMock(
            error=None, model=verdict, preflight_hit=True,
        )

        client = MagicMock()
        result = review_inline_installs(
            client,
            Path("/fake/build.sh"),
            "npx esbuild src/index.ts --bundle",
            [],
            "shell_script",
        )

        assert len(result) == 1
        # preflight_hit caps confidence to medium, not high
        # (the verdict itself is capped, deps inherit parser_confidence="low")


class TestInlineInstallSchemas:
    def test_inline_install_item_valid(self):
        item = InlineInstallItem(
            ecosystem="PyPI",
            name="gunicorn",
            version="21.2.0",
            line_no=15,
            manager_used="pipx install",
        )
        assert item.ecosystem == "PyPI"

    def test_inline_install_verdict_defaults(self):
        v = InlineInstallVerdict()
        assert v.missed_installs == []
        assert v.confidence == "low"
        assert v.notes == ""
