"""Tests for pipeline-level LLM integration (inline review + upgrade impact)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch


from packages.sca.models import (
    Confidence,
    Dependency,
    Manifest,
    PinStyle,
)
from packages.sca.pipeline import (
    _classify_inline_source,
    _run_llm_inline_review,
    _run_upgrade_impact,
    _run_version_diff_review,
)


def _make_manifest(path: Path, ecosystem: str = "Inline") -> Manifest:
    return Manifest(
        path=path,
        ecosystem=ecosystem,
        is_lockfile=False,
    )


def _make_dep(
    name: str = "flask",
    ecosystem: str = "PyPI",
    source_kind: str = "dockerfile",
    declared_in: Path = Path("/fake/Dockerfile"),
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version="1.0.0",
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:pypi/{name}@1.0.0",
        parser_confidence=Confidence(level="high"),
        source_kind=source_kind,
    )


class TestClassifyInlineSource:
    def test_dockerfile(self):
        assert _classify_inline_source(Path("/a/Dockerfile")) == "dockerfile"

    def test_dockerfile_variant(self):
        assert _classify_inline_source(Path("/a/Dockerfile.prod")) == "dockerfile"

    def test_containerfile(self):
        assert _classify_inline_source(Path("/a/Containerfile")) == "dockerfile"

    def test_devcontainer(self):
        assert _classify_inline_source(Path("/a/devcontainer.json")) == "devcontainer"

    def test_shell_script(self):
        assert _classify_inline_source(Path("/a/setup.sh")) == "shell_script"

    def test_bash_script(self):
        assert _classify_inline_source(Path("/a/build.bash")) == "shell_script"

    def test_gha_workflow(self):
        p = Path("/repo/.github/workflows/ci.yml")
        assert _classify_inline_source(p) == "gha_workflow"

    def test_gha_workflow_yaml(self):
        p = Path("/repo/.github/workflows/deploy.yaml")
        assert _classify_inline_source(p) == "gha_workflow"

    def test_random_yaml_not_gha(self):
        p = Path("/repo/config/settings.yml")
        assert _classify_inline_source(p) == "shell_script"

    def test_unknown_defaults_to_shell(self):
        assert _classify_inline_source(Path("/a/Makefile")) == "shell_script"

    def test_shell_script_with_dockerfile_in_name_is_shell(self):
        # A loose "dockerfile"-substring match once won over the .sh
        # suffix; classification must mirror the parser predicates,
        # which parse this file as a shell script.
        p = Path("/a/deploy-dockerfile.sh")
        assert _classify_inline_source(p) == "shell_script"

    def test_dockerfile_suffix_variants_still_dockerfile(self):
        assert _classify_inline_source(Path("/a/app.Dockerfile")) == "dockerfile"
        assert _classify_inline_source(Path("/a/base.dockerfile")) == "dockerfile"


class TestRunLLMInlineReview:
    @patch("packages.sca.llm.get_llm_client", return_value=None)
    def test_no_client_returns_empty(self, _mock):
        result = _run_llm_inline_review(
            manifests=[], raw_deps=[], target=Path("/fake"),
        )
        assert result == []

    @patch("packages.sca.llm.get_llm_client")
    def test_no_inline_manifests_returns_empty(self, mock_client):
        mock_client.return_value = MagicMock()
        pypi_manifest = _make_manifest(Path("/fake/requirements.txt"), ecosystem="PyPI")
        result = _run_llm_inline_review(
            manifests=[pypi_manifest], raw_deps=[], target=Path("/fake"),
        )
        assert result == []

    @patch("packages.sca.llm.inline_install_review.review_inline_installs")
    @patch("packages.sca.llm.get_llm_client")
    def test_calls_review_for_inline_manifest(self, mock_client, mock_review, tmp_path):
        mock_client.return_value = MagicMock()
        mock_review.return_value = []

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\nRUN pip install flask\n")

        manifest = _make_manifest(dockerfile)
        mech_dep = _make_dep("flask", declared_in=dockerfile)

        _run_llm_inline_review(
            manifests=[manifest],
            raw_deps=[mech_dep],
            target=tmp_path,
        )

        mock_review.assert_called_once()
        call_args = mock_review.call_args
        assert call_args[0][1] == dockerfile  # file_path
        assert "flask" in call_args[0][2]  # file_content contains flask
        assert len(call_args[0][3]) == 1  # mechanical deps for this file
        assert call_args[0][4] == "dockerfile"  # source_kind

    @patch("packages.sca.llm.inline_install_review.review_inline_installs")
    @patch("packages.sca.llm.get_llm_client")
    def test_skips_empty_files(self, mock_client, mock_review, tmp_path):
        mock_client.return_value = MagicMock()

        empty = tmp_path / "Dockerfile"
        empty.write_text("")

        manifest = _make_manifest(empty)
        _run_llm_inline_review(
            manifests=[manifest], raw_deps=[], target=tmp_path,
        )

        mock_review.assert_not_called()

    @patch("packages.sca.llm.inline_install_review.review_inline_installs")
    @patch("packages.sca.llm.get_llm_client")
    def test_collects_new_deps(self, mock_client, mock_review, tmp_path):
        mock_client.return_value = MagicMock()

        new_dep = _make_dep("gunicorn", source_kind="llm_inline_review")
        mock_review.return_value = [new_dep]

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\nRUN pipx install gunicorn\n")
        manifest = _make_manifest(dockerfile)

        result = _run_llm_inline_review(
            manifests=[manifest], raw_deps=[], target=tmp_path,
        )

        assert len(result) == 1
        assert result[0].name == "gunicorn"


def _canonical_dep(
    name: str = "lodash",
    version: str = "4.17.21",
    ecosystem: str = "npm",
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("/fake/package-lock.json"),
        scope="main",
        is_lockfile=True,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:npm/{name}@{version}",
        parser_confidence=Confidence(level="high"),
    )


def _prev_run_with_findings(tmp_path: Path, rows: list) -> Path:
    """Create <tmp>/run1/findings.json and return <tmp>/run2 as the
    current output dir."""
    import json

    prev = tmp_path / "run1"
    prev.mkdir()
    (prev / "findings.json").write_text(json.dumps(rows), encoding="utf-8")
    out = tmp_path / "run2"
    out.mkdir()
    return out


class TestRunVersionDiffReview:
    """Previous-run dep versions come from findings.json rows, which
    nest ecosystem/name/version under the "sca" block."""

    @patch("packages.sca.llm.version_diff_review.review_version_diff")
    def test_nested_sca_rows_feed_version_diff(self, mock_review, tmp_path):
        out = _prev_run_with_findings(tmp_path, [
            {
                "id": "x", "tool": "sca",
                "sca": {"ecosystem": "npm", "name": "lodash",
                        "version": "4.10.0"},
            },
        ])
        mock_review.return_value = (
            MagicMock(verdict="ok", summary="s", anomalies=[]), [],
        )

        count = _run_version_diff_review(
            MagicMock(), [_canonical_dep(version="4.17.21")], [],
            MagicMock(), out,
        )

        assert count == 1
        mock_review.assert_called_once()
        old_dep = mock_review.call_args[0][1]
        assert old_dep.version == "4.10.0"

    @patch("packages.sca.llm.version_diff_review.review_version_diff")
    def test_unchanged_version_not_reviewed(self, mock_review, tmp_path):
        out = _prev_run_with_findings(tmp_path, [
            {
                "id": "x", "tool": "sca",
                "sca": {"ecosystem": "npm", "name": "lodash",
                        "version": "4.17.21"},
            },
        ])

        count = _run_version_diff_review(
            MagicMock(), [_canonical_dep(version="4.17.21")], [],
            MagicMock(), out,
        )

        assert count == 0
        mock_review.assert_not_called()

    @patch("packages.sca.llm.version_diff_review.review_version_diff")
    def test_top_level_rows_still_tolerated(self, mock_review, tmp_path):
        """Foreign / older row shapes with top-level keys keep working."""
        out = _prev_run_with_findings(tmp_path, [
            {"ecosystem": "npm", "name": "lodash", "version": "4.10.0"},
        ])
        mock_review.return_value = (
            MagicMock(verdict="ok", summary="s", anomalies=[]), [],
        )

        count = _run_version_diff_review(
            MagicMock(), [_canonical_dep(version="4.17.21")], [],
            MagicMock(), out,
        )

        assert count == 1


class _FakeVulnFinding:
    """Just the attributes _run_upgrade_impact reads."""

    def __init__(self, dependency: Dependency, fixed_version: str):
        self.dependency = dependency
        self.fixed_version = fixed_version
        self.suppressed = False


def _upgrade_verdict():
    from types import SimpleNamespace
    return SimpleNamespace(
        verdict="safe", confidence="low", breaking_changes=[],
        summary="stub",
    )


class TestRunUpgradeImpactDedup:
    """A dep with N advisories must be assessed once per unique
    (ecosystem, name, old, new) upgrade, not once per finding."""

    @patch("packages.sca.llm.upgrade_impact_review.assess_upgrade_impact")
    @patch("packages.sca.llm.get_llm_client")
    def test_repeated_advisories_assessed_once(
        self, mock_client, mock_assess, tmp_path,
    ):
        import json

        mock_client.return_value = MagicMock(total_cost=0.05)
        mock_assess.return_value = _upgrade_verdict()
        dep = _canonical_dep()
        findings = [
            _FakeVulnFinding(dep, "5.0.0"),
            _FakeVulnFinding(dep, "5.0.0"),
            _FakeVulnFinding(dep, "5.0.0"),
        ]

        _run_upgrade_impact(
            vuln_findings=findings, canonical=[dep],
            target=tmp_path, output_dir=tmp_path,
        )

        assert mock_assess.call_count == 1
        rows = json.loads((tmp_path / "upgrade-impact.json").read_text())
        assert len(rows) == 1

    @patch("packages.sca.llm.upgrade_impact_review.assess_upgrade_impact")
    @patch("packages.sca.llm.get_llm_client")
    def test_distinct_upgrades_each_assessed(
        self, mock_client, mock_assess, tmp_path,
    ):
        mock_client.return_value = MagicMock(total_cost=0.05)
        mock_assess.return_value = _upgrade_verdict()
        dep = _canonical_dep()
        findings = [
            _FakeVulnFinding(dep, "5.0.0"),
            _FakeVulnFinding(dep, "6.0.0"),  # different fix target
        ]

        _run_upgrade_impact(
            vuln_findings=findings, canonical=[dep],
            target=tmp_path, output_dir=tmp_path,
        )

        assert mock_assess.call_count == 2
