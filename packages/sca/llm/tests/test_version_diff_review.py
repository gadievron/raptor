"""Tests for LLM version-diff review stage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.sca.llm.schemas import VersionDiffVerdict
from packages.sca.llm.version_diff_review import (
    _archive_url,
    _diff_trees,
    _extract_text_files,
    review_version_diff,
)
from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.supply_chain.version_diff_sinks import (
    SinkChange,
    VersionDiffSinkResult,
)


def _make_dep(
    name: str = "example",
    ecosystem: str = "npm",
    version: str = "1.0.0",
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("/fake/package.json"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence(level="high"),
    )


class TestArchiveUrl:
    def test_npm(self):
        dep = _make_dep(name="lodash", ecosystem="npm", version="4.17.21")
        url = _archive_url(dep)
        assert "registry.npmjs.org" in url
        assert "lodash-4.17.21.tgz" in url

    def test_npm_scoped(self):
        dep = _make_dep(name="@scope/pkg", ecosystem="npm", version="1.0.0")
        url = _archive_url(dep)
        assert "pkg-1.0.0.tgz" in url

    def test_pypi(self):
        dep = _make_dep(name="requests", ecosystem="PyPI", version="2.31.0")
        url = _archive_url(dep)
        assert "files.pythonhosted.org" in url
        assert "requests-2.31.0.tar.gz" in url

    def test_cargo(self):
        dep = _make_dep(name="serde", ecosystem="Cargo", version="1.0.0")
        url = _archive_url(dep)
        assert "crates.io" in url

    def test_maven_sources_jar(self):
        dep = _make_dep(
            name="org.apache.commons:commons-lang3",
            ecosystem="Maven", version="3.14.0",
        )
        url = _archive_url(dep)
        assert "repo.maven.apache.org" in url
        assert "commons-lang3-3.14.0-sources.jar" in url
        assert "org/apache/commons" in url

    def test_maven_no_group_returns_none(self):
        dep = _make_dep(name="no-group", ecosystem="Maven", version="1.0")
        assert _archive_url(dep) is None

    def test_gradle_same_as_maven(self):
        dep = _make_dep(
            name="com.google.guava:guava",
            ecosystem="Gradle", version="33.0.0-jre",
        )
        url = _archive_url(dep)
        assert "repo.maven.apache.org" in url
        assert "guava-33.0.0-jre-sources.jar" in url

    def test_packagist(self):
        dep = _make_dep(
            name="monolog/monolog", ecosystem="Packagist", version="3.5.0",
        )
        url = _archive_url(dep)
        assert "repo.packagist.org" in url

    def test_unsupported_ecosystem(self):
        dep = _make_dep(ecosystem="Hex")
        assert _archive_url(dep) is None

    def test_nuget_lowercase(self):
        dep = _make_dep(
            name="Newtonsoft.Json", ecosystem="NuGet", version="13.0.3",
        )
        url = _archive_url(dep)
        assert "newtonsoft.json" in url


class TestDiffTrees:
    def test_identical_trees(self):
        old = {"a.py": "hello\n", "b.py": "world\n"}
        new = {"a.py": "hello\n", "b.py": "world\n"}
        assert _diff_trees(old, new) == ""

    def test_simple_change(self):
        old = {"a.py": "line1\n"}
        new = {"a.py": "line1\nline2\n"}
        diff = _diff_trees(old, new)
        assert "+line2" in diff
        assert "a/a.py" in diff

    def test_new_file(self):
        old = {}
        new = {"new.js": "console.log('hi');\n"}
        diff = _diff_trees(old, new)
        assert "+console.log" in diff

    def test_deleted_file(self):
        old = {"old.py": "# gone\n"}
        new = {}
        diff = _diff_trees(old, new)
        assert "-# gone" in diff

    def test_truncation(self):
        old = {}
        new = {"big.py": "x\n" * 200_000}
        diff = _diff_trees(old, new)
        assert "truncated" in diff


class TestExtractTextFiles:
    def test_non_text_files_skipped(self):
        import io
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            # Add a text file
            data = b"print('hello')"
            info = tarfile.TarInfo(name="pkg-1.0.0/main.py")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

            # Add a binary file (should be skipped)
            bdata = b"\x00\x01\x02"
            binfo = tarfile.TarInfo(name="pkg-1.0.0/image.png")
            binfo.size = len(bdata)
            tf.addfile(binfo, io.BytesIO(bdata))

        buf.seek(0)
        files = _extract_text_files(buf.read(), "PyPI")
        assert files is not None
        assert "main.py" in files
        assert "image.png" not in files


class TestExtractionBudgets:
    """Aggregate bomb defences: the per-member cap alone doesn't bound
    the sum, so cumulative-bytes and member-count budgets must abort
    the extraction (surfacing as the ``None`` failure result)."""

    @staticmethod
    def _make_zip(files: dict[str, bytes]) -> bytes:
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, blob in files.items():
                zf.writestr(name, blob)
        return buf.getvalue()

    @staticmethod
    def _make_tar(files: dict[str, bytes]) -> bytes:
        import io
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, blob in files.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(blob)
                tf.addfile(info, io.BytesIO(blob))
        return buf.getvalue()

    def test_zip_cumulative_bytes_budget_aborts(self, monkeypatch):
        import packages.sca.llm.version_diff_review as vdr

        monkeypatch.setattr(vdr, "_MAX_TOTAL_EXTRACT_BYTES", 1_000)
        # Each member is under the per-member cap; the sum is not.
        data = self._make_zip({
            f"pkg-1.0.0/f{i}.py": b"a" * 400 for i in range(10)
        })
        assert _extract_text_files(data, "Go") is None

    def test_zip_member_count_budget_aborts(self, monkeypatch):
        import packages.sca.llm.version_diff_review as vdr

        monkeypatch.setattr(vdr, "_MAX_ARCHIVE_MEMBERS", 5)
        data = self._make_zip({
            f"pkg-1.0.0/f{i}.py": b"x" for i in range(10)
        })
        assert _extract_text_files(data, "Go") is None

    def test_zip_under_budget_still_extracts(self):
        data = self._make_zip({"pkg-1.0.0/main.py": b"print('ok')"})
        files = _extract_text_files(data, "Go")
        assert files is not None
        assert "main.py" in files

    def test_tar_cumulative_bytes_budget_aborts(self, monkeypatch):
        import packages.sca.llm.version_diff_review as vdr

        monkeypatch.setattr(vdr, "_MAX_TOTAL_EXTRACT_BYTES", 1_000)
        data = self._make_tar({
            f"pkg-1.0.0/f{i}.py": b"a" * 400 for i in range(10)
        })
        assert _extract_text_files(data, "PyPI") is None

    def test_tar_under_budget_still_extracts(self):
        data = self._make_tar({"pkg-1.0.0/main.py": b"print('ok')"})
        files = _extract_text_files(data, "PyPI")
        assert files is not None
        assert "main.py" in files


class TestSinkAnalysisWiring:
    """Mechanical sink evidence flows into the prompt and the result;
    analyzer failure never blocks the review."""

    _OLD_TREE = {
        "lib/util.py": "def run(cmd, ok):\n    if ok:\n        eval(cmd)\n",
    }
    _NEW_TREE = {
        "lib/util.py": "def run(cmd):\n    eval(cmd)\n",
    }

    @staticmethod
    def _verdict() -> VersionDiffVerdict:
        return VersionDiffVerdict(
            verdict="suspicious",
            confidence="medium",
            changelog_consistent=False,
            summary="Guard dropped around eval",
        )

    @staticmethod
    def _sink_result() -> VersionDiffSinkResult:
        return VersionDiffSinkResult(
            added_sinks=[],
            removed_sinks=[],
            guard_changes=[
                SinkChange(
                    "lib/util.py", "eval", 2, "guard_removed",
                    guard_count_old=1, guard_count_new=0,
                    was_unconditional=False, is_unconditional=True,
                ),
            ],
        )

    @patch("packages.sca.llm.version_diff_review.run_stage")
    @patch(
        "packages.sca.supply_chain.version_diff_sinks"
        ".analyze_version_diff_sinks"
    )
    @patch("packages.sca.llm.version_diff_review._build_diff")
    def test_sink_evidence_in_prompt_and_result(
        self, mock_build, mock_analyze, mock_run_stage,
    ):
        mock_build.return_value = (
            "--- diff ---", self._OLD_TREE, self._NEW_TREE,
        )
        mock_analyze.return_value = self._sink_result()
        mock_run_stage.return_value = MagicMock(
            error=None, model=self._verdict(), preflight_hit=False,
        )

        result = review_version_diff(
            MagicMock(),
            _make_dep(version="1.0.0"),
            _make_dep(version="1.1.0"),
            MagicMock(),
        )

        assert result is not None
        verdict, sink_changes = result
        assert verdict.verdict == "suspicious"
        assert sink_changes is not None
        assert sink_changes["total_changes"] == 1
        assert (
            sink_changes["guard_changes"][0]["change_type"]
            == "guard_removed"
        )
        assert "1 guard(s) removed" in sink_changes["summary"]

        mock_analyze.assert_called_once_with(self._OLD_TREE, self._NEW_TREE)
        blocks = mock_run_stage.call_args.kwargs["untrusted_blocks"]
        sink_blocks = [b for b in blocks if b.kind == "SINK_DIFF"]
        assert len(sink_blocks) == 1
        assert "guard_removed" in sink_blocks[0].content
        assert "eval" in sink_blocks[0].content

    @patch("packages.sca.llm.version_diff_review.run_stage")
    @patch(
        "packages.sca.supply_chain.version_diff_sinks"
        ".analyze_version_diff_sinks"
    )
    @patch("packages.sca.llm.version_diff_review._build_diff")
    def test_analyzer_failure_review_still_runs(
        self, mock_build, mock_analyze, mock_run_stage,
    ):
        mock_build.return_value = (
            "--- diff ---", self._OLD_TREE, self._NEW_TREE,
        )
        mock_analyze.side_effect = RuntimeError("parser exploded")
        mock_run_stage.return_value = MagicMock(
            error=None, model=self._verdict(), preflight_hit=False,
        )

        result = review_version_diff(
            MagicMock(),
            _make_dep(version="1.0.0"),
            _make_dep(version="1.1.0"),
            MagicMock(),
        )

        assert result is not None
        verdict, sink_changes = result
        assert verdict.verdict == "suspicious"
        assert sink_changes is None
        blocks = mock_run_stage.call_args.kwargs["untrusted_blocks"]
        assert not [b for b in blocks if b.kind == "SINK_DIFF"]

    @patch("packages.sca.llm.version_diff_review.run_stage")
    @patch(
        "packages.sca.supply_chain.version_diff_sinks"
        ".analyze_version_diff_sinks"
    )
    @patch("packages.sca.llm.version_diff_review._build_diff")
    def test_empty_sink_result_omits_block(
        self, mock_build, mock_analyze, mock_run_stage,
    ):
        mock_build.return_value = (
            "--- diff ---", self._OLD_TREE, self._NEW_TREE,
        )
        mock_analyze.return_value = VersionDiffSinkResult([], [], [])
        mock_run_stage.return_value = MagicMock(
            error=None, model=self._verdict(), preflight_hit=False,
        )

        result = review_version_diff(
            MagicMock(),
            _make_dep(version="1.0.0"),
            _make_dep(version="1.1.0"),
            MagicMock(),
        )

        assert result is not None
        _, sink_changes = result
        assert sink_changes is None
        blocks = mock_run_stage.call_args.kwargs["untrusted_blocks"]
        assert not [b for b in blocks if b.kind == "SINK_DIFF"]
