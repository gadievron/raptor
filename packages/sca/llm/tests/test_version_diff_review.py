"""Tests for LLM version-diff review stage."""

from __future__ import annotations

from pathlib import Path


from packages.sca.llm.version_diff_review import (
    _archive_url,
    _diff_trees,
    _extract_text_files,
)
from packages.sca.models import Confidence, Dependency, PinStyle


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

    def test_composer(self):
        dep = _make_dep(
            name="monolog/monolog", ecosystem="Composer", version="3.5.0",
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
