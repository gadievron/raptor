"""Exercise the real release stamper against owned copies of the operator docs."""
from pathlib import Path
import re
import subprocess
import sys
import tomllib

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / ".github/scripts/stamp-version"
DOCS = ("README.md", "docs/installation.md")


@pytest.fixture
def checkout(tmp_path):
    for name in (*DOCS, "core/config/__init__.py", "CITATION.cff", "pyproject.toml", "uv.lock"):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    return tmp_path


def stamp(root, tag):
    return subprocess.run([sys.executable, str(SCRIPT), tag], cwd=root,
                          text=True, capture_output=True, timeout=10)


@pytest.mark.parametrize("tag", ["v3.2.0", "v10.20.30-rc.1"])
def test_release_updates_all_operator_tags_without_changing_tools_or_examples(checkout, tag):
    before = {name: (checkout / name).read_text() for name in DOCS}
    previous = re.search(r"raptor:release-tag (\S+) -->", before[DOCS[0]])[1]
    for name in DOCS:
        with (checkout / name).open("a") as stream:
            stream.write("\nUnrelated dependency: v7.8.9. Extended tag: " + previous + "-example\n")
    lock = tomllib.loads((checkout / "uv.lock").read_text())
    result = stamp(checkout, tag)
    assert result.returncode == 0, result.stderr
    expected = lock
    local = next(row for row in expected["package"] if row["name"] == "raptor" and row["source"] == {"virtual": "."})
    local["version"] = tag.removeprefix("v")
    assert tomllib.loads((checkout / "uv.lock").read_text()) == expected
    for name in DOCS:
        text = (checkout / name).read_text()
        assert f"--branch {tag}" in text
        assert f"raptor:release-tag {tag} -->" in text
        assert not re.search(r"(?<![\w.-])" + re.escape(previous) + r"(?![\w.-])", text)
        assert "v7.8.9" in text and previous + "-example" in text
        assert re.findall(r"sha256:[a-f0-9]{64}", text) == re.findall(r"sha256:[a-f0-9]{64}", before[name])
    first = {name: (checkout / name).read_bytes() for name in DOCS}
    assert stamp(checkout, tag).returncode == 0
    assert first == {name: (checkout / name).read_bytes() for name in DOCS}


@pytest.mark.parametrize("name", DOCS)
def test_missing_release_marker_fails_instead_of_silently_leaving_stale_docs(checkout, name):
    path = checkout / name
    before = re.sub(r"<!-- raptor:release-tag .*? -->", "", path.read_text())
    path.write_text(before)
    result = stamp(checkout, "v3.2.0")
    assert result.returncode != 0 and name in result.stderr
    assert path.read_text() == before


def test_release_workflow_commits_installation_reference_updates():
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    add = next(line for line in workflow.splitlines() if "git add core/config/" in line)
    assert all(name in add.split() for name in DOCS)


def test_malformed_local_lock_record_fails_release(checkout):
    path = checkout / "uv.lock"
    path.write_text(path.read_text().replace('name = "raptor"', 'name = "missing"'))
    result = stamp(checkout, "v3.2.0")
    assert result.returncode != 0 and "uv.lock" in result.stderr
