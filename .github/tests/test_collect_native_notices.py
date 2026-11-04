"""Release refreshes preserve evidence without treating source texts as build proof."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("native_notices", ROOT / ".devcontainer/collect-native-notices.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def archive(entries):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as out:
        for name, data in entries:
            item = tarfile.TarInfo(name)
            item.size = len(data)
            out.addfile(item, io.BytesIO(data))
    return result.getvalue()


def test_collects_nested_notices_without_extracting_paths():
    data = archive([("project/LICENSE", b"upstream license"),
                    ("project/vendor/a/NOTICE", b"dependency attribution"),
                    ("project/src/code.c", b"code")])
    records, texts = tool.release_notices(data)
    assert len(records) == len(texts) == 2
    assert {row["source_member"] for row in records} == {"project/LICENSE", "project/vendor/a/NOTICE"}
    assert all("/" not in filename for filename in texts)


@pytest.mark.parametrize("entries", [
    [("../LICENSE", b"text")], [("/LICENSE", b"text")],
    [("p/LICENSE", b"first"), ("p/LICENSE", b"duplicate")],
    [("p/LICENSE", b"\x00binary")], [("p/LICENSE", b"")],
    [("p/code.c", b"no notices")],
])
def test_refuses_ambiguous_or_invalid_release_evidence(entries):
    with pytest.raises(ValueError):
        tool.release_notices(archive(entries))


def test_limits_archive_expansion_and_notice_bytes(monkeypatch):
    data = archive([("p/LICENSE", b"a" * 12)])
    monkeypatch.setattr(tool, "MAX_TEXT", 10)
    with pytest.raises(ValueError, match="bounded"):
        tool.release_notices(data)


def test_version_bump_refreshes_text_and_failure_removes_stale_evidence(tmp_path, monkeypatch):
    binary = tmp_path / "uv"
    binary.write_bytes(b"installed binary")
    monkeypatch.setattr(tool, "identify", lambda *args: "0.7.22")
    monkeypatch.setattr(tool, "download", lambda url: archive([("uv/LICENSE", b"first license")]))
    args = ("uv", binary, [], "unused", "astral-sh/uv", "", tmp_path / "notices")
    first = tool.collect(*args)
    assert first["version"] == "0.7.22"
    assert first["binary_sha256"]
    assert first["source_url"].endswith("/0.7.22")
    monkeypatch.setattr(tool, "identify", lambda *args: "0.7.23")
    monkeypatch.setattr(tool, "download", lambda url: archive([("uv/LICENSE", b"changed license")]))
    second = tool.collect(*args)
    folder = tmp_path / "notices/uv"
    assert second["files"] != first["files"]
    assert not (folder / first["files"][0]["file"]).exists()

    def fail(url):
        raise OSError("upstream unavailable")

    monkeypatch.setattr(tool, "download", fail)
    failed = tool.collect(*args)
    assert failed["status"] == "unavailable" and not failed["files"]
    assert not list(folder.glob("LICENSE-*.txt"))
    assert json.loads((folder / "NOTICE-PROVENANCE.json").read_text())["version"] == "0.7.23"


def test_missing_or_unrecognised_tool_never_fetches_guess(tmp_path, monkeypatch):
    def forbidden(url):
        pytest.fail("must not guess a release")

    monkeypatch.setattr(tool, "download", forbidden)
    result = tool.collect("git", tmp_path / "absent", [], "unused", "git/git", "v", tmp_path / "out")
    assert result["status"] == "unavailable"
