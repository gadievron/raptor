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


def python_sbom(version, url, digest):
    return json.dumps({"spdxVersion": "SPDX-2.3", "documentDescribes": ["python"],
                       "packages": [{"name": "CPython", "versionInfo": version, "SPDXID": "python",
                                     "downloadLocation": url,
                                     "checksums": [{"algorithm": "SHA256", "checksumValue": digest}]}]}).encode()


def test_python_collects_full_license_document_and_retains_bound_source_sbom(tmp_path, monkeypatch):
    import hashlib
    binary = tmp_path / "python3"
    binary.write_bytes(b"installed interpreter")
    data = archive([("Python-3.14.10/LICENSE", b"PSF terms"),
                    ("Python-3.14.10/Doc/license.rst", b"bundled third party license terms"),
                    ("Python-3.14.10/Modules/expat/COPYING", b"Expat copyright and grant")])
    url = "https://www.python.org/ftp/python/3.14.10/Python-3.14.10.tgz"
    sbom = python_sbom("3.14.10", url, hashlib.sha256(data).hexdigest())
    monkeypatch.setattr(tool, "identify", lambda *args: "3.14.10")
    requested = []

    def download(location, **kwargs):
        requested.append((location, kwargs))
        return sbom if location.endswith(".spdx.json") else data

    monkeypatch.setattr(tool, "download", download)
    record = tool.collect("cpython", binary, [], "unused", "python/cpython", "v", tmp_path / "out", python_source=True)
    assert record["status"] == "release_notice_candidates_captured"
    assert record["source_archive_sha256"] == hashlib.sha256(data).hexdigest()
    assert len(record["files"]) == 4
    assert any(row.get("source_member", "").endswith("/Doc/license.rst") for row in record["files"])
    retained = next(row for row in record["files"] if row.get("content_kind") == "source_sbom")
    assert (tmp_path / "out/cpython" / retained["file"]).read_bytes() == sbom
    assert requested[1][1] == {"max_bytes": tool.MAX_SOURCE_SBOM}


@pytest.mark.parametrize("change", ["archive_hash", "version", "url", "identity", "duplicate", "format"])
def test_python_source_metadata_must_match_the_exact_selected_release(change):
    document = json.loads(python_sbom("3.14.10", "https://example.invalid/Python.tgz", "a" * 64))
    package = document["packages"][0]
    if change == "archive_hash":
        package["checksums"][0]["checksumValue"] = "b" * 64
    elif change == "version":
        package["versionInfo"] = "3.14.9"
    elif change == "url":
        package["downloadLocation"] = "https://example.invalid/other.tgz"
    elif change == "identity":
        document["documentDescribes"] = []
    elif change == "duplicate":
        document["packages"] *= 2
    else:
        document["spdxVersion"] = "SPDX-3.0"
    with pytest.raises(ValueError):
        tool.verify_python_source(json.dumps(document).encode(), "3.14.10", "https://example.invalid/Python.tgz", "a" * 64)


def test_failed_python_refresh_removes_old_source_sbom_and_notices(tmp_path, monkeypatch):
    binary = tmp_path / "python3"
    binary.write_bytes(b"interpreter")
    folder = tmp_path / "out/cpython"
    folder.mkdir(parents=True)
    (folder / "LICENSE-old.txt").write_text("old terms")
    (folder / "NOTICE-SOURCE-SBOM-old.json").write_text("old source metadata")
    monkeypatch.setattr(tool, "identify", lambda *args: "3.14.11")
    monkeypatch.setattr(tool, "download", lambda *args, **kwargs: b"mismatched upstream data")
    record = tool.collect("cpython", binary, [], "unused", "python/cpython", "v", tmp_path / "out", python_source=True)
    assert record["status"] == "unavailable" and not record["files"]
    assert not list(folder.glob("LICENSE-*.txt"))
    assert not list(folder.glob("NOTICE-SOURCE-SBOM-*.json"))


def test_python_source_supports_official_spdx_describes_relationship():
    document = json.loads(python_sbom("3.14.10", "https://example.invalid/Python.tgz", "a" * 64))
    del document["documentDescribes"]
    document["SPDXID"] = "SPDXRef-DOCUMENT"
    document["relationships"] = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "python"}]
    tool.verify_python_source(json.dumps(document).encode(), "3.14.10", "https://example.invalid/Python.tgz", "a" * 64)
