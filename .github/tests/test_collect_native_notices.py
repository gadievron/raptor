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


def test_build_definitions_are_retained_and_bound_to_file_claims(tmp_path, monkeypatch):
    import hashlib
    import sys
    from types import SimpleNamespace
    binary = tmp_path / "git"
    binary.write_bytes(b"installed Git")
    source = b"PROGRAM_OBJS += shell.o\n"
    data = archive([("git/LICENSE", b"project license"), ("git/Makefile", source)])
    monkeypatch.setattr(tool, "identify", lambda *args: "2.56.0")
    monkeypatch.setattr(tool, "download", lambda *args, **kwargs: data)

    def inventory(name, path, version, definitions):
        assert name == "git" and path == binary and version == "2.56.0"
        assert definitions == {"Makefile": source.decode()}
        return SimpleNamespace(claims=[{"path": "/usr/local/bin/git-shell", "sha256": "a" * 64,
                                        "basis": "git_release_target_and_elf_version", "metadata_sha256": []}],
                               records=[], contents={}, gaps=[])

    monkeypatch.setitem(sys.modules, "native_build_inventory", SimpleNamespace(collect_build_inventory=inventory))
    result = tool.collect("git", binary, [], "unused", "git/git", "v", tmp_path / "out", build_inventory=True)
    assert result["status"] == "release_notice_candidates_captured"
    assert result["declared_files"][0]["source_definition_sha256"] == [hashlib.sha256(source).hexdigest()]
    assert any(item.get("content_kind") == "build_declaration" for item in result["files"])


def bundled_source(version="3.14.10", header=b"/* Copyright contributors. MIT License. */", commit="a" * 40):
    import hashlib
    source = header + b"\nint library_code;\n"
    member = f"Python-{version}/Modules/vendor/code.c"
    raw = archive([(f"Python-{version}/LICENSE", b"PSF terms"), (member, source)])
    url = f"https://www.python.org/ftp/python/{version}/Python-{version}.tgz"
    document = json.loads(python_sbom(version, url, hashlib.sha256(raw).hexdigest()))
    document["packages"].append({"name": "crypto", "SPDXID": "crypto", "downloadLocation": "https://github.com/example/crypto/archive/" + commit + ".zip"})
    document["files"] = [{"SPDXID": "source", "fileName": "Modules/vendor/code.c",
                           "checksums": [{"algorithm": "SHA256", "checksumValue": hashlib.sha256(source).hexdigest()}]}]
    document["relationships"] = [{"spdxElementId": "crypto", "relationshipType": "CONTAINS", "relatedSpdxElement": "source"}]
    return raw, document, member, header


def test_collects_exact_headers_only_from_checksum_bound_third_party_sources():
    raw, document, member, header = bundled_source()
    selected, dependencies = tool.python_notice_sources(json.dumps(document).encode(), "3.14.10")
    records, contents = tool.release_notices(raw, source_members=selected)
    notice = next(row for row in records if row.get("notice_origin") == "source_header")
    assert notice["source_member"] == member and notice["source_packages"] == ["crypto"]
    assert contents[notice["file"]] == header
    assert b"library_code" not in contents[notice["file"]]
    assert dependencies[0]["name"] == "crypto"


@pytest.mark.parametrize("fault", ["changed_tail", "missing", "bad_hash", "unsafe_path", "duplicate_file"])
def test_source_headers_require_complete_unambiguous_sbom_evidence(fault):
    raw, document, member, header = bundled_source()
    if fault == "changed_tail":
        raw = archive([("Python-3.14.10/LICENSE", b"PSF terms"), (member, header + b"\nint changed_code;\n")])
    elif fault == "missing":
        raw = archive([("Python-3.14.10/LICENSE", b"PSF terms")])
    elif fault == "bad_hash":
        document["files"][0]["checksums"] = []
    elif fault == "unsafe_path":
        document["files"][0]["fileName"] = "../code.c"
    else:
        document["files"].append(document["files"][0])
    with pytest.raises(ValueError):
        selected, _ = tool.python_notice_sources(json.dumps(document).encode(), "3.14.10")
        tool.release_notices(raw, source_members=selected)


def test_header_collection_never_treats_source_code_as_notice_text():
    assert tool.source_header(b'int code = 1; /* Copyright in implementation */') is None
    assert tool.source_header(b"/* Copyright holder */\n#define NOT_A_NOTICE 1") == b"/* Copyright holder */"
    assert tool.source_header(b'# Copyright holder\n"""License and grant."""\nimport code', python=True) == b'# Copyright holder\n"""License and grant."""'
    with pytest.raises(ValueError, match="header budget"):
        tool.source_header(b"/* Copyright " + b"x" * (64 * 1024))


def test_upstream_notice_is_fetched_at_the_sbom_commit_and_checked_as_git_blob(monkeypatch):
    import hashlib
    commit = "a" * 40
    text = b"Publisher Apache license text"
    blob = hashlib.sha1(b"blob " + str(len(text)).encode() + b"\x00" + text).hexdigest()
    requests = []
    def download(url, **kwargs):
        requests.append(url)
        return json.dumps([{"name": "LICENSE", "type": "file", "sha": blob}]).encode() if "/contents?ref=" in url else text
    monkeypatch.setattr(tool, "download", download)
    package = {"SPDXID": "crypto", "downloadLocation": "https://github.com/example/crypto/archive/" + commit + ".zip"}
    records, contents = tool.upstream_commit_notices([package, package])
    assert len(requests) == 2 and all(commit in url for url in requests)
    assert records[0]["git_blob_sha1"] == blob and records[0]["source_package"] == "crypto"
    assert contents[records[0]["file"]] == text
    monkeypatch.setattr(tool, "download", lambda url, **kwargs: json.dumps([{"name": "LICENSE", "type": "file", "sha": "0" * 40}]).encode() if "/contents?ref=" in url else text)
    with pytest.raises(ValueError, match="Git blob"):
        tool.upstream_commit_notices([package])


def test_upstream_notice_fetch_never_guesses_a_mutable_branch(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("mutable source reference must not be fetched")
    monkeypatch.setattr(tool, "download", forbidden)
    assert tool.upstream_commit_notices([{"downloadLocation": "https://github.com/example/crypto/archive/main.zip"}]) == ([], {})


def test_python_version_bump_refreshes_source_headers_and_pinned_upstream_text(tmp_path, monkeypatch):
    import hashlib
    binary = tmp_path / "python3"
    binary.write_bytes(b"interpreter")
    current = {"version": "3.14.10", "commit": "a" * 40}
    monkeypatch.setattr(tool, "identify", lambda *args: current["version"])
    def download(url, **kwargs):
        raw, document, _, _ = bundled_source(current["version"], b"/* Copyright " + current["version"].encode() + b" */", current["commit"])
        text = b"Upstream license " + current["version"].encode()
        blob = hashlib.sha1(b"blob " + str(len(text)).encode() + b"\x00" + text).hexdigest()
        if url.endswith(".spdx.json"):
            return json.dumps(document).encode()
        if "/contents?ref=" in url:
            assert url.endswith(current["commit"])
            return json.dumps([{"name": "LICENSE", "type": "file", "sha": blob}]).encode()
        if "raw.githubusercontent.com" in url:
            assert current["commit"] in url
            return text
        return raw
    monkeypatch.setattr(tool, "download", download)
    first = tool.collect("cpython", binary, [], "unused", "python/cpython", "v", tmp_path / "out", python_source=True)
    assert first["status"] == "release_notice_candidates_captured"
    old = next(row for row in first["files"] if row.get("notice_origin") == "source_header")
    current.update(version="3.14.11", commit="b" * 40)
    second = tool.collect("cpython", binary, [], "unused", "python/cpython", "v", tmp_path / "out", python_source=True)
    assert second["status"] == "release_notice_candidates_captured"
    assert not (tmp_path / "out/cpython" / old["file"]).exists()
    assert any(row.get("upstream_revision") == "b" * 40 for row in second["files"])


def test_source_header_scan_keeps_an_expanded_archive_budget(monkeypatch):
    monkeypatch.setattr(tool, "MAX_EXPANDED", 8)
    with pytest.raises(ValueError, match="expansion budget"):
        tool.release_notices(archive([("p/LICENSE", b"twelve bytes")]))
