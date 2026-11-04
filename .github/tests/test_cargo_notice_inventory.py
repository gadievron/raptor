"""Notice collection preserves source evidence without claiming runtime membership."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("cargo_notice_inventory", ROOT / ".devcontainer/cargo_notice_inventory.py")
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)


def source(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for path, body in files.items():
            member = tarfile.TarInfo("example-1.0.0/" + path)
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    return output.getvalue()


def case(files=None, metadata=""):
    raw = source({"Cargo.toml": ('[package]\nname="example"\nversion="1.0.0"\nlicense="MIT"\n' + metadata).encode(),
                  **({"LICENSE-MIT": b"Publisher copyright and original grant"} if files is None else files)})
    checksum = hashlib.sha256(raw).hexdigest()
    lock = ('version = 4\n[[package]]\nname="example"\nversion="1.0.0"\nsource="' + tool.REGISTRY + '"\nchecksum="' + checksum + '"\n').encode()
    return raw, lock


def test_preserves_original_text_and_conservative_scope():
    raw, lock = case()
    result = tool.collect_cargo_notices(lock, lambda url, **kwargs: raw)
    assert result.summary == {"candidates": 1, "captured": 1, "metadata_only": 0, "unavailable": 0, "scope": "external Cargo.lock candidates"}
    assert list(result.contents.values()) == [b"Publisher copyright and original grant"]
    inventory = json.loads(result.inventory)
    assert inventory["lock_sha256"] == hashlib.sha256(lock).hexdigest()
    assert "not an installed component inventory" in inventory["scope"]
    assert inventory["packages"][0]["license_declared"] == "MIT"
    assert inventory["packages"][0]["archive_sha256"] == hashlib.sha256(raw).hexdigest()
    assert all(hashlib.sha256(result.contents[row["file"]]).hexdigest() == row["sha256"] for row in result.records)


@pytest.mark.parametrize("path,metadata", [("LICENSES/MIT.txt", ""), ("MIT.txt", ""), ("terms.txt", 'license-file="terms.txt"\n')])
def test_license_directories_spdx_filenames_and_declared_paths(path, metadata):
    raw, lock = case({path: b"Exact upstream text"}, metadata)
    result = tool.collect_cargo_notices(lock, lambda url, **kwargs: raw)
    assert result.summary["captured"] == 1
    assert list(result.contents.values()) == [b"Exact upstream text"]


def test_metadata_only_is_not_filled_with_invented_notices():
    raw, lock = case({})
    result = tool.collect_cargo_notices(lock, lambda url, **kwargs: raw)
    assert result.summary["metadata_only"] == 1 and result.contents == {}
    assert json.loads(result.inventory)["packages"][0]["license_declared"] == "MIT"


@pytest.mark.parametrize("fault", ["checksum", "identity", "path", "version", "license_escape", "vcs"])
def test_untrusted_or_inconsistent_source_is_recorded_as_unavailable(fault):
    raw, lock = case()
    if fault == "checksum":
        served = b"changed"
    else:
        files = {"Cargo.toml": b'[package]\nname="example"\nversion="1.0.0"\nlicense="MIT"\n', "LICENSE": b"grant"}
        if fault == "identity":
            files["Cargo.toml"] = b'[package]\nname="other"\nversion="1.0.0"\n'
        elif fault == "path":
            files["../../escape"] = b"payload"
        elif fault == "version":
            files["Cargo.toml"] = b'[package]\nname="example"\nversion="2.0.0"\n'
        elif fault == "license_escape":
            files["Cargo.toml"] += b'license-file="../outside"\n'
        else:
            files[".cargo_vcs_info.json"] = b'[]'
        served = source(files)
        lock = lock.replace(hashlib.sha256(raw).hexdigest().encode(), hashlib.sha256(served).hexdigest().encode())
    result = tool.collect_cargo_notices(lock, lambda url, **kwargs: served)
    assert result.summary["unavailable"] == 1 and not result.contents
    assert json.loads(result.inventory)["packages"][0]["error"]


def test_pinned_vcs_recovers_publisher_notice_without_guessing_tags():
    text = b"Original publisher license"
    blob = hashlib.sha1(b"blob " + str(len(text)).encode() + b"\x00" + text, usedforsecurity=False).hexdigest()
    raw, lock = case({".cargo_vcs_info.json": json.dumps({"git": {"sha1": "a" * 40}}).encode()}, 'repository="https://github.com/publisher/project/tree/main/crate"\n')
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        if "static.crates.io" in url:
            return raw
        if "/git/trees/" in url:
            return json.dumps({"truncated": False, "tree": [{"type": "blob", "path": "LICENSE", "sha": blob}]}).encode()
        return text
    result = tool.collect_cargo_notices(lock, fetch)
    assert result.summary["captured"] == 1
    assert all("a" * 40 in url for url in calls[1:])
    assert json.loads(result.inventory)["packages"][0]["notices"][0]["origin"] == "pinned_upstream_file"


def test_local_workspace_entries_do_not_trigger_dependency_downloads():
    lock = b'[[package]]\nname="workspace"\nversion="1.0.0"\n'
    result = tool.collect_cargo_notices(lock, lambda *args, **kwargs: pytest.fail("local workspace must not be downloaded"))
    assert result.summary["candidates"] == 0
    assert json.loads(result.inventory)["workspace_entries"] == 1


def test_duplicate_lock_identities_are_refused():
    raw, lock = case()
    duplicate = lock + lock[lock.index(b"[[package]]"):]
    with pytest.raises(ValueError, match="duplicate"):
        tool.collect_cargo_notices(duplicate, lambda *args, **kwargs: raw)


def test_notice_aggregate_remains_bounded(monkeypatch):
    raw, lock = case()
    monkeypatch.setattr(tool, "MAX_NOTICE_TOTAL", 1)
    with pytest.raises(ValueError, match="aggregate"):
        tool.collect_cargo_notices(lock, lambda url, **kwargs: raw)


def test_notice_symlink_resolves_only_to_retained_in_archive_text():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for path, body in [('root/Cargo.toml', b'[package]\nlicense="MIT"\n'), ('root/LICENSE', b'Original MIT grant')]:
            member = tarfile.TarInfo(path)
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
        member = tarfile.TarInfo('root/crate/LICENSE')
        member.type = tarfile.SYMTYPE
        member.linkname = '../LICENSE'
        archive.addfile(member)
    _, _, notices = tool._archive(output.getvalue())
    assert notices['crate/LICENSE'] == notices['LICENSE']
