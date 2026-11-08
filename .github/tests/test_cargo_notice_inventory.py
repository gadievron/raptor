"""Notice collection preserves source evidence without claiming runtime membership."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile

import pytest

from core.testing.module_registry import module_registry_scope

ROOT = Path(__file__).resolve().parents[2]
DEBIAN_SPEC = importlib.util.spec_from_file_location("debian_cargo_notices", ROOT / ".devcontainer/debian_cargo_notices.py")
SPEC = importlib.util.spec_from_file_location("cargo_notice_inventory", ROOT / ".devcontainer/cargo_notice_inventory.py")
with module_registry_scope(DEBIAN_SPEC.name, SPEC.name) as modules:
    debian = importlib.util.module_from_spec(DEBIAN_SPEC)
    modules[DEBIAN_SPEC.name] = debian
    tool = importlib.util.module_from_spec(SPEC)
    modules[SPEC.name] = tool
    DEBIAN_SPEC.loader.exec_module(debian)
    SPEC.loader.exec_module(tool)

@pytest.fixture(scope="module", autouse=True)
def _registered_helpers():
    with module_registry_scope(DEBIAN_SPEC.name, SPEC.name) as modules:
        modules[DEBIAN_SPEC.name] = debian
        modules[SPEC.name] = tool
        yield



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


@pytest.mark.parametrize('change', ['none', 'payload', 'manifest', 'missing', 'unrelated', 'bad-commit'])
def test_missing_vcs_recovery_requires_all_published_payload_and_original_manifest(change):
    manifest = b'[package]\nname="example"\nversion="1.0.0"\nlicense="MIT"\nrepository="https://github.com/publisher/project"\n'
    files = {'Cargo.toml': manifest, 'Cargo.toml.orig': manifest, 'src/lib.rs': b'pub fn original() {}'}
    raw = source(files)
    lock = ('[[package]]\nname="example"\nversion="1.0.0"\nsource="' + tool.REGISTRY + '"\nchecksum="' + hashlib.sha256(raw).hexdigest() + '"\n').encode()
    upstream = {'Cargo.toml': manifest, 'src/lib.rs': files['src/lib.rs'], 'LICENSE': b'Original publisher MIT notice'}
    if change == 'payload':
        upstream['src/lib.rs'] += b'// changed'
    elif change == 'manifest':
        upstream['Cargo.toml'] += b'\n# changed'
    elif change == 'missing':
        del upstream['src/lib.rs']
    elif change == 'unrelated':
        upstream = {'Cargo.toml': b'[package]\nname="other"\n', 'LICENSE': b'Unrelated notice'}
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        if 'deb.debian.org' in url:
            return b''
        if 'static.crates.io' in url:
            return raw
        if '/commits?' in url:
            return json.dumps([{'sha': 'not-a-commit' if change == 'bad-commit' else 'a'*40}]).encode()
        assert 'a'*40 in url
        return source(upstream)
    result = tool.collect_cargo_notices(lock, fetch)
    row = json.loads(result.inventory)['packages'][0]
    assert (row['status'] == 'notice_candidates_captured') == (change == 'none')
    if change == 'none':
        assert list(result.contents.values()) == [b'Original publisher MIT notice']
        assert row['notice_source_match']['commit'] == 'a'*40
        assert len(row['notice_source_match']['matched_files']) == 2
        assert row['notices'][0]['origin'] == 'source_matched_upstream_file'
    else:
        assert 'notice_source_match' not in row
        assert not result.contents


def test_distributor_notice_coverage_remains_distinct_from_upstream_text(monkeypatch):
    raw, lock = case({}, 'repository="https://github.com/publisher/project"\n')
    body = b'Unchanged distributor-published copyright and licence text'
    monkeypatch.setattr(tool, '_matched_upstream', lambda *args: ({}, None))
    proof = dict(publisher='Debian', packaging_archive_url='https://deb.debian.org/debian/pool/main/r/rust-example/metadata.tar.xz')
    monkeypatch.setattr(sys.modules['debian_cargo_notices'], 'recover_debian_notice', lambda *args: (proof, body))
    result = tool.collect_cargo_notices(lock, lambda *args, **kwargs: raw)
    assert result.summary['captured'] == result.summary['distributor_notices'] == 1
    assert result.summary['metadata_only'] == result.summary['unavailable'] == 0
    row = json.loads(result.inventory)['packages'][0]
    assert row['status'] == 'distributor_notice_captured'
    assert row['notices'][0]['origin'] == 'debian_distributor_notice'
    assert list(result.contents.values()) == [body]


def test_distributor_transport_failure_preserves_other_package_notices(monkeypatch):
    import http.client
    good, lock = case()
    bad = source({'Cargo.toml': b'[package]\nname="missing"\nversion="1.0.0"\nlicense="MIT"\nrepository="https://github.com/publisher/project"\n'})
    lock += ('\n[[package]]\nname="missing"\nversion="1.0.0"\nsource="' + tool.REGISTRY + '"\nchecksum="' + hashlib.sha256(bad).hexdigest() + '"\n').encode()
    monkeypatch.setattr(tool, '_matched_upstream', lambda *args: ({}, None))
    def fail(*args):
        raise http.client.IncompleteRead(b'partial index')
    monkeypatch.setattr(sys.modules['debian_cargo_notices'], 'recover_debian_notice', fail)
    result = tool.collect_cargo_notices(lock, lambda url, **kwargs: bad if '/missing/' in url else good)
    assert result.summary['captured'] == result.summary['unavailable'] == 1
    assert list(result.contents.values()) == [b'Publisher copyright and original grant']
