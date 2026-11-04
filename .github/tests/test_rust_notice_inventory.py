"""Rust release notices retain source scope and reject incomplete evidence."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('rust_notice_inventory', ROOT / '.devcontainer/rust_notice_inventory.py')
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def fixture(change='none', version='1.88.0'):
    output = io.BytesIO()
    prefix = 'rustc-' + version + '-' + tool.TARGET + '/'
    files = {'LICENSE-APACHE': b'Original Apache notice', 'LICENSE-MIT': b'Original MIT notice',
             'COPYRIGHT': b'Original contributor statement', 'rustc/share/doc/rust/COPYRIGHT-library.html': b'<html>Original library third-party notices</html>'}
    if change == 'missing':
        del files['rustc/share/doc/rust/COPYRIGHT-library.html']
    if change == 'unsafe':
        files['../escape'] = b'bad'
    if change == 'invalid-text':
        files['COPYRIGHT'] = b'\x00'
    with tarfile.open(fileobj=output, mode='w:xz') as archive:
        root = tarfile.TarInfo(prefix)
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        for name, body in files.items():
            item = tarfile.TarInfo(prefix + name)
            item.size = len(body)
            if change == 'symlink' and name == 'COPYRIGHT':
                item.type = tarfile.SYMTYPE
                item.linkname = '/etc/passwd'
                item.size = 0
            archive.addfile(item, io.BytesIO(body))
    raw = output.getvalue()
    checksum = '0'*64 if change == 'checksum' else hashlib.sha256(raw).hexdigest()
    host = 'example.invalid' if change == 'foreign-url' else 'static.rust-lang.org'
    release = '1.89.0' if change == 'wrong-release' else version
    manifest = (f'[pkg.rustc]\nversion="{release} (release)"\n[pkg.rustc.target.{tool.TARGET}]\navailable=true\nxz_url="https://{host}/dist/2025-06-26/rustc-{version}-{tool.TARGET}.tar.xz"\nxz_hash="{checksum}"\n').encode()
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        return manifest if url.endswith('.toml') else raw
    return fetch, calls


def test_retains_original_library_document_and_exact_release_manifest():
    fetch, calls = fixture()
    records, contents, receipt = tool.collect_rust_notices(b'[toolchain]\nchannel="1.88"\n', fetch)
    assert receipt['status'] == 'release_library_notices_captured'
    assert receipt['version'] == '1.88.0' and receipt['notice_files'] == 4
    assert len(records) == len(contents) == 5
    assert 'not compiled membership' in receipt['scope']
    assert any(b'Original library third-party notices' in body for body in contents.values())
    for row in records:
        assert hashlib.sha256(contents[row['file']]).hexdigest() == row['sha256']
        if row.get('content_kind') == 'source_sbom':
            evidence = json.loads(contents[row['file']])
            assert hashlib.sha256(evidence['manifest_toml'].encode()).hexdigest() == receipt['manifest_sha256']
    assert len(calls) == 2


@pytest.mark.parametrize('change', ['missing','unsafe','invalid-text','symlink','checksum','foreign-url','wrong-release'])
def test_incomplete_or_mismatched_release_never_leaves_partial_notice_evidence(change):
    fetch, _ = fixture(change)
    records, contents, receipt = tool.collect_rust_notices(b'[toolchain]\nchannel="1.88.0"\n', fetch)
    assert records == [] and contents == {} and receipt['status'] == 'unavailable'
    assert receipt['error']


@pytest.mark.parametrize('channel', ['stable','nightly','../1.88','1.88.0;command'])
def test_unpinned_or_unsafe_toolchain_does_not_trigger_guessed_download(channel):
    records, contents, receipt = tool.collect_rust_notices(('[toolchain]\nchannel="'+channel+'"\n').encode(), lambda *a, **kw: pytest.fail('must not fetch guessed release'))
    assert not records and not contents and receipt['status'] == 'unavailable'


@pytest.mark.parametrize('budget', ['MAX_ARCHIVE','MAX_EXPANDED','MAX_TEXT','MAX_MANIFEST'])
def test_collection_budgets_are_enforced(monkeypatch, budget):
    fetch, _ = fixture()
    monkeypatch.setattr(tool, budget, 1)
    records, contents, receipt = tool.collect_rust_notices(b'[toolchain]\nchannel="1.88.0"\n', fetch)
    assert not records and not contents and receipt['status'] == 'unavailable'


def test_minor_toolchain_alias_uses_published_patch_release_without_guessing():
    fetch, calls = fixture(version='1.88.1')
    _, _, receipt = tool.collect_rust_notices(b'[toolchain]\nchannel="1.88"\n', fetch)
    assert receipt['status'] == 'release_library_notices_captured'
    assert receipt['version'] == '1.88.1'
    assert calls[0].endswith('channel-rust-1.88.toml')


@pytest.mark.parametrize('kind', ['network', 'compression'])
def test_transport_and_compression_errors_remain_warning_only(kind):
    import http.client
    import lzma
    error = http.client.IncompleteRead(b'partial') if kind == 'network' else lzma.LZMAError('truncated release')
    def fetch(*args, **kwargs):
        raise error
    records, contents, receipt = tool.collect_rust_notices(b'[toolchain]\nchannel="1.88"\n', fetch)
    assert records == [] and contents == {} and receipt['status'] == 'unavailable'
