"""Distributor notices require source, attribution and checksum correspondence."""
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('debian_cargo_notices', ROOT / '.devcontainer/debian_cargo_notices.py')
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)


def archive(files, mode='w:gz'):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode=mode) as tar:
        for name, body in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(body)
            tar.addfile(member, io.BytesIO(body))
    return out.getvalue()


def fixture(change='none', *, declared='MIT', distributor_license='expat'):
    prefix = 'example-1.0.0/'
    files = {prefix+'Cargo.toml': b'[package]\nname="example"\nversion="1.0.0"\nlicense="MIT"\n',
             prefix+'Cargo.toml.orig': b'Original publisher manifest', prefix+'src/lib.rs': b'Library source',
             prefix+'examples/example.rs': b'Development example'}
    files[prefix+'Cargo.toml'] = files[prefix+'Cargo.toml'].replace(b'license="MIT"', ('license="'+declared+'"').encode())
    raw = archive(files)
    original = raw
    if change.startswith('repack'):
        repack = {p:b for p,b in files.items() if '/examples/' not in p}
        if change == 'repack-changed':
            repack[prefix+'src/lib.rs'] = b'Different source'
        elif change == 'repack-manifest':
            repack[prefix+'Cargo.toml.orig'] = b'Different metadata'
        elif change == 'repack-missing':
            del repack[prefix+'src/lib.rs']
        original = archive(repack)
    name = 'unrelated' if change == 'copyright-project' else 'example'
    license_name = 'Apache-2.0' if change == 'license-change' else distributor_license
    copyright = (f'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: {name}\nSource: https://github.com/publisher/project\n\nFiles: *\nCopyright: 2020 The Publisher\nLicense: {license_name}\n\nLicense: expat\n Original distributor-published grant text\n').encode()
    packed = archive({'debian/copyright': copyright}, mode='w:xz')
    packaging_sha = '0'*64 if change == 'packaging-checksum' else hashlib.sha256(packed).hexdigest()
    source = 'rust-unrelated' if change == 'source-identity' else 'rust-example'
    dsc = (f'Format: 3.0 (quilt)\nSource: {source}\nVersion: 1.0.0-2\nChecksums-Sha256:\n {hashlib.sha256(original).hexdigest()} {len(original)} rust-example_1.0.0.orig.tar.gz\n {packaging_sha} {len(packed)} rust-example_1.0.0-2.debian.tar.xz\n').encode()
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        if url.endswith('/'):
            return b'<a href="rust-example_1.0.0-2.dsc">selected</a><a href="rust-example_2.0.0-1.dsc">unrelated version</a>'
        if url.endswith('.dsc'):
            return dsc
        if url.endswith('.debian.tar.xz'):
            return packed
        if url.endswith('.orig.tar.gz'):
            return original
        pytest.fail('unexpected source lookup')
    return raw, copyright, fetch, calls


def test_exact_locked_archive_retains_unchanged_distributor_notice_and_provenance():
    raw, body, fetch, calls = fixture()
    proof, retained = tool.recover_debian_notice('example','1.0.0',raw,'MIT','https://github.com/publisher/project',fetch)
    assert retained == body
    assert proof['source_match']['kind'] == 'archive_sha256'
    assert proof['publisher'] == 'Debian'
    assert 'not upstream-authored' in proof['scope'].lower()
    assert proof['notice_sha256'] == hashlib.sha256(body).hexdigest()
    assert not any(url.endswith('.orig.tar.gz') for url in calls)
    assert all('2.0.0' not in url for url in calls)


def test_repack_requires_identical_library_and_manifests_and_records_omitted_examples():
    raw, body, fetch, _ = fixture('repack')
    proof, retained = tool.recover_debian_notice('example','1.0.0',raw,'MIT','https://github.com/publisher/project',fetch)
    assert retained == body
    assert proof['source_match']['kind'] == 'repacked_source_files'
    assert proof['source_match']['omitted_development_files'] == ['examples/example.rs']
    assert any(p['path'] == 'src/lib.rs' for p in proof['source_match']['matched_files'])


@pytest.mark.parametrize('change', ['repack-changed','repack-manifest','repack-missing','copyright-project','license-change','packaging-checksum','source-identity'])
def test_unrelated_changed_or_mismatched_notice_is_not_reused(change):
    raw, _, fetch, _ = fixture(change)
    assert tool.recover_debian_notice('example','1.0.0',raw,'MIT','https://github.com/publisher/project',fetch) == (None,None)


def test_other_versions_do_not_silently_cover_a_version_bump():
    raw, _, _, _ = fixture()
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        assert url.endswith('/')
        return b'<a href="rust-example_1.0.0-2.dsc">old version</a>'
    assert tool.recover_debian_notice('example','1.0.1',raw,'MIT','https://github.com/publisher/project',fetch) == (None,None)
    assert len(calls) == 1


@pytest.mark.parametrize('path', ['../escape','/absolute','debian/../copyright'])
def test_archive_paths_are_never_extracted_or_followed(path):
    with pytest.raises(ValueError, match='unsafe'):
        tool._archive(archive({path:b'notice'}),mode='r|gz',copyright=True)


def test_reordering_dual_license_alternatives_does_not_reopen_a_gap():
    raw, body, fetch, _ = fixture(declared='MIT OR Apache-2.0', distributor_license='Apache-2.0 or MIT')
    proof, retained = tool.recover_debian_notice('example','1.0.0',raw,'MIT OR Apache-2.0','https://github.com/publisher/project',fetch)
    assert proof is not None and retained == body
