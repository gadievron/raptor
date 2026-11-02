"""Notice recovery must bind every byte to the selected platform manifest."""
import base64
from copy import deepcopy
import gzip
import hashlib
import io
import json
import tarfile

import pytest

from core.oci.blob import WantedEntryRefused, extract_files_from_layer
from core.tar import TarOpenError
from core.oci.evidence import capture, read_catalogue, subject


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def fixture_image(files=None, *, link=False):
    files = files or {'pkg/LICENSE': b'original licence\n', 'usr/bin/tool': b'executable'}
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            if link:
                info.type = tarfile.SYMTYPE
                info.linkname = '/etc/passwd'
            archive.addfile(info, io.BytesIO(data))
    tar = stream.getvalue()
    blob = gzip.compress(tar)
    diff_id = digest(tar)
    config = json.dumps({'os': 'linux', 'architecture': 'amd64',
                         'rootfs': {'type': 'layers', 'diff_ids': [diff_id]}}).encode()
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                           'config': {'digest': digest(config), 'size': len(config)},
                           'layers': [{'digest': digest(blob), 'size': len(blob),
                                       'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip'}]}).encode()
    location = lambda path: {'path': '/' + path, 'layerID': diff_id}
    catalogue = {'schema': {'version': '16.1.11'},
                 'source': {'type': 'image', 'metadata': {
                     'manifestDigest': digest(manifest), 'imageID': digest(config),
                     'manifest': base64.b64encode(manifest).decode(),
                     'config': base64.b64encode(config).decode()}},
                 'descriptor': {'configuration': {'search': {'scope': 'squashed'}}},
                 'files': [{'location': location(name), 'metadata': {'type': 'RegularFile'},
                            'digests': [{'algorithm': 'sha256', 'value': hashlib.sha256(data).hexdigest()}]}
                           for name, data in files.items()],
                 'artifacts': [{'id': 'package-id', 'name': 'package', 'version': '1', 'type': 'npm',
                                'licenses': [{'value': 'MIT', 'locations': [location('pkg/LICENSE')]}]}]}
    return catalogue, blob


def test_verified_original_bytes_and_identity_without_executable_output():
    catalogue, blob = fixture_image()
    report, notices = capture(catalogue, lambda layer: [blob], identify=('/usr/bin/tool',))
    assert list(notices.values()) == [b'original licence\n']
    notice, tool = report['files']
    assert notice['package_ids'] == ['package-id']
    assert notice['layer_blob_digest'] == digest(blob)
    assert notice['catalogue_layer_diff_id'] == catalogue['files'][0]['location']['layerID']
    assert tool['roles'] == ['identity_only']
    assert 'notice_file' not in tool
    assert report['subject']['platform'] == {'os': 'linux', 'architecture': 'amd64'}


@pytest.mark.parametrize('kind', ['manifest', 'config', 'scope', 'platform', 'layer', 'path', 'missing', 'file_digest'])
def test_catalogue_mismatch_refused(kind):
    catalogue, blob = fixture_image()
    if kind in {'manifest', 'config'}:
        catalogue['source']['metadata'][kind] = base64.b64encode(b'{}').decode()
    elif kind == 'scope':
        catalogue['descriptor']['configuration']['search']['scope'] = 'unknown'
    elif kind == 'platform':
        catalogue['source']['metadata']['architecture'] = 'arm64'
    elif kind == 'layer':
        catalogue['files'][0]['location']['layerID'] = 'sha256:' + 'a' * 64
    elif kind == 'path':
        catalogue['files'][0]['location']['path'] = '/pkg/../LICENSE'
    elif kind == 'missing':
        catalogue['artifacts'][0]['licenses'][0]['locations'][0]['path'] = '/missing'
    else:
        catalogue['files'][0]['digests'][0]['value'] = 'a' * 64
    with pytest.raises(ValueError):
        capture(catalogue, lambda layer: [blob])


@pytest.mark.parametrize('change', ['truncate', 'append', 'corrupt'])
def test_full_layer_verification(change):
    catalogue, blob = fixture_image()
    changed = blob[:-1] if change == 'truncate' else blob + b'x' if change == 'append' else bytes([blob[0] ^ 1]) + blob[1:]
    with pytest.raises((ValueError, OSError, TarOpenError)):
        capture(catalogue, lambda layer: [changed])


def test_wanted_symlink_refused():
    catalogue, blob = fixture_image(link=True)
    with pytest.raises((WantedEntryRefused, ValueError)):
        capture(catalogue, lambda layer: [blob])


def test_optional_probe_is_not_claimed_as_runtime_file():
    catalogue, blob = fixture_image({'pkg/LICENSE': b'original licence\n', 'pkg/README.md': b'notice'})
    catalogue['files'] = catalogue['files'][:1]
    catalogue['artifacts'][0]['locations'] = [{'path': '/pkg/package.json', 'layerID': catalogue['files'][0]['location']['layerID']}]
    report, _ = capture(catalogue, lambda layer: [blob])
    readme = next(row for row in report['files'] if row['path'].endswith('README.md'))
    assert readme['visibility'] == 'layer_probe_runtime_visibility_unconfirmed'


def test_duplicate_and_nonfinite_json_refused():
    for raw in (b'{"files": [], "files": []}', b'{"a":NaN}'):
        with pytest.raises(ValueError):
            read_catalogue(raw)


def test_duplicate_file_location_refused():
    catalogue, blob = fixture_image()
    catalogue['files'].append(deepcopy(catalogue['files'][0]))
    with pytest.raises(ValueError, match='duplicate'):
        capture(catalogue, lambda layer: [blob])


def test_selected_payload_memory_budget():
    _, blob = fixture_image()
    with pytest.raises(ValueError, match='memory budget'):
        extract_files_from_layer([blob], {'pkg/LICENSE', 'usr/bin/tool'}, max_selected_bytes=20)
    assert extract_files_from_layer([blob], {'usr/bin/tool'}, max_selected_bytes=10) == {'usr/bin/tool': b'executable'}


def test_unknown_identity_refused():
    catalogue, blob = fixture_image()
    with pytest.raises(ValueError, match='absent'):
        capture(catalogue, lambda layer: [blob], identify=('/missing',))


def test_all_layers_scope_preserved():
    catalogue, _ = fixture_image()
    catalogue['descriptor']['configuration']['search']['scope'] = 'all-layers'
    assert subject(catalogue)[0]['catalogue_scope'] == 'all-layers'


def test_offline_cli_captures_verified_fixture(tmp_path):
    import importlib.util
    from pathlib import Path
    script = Path(__file__).resolve().parents[3] / '.github/scripts/capture_container_evidence.py'
    spec = importlib.util.spec_from_file_location('evidence_cli_test', script)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    catalogue, blob = fixture_image()
    native = tmp_path / 'syft.json'
    native.write_text(json.dumps(catalogue))
    store = tmp_path / 'layout' / 'blobs' / 'sha256'
    store.mkdir(parents=True)
    (store / digest(blob).split(':')[1]).write_bytes(blob)
    out = tmp_path / 'evidence'
    assert tool.main(['--syft', str(native), '--oci-layout', str(store.parents[1]), '--out', str(out)]) == 0
    report = json.loads((out / 'evidence.json').read_bytes())
    assert report['catalogue_sha256'] == hashlib.sha256(native.read_bytes()).hexdigest()
    assert (out / report['files'][0]['notice_file']).read_bytes() == b'original licence\n'
    (store / digest(blob).split(':')[1]).write_bytes(blob + b'tampered')
    bad = tmp_path / 'bad'
    with pytest.raises(ValueError):
        tool.main(['--syft', str(native), '--oci-layout', str(store.parents[1]), '--out', str(bad)])
    assert not bad.exists()


def hardlink_layer(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, kind, value in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
            else:
                info.linkname = value
                archive.addfile(info)
    return gzip.compress(stream.getvalue())


def test_opt_in_layer_local_hardlink_resolution():
    blob = hardlink_layer([('cache/LICENSE', tarfile.REGTYPE, b'notice'),
                           ('pkg/LICENSE', tarfile.LNKTYPE, 'cache/LICENSE')])
    assert extract_files_from_layer([blob], {'pkg/LICENSE'}) == {}
    result = extract_files_from_layer([blob], {'pkg/LICENSE', 'cache/LICENSE'}, resolve_selected_hardlinks=True)
    assert result['pkg/LICENSE'] == b'notice'
    from core.oci.blob import UnresolvedLayerHardlinks
    with pytest.raises(UnresolvedLayerHardlinks) as error:
        extract_files_from_layer([blob], {'pkg/LICENSE'}, resolve_selected_hardlinks=True)
    assert error.value.paths == {'cache/LICENSE'}


@pytest.mark.parametrize('target', ['../etc/passwd', 'cache/../../etc/passwd', 'cache\\LICENSE', 'pkg/LICENSE'])
def test_hardlink_escape_and_cycles_refused(target):
    blob = hardlink_layer([('pkg/LICENSE', tarfile.LNKTYPE, target)])
    with pytest.raises(ValueError):
        extract_files_from_layer([blob], {'pkg/LICENSE'}, resolve_selected_hardlinks=True)


@pytest.mark.parametrize('reverse', [False, True])
def test_hardlink_regular_duplicate_refused(reverse):
    entries = [('pkg/LICENSE', tarfile.REGTYPE, b'notice'), ('pkg/LICENSE', tarfile.LNKTYPE, 'cache/LICENSE')]
    if reverse:
        entries.reverse()
    blob = hardlink_layer(entries)
    with pytest.raises(ValueError):
        extract_files_from_layer([blob], {'pkg/LICENSE'}, resolve_selected_hardlinks=True)


def test_uncompressed_layer_identity_verified():
    _, blob = fixture_image()
    with pytest.raises(ValueError, match='diff ID'):
        extract_files_from_layer([blob], {'pkg/LICENSE'}, expected_diff_id='sha256:' + 'a' * 64)
    assert extract_files_from_layer([blob], {'pkg/LICENSE'}, expected_diff_id=digest(gzip.decompress(blob)))['pkg/LICENSE'] == b'original licence\n'


def test_capture_replays_for_uncatalogued_hardlink_target():
    catalogue, _ = fixture_image()
    blob = hardlink_layer([('cache/LICENSE', tarfile.REGTYPE, b'original licence\n'),
                           ('pkg/LICENSE', tarfile.LNKTYPE, 'cache/LICENSE'),
                           ('usr/bin/tool', tarfile.REGTYPE, b'executable')])
    metadata = catalogue['source']['metadata']
    config = json.loads(base64.b64decode(metadata['config']))
    diff_id = digest(gzip.decompress(blob))
    config['rootfs']['diff_ids'] = [diff_id]
    config_raw = json.dumps(config).encode()
    manifest = json.loads(base64.b64decode(metadata['manifest']))
    manifest['config'] = {'digest': digest(config_raw), 'size': len(config_raw)}
    manifest['layers'][0].update(digest=digest(blob), size=len(blob))
    manifest_raw = json.dumps(manifest).encode()
    metadata.update(config=base64.b64encode(config_raw).decode(), imageID=digest(config_raw),
                    manifest=base64.b64encode(manifest_raw).decode(), manifestDigest=digest(manifest_raw))
    for file in catalogue['files']:
        file['location']['layerID'] = diff_id
    catalogue['artifacts'][0]['licenses'][0]['locations'][0]['layerID'] = diff_id
    calls = []
    def reader(layer):
        calls.append(layer.digest)
        return [blob]
    report, notices = capture(catalogue, reader)
    assert len(calls) == 2
    assert list(notices.values()) == [b'original licence\n']
    assert report['files'][0]['path'] == '/pkg/LICENSE'


def test_metadata_declaration_does_not_close_notice_gap():
    catalogue, blob = fixture_image({'pkg/LICENSE': b'notice', 'pkg/METADATA': b'License-Expression: MIT\n'})
    catalogue['artifacts'][0]['type'] = 'python'
    catalogue['artifacts'][0]['licenses'][0]['locations'][0]['path'] = '/pkg/METADATA'
    report, _ = capture(catalogue, lambda layer: [blob])
    metadata = next(row for row in report['files'] if row['path'].endswith('/METADATA'))
    assert metadata['content_kind'] == 'package_metadata'
    assert report['gaps']['package_ids_without_associated_notice_candidate'] == ['package-id']


def test_catalogue_file_size_must_agree():
    catalogue, blob = fixture_image()
    catalogue['files'][0]['metadata']['size'] = 1
    with pytest.raises(ValueError, match='file size'):
        capture(catalogue, lambda layer: [blob])


@pytest.mark.parametrize("scope", ["squashed", "all-layers"])
@pytest.mark.parametrize("notice_filename", ["LICENSE", "THIRD-PARTY-NOTICES.md"])
def test_python_record_recovers_unindexed_vendor_notice(scope, notice_filename):
    catalogue, blob = fixture_image({'pkg-1.dist-info/METADATA': b'License-Expression: MIT',
                                     f'pkg-1.dist-info/licenses/vendor/{notice_filename}': b'vendor notice'})
    catalogue['descriptor']['configuration']['search']['scope'] = scope
    metadata_file = catalogue['files'][0]
    catalogue['files'] = [metadata_file]
    package = catalogue['artifacts'][0]
    package['type'] = 'python'
    package['locations'] = [dict(metadata_file['location'])]
    package['licenses'][0]['locations'] = package['locations']
    package['metadata'] = {'files': [{'path': f'pkg-1.dist-info/licenses/vendor/{notice_filename}', 'size': '13',
        'digest': {'algorithm': 'sha256', 'value': base64.urlsafe_b64encode(hashlib.sha256(b'vendor notice').digest()).rstrip(b'=').decode()}}]}
    report, blobs = capture(catalogue, lambda layer: [blob])
    assert report['version'] == 2
    row = next(r for r in report['files'] if r['content_kind'] == 'notice_candidate')
    assert row['visibility'] == 'layer_probe_runtime_visibility_unconfirmed'
    assert 'python_record_notice' in row['roles']
    assert blobs[row['sha256']] == b'vendor notice'
    package['metadata']['files'][0]['size'] = '14'
    with pytest.raises(ValueError, match='RECORD'):
        capture(catalogue, lambda layer: [blob])


def test_dynamic_discovery_recovers_unindexed_npm_filename_variant():
    catalogue, blob = fixture_image({'pkg/package.json': b'{"license":"MIT"}', 'pkg/license-MIT': b'notice'})
    catalogue['files'] = catalogue['files'][:1]
    package = catalogue['artifacts'][0]
    package['locations'] = [dict(catalogue['files'][0]['location'])]
    package['licenses'][0]['locations'] = package['locations']
    report, blobs = capture(catalogue, lambda layer: [blob])
    row = next(r for r in report['files'] if r['path'].endswith('license-MIT'))
    assert row['package_ids'] == ['package-id']
    assert blobs[row['sha256']] == b'notice'
