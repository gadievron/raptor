"""Captured notice associations are occurrence-specific evidence, not licences."""
import base64
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

from core.json import save_json
from core.oci.evidence import subject
from packages.sca.sbom_notices import load_notices

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('prepare_notice_test', ROOT / '.github/scripts/prepare_sbom.py')
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def fixture(tmp_path):
    data = {
        '/opt/python/pkg-1.dist-info/METADATA': b'License-Expression: MIT\n',
        '/opt/python/pkg-1.dist-info/licenses/LICENSE': b'python notice',
        '/usr/lib/node_modules/cli/package.json': b'{"license":"SEE LICENSE IN README.md"}',
        '/usr/lib/node_modules/cli/README.md': b'CLI notice',
        '/usr/lib/node_modules/cli/node_modules/other/LICENSE': b'other package notice',
        '/usr/share/doc/deb/copyright': b'Full text in /usr/share/common-licenses/GPL-2.',
        '/usr/share/common-licenses/GPL-2': b'common licence text',
        '/usr/bin/unknown': b'executable bytes',
    }
    diff, blob = 'sha256:' + 'd' * 64, 'sha256:' + 'e' * 64
    config = json.dumps({'os': 'linux', 'architecture': 'amd64',
                         'rootfs': {'type': 'layers', 'diff_ids': [diff]}}).encode()
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                           'config': {'digest': 'sha256:' + sha(config), 'size': len(config)},
                           'layers': [{'digest': blob, 'size': 100, 'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip'}]}).encode()
    loc = lambda path: {'path': path, 'layerID': diff}
    specs = [('a' * 16, 'python', 'pkg', '/opt/python/pkg-1.dist-info/METADATA', 'MIT'),
             ('b' * 16, 'npm', 'cli', '/usr/lib/node_modules/cli/package.json', 'SEE LICENSE IN README.md'),
             ('c' * 16, 'deb', 'deb', '/usr/share/doc/deb/copyright', 'GPL-2.0-only')]
    artifacts = [{'id': identifier, 'type': kind, 'name': name, 'version': '1',
                  'purl': f'pkg:{"pypi" if kind == "python" else kind}/{name}@1',
                  'locations': [loc(path)], 'licenses': [{'value': licence, 'locations': [loc(path)]}]}
                 for identifier, kind, name, path, licence in specs]
    native = {'schema': {'version': '16.1.11'},
              'source': {'type': 'image', 'name': 'example/image', 'version': 'sha256:' + sha(manifest),
                         'metadata': {'manifest': base64.b64encode(manifest).decode(), 'manifestDigest': 'sha256:' + sha(manifest),
                                      'config': base64.b64encode(config).decode(), 'imageID': 'sha256:' + sha(config)}},
              'descriptor': {'configuration': {'search': {'scope': 'squashed'}}}, 'artifacts': artifacts,
              'files': [{'id': f'{i:016x}', 'location': loc(path), 'metadata': {'type': 'RegularFile', 'size': len(raw)},
                         'digests': [{'algorithm': 'sha256', 'value': sha(raw)}]} for i, (path, raw) in enumerate(data.items())]}
    native_raw = json.dumps(native).encode()
    report = {'version': 1, 'catalogue_sha256': sha(native_raw), 'subject': subject(native)[0], 'packages': deepcopy(artifacts), 'files': []}
    report['packages'] = [{k: a[k] for k in ('id', 'name', 'version', 'type', 'purl', 'licenses')} for a in artifacts]
    root = tmp_path / 'capture'
    store = root / 'notices/sha256'
    store.mkdir(parents=True)
    for path, raw in data.items():
        identity = path == '/usr/bin/unknown'
        row = {'path': path, 'layer_blob_digest': blob, 'catalogue_layer_diff_id': diff,
               'sha256': sha(raw), 'size': len(raw), 'roles': ['identity_only'] if identity else ['notice_filename'],
               'package_ids': [], 'visibility': 'catalogue_location',
               'content_kind': 'identity' if identity else 'package_metadata' if path.endswith(('/METADATA', '/package.json')) else 'notice_candidate'}
        if not identity:
            row['notice_file'] = 'notices/sha256/' + sha(raw)
            (store / sha(raw)).write_bytes(raw)
        report['files'].append(row)
    cdx = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
           'metadata': {'component': {'bom-ref': 'image', 'type': 'container', 'name': native['source']['name'], 'version': native['source']['version']}},
           'components': [{'bom-ref': a['id'], 'type': 'library', 'name': a['name'], 'version': a['version'], 'purl': a['purl'],
                           'licenses': [{'license': {'name': a['licenses'][0]['value']}}]} for a in artifacts],
           'dependencies': [{'ref': a['id'], 'dependsOn': []} for a in artifacts]}
    package = lambda identifier, name, version: {'SPDXID': identifier, 'name': name, 'versionInfo': version,
        'filesAnalyzed': False, 'downloadLocation': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION', 'licenseConcluded': 'NOASSERTION'}
    spdx = {'spdxVersion': 'SPDX-2.3', 'SPDXID': 'SPDXRef-DOCUMENT', 'dataLicense': 'CC0-1.0', 'name': 'fixture',
            'documentNamespace': 'https://example.org/sbom/fixture', 'creationInfo': {'created': '2026-11-02T00:00:00Z', 'creators': ['Tool: fixture']},
            'packages': [package('SPDXRef-Image', native['source']['name'], native['source']['version'])] + [
                {**package('SPDXRef-Package-' + a['id'], a['name'], a['version']),
                 'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl', 'referenceLocator': a['purl']}]} for a in artifacts],
            'files': [], 'relationships': []}
    return root, native, sha(native_raw), report, cdx, spdx


def test_associations_are_specific_and_claims_unchanged(fixture):
    root, native, digest, report, cdx, spdx = fixture
    summary, blobs = load_notices(root, native, digest, report)
    records = {p['id']: p for p in summary['packages']}
    python = records['a' * 16]
    assert {r['content_kind'] for r in python['files']} == {'package_metadata', 'notice_candidate'}
    assert any(r['reasons'] == ['python_distribution_notice_candidate'] for r in python['files'])
    assert records['b' * 16]['files'][0]['reasons'] == ['declared_notice_pointer']
    assert any(r['reasons'] == ['copyright_common_licence_reference'] for r in records['c' * 16]['files'])
    assert {r['path'] for r in summary['unassociated_files']} == {'/usr/lib/node_modules/cli/node_modules/other/LICENSE', '/usr/bin/unknown'}
    assert b'executable bytes' not in blobs.values()
    original = deepcopy((cdx, spdx))
    c, s, provenance = tool.prepare(native, cdx, spdx, {'version': 1, 'sources': []}, notice_summary=summary)
    assert (cdx, spdx) == original
    assert c['version'] == 2 and c['dependencies'] == cdx['dependencies']
    assert s['files'] == spdx['files'] and s['relationships'] == spdx['relationships']
    for old, new in zip(cdx['components'], c['components']):
        assert new['licenses'] == old['licenses']
        assert new['externalReferences'][0]['type'] == 'evidence'
    for old, new in zip(spdx['packages'], s['packages']):
        assert new['licenseDeclared'] == old['licenseDeclared'] and new['licenseConcluded'] == old['licenseConcluded']
    assert provenance['notice_evidence'] == summary


@pytest.mark.parametrize('change', ['scope', 'catalogue', 'hash', 'size', 'layer', 'missing', 'duplicate', 'storage', 'package', 'identity', 'unexpected'])
def test_mismatched_capture_refused(fixture, change):
    root, native, digest, report, _, _ = fixture
    row = report['files'][0]
    if change == 'scope':
        report['subject']['catalogue_scope'] = 'all-layers'
    elif change == 'catalogue':
        digest = 'f' * 64
    elif change == 'hash':
        (root / row['notice_file']).write_bytes(b'tampered')
    elif change == 'size':
        row['size'] += 1
    elif change == 'layer':
        row['layer_blob_digest'] = 'sha256:' + 'f' * 64
    elif change == 'missing':
        report['files'].pop(0)
    elif change == 'duplicate':
        report['files'].append(deepcopy(row))
    elif change == 'storage':
        row['notice_file'] = '../../secret'
    elif change == 'package':
        row['package_ids'] = ['unknown']
    elif change == 'identity':
        report['files'][-1]['notice_file'] = row['notice_file']
    else:
        report['files'][-1]['content_kind'] = 'notice_candidate'
        report['files'][-1]['notice_file'] = 'notices/sha256/' + report['files'][-1]['sha256']
    with pytest.raises((ValueError, OSError)):
        load_notices(root, native, digest, report)


def test_capture_store_symlink_refused(fixture, tmp_path):
    root, native, digest, report, _, _ = fixture
    (root / 'notices').rename(tmp_path / 'real-notices')
    (root / 'notices').symlink_to(tmp_path / 'real-notices', target_is_directory=True)
    with pytest.raises(OSError):
        load_notices(root, native, digest, report)


def test_metadata_only_does_not_claim_notice_capture(fixture):
    root, native, digest, report, _, _ = fixture
    native['files'] = [f for f in native['files'] if '/dist-info/' not in f['location']['path'] and '/licenses/LICENSE' not in f['location']['path']]
    report['files'] = [r for r in report['files'] if '/licenses/LICENSE' not in r['path']]
    summary, _ = load_notices(root, native, digest, report)
    assert summary['packages'][0]['status'] == 'metadata_only'
    assert summary['packages'][0]['gaps']


def test_cli_copies_notices_and_sca_preserves_links(fixture, tmp_path, monkeypatch):
    from packages.sca.sbom_import import _read_cyclonedx
    from packages.sca.sbom_spdx_import import _read_spdx
    from packages.sca.sbom import build_bom
    from packages.sca.sbom_spdx import render_sbom_spdx
    root, native, _, report, cdx, spdx = fixture
    native_path = tmp_path / 'syft.json'
    # Use the exact serialized bytes whose hash is bound into the capture.
    native_path.write_text(json.dumps(native))
    save_json(root / 'evidence.json', report)
    save_json(tmp_path / 'raw.cdx.json', cdx)
    save_json(tmp_path / 'raw.spdx.json', spdx)
    save_json(tmp_path / 'manifest.json', {'version': 1, 'sources': []})
    out = tmp_path / 'prepared'
    monkeypatch.setattr(sys, 'argv', ['prepare_sbom', '--syft', str(native_path), '--cyclonedx', str(tmp_path / 'raw.cdx.json'),
        '--spdx', str(tmp_path / 'raw.spdx.json'), '--provenance', str(tmp_path / 'manifest.json'), '--notice-evidence', str(root), '--out', str(out)])
    tool.main()
    c = json.loads((out / 'sbom.cdx.json').read_bytes())
    s = json.loads((out / 'sbom.spdx.json').read_bytes())
    imported_c = _read_cyclonedx(c, out / 'sbom.cdx.json')
    imported_s = _read_spdx(s, out / 'sbom.spdx.json')
    assert build_bom(deps=imported_c.dependencies, source_bom=imported_c)['components'] == c['components']
    assert render_sbom_spdx(deps=imported_s.dependencies, source_bom=imported_s, target_name='fixture')['packages'] == s['packages']
    for component in c['components']:
        for ref in component['externalReferences']:
            assert sha((out / ref['url']).read_bytes()) == ref['hashes'][0]['content']
    assert json.loads((out / 'notice-evidence.json').read_bytes()) == report
    (root / report['files'][0]['notice_file']).unlink()
    bad_out = tmp_path / 'failed-output'
    monkeypatch.setattr(sys, 'argv', sys.argv[:-1] + [str(bad_out)])
    with pytest.raises((ValueError, OSError)):
        tool.main()
    assert not bad_out.exists()


def test_report_package_ids_cannot_create_new_associations(fixture):
    root, native, digest, report, _, _ = fixture
    for row in report['files']:
        row['package_ids'] = ['a' * 16]
    summary, _ = load_notices(root, native, digest, report)
    assert all('/usr/share/doc/' not in row['path'] for row in summary['packages'][0]['files'])


def test_missing_unassociated_required_notice_refused(fixture):
    root, native, digest, report, _, _ = fixture
    report['files'] = [row for row in report['files'] if '/node_modules/other/LICENSE' not in row['path']]
    with pytest.raises(ValueError, match='missing required'):
        load_notices(root, native, digest, report)


def test_ambiguous_common_licence_versions_stay_gaps(fixture):
    from packages.sca.sbom_notices import associate
    root, native, digest, report, _, _ = fixture
    _, blobs = load_notices(root, native, digest, report)
    common = deepcopy(next(r for r in report['files'] if r['path'] == '/usr/share/common-licenses/GPL-2'))
    common['catalogue_layer_diff_id'] = 'sha256:' + 'f' * 64
    summary = associate(native, report['subject'], report['files'] + [common], blobs)
    deb = summary['packages'][2]
    assert deb['gaps'] == ['common licence text missing or ambiguous: GPL-2']
    assert len(deb['files']) == 1


def test_required_notice_cannot_be_hidden_as_identity_only(fixture):
    root, native, digest, report, _, _ = fixture
    row = next(r for r in report['files'] if '/node_modules/other/LICENSE' in r['path'])
    row['content_kind'] = 'identity'
    row['roles'] = ['identity_only']
    del row['notice_file']
    with pytest.raises(ValueError, match='identity-only'):
        load_notices(root, native, digest, report)


def test_shared_directory_cannot_explode_association_count(fixture, monkeypatch):
    from packages.sca import sbom_notices
    root, native, digest, report, _, _ = fixture
    monkeypatch.setattr(sbom_notices, 'MAX_ASSOCIATIONS', 1)
    with pytest.raises(ValueError, match='association count'):
        load_notices(root, native, digest, report)


def with_record(fixture):
    root, native, _, report, cdx, spdx = fixture
    row = next(r for r in report['files'] if r['path'].endswith('/licenses/LICENSE'))
    native['artifacts'][0]['metadata'] = {'files': [{'path': 'pkg-1.dist-info/licenses/LICENSE',
        'digest': {'algorithm': 'sha256', 'value': base64.urlsafe_b64encode(bytes.fromhex(row['sha256'])).rstrip(b'=').decode()},
        'size': str(row['size'])}]}
    native['files'] = [f for f in native['files'] if f['location']['path'] != row['path']]
    digest = sha(json.dumps(native).encode())
    report['catalogue_sha256'] = digest
    return root, native, digest, report, row


def test_version_two_requires_record_notices_but_legacy_capture_remains_usable(fixture):
    root, native, digest, report, row = with_record(fixture)
    report['files'].remove(row)
    summary, _ = load_notices(root, native, digest, report)
    assert summary['packages'][0]['status'] == 'metadata_only'
    report['version'] = 2
    with pytest.raises(ValueError, match='missing required'):
        load_notices(root, native, digest, report)


def test_unindexed_record_notice_checked_and_associated(fixture):
    root, native, digest, report, row = with_record(fixture)
    report['version'] = 2
    row['visibility'] = 'layer_probe_runtime_visibility_unconfirmed'
    summary, _ = load_notices(root, native, digest, report)
    record = next(r for r in summary['packages'][0]['files'] if r['path'] == row['path'])
    assert 'python_record_membership' in record['reasons']
    row['size'] += 1
    with pytest.raises(ValueError, match='RECORD'):
        load_notices(root, native, digest, report)


def test_distro_notice_context_preserves_child_claims_status_and_input(fixture):
    root, native, _, report, cdx, spdx = fixture
    # The enclosing package's copyright is GPL; the child has its own unresolved
    # declaration. Context must not turn that into a child GPL conclusion.
    child = native['artifacts'][1]
    parent = native['artifacts'][2]
    path = child['locations'][0]['path']
    row = next(r for r in report['files'] if r['path'] == path)
    raw = (root / row['notice_file']).read_bytes()
    parent['metadata'] = {'files': [{'path': path, 'digest': {
        'algorithm': 'md5', 'value': hashlib.md5(raw, usedforsecurity=False).hexdigest()}}]}
    report['files'] = [r for r in report['files'] if not r['path'].endswith('/cli/README.md')]
    digest = sha(json.dumps(native).encode())
    report['catalogue_sha256'] = digest
    summary, _ = load_notices(root, native, digest, report)
    original = deepcopy(summary)
    before = deepcopy((cdx, spdx))
    c, s, provenance = tool.prepare(native, cdx, spdx, {'version': 1, 'sources': []}, notice_summary=summary)
    assert summary == original
    context = provenance['notice_evidence']['packages'][1]['distro_owner_context']['checksum_matched_notices'][0]
    assert context['owner_cyclonedx_ref'] == c['components'][2]['bom-ref']
    assert context['owner_spdx_id'] == s['packages'][3]['SPDXID']
    assert context['owner_purl'] == c['components'][2]['purl']
    child_record = provenance['notice_evidence']['packages'][1]
    assert child_record['status'] == 'metadata_only' and child_record['gaps']
    assert c['components'][1]['licenses'] == before[0]['components'][1]['licenses']
    assert s['packages'][2]['licenseDeclared'] == before[1]['packages'][2]['licenseDeclared']
    assert s['packages'][2]['licenseConcluded'] == 'NOASSERTION'
    assert c['dependencies'] == cdx['dependencies'] and s['relationships'] == spdx['relationships']
    assert any('Enclosing distro' in ref.get('comment', '') for ref in c['components'][1]['externalReferences'])


def test_optional_owner_reader_fetches_only_missing_identity_and_does_not_export_bytes(fixture, monkeypatch):
    from core.oci import evidence
    root, native, _, report, _, _ = fixture
    identity = deepcopy(report['files'][-1])
    payload = b'executable bytes'
    identifier = 'd' * 16
    native['artifacts'].append({'id': identifier, 'name': 'tool', 'version': '1', 'type': 'binary',
        'locations': [{'path': identity['path'], 'layerID': identity['catalogue_layer_diff_id']}], 'licenses': []})
    report['packages'].append({k: native['artifacts'][-1][k] for k in ('id', 'name', 'version', 'type', 'licenses')})
    native['artifacts'][2]['metadata'] = {'files': [{'path': identity['path'], 'digest': {
        'algorithm': 'md5', 'value': hashlib.md5(payload, usedforsecurity=False).hexdigest()}}]}
    digest = sha(json.dumps(native).encode())
    report['catalogue_sha256'] = digest
    calls = []
    reader = object()
    def verify(catalogue, source, locations):
        assert catalogue is native and source is reader
        assert locations == {(identity['path'], identity['catalogue_layer_diff_id'])}
        calls.append(locations)
        return {next(iter(locations)): ({**identity, 'method': 'verified_image_layer'}, payload)}
    monkeypatch.setattr(evidence, 'read_identity_files', verify)
    before, _ = load_notices(root, native, digest, report)
    assert calls == [] and before['distro_owner_statistics']['packages_with_unresolved_owner_leads'] == 1
    summary, blobs = load_notices(root, native, digest, report, owner_reader=reader)
    assert len(calls) == 1 and summary['distro_owner_statistics']['packages_with_unresolved_owner_leads'] == 0
    assert identity['sha256'] not in blobs and payload not in blobs.values()
    assert summary['owner_file_verification'][0]['sha256'] == identity['sha256']
    assert summary['packages'][-1]['status'] == 'no_associated_evidence'
    json.dumps(summary)  # No transient bytes can enter the serialised report.


@pytest.mark.parametrize('owner_args', [['--owner-registry-ref', ''], ['--owner-oci-layout', '.']])
def test_owner_source_requires_notice_evidence_before_reading_inputs(monkeypatch, owner_args):
    monkeypatch.setattr(sys, 'argv', ['prepare', '--syft', 'absent', '--cyclonedx', 'absent', '--spdx', 'absent',
                                    '--out', 'absent-output'] + owner_args)
    with pytest.raises(SystemExit) as error:
        tool.main()
    assert error.value.code == 2


def test_bad_output_is_rejected_before_owner_source_access(tmp_path, monkeypatch):
    from core.oci import evidence_source
    out = tmp_path / 'output'
    out.mkdir()
    marker = out / 'sbom.cdx.json'
    marker.write_text('keep')
    monkeypatch.setattr(evidence_source, 'registry_reader', lambda *a: pytest.fail('must not create network source'))
    monkeypatch.setattr(sys, 'argv', ['prepare', '--syft', 'absent', '--cyclonedx', 'absent', '--spdx', 'absent',
        '--notice-evidence', 'absent', '--owner-registry-ref', 'example/image@sha256:' + 'a' * 64, '--out', str(out)])
    with pytest.raises(ValueError, match='fresh output'):
        tool.main()
    assert marker.read_text() == 'keep'


def test_cli_offline_owner_verification_measures_without_persisting_binary(fixture, tmp_path, monkeypatch):
    import gzip
    import io
    import tarfile
    from core.oci import evidence_source
    root, native, _, report, cdx, spdx = fixture
    payload = b'executable bytes'
    identity = report['files'][-1]
    identifier = 'd' * 16
    purl = 'pkg:generic/tool@1'
    native['artifacts'].append({'id': identifier, 'name': 'tool', 'version': '1', 'type': 'binary', 'purl': purl,
        'locations': [{'path': identity['path'], 'layerID': identity['catalogue_layer_diff_id']}], 'licenses': []})
    native['artifacts'][2]['metadata'] = {'files': [{'path': identity['path'], 'digest': {
        'algorithm': 'md5', 'value': hashlib.md5(payload, usedforsecurity=False).hexdigest()}}]}
    cdx['components'].append({'bom-ref': identifier, 'type': 'application', 'name': 'tool', 'version': '1', 'purl': purl})
    cdx['dependencies'].append({'ref': identifier, 'dependsOn': []})
    spdx['packages'].append({'SPDXID': 'SPDXRef-Package-' + identifier, 'name': 'tool', 'versionInfo': '1',
        'filesAnalyzed': False, 'downloadLocation': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION', 'licenseConcluded': 'NOASSERTION',
        'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl', 'referenceLocator': purl}]})
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as tar:
        for row in report['files']:
            raw = payload if row['content_kind'] == 'identity' else (root / row['notice_file']).read_bytes()
            header = tarfile.TarInfo(row['path'].lstrip('/'))
            header.size = len(raw)
            tar.addfile(header, io.BytesIO(raw))
    tar_bytes = archive.getvalue()
    compressed = gzip.compress(tar_bytes)
    origin = 'sha256:' + sha(tar_bytes)
    blob = 'sha256:' + sha(compressed)
    metadata = native['source']['metadata']
    config = json.loads(base64.b64decode(metadata['config']))
    config['rootfs']['diff_ids'] = [origin]
    config_bytes = json.dumps(config).encode()
    manifest = json.loads(base64.b64decode(metadata['manifest']))
    manifest['config'].update(digest='sha256:' + sha(config_bytes), size=len(config_bytes))
    manifest['layers'][0].update(digest=blob, size=len(compressed))
    manifest_bytes = json.dumps(manifest).encode()
    metadata.update(config=base64.b64encode(config_bytes).decode(), imageID='sha256:' + sha(config_bytes),
                    manifest=base64.b64encode(manifest_bytes).decode(), manifestDigest='sha256:' + sha(manifest_bytes))
    native['source']['version'] = metadata['manifestDigest']
    cdx['metadata']['component']['version'] = native['source']['version']
    spdx['packages'][0]['versionInfo'] = native['source']['version']
    for file in native['files']:
        file['location']['layerID'] = origin
    for artifact in native['artifacts']:
        for loc in artifact.get('locations', []):
            loc['layerID'] = origin
        for licence in artifact.get('licenses', []):
            for loc in licence.get('locations', []):
                loc['layerID'] = origin
    report['subject'] = subject(native)[0]
    report['packages'] = [{k: a[k] for k in ('id', 'name', 'version', 'type', 'purl', 'licenses') if k in a} for a in native['artifacts']]
    for row in report['files']:
        row.update(catalogue_layer_diff_id=origin, layer_blob_digest=blob)
    native_bytes = json.dumps(native).encode()
    report['catalogue_sha256'] = sha(native_bytes)
    (tmp_path / 'native.json').write_bytes(native_bytes)
    save_json(root / 'evidence.json', report)
    save_json(tmp_path / 'raw.cdx.json', cdx)
    save_json(tmp_path / 'raw.spdx.json', spdx)
    save_json(tmp_path / 'manifest.json', {'version': 1, 'sources': []})
    store = tmp_path / 'layout/blobs/sha256'
    store.mkdir(parents=True)
    (store / sha(compressed)).write_bytes(compressed)
    out = tmp_path / 'verified'
    args = ['prepare', '--syft', str(tmp_path / 'native.json'), '--cyclonedx', str(tmp_path / 'raw.cdx.json'),
        '--spdx', str(tmp_path / 'raw.spdx.json'), '--provenance', str(tmp_path / 'manifest.json'),
        '--notice-evidence', str(root), '--owner-oci-layout', str(tmp_path / 'layout'), '--out', str(out)]
    monkeypatch.setattr(evidence_source, 'registry_reader', lambda *a: pytest.fail('offline path must not create a registry client'))
    monkeypatch.setattr(sys, 'argv', args)
    tool.main()
    result = json.loads((out / 'provenance.json').read_bytes())['notice_evidence']
    measured = result['owner_file_verification']
    assert len(measured) == 1 and measured[0]['sha256'] == sha(payload)
    assert result['distro_owner_statistics']['packages_with_unresolved_owner_leads'] == 0
    assert result['packages'][-1]['status'] == 'no_associated_evidence'
    assert not (out / 'notices/sha256' / sha(payload)).exists()
    assert payload not in [p.read_bytes() for p in (out / 'notices/sha256').iterdir()]
    (store / sha(compressed)).write_bytes(compressed + b'tampered')
    failed = tmp_path / 'failed'
    monkeypatch.setattr(sys, 'argv', args[:-1] + [str(failed)])
    with pytest.raises(ValueError):
        tool.main()
    assert not failed.exists()


def test_python_record_context_exports_separately_and_preserves_claims(fixture):
    root, native, _, report, cdx, spdx = fixture
    payload = b'executable bytes'
    identity = report['files'][-1]
    identity['path'] = '/opt/python/vendor/tool'
    native['files'][-1]['location']['path'] = identity['path']
    identifier = 'd' * 16
    purl = 'pkg:generic/tool@1'
    child = {'id': identifier, 'name': 'tool', 'version': '1', 'type': 'binary', 'purl': purl,
             'locations': [{'path': identity['path'], 'layerID': identity['catalogue_layer_diff_id']}], 'licenses': []}
    native['artifacts'].append(child)
    parent = native['artifacts'][0]
    parent['metadata'] = {'sitePackagesRootPath': '/opt/python', 'files': [
        {'path': 'vendor/tool', 'size': str(len(payload)), 'digest': {'algorithm': 'sha256',
            'value': base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b'=').decode()}}]}
    report['packages'].append({k: deepcopy(child[k]) for k in ('id', 'name', 'version', 'type', 'purl', 'licenses')})
    digest = sha(json.dumps(native).encode()); report['catalogue_sha256'] = digest
    cdx['components'].append({'bom-ref': identifier, 'type': 'application', 'name': 'tool', 'version': '1', 'purl': purl})
    cdx['dependencies'].append({'ref': identifier, 'dependsOn': []})
    spdx['packages'].append({'SPDXID': 'SPDXRef-Package-' + identifier, 'name': 'tool', 'versionInfo': '1',
        'filesAnalyzed': False, 'downloadLocation': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION', 'licenseConcluded': 'NOASSERTION',
        'externalRefs': [{'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl', 'referenceLocator': purl}]})
    summary, blobs = load_notices(root, native, digest, report)
    original = deepcopy((native, summary, cdx, spdx))
    c, s, provenance = tool.prepare(native, cdx, spdx, {'version': 1, 'sources': []}, notice_summary=summary)
    assert original == (native, summary, cdx, spdx)
    record = provenance['notice_evidence']['packages'][-1]
    context = record['python_record_owner_context']['checksum_matched_notices'][0]
    assert context['owner_cyclonedx_ref'] == c['components'][0]['bom-ref']
    assert context['owner_spdx_id'] == s['packages'][1]['SPDXID']
    assert context['owner_purl'] == c['components'][0]['purl']
    assert record['status'] == 'no_associated_evidence' and record['files'] == [] and record['gaps']
    assert provenance['notice_evidence']['python_record_owner_statistics']['packages_with_checksum_matched_notice_context'] == 1
    assert payload not in blobs.values() and identity['sha256'] not in blobs
    assert c['components'][-1].get('licenses') is None
    assert s['packages'][-1]['licenseDeclared'] == 'NOASSERTION' and s['packages'][-1]['licenseConcluded'] == 'NOASSERTION'
    assert c['dependencies'] == cdx['dependencies'] and s['relationships'] == spdx['relationships']
    assert 'python_record_owner_context' in s['packages'][-1]['comment']
    assert any('Enclosing Python distribution' in x.get('comment', '') for x in c['components'][-1]['externalReferences'])


@pytest.mark.parametrize('version', [1, 2])
def test_legacy_capture_without_unclaimed_metadata_remains_readable(fixture, version):
    root, native, _, report, _, _ = fixture
    native['artifacts'][0]['licenses'] = []
    report['packages'][0]['licenses'] = []
    report['files'] = [row for row in report['files'] if not row['path'].endswith('/METADATA')]
    digest = sha(json.dumps(native).encode())
    report.update(version=version, catalogue_sha256=digest)
    summary, _ = load_notices(root, native, digest, report)
    assert summary['packages'][0]['status'] == 'notice_candidate_captured'
    assert 'recovered_distribution_license' not in summary['packages'][0]
    report['version'] = 3
    with pytest.raises(ValueError, match='missing required'):
        load_notices(root, native, digest, report)


def test_verified_trove_declaration_enriches_exports_without_a_conclusion(fixture):
    root, native, _, report, cdx, spdx = fixture
    native['artifacts'][0]['licenses'] = []
    report['packages'][0]['licenses'] = []
    cdx['components'][0]['licenses'] = []
    path = '/opt/python/pkg-1.dist-info/METADATA'
    raw = b'Name: pkg\nVersion: 1\nClassifier: License :: OSI Approved :: MIT License\n'
    row = next(row for row in report['files'] if row['path'] == path)
    row.update(sha256=sha(raw), size=len(raw))
    (root / row['notice_file']).unlink()
    row['notice_file'] = 'notices/sha256/' + sha(raw)
    (root / row['notice_file']).write_bytes(raw)
    file = next(file for file in native['files'] if file['location']['path'] == path)
    file['metadata']['size'] = len(raw)
    file['digests'] = [{'algorithm': 'sha256', 'value': sha(raw)}]
    digest = sha(json.dumps(native).encode())
    report.update(version=3, catalogue_sha256=digest)
    summary, _ = load_notices(root, native, digest, report)
    declaration = summary['packages'][0]['recovered_distribution_license']
    assert declaration['expression'] == 'MIT' and declaration['metadata_field'] == 'Classifier'
    assert declaration['metadata_sha256'] == sha(raw)
    c, s, provenance = tool.prepare(native, cdx, spdx, {'version': 1, 'sources': []}, notice_summary=summary)
    assert c['components'][0]['licenses'] == [{'expression': 'MIT'}]
    assert s['packages'][1]['licenseDeclared'] == 'MIT'
    assert s['packages'][1]['licenseConcluded'] == 'NOASSERTION'
    assert cdx['components'][0]['licenses'] == [] and spdx['packages'][1]['licenseDeclared'] == 'NOASSERTION'
    assert provenance['notice_evidence']['packages'][0]['recovered_distribution_license']['original_catalogue_licenses'] == []
    # Identification does not turn absent notice text into a captured notice.
    notice_path = '/opt/python/pkg-1.dist-info/licenses/LICENSE'
    report['files'] = [row for row in report['files'] if row['path'] != notice_path]
    native['files'] = [file for file in native['files'] if file['location']['path'] != notice_path]
    digest = sha(json.dumps(native).encode())
    report['catalogue_sha256'] = digest
    missing, _ = load_notices(root, native, digest, report)
    assert missing['packages'][0]['status'] == 'metadata_only'
    assert missing['packages'][0]['gaps']
    assert missing['packages'][0]['recovered_distribution_license']['expression'] == 'MIT'
