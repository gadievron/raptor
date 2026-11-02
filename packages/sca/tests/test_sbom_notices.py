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
