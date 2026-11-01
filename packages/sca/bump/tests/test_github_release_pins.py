"""Generic release manifests are updated without application-specific mappings."""
from copy import deepcopy
import json

import pytest

from packages.sca.bump.orchestrator import run_bump
from packages.sca.bump.policy import BumpPolicy, SkipRule, Thresholds
from packages.sca.discovery import find_manifests
from packages.sca.parsers import parse_manifest
from packages.sca.parsers.github_release_pins import load_pins
from packages.sca.rewriters import RewriteEdit, rewrite


class Http:
    def __init__(self, release):
        self.release = release
        self.calls = []

    def get_json(self, url, **kwargs):
        self.calls.append(url)
        assert url == 'https://api.github.com/repos/example/lint-engine/releases/latest'
        return self.release


@pytest.fixture
def pins(tmp_path):
    path = tmp_path / 'config/github-release-pins.json'
    path.parent.mkdir()
    tool = {'repository': 'example/lint-engine', 'version': 'v1.2.3', 'assets': {}}
    release = {'tag_name': 'v1.3.0', 'draft': False, 'prerelease': False, 'assets': []}
    for index, (label, name) in enumerate((('s390x', 'lint-linux-s390x.tar.gz'), ('wasi', 'lint.wasm'))):
        tool['assets'][label] = {'name': name, 'sha256': 'a' * 64, 'size': 100 + index}
        release['assets'].append({
            'name': name, 'state': 'uploaded', 'size': 200 + index,
            'digest': 'sha256:' + str(index + 1) * 64,
            'browser_download_url': f'https://github.com/example/lint-engine/releases/download/v1.3.0/{name}',
        })
    path.write_text(json.dumps({'schema_version': 1, 'tools': {'linter': tool}}, indent=2) + '\n')
    return tmp_path, path, release


def test_discovery_and_inventory_parser(pins):
    root, path, _ = pins
    manifests = find_manifests(root)
    assert len(manifests) == 1 and manifests[0].path == path
    deps = parse_manifest(manifests[0])
    assert len(deps) == 1
    assert deps[0].name == 'example/lint-engine'
    assert deps[0].ecosystem == 'GitHub' and deps[0].version == 'v1.2.3'


def test_dry_run_apply_and_idempotence(pins):
    root, path, release = pins
    before = path.read_text()
    report = run_bump(root, http=Http(release), policy=BumpPolicy())
    assert len(report.candidates) == 1 and path.read_text() == before
    assert report.candidates[0].kind == 'github_release_pin'
    report = run_bump(root, http=Http(release), apply=True, policy=BumpPolicy())
    assert report.results[0].rewrite_result.applied
    tool = load_pins(path.read_text())['tools']['linter']
    assert tool['version'] == 'v1.3.0'
    assert tool['assets']['s390x']['sha256'] == '1' * 64
    assert tool['assets']['wasi']['size'] == 201
    assert not run_bump(root, http=Http(release), apply=True, policy=BumpPolicy()).candidates


@pytest.mark.parametrize('bad', ['missing_asset', 'duplicate', 'digest', 'size', 'url', 'prerelease', 'tag'])
def test_invalid_release_never_changes_any_pin(pins, bad):
    root, path, release = pins
    before = path.read_text()
    if bad == 'missing_asset':
        release['assets'].pop()
    elif bad == 'duplicate':
        release['assets'].append(deepcopy(release['assets'][0]))
    elif bad == 'digest':
        release['assets'][1]['digest'] = None
    elif bad == 'size':
        release['assets'][1]['size'] = True
    elif bad == 'url':
        release['assets'][1]['browser_download_url'] = 'https://evil.invalid/asset.zip'
    elif bad == 'prerelease':
        release['prerelease'] = True
    else:
        release['tag_name'] = 'v1.3.0";evil()'
    report = run_bump(root, http=Http(release), apply=True, policy=BumpPolicy())
    assert not report.candidates
    assert 'release asset pins unavailable' in report.skipped[0][2]
    assert path.read_text() == before


def test_exclude_avoids_lookup_and_policy_skip_avoids_apply(pins):
    root, path, release = pins
    http = Http(release)
    before = path.read_text()
    report = run_bump(root, http=http, apply=True, exclude=['config/**'], policy=BumpPolicy())
    assert not http.calls and not report.candidates
    policy = BumpPolicy(skip=[SkipRule(locator='linter', reason='operator pin')])
    assert not run_bump(root, http=http, apply=True, policy=policy).candidates
    assert path.read_text() == before


def test_stale_plan_or_partial_metadata_cannot_rewrite(pins):
    root, path, release = pins
    cand = run_bump(root, http=Http(release), policy=BumpPolicy()).candidates[0]
    edit = RewriteEdit(cand.locator, cand.current_version, cand.target_version, cand.extra)
    text = path.read_text().replace('"size": 100', '"size": 101')
    path.write_text(text)
    assert not rewrite(path, [edit])[0].applied and path.read_text() == text
    edit.extra['new_tool']['assets'].pop('wasi')
    assert not rewrite(path, [edit])[0].applied and path.read_text() == text


def test_upstream_failure_is_reported_without_writes(pins):
    from core.http import HttpError

    root, path, release = pins
    before = path.read_text()

    class Offline(Http):
        def get_json(self, url, **kwargs):
            raise HttpError('offline')

    report = run_bump(root, http=Offline(release), apply=True, policy=BumpPolicy())
    assert not report.candidates and 'offline' in report.skipped[0][2]
    assert path.read_text() == before


def test_existing_version_policy_applies(pins):
    root, path, release = pins
    before = path.read_text()
    policy = BumpPolicy(thresholds=Thresholds(block_on_minor_skew=1))
    report = run_bump(root, http=Http(release), apply=True, policy=policy)
    assert report.results[0].verdict_label == 'Block'
    assert report.results[0].rewrite_result is None and path.read_text() == before


def test_duplicate_keys_are_refused_before_network(pins):
    root, path, release = pins
    text = path.read_text().replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
    path.write_text(text)
    http = Http(release)
    report = run_bump(root, http=http, apply=True, policy=BumpPolicy())
    assert not http.calls and not report.candidates
    assert 'duplicate' in report.skipped[0][2] and path.read_text() == text


def test_multiple_tools_update_without_losing_siblings(pins):
    root, path, release = pins
    data = load_pins(path.read_text())
    data['tools']['second-tool'] = deepcopy(data['tools']['linter'])
    path.write_text(json.dumps(data))
    report = run_bump(root, http=Http(release), apply=True, policy=BumpPolicy())
    assert len(report.results) == 2 and all(r.rewrite_result.applied for r in report.results)
    assert all(t['version'] == 'v1.3.0' for t in load_pins(path.read_text())['tools'].values())


def prefixed_release(release, tag):
    result = deepcopy(release)
    old_tag = result['tag_name']
    result['tag_name'] = tag
    for asset in result['assets']:
        asset['browser_download_url'] = asset['browser_download_url'].replace('/' + old_tag + '/', '/' + tag + '/')
    return result


def stream_pins(pins):
    root, path, release = pins
    data = load_pins(path.read_text())
    data['tools']['linter']['release_tag_prefix'] = 'engine-v'
    data['tools']['linter']['version'] = 'engine-v1.2.3'
    path.write_text(json.dumps(data))
    return root, path, release


class Pages:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def get_json(self, url, **kwargs):
        self.calls.append(url)
        assert '/releases?per_page=100&page=' in url
        return self.pages[int(url.rsplit('=', 1)[1])]


def test_prefixed_stream_filters_other_releases_and_paginates(pins):
    root, path, release = stream_pins(pins)
    action = prefixed_release(release, 'v99.0.0')
    draft = prefixed_release(release, 'engine-v9.0.0')
    draft['draft'] = True
    prerelease = prefixed_release(release, 'engine-v8.0.0')
    prerelease['prerelease'] = True
    http = Pages({1: [action] * 97 + [draft, prerelease, prefixed_release(release, 'engine-v1.9.0')],
                  2: [prefixed_release(release, 'engine-v1.10.0'),
                      prefixed_release(release, 'other-engine-v99.0.0'),
                      prefixed_release(release, 'engine-v2.0.0-rc1')]})
    report = run_bump(root, http=http, apply=True, policy=BumpPolicy())
    assert len(http.calls) == 2
    assert report.results[0].rewrite_result.applied
    tool = load_pins(path.read_text())['tools']['linter']
    assert tool['version'] == 'engine-v1.10.0'
    assert tool['release_tag_prefix'] == 'engine-v'
    assert tool['assets']['s390x']['sha256'] == '1' * 64


@pytest.mark.parametrize('target,thresholds', [
    ('engine-v2.0.0', Thresholds(block_on_major=True)),
    ('engine-v1.4.0', Thresholds(block_on_minor_skew=2)),
])
def test_prefixed_stream_still_obeys_version_policy(pins, target, thresholds):
    root, path, release = stream_pins(pins)
    before = path.read_text()
    report = run_bump(root, http=Pages({1: [prefixed_release(release, target)]}),
                      apply=True, policy=BumpPolicy(thresholds=thresholds))
    assert report.results[0].verdict_label == 'Block'
    assert path.read_text() == before


def test_prefix_scan_bound_refuses_partial_answer(pins):
    root, path, release = stream_pins(pins)
    before = path.read_text()
    http = Pages({page: [prefixed_release(release, 'engine-v1.3.0')] * 100 for page in range(1, 11)})
    report = run_bump(root, http=http, apply=True, policy=BumpPolicy())
    assert len(http.calls) == 10 and not report.candidates
    assert 'search bound' in report.skipped[0][2]
    assert path.read_text() == before


@pytest.mark.parametrize('releases', [[], [{'tag_name': 'v99.0.0', 'draft': False, 'prerelease': False}],
                                       {'not': 'a list'}])
def test_prefix_missing_or_invalid_listing_leaves_pins_unchanged(pins, releases):
    root, path, _ = stream_pins(pins)
    before = path.read_text()
    report = run_bump(root, http=Pages({1: releases}), apply=True, policy=BumpPolicy())
    assert not report.candidates and report.skipped
    assert path.read_text() == before


@pytest.mark.parametrize('prefix', ['', None, True, '../', 'unrelated-', 'engine-v\n'])
def test_invalid_or_mismatched_prefix_is_rejected(pins, prefix):
    root, path, release = stream_pins(pins)
    data = json.loads(path.read_text())
    data['tools']['linter']['release_tag_prefix'] = prefix
    text = json.dumps(data)
    path.write_text(text)
    http = Http(release)
    report = run_bump(root, http=http, apply=True, policy=BumpPolicy())
    assert not http.calls and not report.candidates
    assert path.read_text() == text


def test_release_stream_cannot_change_between_plan_and_apply(pins):
    root, path, release = stream_pins(pins)
    report = run_bump(root, http=Pages({1: [prefixed_release(release, 'engine-v1.3.0')]}), policy=BumpPolicy())
    cand = report.candidates[0]
    before = path.read_text()
    cand.extra['new_tool']['release_tag_prefix'] = 'engine-'
    result = rewrite(path, [RewriteEdit(cand.locator, cand.current_version, cand.target_version, cand.extra)])[0]
    assert not result.applied and path.read_text() == before
