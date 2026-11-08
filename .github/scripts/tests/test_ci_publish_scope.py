"""Image publication follows actual Git inputs, including deletes and renames."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from core.testing.module_registry import module_registry_scope


from core.testing.module_bindings import patch_module_attribute


SCRIPTS = Path(__file__).resolve().parents[1]
with patch.object(sys, "path", sys.path.copy()), module_registry_scope('ci_change_scope', 'dockerhub_scope') as modules:
    modules.pop('ci_change_scope', None)
    modules.pop('dockerhub_scope', None)
    sys.path.insert(0, str(SCRIPTS))
    import ci_change_scope as changes
    import dockerhub_scope as image


@pytest.fixture(scope="module", autouse=True)
def _registered_helpers():
    with module_registry_scope('ci_change_scope', 'dockerhub_scope') as modules:
        modules['ci_change_scope'] = changes
        modules['dockerhub_scope'] = image
        yield


def git(repo, *args):
    return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', *args], cwd=repo, stderr=subprocess.DEVNULL).decode().strip()


def commit(repo):
    git(repo, 'add', '.')
    git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'test')
    return git(repo, 'rev-parse', 'HEAD')


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, 'init', '-q')
    for name in image.BUILD_INPUTS + [image.SCOPE_SCRIPT]:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if name != ".github/actions/enable-userns":
            path.write_text('input\n')
        else:
            path.mkdir()
            (path / 'action.yml').write_text('input\n')
    (tmp_path / '.devcontainer/helper.py').write_text('print(1)\n')
    (tmp_path / '.devcontainer/notices').mkdir()
    (tmp_path / '.devcontainer/notices/LICENSE').write_text('notice\n')
    (tmp_path / image.DOCKERFILE).write_text('FROM base\nCOPY .devcontainer/helper.py /helper\nCOPY .devcontainer/notices/ /notices/\nCOPY pyproject.toml uv.lock /tmp/\n')
    (tmp_path / 'pyproject.toml').write_text('[project]\n')
    (tmp_path / 'uv.lock').write_text('lock\n')
    commit(tmp_path)
    return tmp_path


@pytest.mark.parametrize('name,expected', [
    ('README.md', False), ('docs/installation.md', False),
    ('.github/published-image.json', False),
    ('.github/scripts/dockerhub_scope.py', False),
    ('.devcontainer/README.md', False), ('.devcontainer/test_helper.py', False),
    ('.github/scripts/report_sbom_licenses.py', False), ('core/oci/tests/test_ownership.py', False),
    ('.gitattributes', True), ('.devcontainer/.gitattributes', True),
    ('.dockerignore', True), ('.devcontainer/Dockerfile.dockerignore', True),
    ('.devcontainer/helper.py', True), ('.devcontainer/notices/LICENSE', True),
    ('.devcontainer/notices/NEW_NOTICE', True), ('pyproject.toml', True), ('uv.lock', True),
    ('.github/actions/enable-userns/action.yml', True),
    ('.github/scripts/prepare_sbom.py', True),
    ('.github/scripts/check_playwright_source.py', True),
    ('.github/scripts/check_node_release.py', True),
    ('.github/scripts/write_sbom_checksums.py', True),
    ('.github/scripts/check_uv_provenance.py', True),
    ('packages/sca/sbom_inventory/uv_provenance.py', True),
])
def test_image_inputs_not_audit_or_test_changes(repo, name, expected):
    base = git(repo, 'rev-parse', 'HEAD')
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('changed\n')
    commit(repo)
    assert image.should_build(repo, 'push', image.fingerprint(repo, base)) is expected


@pytest.mark.parametrize('operation', ['delete', 'rename', 'chmod'])
def test_removed_renamed_and_mode_changed_copy_inputs_build(repo, operation):
    base = image.fingerprint(repo, 'HEAD')
    path = repo / '.devcontainer/helper.py'
    if operation == 'delete':
        path.unlink()
    elif operation == 'rename':
        path.rename(path.with_name('renamed.py'))
    else:
        path.chmod(0o755)
    commit(repo)
    assert image.should_build(repo, 'push', base)


def test_selector_copied_into_image_is_still_an_image_input(repo):
    selector = repo / image.SCOPE_SCRIPT
    selector.write_text('selector version one\n')
    dockerfile = repo / image.DOCKERFILE
    dockerfile.write_text(dockerfile.read_text() + f'COPY {image.SCOPE_SCRIPT} /selector\n')
    commit(repo)
    published = image.fingerprint(repo, 'HEAD')
    selector.write_text('selector version two\n')
    commit(repo)
    assert image.should_build(repo, 'push', published)


def test_selector_comparison_errors_refuse_publication(repo, monkeypatch):
    git(repo, 'branch', '-M', 'main')
    git(repo, 'remote', 'add', 'origin', str(repo))
    monkeypatch.chdir(repo)
    monkeypatch.setenv('IMAGE_INPUTS', image.fingerprint(repo, 'HEAD'))
    real_run = image.subprocess.run

    def unavailable(command, *args, **kwargs):
        if command[:3] == ['git', 'diff', '--quiet']:
            raise subprocess.CalledProcessError(128, command)
        return real_run(command, *args, **kwargs)

    patch_module_attribute(monkeypatch, image, 'subprocess', 'run', unavailable)
    with pytest.raises(SystemExit) as error:
        image.main(['--check-main'])
    assert error.value.code == 2


def test_missing_selector_source_refuses_publication(repo, monkeypatch):
    (repo / image.SCOPE_SCRIPT).unlink()
    commit(repo)
    git(repo, 'branch', '-M', 'main')
    git(repo, 'remote', 'add', 'origin', str(repo))
    monkeypatch.chdir(repo)
    monkeypatch.setenv('IMAGE_INPUTS', image.fingerprint(repo, 'HEAD'))
    with pytest.raises(SystemExit) as error:
        image.main(['--check-main'])
    assert error.value.code == 2


def test_full_push_range_and_rename_keep_both_paths(repo):
    base = git(repo, 'rev-parse', 'HEAD')
    (repo / 'first.txt').write_text('one')
    commit(repo)
    (repo / '.devcontainer/helper.py').rename(repo / '.devcontainer/renamed.py')
    commit(repo)
    paths = changes.changed_paths(repo, base)
    assert {'first.txt', '.devcontainer/helper.py', '.devcontainer/renamed.py'} <= set(paths)


def test_nul_diff_preserves_newlines_in_paths(repo):
    base = git(repo, 'rev-parse', 'HEAD')
    (repo / 'line\nbreak.txt').write_text('one')
    commit(repo)
    assert changes.changed_paths(repo, base) == ['line\nbreak.txt']


@pytest.mark.parametrize('base', ['', '0' * 40, 'not-a-sha', '--help'])
def test_unknown_history_builds(repo, base):
    assert changes.changed_paths(repo, base) is None
    assert image.should_build(repo, 'push', base)


def test_missing_history_and_fetch_failure_build(repo, monkeypatch):
    def failed(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0])
    patch_module_attribute(monkeypatch, changes, 'subprocess', 'run', failed)
    assert changes.changed_paths(repo, 'f' * 40) is None
    assert image.should_build(repo, 'push', None)


def test_schedule_and_release_force_security_refresh(repo):
    base = image.fingerprint(repo, 'HEAD')
    assert not image.should_build(repo, 'push', base)
    assert image.should_build(repo, 'schedule', base)
    assert image.should_build(repo, 'workflow_dispatch', base)


@pytest.mark.parametrize('text,expected', [
    ('COPY --from=base /uv /uv\nCOPY --chown=0:0 a b /dest/', ['a', 'b']),
    ('COPY ["file with spaces", "/dest"]', ['file with spaces']),
    ('COPY\ta /dest', ['a']), ('COPY a \\\n b /dest', ['a', 'b']),
])
def test_copy_syntax(text, expected):
    assert image.copy_sources(text) == expected


@pytest.mark.parametrize('source', ['$VARIABLE', '../outside', '/absolute', 'https://example.invalid/source'])
def test_unresolved_sources_are_not_silently_omitted(source):
    with pytest.raises(ValueError):
        image.copy_sources(f'COPY {source} /dest')


def test_unresolved_dockerfile_forces_build(repo):
    (repo / image.DOCKERFILE).write_text('FROM base\nCOPY $VARIABLE /dest\n')
    base = commit(repo)
    assert image.should_build(repo, 'push', base)


def test_image_scope_cli_skips_identical_inputs(repo, monkeypatch):
    monkeypatch.chdir(repo)
    monkeypatch.setenv('EVENT', 'push')
    monkeypatch.setattr(image, 'published_fingerprint', lambda: image.fingerprint(repo, 'HEAD'))
    output = repo / 'output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(output))
    image.main([])
    assert output.read_text().startswith('build=false\nfingerprint=')


def test_failed_publish_is_retried_after_unrelated_push(repo):
    published = image.fingerprint(repo, 'HEAD')
    (repo / '.devcontainer/helper.py').write_text('updated image input')
    commit(repo)  # Imagine its publish failed.
    (repo / '.devcontainer/README.md').write_text('unrelated next commit')
    commit(repo)
    assert image.should_build(repo, 'push', published)
    assert not image.should_build(repo, 'push', image.fingerprint(repo, 'HEAD'))


@pytest.mark.parametrize('valid,labels', [(True, True), (True, False), (False, True)])
def test_registry_label_requires_verified_config_digest(monkeypatch, valid, labels):
    import hashlib
    import io
    import json
    config = json.dumps({'config': {'Labels': {image.LABEL: 'a' * 64} if labels else {}}}).encode()
    digest = 'sha256:' + (hashlib.sha256(config).hexdigest() if valid else '0' * 64)
    class Opener:
        def open(self, request, timeout):
            if request.full_url.startswith('https://auth.docker.io/'):
                return io.BytesIO(b'{"token":"public-read-only"}')
            assert request.get_header('Authorization') == 'Bearer public-read-only'
            if '/manifests/' in request.full_url:
                return io.BytesIO(json.dumps({'config': {'digest': digest}}).encode())
            return io.BytesIO(config)
    monkeypatch.setattr(image.urllib.request, 'build_opener', lambda *args: Opener())
    assert image.published_fingerprint() == ('a' * 64 if valid and labels else None)


def test_registry_failure_does_not_suppress_build(monkeypatch, repo):
    class Broken:
        def open(self, *args, **kwargs):
            raise image.HTTPException('truncated response')
    monkeypatch.setattr(image.urllib.request, 'build_opener', lambda *args: Broken())
    assert image.published_fingerprint() is None
    assert image.should_build(repo, 'push', image.published_fingerprint())


def test_registry_redirect_does_not_forward_auth_to_cdn():
    request = image.urllib.request.Request('https://registry-1.docker.io/blob', headers={'Authorization': 'Bearer read-only'})
    redirected = image.RegistryRedirects().redirect_request(request, None, 302, 'Moved', {}, 'https://cdn.example.invalid/blob')
    assert redirected.get_header('Authorization') is None
    with pytest.raises(ValueError):
        image.RegistryRedirects().redirect_request(request, None, 302, 'Moved', {}, 'http://cdn.example.invalid/blob')


def test_every_actual_image_input_can_wake_the_publish_workflow():
    """A future COPY outside .devcontainer must also extend the event filter."""
    import ast
    import re
    root = SCRIPTS.parents[1]
    workflow = (root / '.github/workflows/dockerhub-publish.yml').read_text()
    patterns = [ast.literal_eval(value) for value in re.findall(r"^      - ('[^']*')$", workflow, re.MULTILINE)]
    sources = image.BUILD_INPUTS + image.OPTIONAL_INPUTS + image.copy_sources((root / image.DOCKERFILE).read_text())
    sources += image.attribute_inputs(sources)
    def covered(source):
        source = source.rstrip('/')
        return any(source == p or p == '**/.gitattributes' and source.endswith('/.gitattributes') or p.endswith('/**') and
                   (source == p[:-3] or source.startswith(p[:-3] + '/')) for p in patterns)
    assert all(covered(source) for source in sources), [source for source in sources if not covered(source)]
    assert covered(image.SCOPE_SCRIPT)  # selector changes must still wake the scope job
    assert 'schedule:' in workflow  # mutable external image/package inputs need refreshing


@pytest.mark.parametrize('change,expected', [('README.md', True), ('.devcontainer/helper.py', False),
                                                     ('.github/scripts/dockerhub_scope.py', False)])
def test_main_movement_only_supersedes_changed_image_inputs(repo, change, expected):
    built_sha = git(repo, 'rev-parse', 'HEAD')
    built_inputs = image.fingerprint(repo, 'HEAD')
    git(repo, 'branch', '-M', 'work')
    (repo / change).write_text('new main content')
    newer = commit(repo)
    git(repo, 'update-ref', 'refs/heads/main', newer)
    git(repo, 'checkout', '-q', '--detach', built_sha)
    git(repo, 'remote', 'add', 'origin', str(repo))
    assert image.matches_main(repo, built_inputs) is expected
    assert not image.matches_main(repo, '')  # no fingerprint needs the exact commit


def test_publication_cannot_continue_when_main_cannot_be_verified(repo, monkeypatch):
    monkeypatch.chdir(repo)
    monkeypatch.setenv('IMAGE_INPUTS', image.fingerprint(repo, 'HEAD'))
    with pytest.raises(SystemExit) as error:
        image.main(['--check-main'])
    assert error.value.code == 2


@pytest.mark.parametrize('status,expected', [(1, 0), (2, 2)])
def test_workflow_does_not_publish_on_supersession_or_failed_main_lookup(tmp_path, status, expected):
    import os
    import textwrap
    root = SCRIPTS.parents[1]
    workflow = (root / '.github/workflows/dockerhub-publish.yml').read_text()
    step = workflow.split('      - name: Publish verified image\n', 1)[1]
    script = textwrap.dedent(step.split('        run: |\n', 1)[1])
    python = tmp_path / 'python3'
    python.write_text(f'#!/bin/sh\nexit {status}\n')
    python.chmod(0o755)
    skopeo = tmp_path / 'skopeo'
    skopeo.write_text('#!/bin/sh\ntouch "$PUBLISH_MARKER"\n')
    skopeo.chmod(0o755)
    marker = tmp_path / 'published'
    result = subprocess.run(['bash', '-c', script], env=dict(os.environ,
        PATH=str(tmp_path) + os.pathsep + os.defpath, INPUT_TAG='', IMAGE_INPUTS='a' * 64,
        TAGS='image:latest', PUBLISH_MARKER=str(marker)), capture_output=True, text=True)
    assert result.returncode == expected, result.stdout + result.stderr
    assert not marker.exists()


def _reference_fingerprint(repo, ref='HEAD'):
    """Original per-path Git protocol: published fingerprint compatibility."""
    import hashlib

    def tree(*args):
        return subprocess.check_output(['git', *args], cwd=repo, stderr=subprocess.DEVNULL)
    dockerfile = tree('show', f'{ref}:{image.DOCKERFILE}').decode()
    required = sorted(set(image.BUILD_INPUTS + image.copy_sources(dockerfile)))
    optional = sorted(set(image.OPTIONAL_INPUTS + image.attribute_inputs(required)))
    digest = hashlib.sha256()
    for source in required + optional:
        records = tree('ls-tree', '-r', '-z', ref, '--', source)
        if source in required and not records:
            raise ValueError('missing image input: ' + source)
        digest.update(source.encode() + b'\0' + records)
    return digest.hexdigest()


def _record_fingerprint_git(monkeypatch):
    from types import SimpleNamespace

    calls = []
    def execute(command, **kwargs):
        calls.append(command)
        return subprocess.check_output(command, **kwargs)
    monkeypatch.setattr(image, 'subprocess', SimpleNamespace(
        check_output=execute, DEVNULL=subprocess.DEVNULL, SubprocessError=subprocess.SubprocessError))
    return calls


@pytest.mark.parametrize('shape', [
    'ordinary', 'overlap', 'unusual-names', 'executable', 'symlink', 'gitlink', 'gitlink-trailing',
    'root-copy', 'noncanonical', 'backslash', 'colon',
])
def test_fingerprint_matches_original_git_protocol(repo, monkeypatch, shape):
    import json

    sources = []
    if shape == 'overlap':
        sources = ['.devcontainer/', '.devcontainer/notices/LICENSE']
        (repo / '.devcontainer/notices-extra').write_text('prefix collision\n')
    elif shape == 'unusual-names':
        sources = ['.devcontainer/space name', '.devcontainer/café',
                   '.devcontainer/tab\tname', '.devcontainer/line\nname']
        for source in sources:
            (repo / source).write_text('owned input\n')
    elif shape == 'executable':
        (repo / '.devcontainer/helper.py').chmod(0o755)
    elif shape == 'symlink':
        sources = ['.devcontainer/link']
        (repo / sources[0]).symlink_to('notices/LICENSE')
    elif shape in {'gitlink', 'gitlink-trailing'}:
        sources = ['.devcontainer/vendor' + ('/' if shape == 'gitlink-trailing' else '')]
    elif shape == 'root-copy':
        sources = ['.']
    elif shape == 'noncanonical':
        sources = ['./.devcontainer/helper.py']
    elif shape in {'backslash', 'colon'}:
        sources = ['.devcontainer/back\\slash' if shape == 'backslash' else '.devcontainer/license:notice']
        (repo / sources[0]).write_text('owned input\n')
    dockerfile = repo / image.DOCKERFILE
    if sources:
        dockerfile.write_text(dockerfile.read_text() + 'COPY ' + json.dumps([*sources, '/extra/']) + '\n')
    # Present and absent optional attributes must both match the old protocol.
    (repo / '.gitattributes').write_text('*.py text eol=lf\n')
    git(repo, 'add', '-A')
    if shape in {'gitlink', 'gitlink-trailing'}:
        target = git(repo, 'rev-parse', 'HEAD')
        git(repo, 'update-index', '--add', '--cacheinfo', f'160000,{target},.devcontainer/vendor')
    git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'input shape')
    expected = _reference_fingerprint(repo)
    calls = _record_fingerprint_git(monkeypatch)
    assert image.fingerprint(repo, 'HEAD') == expected
    if shape in {'ordinary', 'overlap', 'unusual-names', 'executable', 'symlink', 'gitlink', 'gitlink-trailing'}:
        assert len(calls) == 2
        assert sum(command[1] == 'ls-tree' for command in calls) == 1
    else:
        assert len(calls) > 2  # Ambiguous paths retain Git's own selection.


@pytest.mark.parametrize('source', ['.devcontainer/helper.py/', '.devcontainer/missing', '.devcontainer/*'])
def test_missing_or_unmodelled_input_still_refuses_fingerprint(repo, source):
    import json

    dockerfile = repo / image.DOCKERFILE
    dockerfile.write_text(dockerfile.read_text() + 'COPY ' + json.dumps([source, '/extra/']) + '\n')
    commit(repo)
    with pytest.raises(ValueError, match='missing image input'):
        image.fingerprint(repo, 'HEAD')
    assert image.should_build(repo, 'push', 'a' * 64)


def test_large_pathspec_list_keeps_bounded_git_commands(repo, monkeypatch):
    import json

    sources = [f'not-present-{i:04d}-' + 'x' * 40 for i in range(700)]
    dockerfile = repo / image.DOCKERFILE
    dockerfile.write_text(dockerfile.read_text() + 'COPY ' + json.dumps([*sources, '/extra/']) + '\n')
    commit(repo)
    calls = _record_fingerprint_git(monkeypatch)
    with pytest.raises(ValueError, match='missing image input'):
        image.fingerprint(repo, 'HEAD')
    assert all(len(command) == 7 for command in calls if command[1] == 'ls-tree')


def test_case_insensitive_pathspec_setting_retains_git_selection(repo, monkeypatch):
    # The Git tree can contain case-distinct paths even when the host cannot.
    blob = git(repo, 'hash-object', '-w', '.devcontainer/helper.py')
    git(repo, '-c', 'core.ignorecase=false', 'update-index', '--add', '--cacheinfo',
        f'100644,{blob},.DEVCONTAINER/helper.py')
    git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
        'commit', '-qm', 'case-distinct indexed input')
    monkeypatch.setenv('GIT_ICASE_PATHSPECS', '1')
    calls = _record_fingerprint_git(monkeypatch)
    # ls-tree currently rejects icase magic. If Git gains support, compare
    # its actual selections rather than freezing that version limitation.
    try:
        expected = _reference_fingerprint(repo)
    except subprocess.CalledProcessError as error:
        with pytest.raises(subprocess.CalledProcessError) as actual:
            image.fingerprint(repo, 'HEAD')
        assert actual.value.returncode == error.returncode
        assert image.should_build(repo, 'push', 'a' * 64)
    else:
        assert image.fingerprint(repo, 'HEAD') == expected
    assert all(len(command) == 7 for command in calls if command[1] == 'ls-tree')
