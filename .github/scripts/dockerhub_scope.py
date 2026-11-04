"""Publish dependency images only when tracked image/build inputs change.

Parse COPY/ADD sources in each Git tree, rather than maintaining another list
of notice directories and helpers. Weekly and explicit builds refresh mutable
external inputs. Unknown Dockerfile syntax or missing history requests a build.
"""
from __future__ import annotations

import argparse
import hashlib
from http.client import HTTPException
import json
import os
import re
from pathlib import Path, PurePosixPath
import shlex
import subprocess
import sys
import urllib.parse
import urllib.request


DOCKERFILE = '.devcontainer/Dockerfile'
OPTIONAL_INPUTS = ['.dockerignore', '.devcontainer/Dockerfile.dockerignore']
BUILD_INPUTS = [DOCKERFILE, '.github/workflows/dockerhub-publish.yml',
                '.github/scripts/dockerhub_scope.py',
                '.github/scripts/prepare_sbom.py',
                '.github/scripts/check_playwright_source.py',
                '.github/scripts/check_node_release.py',
                '.github/actions/enable-userns']


def copy_sources(text: str) -> list[str]:
    sources = []
    logical = text.replace('\\\n', ' ')
    for line in logical.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        parts = line.strip().split(None, 1)
        instruction, body = parts[0], parts[1] if len(parts) > 1 else ''
        if instruction.upper() == 'RUN' and body.lstrip().startswith('--mount'):
            raise ValueError('unmodelled build context mount')
        if instruction.upper() not in {'COPY', 'ADD'}:
            continue
        # Docker supports only name=value flags on COPY/ADD.
        flags = []
        while body.lstrip().startswith('--'):
            flag, _, body = body.lstrip().partition(' ')
            flags.append(flag)
        if any(flag.startswith('--from=') for flag in flags):
            continue  # stage-local inputs are captured by that stage's COPYs
        if any('=' not in flag and flag != '--link' for flag in flags):
            raise ValueError('unknown COPY flag')
        args = json.loads(body) if body.lstrip().startswith('[') else shlex.split(body)
        if len(args) < 2:
            raise ValueError('unknown COPY syntax')
        for source in args[:-1]:
            path = PurePosixPath(source)
            if ('$' in source or path.is_absolute() or '..' in path.parts
                    or source.startswith(':') or '://' in source):
                raise ValueError('unresolved COPY input')
            sources.append(source)
    if not sources:
        raise ValueError('no local image inputs found')
    return sources


def attribute_inputs(sources: list[str]) -> list[str]:
    # Checkout attributes can change copied bytes even when Git blob IDs do
    # not change (for example eol and working-tree-encoding transformations).
    return sorted({(parent / '.gitattributes').as_posix()
                   for source in sources for parent in PurePosixPath(source).parents})


def fingerprint(repo: Path, ref: str) -> str:
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=repo, stderr=subprocess.DEVNULL, timeout=30)
    dockerfile = git('show', f'{ref}:{DOCKERFILE}').decode()
    inputs = sorted(set(BUILD_INPUTS + copy_sources(dockerfile)))
    digest = hashlib.sha256()
    for source in inputs:
        records = git('ls-tree', '-r', '-z', ref, '--', source)
        if not records:
            raise ValueError('missing image input: ' + source)
        digest.update(source.encode() + b'\0' + records)
    for source in sorted(set(OPTIONAL_INPUTS + attribute_inputs(inputs))):
        digest.update(source.encode() + b'\0' + git('ls-tree', '-r', '-z', ref, '--', source))
    return digest.hexdigest()


LABEL = 'io.raptor.ci.inputs'
IMAGE = 'danielcuthbert/raptor'


class RegistryRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).scheme != 'https':
            raise ValueError('registry redirect must use HTTPS')
        redirected = super().redirect_request(request, fp, code, msg, headers, newurl)
        if redirected and urllib.parse.urlparse(request.full_url).netloc != urllib.parse.urlparse(newurl).netloc:
            redirected.remove_header('Authorization')
        return redirected


def published_fingerprint() -> str | None:
    """Read the label from the actual latest image, without publishing credentials.

    A missing label, registry outage, rate limit or unknown manifest format
    requests a build. A failed previous build therefore cannot suppress retries.
    """
    opener = urllib.request.build_opener(RegistryRedirects())
    def read(url, headers=None):
        with opener.open(urllib.request.Request(url, headers=headers or {}), timeout=10) as response:
            data = response.read(8 * 1024 * 1024 + 1)
        if len(data) > 8 * 1024 * 1024:
            raise ValueError('registry response too large')
        return data
    try:
        token_url = 'https://auth.docker.io/token?' + urllib.parse.urlencode({
            'service': 'registry.docker.io', 'scope': 'repository:' + IMAGE + ':pull',
        })
        token = json.loads(read(token_url))['token']
        headers = {'Authorization': 'Bearer ' + token,
                   'Accept': 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'}
        registry = 'https://registry-1.docker.io/v2/' + IMAGE
        manifest = json.loads(read(registry + '/manifests/latest', headers))
        digest = manifest['config']['digest']
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            return None
        config = read(registry + '/blobs/' + digest, headers)
        if 'sha256:' + hashlib.sha256(config).hexdigest() != digest:
            return None
        label = json.loads(config).get('config', {}).get('Labels', {}).get(LABEL)
        return label if isinstance(label, str) and re.fullmatch(r'[0-9a-f]{64}', label) else None
    except (OSError, ValueError, KeyError, TypeError, AttributeError, HTTPException) as error:
        print(f'Published input comparison unavailable ({type(error).__name__}); rebuilding')
        return None


def should_build(repo: Path, event: str, published: str | None) -> bool:
    if event != 'push' or not published:
        return True  # release/manual/security refresh, or unknown published state
    try:
        return fingerprint(repo, 'HEAD') != published
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        return True


def matches_main(repo: Path, expected: str) -> bool:
    subprocess.run(['git', 'fetch', '--no-tags', '--depth=1', 'origin', 'refs/heads/main'],
                   cwd=repo, check=True, capture_output=True, timeout=30)
    if expected:
        try:
            return fingerprint(repo, 'FETCH_HEAD') == expected
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            pass
    # An unmodelled input can only be published from the exact main commit.
    def sha(ref):
        return subprocess.check_output(['git', 'rev-parse', ref], cwd=repo, timeout=10).strip()
    return sha('HEAD') == sha('FETCH_HEAD')


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-main', action='store_true')
    args = parser.parse_args(argv)
    if args.check_main:
        try:
            matches = matches_main(Path.cwd(), os.environ.get('IMAGE_INPUTS', ''))
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            print('Cannot verify current main before publication: ' + type(error).__name__, file=sys.stderr)
            raise SystemExit(2) from error
        if not matches:
            print('Image inputs were superseded on main; publication skipped')
            raise SystemExit(1)
        return
    event = os.environ.get('EVENT', '')
    published = published_fingerprint() if event == 'push' else None
    build = should_build(Path.cwd(), event, published)
    try:
        current = fingerprint(Path.cwd(), 'HEAD') if not os.environ.get('INPUT_TAG') else ''
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        current = ''
    if build and not os.environ.get('INPUT_TAG'):
        try:
            if not matches_main(Path.cwd(), current):
                build = False
                print('Image inputs superseded on main; a newer input build owns latest')
        except (OSError, ValueError, subprocess.SubprocessError):
            print('Main comparison unavailable; retaining build and rechecking before publication')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('build=' + str(build).lower() + '\n')
        output.write('fingerprint=' + current + '\n')
    print('Container image inputs changed or refresh requested' if build else 'Published image already has these inputs; publication skipped')


if __name__ == '__main__':
    main()
