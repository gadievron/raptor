"""Resolve all required assets of a declarative GitHub tool release together."""
from copy import deepcopy

from core.upstream_latest._version_filter import parse_stable
from ..parsers.github_release_pins import validate_tool, version_suffix


def latest_tool_release(tool, *, http, cache=None, github_token=None):
    """Select a stable release, refusing to guess from a truncated listing.

    Repositories can interleave independent release streams, and publication
    order is not numeric version order. Prefix selection scans up to 1,000
    releases and compares numeric suffixes; a full final page fails closed.
    """
    from core.upstream_latest.github_releases import _fetch_cached_json, UpstreamLookupError

    base = f"https://api.github.com/repos/{tool['repository']}/releases"

    def fetch(url):
        return _fetch_cached_json(url, http=http, cache=cache,
                                  ttl_seconds=24 * 3600, github_token=github_token)

    if 'release_tag_prefix' not in tool:
        return fetch(base + '/latest')
    selected = None
    highest = None
    for page in range(1, 11):
        releases = fetch(f'{base}?per_page=100&page={page}')
        if not isinstance(releases, list) or len(releases) > 100:
            raise UpstreamLookupError('release listing is not a page of at most 100 releases')
        for release in releases:
            if not isinstance(release, dict):
                raise UpstreamLookupError('release listing contains a non-object')
            if release.get('draft') is not False or release.get('prerelease') is not False:
                continue
            suffix = version_suffix(tool, release.get('tag_name'))
            if suffix is None:
                continue
            version = parse_stable(suffix)
            if highest is None or version > highest:
                selected, highest = release, version
            elif version == highest and release.get('tag_name') != selected.get('tag_name'):
                raise UpstreamLookupError('release stream has ambiguous equal-version tags')
        if len(releases) < 100:
            if selected is None:
                raise UpstreamLookupError('no stable releases match release_tag_prefix')
            return selected
    raise UpstreamLookupError('release listing exceeds the 1,000-release search bound; latest is unknown')


def release_tool(current, release):
    if (not isinstance(release, dict) or release.get('draft') is not False
            or release.get('prerelease') is not False):
        raise ValueError('release must be stable and published')
    tag = release.get('tag_name')
    if version_suffix(current, tag) is None:
        raise ValueError('release tag must be stable semver')
    raw_assets = release.get('assets')
    if not isinstance(raw_assets, list):
        raise ValueError('release has no asset list')
    proposed = deepcopy(current)
    proposed['version'] = tag
    for asset in proposed['assets'].values():
        name = asset['name']
        matches = [a for a in raw_assets if isinstance(a, dict) and a.get('name') == name]
        if len(matches) != 1:
            raise ValueError(f'release requires exactly one {name}')
        upstream = matches[0]
        url = f"https://github.com/{current['repository']}/releases/download/{tag}/{name}"
        digest = upstream.get('digest')
        if (upstream.get('state') != 'uploaded' or upstream.get('browser_download_url') != url
                or not isinstance(digest, str) or not digest.startswith('sha256:')):
            raise ValueError(f'asset has no usable uploaded SHA-256 pin: {name}')
        asset.update(sha256=digest.removeprefix('sha256:'), size=upstream.get('size'))
    validate_tool(proposed)
    return proposed
