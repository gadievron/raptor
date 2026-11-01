"""Declarative GitHub release assets, for any project's downloaded tools.

``github-release-pins.json`` schema v1 maps tool IDs to repository, exact
release tag, and named asset records (name, sha256, size). The IDs and asset
labels are operator-chosen; this module has no application-specific mappings.
"""
from __future__ import annotations

import json
import logging
import re

from . import _safe_read, register
from ..models import Confidence, Dependency, PinStyle

FILENAME = 'github-release-pins.json'
logger = logging.getLogger(__name__)
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}')
_REPO = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
_SHA = re.compile(r'[0-9a-f]{64}')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate release pin key: {key}')
        result[key] = value
    return result


def validate_tool(tool):
    required = {'repository', 'version', 'assets'}
    if (not isinstance(tool, dict) or not required <= set(tool)
            or set(tool) - required - {'release_tag_prefix'}):
        raise ValueError('release pin requires repository, version, and assets')
    repo, version, assets = tool['repository'], tool['version'], tool['assets']
    if (not isinstance(repo, str) or len(repo) > 256 or not _REPO.fullmatch(repo)
            or any(set(part) == {'.'} for part in repo.split('/'))):
        raise ValueError('release pin repository must be owner/name')
    if not isinstance(version, str) or not _ID.fullmatch(version):
        raise ValueError('release pin version must be an exact tag')
    if 'release_tag_prefix' in tool:
        prefix = tool['release_tag_prefix']
        if (not isinstance(prefix, str) or not _ID.fullmatch(prefix)
                or version_suffix(tool, version) is None):
            raise ValueError('release_tag_prefix must match the pinned stable version tag')
    if not isinstance(assets, dict) or not 1 <= len(assets) <= 128:
        raise ValueError('release pin requires between 1 and 128 assets')
    names = set()
    for label, asset in assets.items():
        if not isinstance(label, str) or not _ID.fullmatch(label):
            raise ValueError('invalid release asset label')
        if not isinstance(asset, dict) or set(asset) != {'name', 'sha256', 'size'}:
            raise ValueError('release asset requires name, sha256, and size')
        name, digest, size = asset['name'], asset['sha256'], asset['size']
        if (not isinstance(name, str) or not _ID.fullmatch(name) or name in names
                or not isinstance(digest, str) or not _SHA.fullmatch(digest)
                or type(size) is not int or not 0 < size < 2**63):
            raise ValueError('invalid release asset name, SHA-256, or size')
        names.add(name)


def version_suffix(tool, tag):
    """Stable numeric suffix of a tag in this tool's literal release stream."""
    from core.upstream_latest._version_filter import parse_stable

    prefix = tool.get('release_tag_prefix', '')
    if not isinstance(tag, str) or not tag.startswith(prefix):
        return None
    suffix = tag[len(prefix):]
    return suffix if parse_stable(suffix) is not None else None


def load_pins(text):
    data = json.loads(text, object_pairs_hook=_unique)
    if (not isinstance(data, dict) or set(data) != {'schema_version', 'tools'}
            or type(data['schema_version']) is not int or data['schema_version'] != 1
            or not isinstance(data['tools'], dict) or not 1 <= len(data['tools']) <= 128):
        raise ValueError('expected release pin schema_version 1 and tools map')
    for name, tool in data['tools'].items():
        if not isinstance(name, str) or not _ID.fullmatch(name):
            raise ValueError('invalid release tool ID')
        validate_tool(tool)
    return data


@register(filenames=[FILENAME])
def parse(path):
    text = _safe_read.read_bounded(path, follow_symlinks=False)
    if text is None:
        return []
    try:
        data = load_pins(text)
    except (ValueError, RecursionError) as exc:
        logger.warning('sca.parsers.github_release_pins: JSON parse failed for %s: %s', path, exc)
        return []
    return [Dependency(
        ecosystem='GitHub', name=tool['repository'], version=tool['version'],
        declared_in=path, scope='optional', is_lockfile=True,
        pin_style=PinStyle.EXACT, direct=True,
        purl=f"pkg:github/{tool['repository']}@{tool['version']}",
        parser_confidence=Confidence('high', reason='Exact release tag and asset SHA-256 pins'),
        source_kind='github_release_pin', source_extra={'tool_id': name, 'assets': tool['assets']},
    ) for name, tool in data['tools'].items()]
