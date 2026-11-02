"""Shared, bounded selection of package-local image notice candidates."""
from __future__ import annotations

import base64
import posixpath
from pathlib import PurePosixPath
import re
import unicodedata

NOTICE_NAME = re.compile(r"(?:licen[cs]e|copying|copyright|notice|authors)(?:[._-].*)?\Z", re.I)
METADATA_NAMES = frozenset({"package.json", "METADATA", "PKG-INFO", "pyproject.toml", "Cargo.toml", "pom.xml"})
SOURCE_SUFFIXES = frozenset({".py", ".pyc", ".js", ".ts", ".c", ".h", ".go", ".java", ".class", ".so", ".a", ".o", ".exe", ".dll", ".bin"})


def image_path(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError("image path must be absolute")
    normal = unicodedata.normalize("NFKC", value)
    if (normal != value or "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(p in {"", ".", ".."} for p in value[1:].split("/"))):
        raise ValueError("unsafe or ambiguous image path")
    return value


def notice_name(path: str) -> bool:
    name = PurePosixPath(path)
    return bool(NOTICE_NAME.fullmatch(name.name)) and name.suffix.lower() not in SOURCE_SUFFIXES


class PackageNoticePaths:
    """Select within distribution metadata or directly in an npm package.

    Wheel RECORD claims may add required files missing from Syft's file index.
    Paths never leave the package's own .dist-info/.egg-info directory. SHA-256
    and size claims are validated and later checked against recovered bytes.
    """

    def __init__(self, artifacts: list[dict]):
        self.directories: dict[tuple[str, str], dict[tuple[str, str], None]] = {}
        self.pointers: dict[tuple[str, str], set[str]] = {}
        self.records: dict[tuple[str, str], dict] = {}
        for artifact in artifacts:
            kind, identifier = artifact['type'], artifact['id']
            for location in artifact.get('locations', []):
                path = PurePosixPath(location['path'])
                python = (kind == 'python' and path.name in {'METADATA', 'PKG-INFO'}
                          and path.parent.name.endswith(('.dist-info', '.egg-info')))
                npm = kind == 'npm' and path.name == 'package.json'
                if not python and not npm:
                    continue
                image_path(location['path'])
                root, layer = image_path(str(path.parent)), location['layerID']
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", layer):
                    raise ValueError("invalid package notice layer")
                key = root, layer
                owner = kind, identifier
                owners = self.directories.setdefault(key, {})
                if owner in owners:
                    continue
                owners[owner] = None
                if npm:
                    for licence in artifact.get('licenses', []):
                        match = re.fullmatch(r'SEE LICEN[CS]E IN ([A-Za-z0-9][A-Za-z0-9._-]*)', licence.get('value', ''), re.I)
                        if match:
                            self.pointers.setdefault(key, set()).add(match[1])
                else:
                    self._records(artifact, path.parent, layer)

    def _records(self, artifact: dict, root: PurePosixPath, layer: str) -> None:
        for entry in (artifact.get('metadata') or {}).get('files', []):
            relative = re.sub(r'^(?:\./)+', '', entry['path'])
            # RECORD also lists scripts and package code outside the metadata
            # directory. They are outside this selection and are not inferred.
            dedicated = relative.startswith((root.name + '/licenses/', str(root) + '/licenses/'))
            if not notice_name(relative) and not dedicated:
                continue
            if relative.startswith(str(root) + '/'):
                path = image_path(relative)
            elif relative.startswith(root.name + '/'):
                path = image_path(str(root.parent).rstrip('/') + '/' + relative)
            else:
                continue
            digest = entry.get('digest')
            expected_sha = None
            if digest:
                if digest.get('algorithm', '').lower() != 'sha256':
                    raise ValueError('unsupported Python RECORD notice digest')
                value = digest['value']
                if not re.fullmatch(r'[A-Za-z0-9_-]{43}=?', value):
                    raise ValueError('invalid Python RECORD SHA-256')
                decoded = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
                if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b'=').decode() != value.rstrip('='):
                    raise ValueError('noncanonical Python RECORD SHA-256')
                expected_sha = decoded.hex()
            size = entry.get('size')
            if size == '':
                size = None
            if size is not None:
                if not isinstance(size, str) or not re.fullmatch(r'[0-9]{1,12}', size):
                    raise ValueError('invalid Python RECORD notice size')
                size = int(size)
            key = path, layer
            expected = {'sha256': expected_sha, 'size': size}
            previous = self.records.setdefault(key, {**expected, 'package_ids': set()})
            if any(previous[field] != expected[field] for field in expected):
                raise ValueError('conflicting Python RECORD notice claims')
            previous['package_ids'].add(artifact['id'])

    def matches(self, path: str, layer: str) -> list[tuple[str, str]]:
        """Return candidate associations without traversing unrelated packages."""
        original = path
        path = posixpath.normpath(path)
        parent, _, name = path.rpartition('/')
        matches = []
        is_notice = notice_name(path)
        for kind, identifier in self.directories.get((parent, layer), []):
            if kind == 'npm' and (is_notice or name in self.pointers.get((parent, layer), ())):
                matches.append((identifier, 'declared_notice_pointer' if name in self.pointers.get((parent, layer), ()) else 'npm_directory_notice_candidate'))
        for suffix in ('.dist-info/', '.egg-info/'):
            offset = path.rfind(suffix)
            if offset < 0:
                continue
            root = path[:offset + len(suffix) - 1]
            for kind, identifier in self.directories.get((root, layer), []):
                if kind == 'python' and (is_notice or path.startswith(root + '/licenses/')):
                    matches.append((identifier, 'python_distribution_notice_candidate'))
        if matches:
            image_path(original)
        return matches
