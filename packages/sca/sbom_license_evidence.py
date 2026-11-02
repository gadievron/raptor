"""Recover explicit publisher declarations from verified Python metadata.

Exact SPDX expressions and unambiguous Trove classifiers are translated.
Reviewed complete notice fingerprints cover legacy metadata without guessing
BSD variants or choice operators. No enclosing-package licence is inherited.
"""
from __future__ import annotations

from email.message import Message
from email.parser import BytesParser
from functools import lru_cache
import hashlib
from pathlib import Path, PurePosixPath
import re

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression

from core.json import loads
from core.source import read_text_gated

# The names themselves identify these licences; generic family classifiers do not.
_TROVE = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
}
_UNKNOWN = re.compile(r"(?:^|[ (])(?:LicenseRef-)?(?:UNKNOWN|NOASSERTION|NONE|UNLICENSED)(?:$|[ )])", re.I)


def catalogue_declaration_missing(artifact: dict) -> bool:
    licences = artifact.get("licenses", [])
    if not isinstance(licences, list) or not licences:
        return True
    for licence in licences:
        if not isinstance(licence, dict):
            return True
        value = licence.get("spdxExpression") or licence.get("value")
        if not isinstance(value, str) or not value.strip() or _UNKNOWN.search(value):
            return True
    return False


def _metadata_context(artifact: dict, files: list[dict], blobs: dict[str, bytes]) -> tuple[dict, Message] | None:
    if artifact.get("type") != "python" or not catalogue_declaration_missing(artifact):
        return None
    if not isinstance(artifact.get("licenses", []), list):
        return None
    for licence in artifact.get("licenses", []):
        if not isinstance(licence, dict):
            return None
        value = licence.get("spdxExpression") or licence.get("value")
        if isinstance(value, str) and value.strip() and not _UNKNOWN.search(value):
            return None  # A known claim plus an unknown claim needs review, not replacement.
    locations = {(loc["path"], loc["layerID"]) for loc in artifact.get("locations", [])
                 if PurePosixPath(loc["path"]).name in {"METADATA", "PKG-INFO"}
                 and PurePosixPath(loc["path"]).parent.name.endswith((".dist-info", ".egg-info"))}
    candidates = [row for row in files if row.get("content_kind") == "package_metadata"
                  and (row["path"], row["catalogue_layer_diff_id"]) in locations]
    if len(candidates) != 1:
        return None
    row = candidates[0]
    data = blobs.get(row["sha256"])
    if data is None or len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != row["sha256"]:
        return None
    metadata = BytesParser().parsebytes(data)
    names, versions = metadata.get_all("Name", []), metadata.get_all("Version", [])
    normalize = lambda value: re.sub(r"[-_.]+", "-", value).lower()
    if (len(names) != 1 or len(versions) != 1 or normalize(names[0].strip()) != normalize(artifact["name"])
            or versions[0].strip() != artifact["version"]):
        return None
    return row, metadata


def declaration_from_metadata(artifact: dict, files: list[dict], blobs: dict[str, bytes]) -> dict | None:
    context = _metadata_context(artifact, files, blobs)
    if context is None:
        return None
    row, metadata = context
    expressions, legacy = metadata.get_all("License-Expression", []), metadata.get_all("License", [])
    if len(expressions) > 1 or len(legacy) > 1 or expressions and legacy:
        return None
    field = "License-Expression" if expressions else "License"
    value = (expressions or legacy or [""])[0].strip()
    if expressions or value and value.upper() not in {"UNKNOWN", "NOASSERTION"}:
        try:
            expression = canonicalize_license_expression(value)
        except InvalidLicenseExpression:
            return None
        if "LicenseRef-" in expression:
            return None
        publisher_values = [value]
    else:
        classifiers = [value.strip() for value in metadata.get_all("Classifier", []) if value.startswith("License :: ")]
        if not classifiers or any(value not in _TROVE for value in classifiers):
            return None
        identifiers = {_TROVE[value] for value in classifiers}
        if len(identifiers) != 1:
            return None
        expression = identifiers.pop()
        field, publisher_values = "Classifier", sorted(set(classifiers))
    return {"expression": expression, "basis": "installed_distribution_metadata", "metadata_field": field, "publisher_values": publisher_values,
            "metadata_path": row["path"], "metadata_sha256": row["sha256"],
            "catalogue_layer_diff_id": row["catalogue_layer_diff_id"], "layer_blob_digest": row["layer_blob_digest"],
            "original_catalogue_licenses": artifact.get("licenses", []),
            "scope": "Explicit installed-distribution declaration recovered from verified metadata; no licence conclusion or build-source certification."}


@lru_cache(maxsize=1)
def _reviewed_rules() -> dict:
    path = Path(__file__).with_name('data') / 'license_identifications.json'
    data = loads(read_text_gated(path, 256 * 1024, follow_symlinks=False))
    if not isinstance(data, dict):
        raise ValueError("missing or invalid licence identification corpus")
    if type(data.get('schema_version')) is not int or data['schema_version'] != 1:
        raise ValueError('unsupported licence identification corpus')
    for name, rule in data['packages'].items():
        if not name or canonicalize_license_expression(rule['expression']) != rule['expression'] or 'LicenseRef-' in rule['expression']:
            raise ValueError('invalid reviewed licence expression')
        if not rule['notices'] or any(not re.fullmatch(r'[0-9a-f]{64}', sha) for sha in rule['notices'].values()):
            raise ValueError('invalid reviewed licence notice fingerprints')
    return data['packages']


def _reviewed_notice_declaration(artifact: dict, files: list[dict], blobs: dict[str, bytes]) -> dict | None:
    context = _metadata_context(artifact, files, blobs)
    if context is None:
        return None
    row, _ = context
    name = re.sub(r'[-_.]+', '-', artifact['name']).lower()
    rule = _reviewed_rules().get(name)
    if rule is None:
        return None
    root = PurePosixPath(row['path']).parent
    observed = {}
    evidence = []
    for notice in files:
        if notice.get('content_kind') != 'notice_candidate':
            continue
        if notice['catalogue_layer_diff_id'] != row['catalogue_layer_diff_id']:
            return None
        try:
            parts = PurePosixPath(notice['path']).relative_to(root).parts
        except ValueError:
            return None
        if parts and parts[0].lower() == 'licenses':
            parts = parts[1:]
        if not parts:
            return None
        key = '/'.join(parts).upper()
        for suffix in ('.TXT', '.MD', '.RST'):
            if key.endswith(suffix):
                key = key[:-len(suffix)]
                break
        data = blobs.get(notice['sha256'])
        if key in observed or data is None or hashlib.sha256(data).hexdigest() != notice['sha256']:
            return None
        observed[key] = notice['sha256']
        evidence.append({field: notice[field] for field in ('path', 'sha256', 'catalogue_layer_diff_id', 'layer_blob_digest')})
    if observed != rule['notices']:
        return None
    return {'expression': rule['expression'], 'basis': 'reviewed_distribution_notices',
            'metadata_path': row['path'], 'metadata_sha256': row['sha256'],
            'notice_files': evidence, 'original_catalogue_licenses': artifact.get('licenses', []),
            'scope': 'Exact complete texts of this distribution match reviewed licence evidence; no enclosing licence or build-source conclusion is inferred.'}


def recover_distribution_license(artifact: dict, files: list[dict], blobs: dict[str, bytes]) -> dict | None:
    metadata = declaration_from_metadata(artifact, files, blobs)
    reviewed = _reviewed_notice_declaration(artifact, files, blobs)
    if metadata is not None:
        if reviewed is not None and metadata['expression'] != reviewed['expression']:
            return None
        return metadata
    if reviewed is None:
        return None
    context = _metadata_context(artifact, files, blobs)
    _, headers = context
    values = headers.get_all('License-Expression', []) + headers.get_all('License', [])
    if len(headers.get_all('License-Expression', [])) > 1 or len(headers.get_all('License', [])) > 1:
        return None
    if any(value.strip().upper() not in {'', 'UNKNOWN', 'NOASSERTION', 'LICENSEREF-UNKNOWN'} for value in values):
        return None
    # Do not discard a specific conflicting classifier while using a legacy text.
    identifiers = set(re.findall(r'[A-Za-z0-9.+-]+', reviewed['expression']))
    for value in headers.get_all('Classifier', []):
        if value in _TROVE and _TROVE[value] not in identifiers:
            return None
    return reviewed
