"""Enclosing distro-package notice context, scoped to checksum-matched files.

Inventory checksums (including MD5) support correspondence to an unsigned file
inventory. They do not attest ownership, establish component-specific licence
coverage, or justify inheriting the enclosing package's licence declaration.
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
import hashlib
import re

from core.oci.notice_paths import image_path

_MATCHED = frozenset({'captured_bytes_match_inventory_checksum', 'verified_image_bytes_match_inventory_checksum'})

_LENGTHS = {'md5': 32, 'sha1': 40, 'sha256': 64, 'sha512': 128}


def add_owner_context(native: dict, rows: list[dict], blobs: dict[str, bytes],
                      records: list[dict], *, limit: int, verified_files: dict | None = None, max_chars: int = 8 * 1024 * 1024) -> dict:
    """Add context to fresh association records, retaining their own statuses/gaps.

    Call after capture validation. Read no files, follow no aliases, and use only
    the exact captured path/layer pair. Ambiguous or conflicting inventories and
    unavailable bytes remain leads without automatic parent-notice links.
    """
    verified_files = verified_files or {}
    artifacts = {a['id']: a for a in native['artifacts']}
    by_id = {r['id']: r for r in records}
    captured = {(r['path'], r['catalogue_layer_diff_id']): r for r in rows}
    targets = {}
    target_paths = set()
    count = 0
    text_count = 0

    def charge(amount=1, payload=None):
        nonlocal count, text_count
        count += amount
        if count > limit:
            raise ValueError('owner notice context exceeds association budget')
        stack = [payload]
        while stack:
            value = stack.pop()
            if isinstance(value, str):
                text_count += len(value)
            elif isinstance(value, dict):
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
            if text_count > max_chars:
                raise ValueError('owner notice context exceeds text budget')

    for record in records:
        artifact = artifacts[record['id']]
        if artifact['type'] == 'deb' or record['status'] == 'notice_candidate_captured':
            continue
        locations = artifact.get('locations', [])
        primary = [loc for loc in locations if (loc.get('annotations') or {}).get('evidence') == 'primary']
        if not primary:
            primary = [loc for loc in locations if 'evidence' not in (loc.get('annotations') or {})]
        keys = {(image_path(loc['path']), loc.get('layerID')) for loc in primary}
        charge(len(keys))
        targets[record['id']] = sorted(keys, key=lambda k: (k[0], k[1] or ''))
        target_paths.update(path for path, _ in keys)
    inventories = defaultdict(dict)
    for artifact in native['artifacts']:
        if artifact['type'] != 'deb':
            continue
        for entry in (artifact.get('metadata') or {}).get('files', []):
            path = entry.get('path')
            if not isinstance(path, str) or path not in target_paths:
                continue
            raw_digest = entry.get('digest')
            malformed = raw_digest is not None and not isinstance(raw_digest, dict)
            digest = raw_digest if isinstance(raw_digest, dict) else {}
            algorithm, value = digest.get('algorithm'), digest.get('value')
            claim = {'algorithm': algorithm.lower() if isinstance(algorithm, str) else '',
                     'value': value.lower() if isinstance(value, str) else ''}
            existing = inventories[path].get(artifact['id'])
            if existing is None:
                charge(payload=claim)
                inventories[path][artifact['id']] = {'digest': claim, 'conflicting': False, 'malformed': malformed}
            elif existing['digest'] != claim or existing['malformed'] != malformed:
                existing['conflicting'] = True
    checksum_cache = {}
    statistics = {'packages_with_checksum_matched_notice_context': 0,
                  'packages_with_unresolved_owner_leads': 0, 'ambiguous_locations': 0}
    for identifier, locations in targets.items():
        linked, unresolved = {}, []
        for path, origin in locations:
            owners = inventories.get(path, {})
            if not owners:
                continue
            charge(0, payload=[path, origin])
            row = captured.get((path, origin))
            data = blobs[row['sha256']] if row and 'notice_file' in row else None
            match_status = 'captured_bytes_match_inventory_checksum'
            if data is None and (path, origin) in verified_files:
                row, data = verified_files[(path, origin)]
                match_status = 'verified_image_bytes_match_inventory_checksum'
            if data is not None:
                charge(0, payload=row['sha256'])
            candidates, matched = [], []
            for owner_id, inventory in sorted(owners.items()):
                charge()
                owner = artifacts[owner_id]
                digest = inventory['digest']
                algorithm, expected = digest['algorithm'], digest['value']
                if inventory['malformed']:
                    status = 'invalid_inventory_checksum'
                elif inventory['conflicting']:
                    status = 'conflicting_inventory_claims'
                elif not algorithm and not expected:
                    status = 'inventory_checksum_unavailable'
                elif algorithm not in _LENGTHS:
                    status = 'unsupported_inventory_checksum'
                elif not re.fullmatch(r'[0-9a-f]{' + str(_LENGTHS[algorithm]) + r'}', expected):
                    status = 'invalid_inventory_checksum'
                elif data is None:
                    status = 'captured_bytes_unavailable'
                else:
                    cache_key = row['sha256'], algorithm
                    if cache_key not in checksum_cache:
                        # Dpkg MD5/SHA1 values are inventory diagnostics, never
                        # cryptographic authentication or a licence conclusion.
                        checksum_cache[cache_key] = hashlib.new(algorithm, data, usedforsecurity=False).hexdigest()
                    status = (match_status if checksum_cache[cache_key] == expected
                              else 'inventory_checksum_mismatch')
                candidate = {'owner_package_id': owner_id, 'owner_name': owner['name'],
                             'owner_version': owner.get('version', ''), 'inventory_digest': deepcopy(digest),
                             'verification': status}
                charge(0, payload=candidate)
                candidates.append(candidate)
                if status in _MATCHED:
                    matched.append(candidate)
            uncertain = any(c['verification'] not in (_MATCHED | {'inventory_checksum_mismatch'})
                            for c in candidates)
            ambiguous = len(matched) > 1 or bool(matched and uncertain)
            if len(matched) == 1 and not ambiguous:
                match = matched[0]
                owner_id = match['owner_package_id']
                notices = [f for f in by_id[owner_id]['files'] if f['content_kind'] == 'notice_candidate']
                if notices:
                    context = linked.get(owner_id)
                    if context is None:
                        charge(len(notices), payload=notices)
                        charge(0, payload=by_id[owner_id]['gaps'])
                        context = linked[owner_id] = {k: match[k] for k in ('owner_package_id', 'owner_name', 'owner_version')}
                        context.update(files=deepcopy(notices), matched_locations=[],
                                       owner_notice_gaps=deepcopy(by_id[owner_id]['gaps']),
                                       scope='enclosing_distro_package_notice_context; component_coverage_unreviewed')
                    charge(0, payload=candidates)
                    context['matched_locations'].append({'path': path, 'catalogue_layer_diff_id': origin,
                        'layer_blob_digest': row['layer_blob_digest'], 'visibility': row['visibility'],
                        'inventory_candidates': deepcopy(candidates),
                        'captured_sha256': row['sha256'], 'inventory_digest': deepcopy(match['inventory_digest']),
                        'verification': match['verification']})
                    continue
                reason = 'matched_owner_has_no_notice_candidate'
            else:
                reason = 'ambiguous_owner_inventory' if ambiguous else 'owner_correspondence_unverified'
                if ambiguous:
                    statistics['ambiguous_locations'] += 1
            unresolved.append({'path': path, 'catalogue_layer_diff_id': origin,
                               'reason': reason, 'candidates': candidates})
        if linked or unresolved:
            by_id[identifier]['distro_owner_context'] = {
                'checksum_matched_notices': [linked[k] for k in sorted(linked)], 'unresolved_locations': unresolved,
                'scope': 'inventory correspondence and enclosing notices; component-specific terms remain unreviewed'}
            statistics['packages_with_checksum_matched_notice_context'] += bool(linked)
            statistics['packages_with_unresolved_owner_leads'] += bool(unresolved)
    return statistics
