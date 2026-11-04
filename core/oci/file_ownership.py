"""Match image files to package records and externally validated native identities.

These pure functions consume catalogue hashes; they never execute image code,
read host paths, or infer ownership from directory names. A native identity
reference must already be validated by its caller. File membership and binary
identity do not establish license completeness or build-source correspondence.
"""
from __future__ import annotations

import base64
import posixpath
import re

from core.oci.notice_paths import image_path


def match_inventory_ownership(native, candidates):
    """Resolve exact same-layer paths only when package and file SHA-256 agree.

    Package records establish file membership, not dependency or license
    completeness. Directory context, filenames and versions alone never resolve
    candidates. Conflicting or missing evidence remains inspectable.
    """
    keys = {(row["path"], row["layer_id"]) for row in candidates}
    claims = {}
    for artifact in native["artifacts"]:
        kind = artifact["type"]
        if kind not in {"python", "deb"}:
            continue
        for location in artifact.get("locations", []):
            path = location["path"]
            layer = location.get("layerID")
            if not layer:
                continue
            if kind == "python":
                directory = posixpath.dirname(path)
                if (posixpath.basename(path) not in {"METADATA", "PKG-INFO"}
                        or not directory.endswith((".dist-info", ".egg-info"))):
                    continue
                root = posixpath.dirname(directory)
            else:
                root = "/"
            for entry in (artifact.get("metadata") or {}).get("files", []):
                relative = entry.get("path")
                if not isinstance(relative, str) or "\x00" in relative:
                    continue
                member = posixpath.normpath(posixpath.join(root, relative))
                key = member, layer
                if key not in keys:
                    continue
                digest = entry.get("digest") or {}
                if digest.get("algorithm", "").lower() != "sha256":
                    continue
                value = digest.get("value", "")
                if not isinstance(value, str):
                    continue
                if kind == "python":
                    if not re.fullmatch(r"[A-Za-z0-9_-]{43}=?", value):
                        continue
                    decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
                    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value.rstrip("="):
                        continue
                    value = decoded.hex()
                elif not re.fullmatch(r"[a-fA-F0-9]{64}", value):
                    continue
                owner = {"package_id": artifact["id"], "name": artifact["name"],
                         "version": artifact.get("version", ""), "expected_sha256": value.lower()}
                claims.setdefault(key, {})[(artifact["id"], value.lower())] = owner
    indexed = {}
    for entry in native["files"]:
        key = entry["location"]["path"], entry["location"].get("layerID")
        if key in keys:
            indexed.setdefault(key, []).append(entry)
    resolved, pending = [], []
    for candidate in candidates:
        key = candidate["path"], candidate["layer_id"]
        owners = list(claims.get(key, {}).values())
        rows = indexed.get(key, [])
        reason = "no_sha256_package_file_record"
        actual = set()
        for row in rows:
            for digest in row.get("digests", []):
                if digest.get("algorithm", "").lower() == "sha256":
                    value = digest.get("value", "")
                    if isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value):
                        actual.add(value.lower())
        if owners:
            if len(owners) != 1:
                reason = "ambiguous_package_file_records"
            elif len(rows) != 1 or len(actual) > 1:
                reason = "ambiguous_file_inventory"
            elif (rows[0].get("metadata") or {}).get("type") not in {None, "RegularFile"}:
                reason = "non_regular_file_requires_identity_verification"
            elif not actual:
                reason = "file_sha256_unavailable"
            elif owners[0]["expected_sha256"] not in actual:
                reason = "package_file_checksum_mismatch"
            else:
                resolved.append({**candidate, **owners[0], "sha256": next(iter(actual)),
                                 "method": "same_layer_package_file_sha256"})
                continue
        pending.append({**candidate, "ownership_gap": reason, "package_file_claims": owners})
    return resolved, pending


def _sha256(entry):
    if (entry.get("metadata") or {}).get("type") != "RegularFile":
        return None
    hashes = {digest.get("value", "").lower() for digest in entry.get("digests", [])
              if digest.get("algorithm", "").lower() == "sha256"
              and isinstance(digest.get("value"), str)
              and re.fullmatch(r"[a-fA-F0-9]{64}", digest["value"])}
    return next(iter(hashes)) if len(hashes) == 1 else None


def _anchor(indexed, path, layer):
    """Resolve only catalogued, same-layer links; never access a host path."""
    seen = set()
    for _ in range(16):
        try:
            image_path(path)
        except (ValueError, TypeError):
            return None
        if path in seen:
            return None
        seen.add(path)
        rows = indexed.get((path, layer), [])
        if len(rows) != 1:
            return None
        row = rows[0]
        metadata = row.get("metadata") or {}
        if metadata.get("type") == "RegularFile":
            sha = _sha256(row)
            return (path, sha) if sha else None
        if metadata.get("type") != "SymbolicLink":
            return None
        target = metadata.get("linkDestination")
        if not isinstance(target, str) or not target:
            return None
        path = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    return None


def match_native_identities(native, candidates, identities):
    """Recognize primary binaries and byte-identical aliases, not whole trees.

    Each identity carries a source reference already checked by the caller
    (for example a digest-bound notice receipt). Its anchor must resolve to
    exactly one regular file whose actual SHA-256 matches in the same layer.
    Distinct identities claiming identical bytes stay ambiguous.
    """
    indexed = {}
    for entry in native["files"]:
        key = entry["location"]["path"], entry["location"].get("layerID")
        indexed.setdefault(key, []).append(entry)
    claims = {}
    for identity in identities:
        if (not isinstance(identity.get("name"), str) or not identity["name"]
                or not isinstance(identity.get("version"), str) or not identity["version"]
                or not isinstance(identity.get("sha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", identity["sha256"])
                or not isinstance(identity.get("evidence_sha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", identity["evidence_sha256"])):
            continue
        layer = identity.get("layer_id")
        if not isinstance(layer, str) or not layer:
            continue
        anchor = _anchor(indexed, identity.get("anchor_path"), layer)
        if anchor is None or anchor[1] != identity["sha256"]:
            continue
        claim = {**identity, "resolved_anchor_path": anchor[0]}
        claims.setdefault((layer, anchor[1]), {})[(identity["name"], identity["version"])] = claim
    resolved, pending = [], []
    for candidate in candidates:
        key = candidate["path"], candidate["layer_id"]
        rows = indexed.get(key, [])
        digest = _sha256(rows[0]) if len(rows) == 1 else None
        owners = list(claims.get((key[1], digest), {}).values()) if digest else []
        if len(owners) == 1:
            proof = owners[0]
            resolved.append({"path": key[0], "layer_id": key[1], "sha256": digest,
                             "identity": proof, "method": "same_layer_native_identity_sha256"})
        else:
            pending.append({**candidate, "native_identity_gap":
                            "ambiguous_native_identities" if owners else "no_verified_native_identity"})
    return resolved, pending
