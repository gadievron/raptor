"""Identify reviewed Java payloads without inheriting an enclosing license."""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import hashlib
from pathlib import Path
import re

from packaging.licenses import canonicalize_license_expression

from core.json import loads
from core.source import read_text_gated
from core.zip import (
    extract_files_from_zip,
    ZipEntryCountExceeded,
    ZipOpenError,
    ZipTotalBytesExceeded,
)

MAX_JAR_BYTES = 64 * 1024


@lru_cache(maxsize=1)
def _rules() -> list[dict]:
    path = Path(__file__).with_name("data") / "license_identifications.json"
    corpus = loads(read_text_gated(path, 256 * 1024, follow_symlinks=False))
    if (
        not isinstance(corpus, dict)
        or type(corpus.get("schema_version")) is not int
        or corpus["schema_version"] != 1
    ):
        raise ValueError("invalid Java license evidence corpus")
    rules = corpus.get("java_components", [])
    if not isinstance(rules, list):
        raise ValueError("invalid Java license evidence rules")
    for rule in rules:
        if (
            rule["type"] != "java-archive"
            or not rule["classes"]
            or canonicalize_license_expression(rule["expression"]) != rule["expression"]
            or "LicenseRef-" in rule["expression"]
            or any(
                not re.fullmatch(r"[0-9a-f]{64}", sha)
                for sha in rule["classes"].values()
            )
        ):
            raise ValueError("invalid reviewed Java payload or expression")
        re.compile(rule["path_pattern"])
    return rules


def _candidate(artifact: dict) -> dict | None:
    if artifact["type"] != "java-archive" or len(artifact.get("locations", [])) != 1:
        return None
    for claim in artifact.get("licenses", []):
        value = claim.get("spdxExpression") or claim.get("value")
        if not isinstance(value, str) or value.upper() not in {
            "UNKNOWN",
            "NOASSERTION",
            "LICENSEREF-UNKNOWN",
        }:
            return None
    path = artifact["locations"][0]["path"]
    candidates = [
        rule
        for rule in _rules()
        if rule["name"] == artifact["name"] and re.fullmatch(rule["path_pattern"], path)
    ]
    return candidates[0] if len(candidates) == 1 else None


def reviewed_java_locations(native: dict) -> set[tuple[str, str]]:
    """Select only potentially reviewed jars for explicit image-byte verification."""
    return {
        (a["locations"][0]["path"], a["locations"][0]["layerID"])
        for a in native["artifacts"]
        if _candidate(a) is not None
    }


def _class_hashes(data: bytes) -> dict | None:
    if (
        len(data) > MAX_JAR_BYTES
        or not data.startswith(b"PK\x03\x04")
        or data[-22:-18] != b"PK\x05\x06"
        or data[-2:] != b"\0\0"
    ):
        return None  # No executable prefix, archive comment or appended payload.
    seen = set()

    def select(info):
        if info.filename in seen or info.comment:
            raise ValueError("duplicate or commented Java archive member")
        seen.add(info.filename)
        return info.filename

    def refuse(info, reason):
        raise ValueError("refused Java archive member: " + reason)

    try:
        files = extract_files_from_zip(
            data,
            selector=select,
            max_member_bytes=32 * 1024,
            max_entry_count=16,
            max_total_bytes=MAX_JAR_BYTES,
            on_skipped=refuse,
        )
        manifest = files.pop("META-INF/MANIFEST.MF").decode("utf-8")
        headers = [line.split(": ", 1) for line in manifest.splitlines() if line]
        if len(headers) != 2 or any(len(row) != 2 for row in headers):
            return None
        fields = dict(headers)
        if (
            set(fields) != {"Manifest-Version", "Created-By"}
            or fields["Manifest-Version"] != "1.0"
            or not re.fullmatch(
                r"[0-9][A-Za-z0-9.+_-]* \(Debian\)", fields["Created-By"]
            )
            or any(not name.endswith(".class") for name in files)
        ):
            return None
        return {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}
    except (
        ValueError,
        KeyError,
        ZipOpenError,
        ZipEntryCountExceeded,
        ZipTotalBytesExceeded,
    ):
        return None  # Failed inspection remains unresolved; no partial payload is promoted.


def recover_java_license(
    artifact: dict,
    package: dict,
    verified: dict,
    native: dict,
    rows: list[dict],
    blobs: dict[str, bytes],
) -> tuple[dict, list[dict]] | None:
    """Require actual jar bytes, complete reviewed payload and scoped owner notices."""
    rule = _candidate(artifact)
    if rule is None:
        return None
    loc = artifact["locations"][0]
    identity = verified.get((loc["path"], loc["layerID"]))
    if identity is None:
        return None
    measurement, data = identity
    sha = hashlib.sha256(data).hexdigest()
    if (
        measurement.get("method") != "verified_image_layer"
        or measurement["path"] != loc["path"]
        or measurement["catalogue_layer_diff_id"] != loc["layerID"]
        or measurement["sha256"] != sha
        or measurement["size"] != len(data)
        or _class_hashes(data) != rule["classes"]
    ):
        return None
    owners = {a["id"]: a for a in native["artifacts"] if a["type"] == "deb"}
    contexts = []
    for context in package.get("distro_owner_context", {}).get(
        "checksum_matched_notices", []
    ):
        owner = owners.get(context["owner_package_id"])
        if (
            owner is None
            or owner["name"] != rule["owner_name"]
            or owner["version"] != context["owner_version"]
            or context["owner_name"] != owner["name"]
        ):
            continue
        matches = [
            row
            for row in context["matched_locations"]
            if row["path"] == loc["path"]
            and row["catalogue_layer_diff_id"] == loc["layerID"]
            and row["verification"] == "verified_image_bytes_match_inventory_checksum"
            and row.get("captured_sha256") == sha
            and row.get("layer_blob_digest") == measurement["layer_blob_digest"]
        ]
        if len(matches) == 1:
            contexts.append(context)
    if len(contexts) != 1:
        return None
    context = contexts[0]
    notices = [
        row
        for row in context["files"]
        if row["path"] == "/usr/share/doc/" + rule["owner_name"] + "/copyright"
        and row["sha256"] == rule["copyright_sha256"]
        and row["content_kind"] == "notice_candidate"
    ]
    if len(notices) != 1:
        return None
    for filename, expected_sha in rule["common_licenses"].items():
        candidates = [
            row
            for row in rows
            if row["path"] == "/usr/share/common-licenses/" + filename
            and row["content_kind"] == "notice_candidate"
            and row["sha256"] == expected_sha
        ]
        if len(candidates) != 1:
            return None
        notices.append(candidates[0])
    if any(
        row["sha256"] not in blobs
        or hashlib.sha256(blobs[row["sha256"]]).hexdigest() != row["sha256"]
        for row in notices
    ):
        return None
    proof = {
        "expression": rule["expression"],
        "basis": "reviewed_java_class_payload",
        "identity": deepcopy(measurement),
        "class_sha256": deepcopy(rule["classes"]),
        "source_review": deepcopy(rule["review"]),
        "owner_package_id": context["owner_package_id"],
        "notice_files": [
            {
                key: row[key]
                for key in (
                    "path",
                    "sha256",
                    "catalogue_layer_diff_id",
                    "layer_blob_digest",
                )
            }
            for row in notices
        ],
        "original_catalogue_licenses": deepcopy(artifact.get("licenses", [])),
        "scope": "Reviewed class payload and component-specific publisher source grant; no enclosing-license inheritance, license conclusion or complete redistribution certification.",
    }
    return proof, notices
