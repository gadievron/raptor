#!/usr/bin/env python3
"""Prepare paired Syft exports using explicit repository/build provenance.

No network, installation, image execution or publication. Raw inputs remain
unchanged. Source candidates are never promoted to verified build sources.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import fnmatch
from pathlib import Path, PurePosixPath
import re
import sys
import subprocess
import tomllib
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from core.json import save_json
from core.security.capped_read import read_capped
from packages.sca.sbom_import import _check_document, _unique_object, _read_cyclonedx
from packages.sca.sbom_spdx_import import _read_spdx
import json

MAX_BYTES = 50 * 1024 * 1024
REPOSITORY = "https://github.com/gadievron/raptor"


def read_document(path: Path) -> tuple[dict, str]:
    raw = read_capped(path, MAX_BYTES, follow_symlinks=True, raise_on_refusal=True)
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(document, dict):
        raise ValueError("inventory input must be an object")
    _check_document(document)
    return document, hashlib.sha256(raw).hexdigest()


def source_entries(manifest: dict) -> dict[tuple[str, str, str], dict]:
    if type(manifest.get("version")) is not int or manifest["version"] != 1 or not isinstance(manifest.get("sources"), list):
        raise ValueError("unsupported provenance manifest")
    entries = {}
    for entry in manifest["sources"]:
        if not isinstance(entry, dict) or any(not isinstance(entry.get(k), str) or not entry[k]
                                             for k in ("type", "name", "version", "repository", "tag", "revision", "licence_path")):
            raise ValueError("invalid source candidate")
        if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", entry["repository"]):
            raise ValueError("source candidate requires an explicit GitHub repository")
        if not re.fullmatch(r"[0-9a-f]{40}", entry["revision"]):
            raise ValueError("source candidate requires a pinned commit")
        if entry["licence_path"] in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]+", entry["licence_path"]):
            raise ValueError("invalid licence path")
        key = entry["type"], entry["name"], entry["version"]
        if key in entries:
            raise ValueError("duplicate source candidate")
        entries[key] = entry
    return entries


def local_project(artifact: dict, project: dict) -> bool:
    return (artifact.get("type") == "python"
            and (artifact.get("name"), artifact.get("version")) == (project["name"], project["version"])
            and (artifact.get("metadata") or {}).get("index") == "."
            and any(location.get("path") in {"uv.lock", "/uv.lock"} for location in artifact.get("locations", [])))


def _python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _https_url(value: str) -> bool:
    if not isinstance(value, str) or any(ord(c) < 33 for c in value):
        return False
    parsed = urllib.parse.urlsplit(value)
    return parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password and not parsed.fragment


def locked_sources(lock: dict) -> dict[tuple[str, str, str], dict]:
    """Retain lock-declared source archives; no download/build verification."""
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ValueError("lockfile package inventory is unavailable")
    entries = {}
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("source"), dict):
            raise ValueError("invalid lockfile package source")
        source = package["source"]
        if "registry" not in source:
            continue
        name, version, registry = package.get("name"), package.get("version"), source["registry"]
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version or not _https_url(registry):
            raise ValueError("invalid locked registry identity")
        key = _python_name(name), version, registry
        if key in entries:
            raise ValueError("duplicate locked registry identity")
        entry = {"name": name, "version": version, "registry": registry}
        if "sdist" in package:
            archive = package["sdist"]
            if not isinstance(archive, dict) or not _https_url(archive.get("url")) or not isinstance(archive.get("hash"), str) or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", archive["hash"]):
                raise ValueError("invalid locked source archive URL or SHA-256")
            entry["source"] = {"type": "distribution", "url": archive["url"],
                               "status": "lockfile_source_archive_content_unverified",
                               "registry": registry,
                               "hashes": [{"alg": "SHA-256", "content": archive["hash"][7:].lower()}]}
        entries[key] = entry
    return entries


def root_lock_package(artifact: dict) -> bool:
    return artifact.get("type") == "python" and any(
        location.get("path") in {"uv.lock", "/uv.lock"} for location in artifact.get("locations", []))


def plan(artifact: dict, candidates: dict, project: dict | None, locked: dict | None = None) -> dict | None:
    kind, name, version = (artifact.get(k) for k in ("type", "name", "version"))
    metadata = artifact.get("metadata") or {}
    result = {"id": artifact["id"], "name": name, "version": version,
              "original_purl": artifact.get("purl", ""), "sources": [], "gaps": []}
    if project and local_project(artifact, project):
        revision = project["revision"]
        result.update(purl=f"pkg:generic/gadievron/raptor@{revision}", version=revision,
                      original_version=version, original_code_licence="MIT")
        result["sources"].append({"type": "vcs", "url": REPOSITORY + "/tree/" + revision,
                                  "status": "repository_commit", "licence_url": REPOSITORY + "/blob/" + revision + "/LICENSE"})
    elif kind == "npm" and name == "nvm" and metadata.get("homepage") == "https://github.com/nvm-sh/nvm" and metadata.get("url") == "git://github.com/nvm-sh/nvm.git":
        result["purl"] = "pkg:generic/nvm-sh/nvm@" + urllib.parse.quote(version, safe="")
        result["origin"] = "https://github.com/nvm-sh/nvm"
        result["gaps"].append("installed source revision is not established by package.json version")
    elif kind == "deb" and name == "nodejs" and re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]*nodesource[0-9]+", version or ""):
        # The version label alone is insufficient provenance for a new origin.
        if metadata.get("maintainer") != "NodeSource Support <support@nodesource.com>":
            result["gaps"].append("NodeSource-looking version has no matching vendor maintainer evidence")
        else:
            result["purl"] = "pkg:deb/nodesource/nodejs@" + urllib.parse.quote(version, safe="")
            arch = metadata.get("architecture", "")
            if arch:
                result["purl"] += "?arch=" + urllib.parse.quote(arch, safe="")
            result["origin"] = "https://deb.nodesource.com"
        result["gaps"].append("exact vendor source and build correspondence unavailable; do not use Debian source")
    if locked is not None and root_lock_package(artifact) and not (project and local_project(artifact, project)):
        entry = locked.get((_python_name(name), version, metadata.get("index", "")))
        if entry is None:
            result["gaps"].append("root-lock package identity/origin does not match the supplied lockfile")
        elif "source" not in entry:
            result["gaps"].append("lockfile declares no source archive for this package version")
        else:
            result["sources"].append(deepcopy(entry["source"]))
    key = kind, name, version
    candidate = candidates.get(key)
    # An nvm pin is useful only after its upstream origin is independently identified.
    if candidate and (name != "nvm" or result.get("origin") == candidate["repository"]):
        repo, revision = candidate["repository"], candidate["revision"]
        result["sources"].append({"type": "vcs", "url": repo + "/tree/" + revision,
                                  "status": "candidate_build_correspondence_unverified",
                                  "tag": candidate["tag"],
                                  "licence_url": repo + "/blob/" + revision + "/" + candidate["licence_path"]})
        result["gaps"].append("upstream tag/commit is a source candidate; correspondence to installed artifact is unverified")
    elif candidate:
        result["gaps"].append("source candidate not applied: upstream origin is not established by package metadata")
    elif any((t, n) == (kind, name) for t, n, _ in candidates):
        result["gaps"].append("no source candidate is recorded for this package version")
    return result if result["sources"] or result["gaps"] or "purl" in result else None


def _properties(component: dict, record: dict) -> None:
    props = component.setdefault("properties", [])
    props.append({"name": "raptor:provenance:original-purl", "value": record["original_purl"]})
    if record.get("origin"):
        props.append({"name": "raptor:provenance:origin", "value": record["origin"]})
    if record.get("original_version"):
        props.append({"name": "raptor:provenance:declared-version", "value": record["original_version"]})
    for gap in record["gaps"]:
        props.append({"name": "raptor:provenance:gap", "value": gap})
    refs = component.setdefault("externalReferences", [])
    for source in record["sources"]:
        reference = {"type": source["type"], "url": source["url"], "comment": source["status"]}
        if source.get("hashes"):
            reference["hashes"] = deepcopy(source["hashes"])
        refs.append(reference)
        if source.get("licence_url"):
            refs.append({"type": "license", "url": source["licence_url"], "comment": source["status"]})
        props.append({"name": "raptor:provenance:source-status", "value": source["status"]})


def prepare(native: dict, cdx: dict, spdx: dict, manifest: dict, project: dict | None = None, lock: dict | None = None, notice_summary: dict | None = None) -> tuple[dict, dict, dict]:
    if native.get("schema", {}).get("version", "").split(".", 1)[0] != "16":
        raise ValueError("expected Syft JSON schema 16.x")
    if cdx.get("bomFormat") != "CycloneDX" or cdx.get("specVersion") != "1.5" or spdx.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("expected CycloneDX 1.5 and SPDX 2.3 exports")
    artifacts = native.get("artifacts")
    if not isinstance(artifacts, list) or any(not isinstance(a, dict) or not re.fullmatch(r"[0-9a-f]{16}", a.get("id", "")) for a in artifacts):
        raise ValueError("invalid Syft package identities")
    if len({a["id"] for a in artifacts}) != len(artifacts):
        raise ValueError("duplicate Syft package identity")
    if project and sum(local_project(a, project) for a in artifacts) != 1:
        raise ValueError("native inventory does not identify exactly one local RAPTOR project")
    if lock is not None and project is None:
        raise ValueError("lock source enrichment requires repository provenance")
    locked = locked_sources(lock) if lock is not None else None
    candidates = source_entries(manifest)
    cdx, spdx = deepcopy(cdx), deepcopy(spdx)
    # Keep bom-ref/SPDXID stable: these are occurrence identifiers, not lookup
    # coordinates. Existing file, graph and VEX references continue to resolve.
    source = native.get("source", {})
    root = cdx.get("metadata", {}).get("component", {})
    if not source.get("name") or not source.get("version") or (root.get("name"), root.get("version")) != (source["name"], source["version"]):
        raise ValueError("paired exports disagree on the inventory subject")
    if not any((p.get("name"), p.get("versionInfo")) == (source["name"], source["version"]) for p in spdx.get("packages", [])):
        raise ValueError("SPDX export disagrees on the inventory subject")
    components = cdx.get("components", [])
    packages = spdx.get("packages", [])
    cdx_by_id, spdx_by_id = {}, {}
    for component in components:
        ref = component.get("bom-ref", "")
        identifier = ref if re.fullmatch(r"[0-9a-f]{16}", ref) else None
        if ref.startswith("pkg:"):
            qualifiers = urllib.parse.parse_qs(ref.partition("#")[0].partition("?")[2], strict_parsing=True, max_num_fields=64)
            if "package-id" in qualifiers:
                if len(qualifiers["package-id"]) != 1 or not re.fullmatch(r"[0-9a-f]{16}", qualifiers["package-id"][0]):
                    raise ValueError("ambiguous CycloneDX occurrence identity")
                identifier = qualifiers["package-id"][0]
        if identifier:
            if identifier in cdx_by_id:
                raise ValueError("duplicate CycloneDX package occurrence")
            cdx_by_id[identifier] = component
    for package in packages:
        match = re.search(r"-([0-9a-f]{16})$", package.get("SPDXID", ""))
        if match:
            if match[1] in spdx_by_id:
                raise ValueError("duplicate SPDX package occurrence")
            spdx_by_id[match[1]] = package
    records = []
    for artifact in artifacts:
        identifier = artifact["id"]
        component, package = cdx_by_id.get(identifier), spdx_by_id.get(identifier)
        if component is None or package is None:
            raise ValueError("paired exports are missing a native package occurrence")
        purls = [r["referenceLocator"] for r in package.get("externalRefs", []) if r.get("referenceType") == "purl"]
        if (component.get("name"), component.get("version", ""), component.get("purl", "")) != (artifact["name"], artifact.get("version", ""), artifact.get("purl", "")) or package.get("name") != artifact["name"] or package.get("versionInfo", "") != artifact.get("version", "") or purls != ([artifact["purl"]] if artifact.get("purl") else []):
            raise ValueError("paired exports conflict with native package identity")
        record = plan(artifact, candidates, project, locked)
        if record is None:
            continue
        records.append(record)
        if "purl" in record:
            component["purl"] = record["purl"]
            component["version"] = record["version"]
            record["original_cpes"] = artifact.get("cpes", [])
            component.pop("cpe", None)
            component["properties"] = [p for p in component.get("properties", []) if p.get("name") != "syft:cpe23"]
            package["versionInfo"] = record["version"]
            package["externalRefs"] = [r for r in package.get("externalRefs", []) if r.get("referenceType") not in {"purl", "cpe23Type", "cpe22Type"}]
            package["externalRefs"].append({"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": record["purl"]})
        component.pop("signature", None)
        _properties(component, record)
        if record.get("original_code_licence"):
            component["licenses"] = [{"license": {"id": "MIT"}}]
            package["licenseDeclared"] = "MIT"
        # sourceInfo is evidence, not a replacement binary downloadLocation or
        # an inferred licence conclusion. Preserve both original fields.
        package["sourceInfo"] = package.get("sourceInfo", "") + "\nRAPTOR provenance: " + json.dumps(record, ensure_ascii=True, sort_keys=True)
    if notice_summary is not None:
        from packages.sca.sbom_notices import append_notices
        append_notices(cdx, spdx, cdx_by_id, spdx_by_id, notice_summary)
    if records or notice_summary is not None:
        cdx.pop("signature", None)
        cdx["version"] = cdx.get("version", 1) + 1
    report = {"version": 1, "packages": records,
              "scope": "identity corrections and source candidates only; not a complete licence/source inventory",
              "gaps": ["original installed licence texts and build-source correspondence remain separate evidence requirements"]}
    if notice_summary is not None:
        report["notice_evidence"] = deepcopy(notice_summary)
        report["scope"] = "identity/source candidates and captured notice associations; not a complete licence/source inventory"
        report["gaps"] = ["notice candidates need term review; text completeness remains unverified",
                          "build-source correspondence remains a separate evidence requirement"]
    if locked is not None:
        observed = {(_python_name(a["name"]), a["version"], (a.get("metadata") or {}).get("index", ""))
                    for a in artifacts if root_lock_package(a)}
        missing = [entry for key, entry in locked.items() if key not in observed]
        report["lock_inventory"] = {"expected_packages": len(locked), "matched_packages": len(locked) - len(missing),
                                    "missing_packages": [{k: e[k] for k in ("name", "version", "registry")} for e in missing]}
        if missing:
            raise ValueError("native inventory is missing package identities from the supplied root lockfile")
    return cdx, spdx, report



def _relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or any(ord(c) < 32 for c in value):
        raise ValueError("invalid bundle path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in {".", ".."} for p in path.parts) or str(path) != value:
        raise ValueError("bundle paths must be normalized and repository-relative")
    return value


def _tracked_tree(repo: Path, revision: str) -> dict[str, tuple[str, str]]:
    output = subprocess.check_output(["git", "-C", str(repo), "ls-tree", "-rz", "--full-tree", revision])
    tree = {}
    for row in output.decode("utf-8").split("\0"):
        if not row:
            continue
        info, name = row.split("\t", 1)
        mode, _, oid = info.split()
        tree[_relative_path(name)] = mode, oid
    return tree


def _material_file(repo: Path, path: str, tree: dict, revision: str) -> tuple[dict, bytes]:
    if path not in tree or tree[path][0] not in {"100644", "100755"}:
        raise ValueError("bundle evidence must be a committed regular file")
    raw = read_capped(repo / path, MAX_BYTES, raise_on_refusal=True)
    # Git's SHA-1 blob identity proves that URL/hash evidence describes the
    # committed bytes, including refusing worktree EOL conversions. The
    # published content checksum remains SHA-256.
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw, usedforsecurity=False).hexdigest()
    if blob != tree[path][1]:
        raise ValueError("bundle evidence differs from committed bytes")
    url = "https://raw.githubusercontent.com/gadievron/raptor/" + revision + "/" + urllib.parse.quote(path, safe="/")
    return {"path": path, "url": url, "sha256": hashlib.sha256(raw).hexdigest()}, raw


def _finding_origins(repo: Path, path: str, tree: dict, revision: str) -> list[str]:
    _, raw = _material_file(repo, path, tree, revision)
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    _check_document(document)
    if not isinstance(document, dict) or not isinstance(document.get("intermediate_steps", []), list):
        raise ValueError("finding evidence must have an object/step structure")
    steps = [document.get("source", {}), document.get("sink", {}), *document.get("intermediate_steps", [])]
    paths = []
    for step in steps:
        if isinstance(step, dict) and step.get("snippet"):
            paths.append(_relative_path(step.get("file_path")))
    return paths


def bundled_materials(repo: Path, revision: str, manifest: dict) -> tuple[list[dict], list[dict]]:
    """Inventory committed material; fetched corpus trees are never scanned."""
    rules = manifest.get("bundles")
    if not isinstance(rules, list):
        raise ValueError("repository bundled-material inventory is unavailable")
    tree = _tracked_tree(repo, revision)
    records, seen = [], set()
    findings = {}
    for rule in rules:
        if not isinstance(rule, dict) or not re.fullmatch(r"[a-z][a-z0-9-]*", rule.get("id", "")) or rule["id"] in seen:
            raise ValueError("invalid or duplicate bundled-material identity")
        seen.add(rule["id"])
        root = _relative_path(rule["root"])
        if not isinstance(rule.get("name"), str) or not rule["name"] or not isinstance(rule.get("license_scope"), str) or not rule["license_scope"]:
            raise ValueError("bundle requires a name and licence scope")
        if rule.get("license") not in {None, "MIT", "MPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "curl"}:
            raise ValueError("bundle licence requires a reviewed identifier or explicit unknown")
        if not _https_url(rule.get("upstream")) or not isinstance(rule.get("notice_paths"), list) or not rule["notice_paths"]:
            raise ValueError("bundle requires upstream and notice evidence")
        if len(set(rule["notice_paths"])) != len(rule["notice_paths"]):
            raise ValueError("duplicate bundle notice evidence")
        if rule.get("upstream_type", "website") not in {"vcs", "website", "distribution"}:
            raise ValueError("invalid upstream reference type")
        selector = rule.get("files")
        snippet = rule.get("snippet_path") or rule.get("snippet_prefix")
        if bool(selector) == bool(snippet) or (selector and (not isinstance(selector, list) or any(not isinstance(x, str) or not x or ".." in PurePosixPath(x).parts or x.startswith("/") for x in selector))):
            raise ValueError("bundle requires exactly one file or snippet selector")
        if snippet:
            _relative_path(snippet.rstrip("/"))
            if "snippet_prefix" in rule and not snippet.endswith("/"):
                raise ValueError("snippet prefix must end at a directory boundary")
        if "snippet_path" in rule and "snippet_prefix" in rule:
            raise ValueError("bundle snippet selector is ambiguous")
        selected = []
        for path in tree:
            if not path.startswith(root + "/"):
                continue
            relative = path[len(root) + 1:]
            if selector:
                if any(fnmatch.fnmatchcase(relative, pattern) for pattern in selector):
                    selected.append(path)
            elif path.endswith(".json"):
                if path not in findings:
                    findings[path] = _finding_origins(repo, path, tree, revision)
                if any(p == snippet if "snippet_path" in rule else p.startswith(snippet) for p in findings[path]):
                    selected.append(path)
        if not selected:
            raise ValueError("bundle has no committed material; review stale provenance rules")
        files, credits = [], []
        for path in sorted(selected):
            record, raw = _material_file(repo, path, tree, revision)
            files.append(record)
            if rule.get("source_credits") and path.endswith(".json"):
                document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
                _check_document(document)
                if isinstance(document, dict) and "_source" in document:
                    credits.append({"path": path, "source": document["_source"]})
        notices = [_material_file(repo, _relative_path(path), tree, revision)[0] for path in rule["notice_paths"]]
        record = {k: rule[k] for k in ("id", "name", "license_scope", "upstream")}
        record.update(material_kind="data", version=revision, license=rule.get("license"), upstream_type=rule.get("upstream_type", "website"), files=files, notices=notices,
                      source_credits=credits, status="committed_material_bytes_verified_locally", gaps=[])
        if not record["license"]:
            record["gaps"].append("no blanket licence asserted; review the retained source credits and notices")
        if snippet:
            record["snippet_origins"] = sorted({p for path in selected for p in findings[path]
                if (p == snippet if "snippet_path" in rule else p.startswith(snippet))})
        if rule["id"] == "public-suffix-list":
            body = _material_file(repo, selected[0], tree, revision)[1].decode("utf-8")
            commit = re.search(r"^// COMMIT: ([0-9a-f]{40})$", body, re.MULTILINE)
            version = re.search(r"^// VERSION: (.+)$", body, re.MULTILINE)
            if len(selected) != 1 or not commit or not version:
                raise ValueError("PSL snapshot upstream revision is unavailable")
            record["upstream_revision"], record["upstream_version"] = commit[1], version[1]
        records.append(record)
    # Coverage floors are part of this RAPTOR producer's contract. They keep
    # deleting all rules for a material class from silently omitting it.
    covered = {f["path"] for record in records for f in record["files"]}
    required = {path for path in tree if path == "core/domains/data/public_suffix_list.dat"
                or (path.endswith(".json") and (path.startswith("packages/sca/data/calibration/")
                                                or path.startswith("packages/cve_diff/data/samples/")))}
    if required - covered:
        raise ValueError("committed bundled material has no inventory rule")
    for path in tree:
        if path.startswith("core/dataflow/corpus/findings/") and path.endswith(".json") and path not in findings:
            findings[path] = _finding_origins(repo, path, tree, revision)
    # Every retained non-project snippet must have an explicit scope rule.
    selectors = [r for r in rules if r.get("snippet_path") or r.get("snippet_prefix")]
    for paths in findings.values():
        for path in paths:
            if path in tree:
                continue
            if not any(path == r["snippet_path"] if "snippet_path" in r else path.startswith(r["snippet_prefix"]) for r in selectors):
                raise ValueError("retained external snippet origin has no bundled-material rule")
    references = []
    for path, (mode, oid) in tree.items():
        if mode != "160000":
            continue
        directory = repo / path
        if directory.is_dir() and any(directory.iterdir()):
            raise ValueError("populated submodules require their own material inventory")
        references.append({"path": path, "revision": oid, "status": "reference_only_unpopulated_gitlink"})
    return records, references


def append_bundles(cdx: dict, spdx: dict, records: list[dict]) -> None:
    root = cdx["metadata"]["component"]
    subjects = [p for p in spdx["packages"] if (p.get("name"), p.get("versionInfo")) == (root["name"], root["version"])]
    if len(subjects) != 1:
        raise ValueError("bundled-material containment requires an unambiguous SPDX subject")
    for record in records:
        if record["version"] != root["version"]:
            raise ValueError("bundled-material revision does not match the inventory subject")
        identifier = record["id"] + "-" + record["version"]
        ref = "urn:raptor:bundle:" + identifier
        spdx_id = "SPDXRef-RaptorBundle-" + identifier
        component = {"type": "data", "name": record["name"], "version": record["version"],
                     "bom-ref": ref, "description": record["license_scope"],
                     "properties": [{"name": "raptor:bundle:status", "value": record["status"]}],
                     "externalReferences": [{"type": record["upstream_type"], "url": record["upstream"]}]}
        if record.get("upstream_revision"):
            component["properties"].append({"name": "raptor:bundle:upstream-revision", "value": record["upstream_revision"]})
        for role, entries in [("distribution", record["files"]), ("license", record["notices"])]:
            component["externalReferences"] += [{"type": role, "url": f["url"],
                "hashes": [{"alg": "SHA-256", "content": f["sha256"]}], "comment": record["license_scope"]} for f in entries]
        for gap in record["gaps"]:
            component["properties"].append({"name": "raptor:provenance:gap", "value": gap})
        if record["license"]:
            component["licenses"] = [{"license": {"id": record["license"]}}]
        root.setdefault("components", []).append(component)
        spdx["packages"].append({"SPDXID": spdx_id, "name": record["name"], "versionInfo": record["version"],
            "primaryPackagePurpose": "OTHER", "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseDeclared": record["license"] or "NOASSERTION", "licenseConcluded": "NOASSERTION",
            "licenseComments": record["license_scope"], "copyrightText": "NOASSERTION",
            "sourceInfo": "RAPTOR bundled material: " + json.dumps(record, ensure_ascii=True, sort_keys=True)})
        spdx.setdefault("relationships", []).append({"spdxElementId": subjects[0]["SPDXID"],
            "relationshipType": "CONTAINS", "relatedSpdxElement": spdx_id})
    if records:
        root.pop("signature", None)
        cdx.pop("signature", None)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syft", type=Path, required=True)
    parser.add_argument("--cyclonedx", type=Path, required=True)
    parser.add_argument("--spdx", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, default=ROOT / ".github/sbom-provenance.json")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--repo", type=Path, help="RAPTOR checkout used to produce the directory inventory")
    scope.add_argument("--notice-evidence", type=Path, help="container capture directory containing evidence.json and notices/")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    paths = [args.syft, args.cyclonedx, args.spdx, args.provenance]
    if args.notice_evidence:
        paths.append(args.notice_evidence / "evidence.json")
    loaded = [read_document(p) for p in paths]
    native, cdx, spdx, manifest = [d for d, _ in loaded[:4]]
    notice_summary, notice_blobs = None, {}
    if args.notice_evidence:
        from packages.sca.sbom_notices import load_notices
        notice_summary, notice_blobs = load_notices(args.notice_evidence, native, loaded[0][1], loaded[4][0])
    project, lock = None, None
    repo_inputs = []
    if native.get("source", {}).get("name") == REPOSITORY and native.get("source", {}).get("type") == "directory" and not args.repo:
        raise ValueError("RAPTOR directory inventory requires --repo for local-project provenance")
    if args.repo:
        config_raw = read_capped(args.repo / "pyproject.toml", 1024 * 1024, raise_on_refusal=True)
        config = tomllib.loads(config_raw.decode("utf-8"))["project"]
        revision = native.get("source", {}).get("version", "")
        if native.get("source", {}).get("name") != REPOSITORY or not re.fullmatch(r"[0-9a-f]{40}", revision) or config.get("name") != "raptor" or config.get("license") != "MIT":
            raise ValueError("repository inventory lacks explicit RAPTOR identity/revision")
        head = subprocess.check_output(["git", "-C", str(args.repo), "rev-parse", "HEAD"], text=True).strip()
        if head != revision:
            raise ValueError("checkout revision does not match the inventoried repository")
        subprocess.run(["git", "-C", str(args.repo), "diff", "--no-ext-diff", "--no-textconv", "--exit-code", "HEAD", "--", "pyproject.toml", "uv.lock"], check=True, stdout=subprocess.DEVNULL)
        lock_raw = read_capped(args.repo / "uv.lock", MAX_BYTES, raise_on_refusal=True)
        lock = tomllib.loads(lock_raw.decode("utf-8"))
        local = [p for p in lock.get("package", [])
                 if (p.get("name"), p.get("version")) == (config["name"], config["version"])]
        if len(local) != 1 or local[0].get("source") not in ({"editable": "."}, {"virtual": "."}):
            raise ValueError("lockfile does not establish a local RAPTOR project")
        project = {"name": config["name"], "version": config["version"], "revision": revision}
        repo_inputs = [{"path": str(args.repo / name), "sha256": hashlib.sha256(raw).hexdigest()}
                       for name, raw in [("pyproject.toml", config_raw), ("uv.lock", lock_raw)]]
    prepared_cdx, prepared_spdx, report = prepare(native, cdx, spdx, manifest, project, lock, notice_summary)
    if args.repo:
        bundles, references = bundled_materials(args.repo, project["revision"], manifest)
        append_bundles(prepared_cdx, prepared_spdx, bundles)
        report["bundles"], report["references"] = bundles, references
        report["scope"] = "repository identity, source archives and committed bundled-material evidence; not a complete build-source or licence assessment"
    # Refuse malformed retained evidence before creating any output artifacts.
    _read_cyclonedx(prepared_cdx, args.cyclonedx)
    _read_spdx(prepared_spdx, args.spdx)
    outputs = [args.out / name for name in ("sbom.cdx.json", "sbom.spdx.json", "provenance.json")]
    if args.notice_evidence and any((args.out / name).exists() or (args.out / name).is_symlink() for name in ("notice-evidence.json", "notices")):
        raise ValueError("use a fresh notice evidence output directory")
    if any(output.exists() for output in outputs) or any(args.out.resolve() == p.parent.resolve() for p in paths):
        raise ValueError("use a fresh output directory; input artifacts must remain unchanged")
    report["inputs"] = [{"path": str(p), "sha256": digest} for p, (_, digest) in zip(paths, loaded)] + repo_inputs
    args.out.mkdir(parents=True, exist_ok=True)
    if args.notice_evidence:
        from core.atomic_fs import write_bytes_atomically
        for sha, data in sorted(notice_blobs.items()):
            write_bytes_atomically(args.out / "notices" / "sha256" / sha, data)
        save_json(args.out / "notice-evidence.json", loaded[4][0])
    for path, document in zip(outputs, (prepared_cdx, prepared_spdx, report)):
        save_json(path, document)


if __name__ == "__main__":
    main()
