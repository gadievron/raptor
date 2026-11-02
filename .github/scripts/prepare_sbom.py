#!/usr/bin/env python3
"""Prepare paired Syft exports using explicit repository/build provenance.

No network, installation, image execution or publication. Raw inputs remain
unchanged. Source candidates are never promoted to verified build sources.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
from pathlib import Path
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


def prepare(native: dict, cdx: dict, spdx: dict, manifest: dict, project: dict | None = None, lock: dict | None = None) -> tuple[dict, dict, dict]:
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
    if records:
        cdx.pop("signature", None)
        cdx["version"] = cdx.get("version", 1) + 1
    report = {"version": 1, "packages": records,
              "scope": "identity corrections and source candidates only; not a complete licence/source inventory",
              "gaps": ["original installed licence texts and build-source correspondence remain separate evidence requirements"]}
    if locked is not None:
        observed = {(_python_name(a["name"]), a["version"], (a.get("metadata") or {}).get("index", ""))
                    for a in artifacts if root_lock_package(a)}
        missing = [entry for key, entry in locked.items() if key not in observed]
        report["lock_inventory"] = {"expected_packages": len(locked), "matched_packages": len(locked) - len(missing),
                                    "missing_packages": [{k: e[k] for k in ("name", "version", "registry")} for e in missing]}
        if missing:
            raise ValueError("native inventory is missing package identities from the supplied root lockfile")
    return cdx, spdx, report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syft", type=Path, required=True)
    parser.add_argument("--cyclonedx", type=Path, required=True)
    parser.add_argument("--spdx", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, default=ROOT / ".github/sbom-provenance.json")
    parser.add_argument("--repo", type=Path, help="RAPTOR checkout used to produce the directory inventory")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    paths = [args.syft, args.cyclonedx, args.spdx, args.provenance]
    loaded = [read_document(p) for p in paths]
    native, cdx, spdx, manifest = [d for d, _ in loaded]
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
    prepared_cdx, prepared_spdx, report = prepare(native, cdx, spdx, manifest, project, lock)
    # Refuse malformed retained evidence before creating any output artifacts.
    _read_cyclonedx(prepared_cdx, args.cyclonedx)
    _read_spdx(prepared_spdx, args.spdx)
    outputs = [args.out / name for name in ("sbom.cdx.json", "sbom.spdx.json", "provenance.json")]
    if any(output.exists() for output in outputs) or any(args.out.resolve() == p.parent.resolve() for p in paths):
        raise ValueError("use a fresh output directory; input artifacts must remain unchanged")
    report["inputs"] = [{"path": str(p), "sha256": digest} for p, (_, digest) in zip(paths, loaded)] + repo_inputs
    args.out.mkdir(parents=True, exist_ok=True)
    for path, document in zip(outputs, (prepared_cdx, prepared_spdx, report)):
        save_json(path, document)


if __name__ == "__main__":
    main()
