"""Collect publisher notice candidates from checksum-pinned Cargo sources.

Cargo.lock includes build, development and other-platform dependencies. This
inventory is deliberately conservative and must not become an installed SBOM.
No downloaded manifests, scripts or binaries are executed.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import http.client
import io
import json
from pathlib import PurePosixPath
import re
import tarfile
import tomllib
import urllib.parse

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_TEXT = 512 * 1024
MAX_INVENTORY = 4 * 1024 * 1024
MAX_NOTICE_TOTAL = 8 * 1024 * 1024
NOTICE = re.compile(r"(?:licen[cs]e|copying|copyright|notice|authors|unlicen[cs]e|patents)(?:[._-].*)?\Z", re.I)
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


@dataclass
class CargoNotices:
    records: list[dict]
    contents: dict[str, bytes]
    inventory: bytes
    summary: dict


def _path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or str(path) != name:
        raise ValueError("unsafe Cargo source path")
    return path



def _relative(parent, name):
    if PurePosixPath(name).is_absolute() or "\\" in name:
        raise ValueError("unsafe Cargo license path")
    parts = []
    for part in (*PurePosixPath(parent).parts, *PurePosixPath(name).parts):
        if part == ".":
            continue
        if part == "..":
            if not parts:
                raise ValueError("Cargo license path escapes source archive")
            parts.pop()
        else:
            parts.append(part)
    return str(PurePosixPath(*parts))

def _notice(path, expression=""):
    identifiers = set(re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*", expression or "")) - {"AND", "OR", "WITH"}
    return (bool(NOTICE.fullmatch(path.name)) or path.stem in identifiers
            or any(part.lower() in {"licenses", "licences"} for part in path.parts[:-1]))


def _archive(raw, header_reader=None):
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("Cargo archive exceeds compressed budget")
    notices, manifests, vcs = {}, {}, None
    seen, total, prefix = set(), 0, None
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r|gz") as archive:
        for index, member in enumerate(archive):
            total += member.size
            if index >= 30000 or total > 512 * 1024 * 1024:
                raise ValueError("Cargo archive exceeds expanded budget")
            path = _path(member.name.rstrip("/"))
            if prefix is None:
                prefix = path.parts[0]
            if path.parts[0] != prefix or member.name in seen:
                raise ValueError("ambiguous Cargo archive layout")
            seen.add(member.name)
            if not member.isfile():
                continue
            relative = PurePosixPath(*path.parts[1:])
            metadata = relative.name == "Cargo.toml" or str(relative) == ".cargo_vcs_info.json"
            text_candidate = _notice(relative)
            code = header_reader is not None and relative.suffix.lower() in {".rs", ".c", ".h", ".py"}
            if not metadata and not text_candidate and not code:
                continue
            with archive.extractfile(member) as stream:
                if metadata or text_candidate:
                    if member.size > MAX_TEXT:
                        raise ValueError("Cargo notice or manifest exceeds text budget")
                    body = stream.read(MAX_TEXT + 1)
                else:
                    body = stream.read(min(member.size, 64 * 1024))
            if metadata:
                if relative.name == "Cargo.toml":
                    manifest = tomllib.loads(body.decode("utf-8"))
                    if not isinstance(manifest.get("package", {}), dict) or not isinstance(manifest.get("workspace", {}), dict):
                        raise ValueError("invalid Cargo package/workspace metadata")
                    if not isinstance(manifest.get("workspace", {}).get("package", {}), dict):
                        raise ValueError("invalid inherited Cargo package metadata")
                    manifests[str(relative)] = manifest
                else:
                    vcs = json.loads(body)
                    if not isinstance(vcs, dict) or not isinstance(vcs.get("git", {}), dict):
                        raise ValueError("invalid Cargo VCS metadata")
            elif text_candidate:
                notices[str(relative)] = (body, "publisher_file")
            elif code:
                try:
                    header = header_reader(body, python=relative.suffix == ".py")
                except (ValueError, UnicodeError):
                    header = None
                if header:
                    notices[str(relative)] = (header, "source_header")
    # SPDX-named texts and explicitly declared license files need not start
    # with LICENSE. Resolve them using the manifest, not a crate allowlist.
    requested = set()
    links = {}
    for name, manifest in manifests.items():
        package = manifest.get("package", {})
        value = package.get("license-file", package.get("license_file"))
        if isinstance(value, str):
            requested.add(_relative(str(PurePosixPath(name).parent), value))
    expressions = " ".join(m.get("package", {}).get("license", "") for m in manifests.values()
                           if isinstance(m.get("package", {}).get("license"), str))
    if requested or expressions:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r|gz") as archive:
            for member in archive:
                path = _path(member.name.rstrip("/"))
                relative = PurePosixPath(*path.parts[1:])
                if str(relative) not in requested and not _notice(relative, expressions):
                    continue
                if member.isdir() and str(relative) not in requested:
                    continue
                if member.issym():
                    links[str(relative)] = _relative(str(relative.parent), member.linkname)
                    continue
                if not member.isfile() or member.size > MAX_TEXT:
                    raise ValueError("declared Cargo notice is not a bounded regular file")
                with archive.extractfile(member) as stream:
                    notices[str(relative)] = (stream.read(MAX_TEXT + 1), "declared_license_file")
        for link, target in links.items():
            if target not in notices:
                raise ValueError("Cargo notice link lacks an in-archive regular notice target")
            notices[link] = notices[target]
        if not requested <= set(notices):
            raise ValueError("declared Cargo license file is absent")
    return manifests, vcs, notices


def _github_repo(value):
    if not isinstance(value, str):
        return None
    url = urllib.parse.urlsplit(value)
    parts = url.path.strip("/").split("/")
    if url.hostname != "github.com" or url.username or len(parts) < 2:
        return None
    repository = "/".join(parts[:2]).removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or any(p in {".", ".."} for p in repository.split("/")):
        return None
    return repository


def _upstream(manifest, vcs, fetch):
    commit = ((vcs or {}).get("git") or {}).get("sha1", "")
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or (vcs or {}).get("git", {}).get("dirty"):
        return {}
    results, attempted = {}, set()
    for field in ("repository", "homepage"):
        repository = _github_repo(manifest.get(field))
        if not repository or repository in attempted:
            continue
        attempted.add(repository)
        try:
            tree = json.loads(fetch(f"https://api.github.com/repos/{repository}/git/trees/{commit}?recursive=1", max_bytes=MAX_INVENTORY))
            if not isinstance(tree, dict) or tree.get("truncated") or not isinstance(tree.get("tree"), list):
                raise ValueError("upstream notice tree is incomplete")
            for entry in tree["tree"]:
                path = _path(entry["path"])
                if entry.get("type") != "blob" or not _notice(path, manifest.get("license", "")):
                    continue
                url = f"https://raw.githubusercontent.com/{repository}/{commit}/{path}"
                body = fetch(url, max_bytes=MAX_TEXT)
                blob = b"blob " + str(len(body)).encode() + b"\x00" + body
                if hashlib.sha1(blob, usedforsecurity=False).hexdigest() != entry["sha"]:
                    raise ValueError("upstream Cargo notice differs from pinned Git blob")
                results[url] = (body, "pinned_upstream_file")
            if results:
                return results
        except (OSError, ValueError, KeyError, TypeError):
            # The immutable source archive also works when public API quotas
            # are exhausted. No mutable branch or guessed release is used.
            url = f"https://codeload.github.com/{repository}/tar.gz/{commit}"
            try:
                _, _, files = _archive(fetch(url, max_bytes=MAX_ARCHIVE))
                results.update({url + "#" + path: (body, "pinned_upstream_file")
                                for path, (body, _) in files.items()})
                if results:
                    return results
            except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
                continue
    return results



def _published_payload(raw, *, generated_manifest=True):
    """Hash all shipped regular files, retaining the original manifest identity.

    _archive validates paths, duplicates and expansion before this bounded pass.
    Cargo generates the normalized manifest, lockfile and VCS receipt; those
    cannot be compared byte for byte to an upstream working tree.
    """
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r|gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            relative = str(PurePosixPath(*_path(member.name).parts[1:]))
            if relative in {"Cargo.lock", ".cargo_vcs_info.json"} or (generated_manifest and relative == "Cargo.toml"):
                continue
            if relative == "Cargo.toml.orig":
                relative = "Cargo.toml"
            digest = hashlib.sha256()
            with archive.extractfile(member) as stream:
                while block := stream.read(128 * 1024):
                    digest.update(block)
            result[relative] = digest.hexdigest()
    return result


def _matched_upstream(raw, metadata, fetch):
    """Recover notices only when every published payload file still matches.

    Older crates can omit VCS metadata and exclude LICENSE from their package.
    The current upstream commit is only a discovery candidate: a missing or
    changed original manifest or payload prevents reuse of its notice texts.
    """
    payload = _published_payload(raw)
    if "Cargo.toml" not in payload or len(payload) < 2:
        return {}, None
    for field in ("repository", "homepage"):
        repository = _github_repo(metadata.get(field))
        if not repository:
            continue
        try:
            commits = json.loads(fetch(f"https://api.github.com/repos/{repository}/commits?per_page=1", max_bytes=MAX_INVENTORY))
            commit = commits[0]["sha"]
            if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
                raise ValueError("upstream discovery did not return an immutable commit")
            url = f"https://codeload.github.com/{repository}/tar.gz/{commit}"
            source = fetch(url, max_bytes=MAX_ARCHIVE)
            _, _, notices = _archive(source)
            upstream = _published_payload(source, generated_manifest=False)
            if any(upstream.get(path) != digest for path, digest in payload.items()):
                continue
            if notices:
                proof = {"repository": repository, "commit": commit,
                         "archive_sha256": hashlib.sha256(source).hexdigest(),
                         "matched_files": [{"path": path, "sha256": payload[path]} for path in sorted(payload)],
                         "scope": "all published payload files and original manifest; not build correspondence"}
                return {url + "#" + path: (body, "source_matched_upstream_file")
                        for path, (body, _) in notices.items()}, proof
        except (OSError, ValueError, KeyError, TypeError, IndexError, tarfile.TarError, EOFError):
            continue
    return {}, None


def _candidate(package, fetch, header_reader):
    result = {key: package.get(key, "") for key in ("name", "version", "source")}
    result.update(status="unavailable", notices=[])
    try:
        name, version, source = (package[key] for key in ("name", "version", "source"))
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or not re.fullmatch(r"[A-Za-z0-9.+-]+", version):
            raise ValueError("invalid Cargo source identity")
        if source == REGISTRY:
            checksum = package.get("checksum", "")
            if not re.fullmatch(r"[a-f0-9]{64}", checksum):
                raise ValueError("registry dependency has no pinned SHA-256")
            url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
        elif source.startswith("git+https://"):
            parsed = urllib.parse.urlsplit(source[4:])
            repository = _github_repo(source[4:])
            if not repository or not re.fullmatch(r"[a-f0-9]{40}", parsed.fragment):
                raise ValueError("unsupported or unpinned Git dependency")
            checksum = None
            url = f"https://codeload.github.com/{repository}/tar.gz/{parsed.fragment}"
        else:
            raise ValueError("unsupported Cargo source registry")
        raw = fetch(url, max_bytes=MAX_ARCHIVE)
        digest = hashlib.sha256(raw).hexdigest()
        if checksum is not None and digest != checksum:
            raise ValueError("crate archive differs from Cargo.lock checksum")
        result.update(archive_url=url, archive_sha256=digest)
        manifests, vcs, notices = _archive(raw, header_reader)
        metadata = next((m["package"] for m in manifests.values() if m.get("package", {}).get("name") == name), None)
        if metadata is None:
            raise ValueError("archive does not identify the locked crate")
        actual_version = metadata.get("version")
        if isinstance(actual_version, dict) and actual_version.get("workspace"):
            versions = {m.get("workspace", {}).get("package", {}).get("version") for m in manifests.values()
                        if isinstance(m.get("workspace", {}).get("package", {}).get("version"), str)}
            actual_version = next(iter(versions)) if len(versions) == 1 else None
        if actual_version != version:
            raise ValueError("archive version differs from locked crate")
        declared = metadata.get("license")
        if isinstance(declared, dict) and declared.get("workspace"):
            values = {m.get("workspace", {}).get("package", {}).get("license") for m in manifests.values()
                      if isinstance(m.get("workspace", {}).get("package", {}).get("license"), str)}
            declared = next(iter(values)) if len(values) == 1 else None
        result["license_declared"] = declared
        if not notices:
            notices = _upstream(metadata, vcs, fetch)
        if not notices and not vcs:
            notices, proof = _matched_upstream(raw, metadata, fetch)
            if proof is not None:
                result["notice_source_match"] = proof
        if not notices and source == REGISTRY:
            from debian_cargo_notices import recover_debian_notice
            proof, body = recover_debian_notice(name, version, raw, declared, metadata.get("repository"), fetch)
            if proof is not None:
                result["distributor_notice"] = proof
                notices = {proof["packaging_archive_url"] + "#debian/copyright": (body, "debian_distributor_notice")}
        contents = {}
        for path, (body, origin) in notices.items():
            body.decode("utf-8")
            if not body.strip() or b"\x00" in body or len(body) > MAX_TEXT:
                raise ValueError("invalid Cargo notice text")
            sha = hashlib.sha256(body).hexdigest()
            if sha not in contents:
                result["notices"].append({"source_member": path, "sha256": sha, "origin": origin})
                contents[sha] = body
        result["status"] = ("distributor_notice_captured" if result.get("distributor_notice") else "notice_candidates_captured") if contents else "metadata_only"
        if not contents:
            result["gap"] = "No original notice text located; publisher license declaration retained"
        return result, contents
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, EOFError, RecursionError, http.client.HTTPException) as error:
        result["error"] = type(error).__name__ + ": " + str(error)[:400]
        return result, {}


def collect_cargo_notices(lock, fetch, header_reader=None):
    document = tomllib.loads(lock.decode("utf-8"))
    packages = document.get("package")
    if not isinstance(packages, list) or len(packages) > 5000:
        raise ValueError("invalid or oversized Cargo lock inventory")
    external = [package for package in packages if "source" in package]
    keys = [(p["name"], p["version"], p["source"]) for p in external]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate locked Cargo identity")
    rows, contents = [], {}
    with ThreadPoolExecutor(max_workers=4) as workers:
        for row, texts in workers.map(lambda package: _candidate(package, fetch, header_reader), external):
            rows.append(row)
            contents.update({"LICENSE-" + sha + ".txt": body for sha, body in texts.items()})
            if sum(map(len, contents.values())) > MAX_NOTICE_TOTAL:
                raise ValueError("Cargo notices exceed aggregate text budget")
    inventory = {"format": "raptor-cargo-source-inventory", "version": 1,
                 "lock_sha256": hashlib.sha256(lock).hexdigest(), "packages": rows,
                 "workspace_entries": len(packages) - len(external),
                 "scope": "External lockfile candidates, including build, development and other-platform dependencies; not an installed component inventory.",
                 "limitations": ["Compiled dependency membership and Rust standard-library completeness are not established."]}
    raw = (json.dumps(inventory, indent=2, ensure_ascii=True) + "\n").encode()
    if len(raw) > MAX_INVENTORY:
        raise ValueError("Cargo source inventory exceeds byte budget")
    records = [{"file": filename, "sha256": filename[8:-4]} for filename in sorted(contents)]
    summary = {"candidates": len(rows), "captured": sum(r["status"] in {"notice_candidates_captured", "distributor_notice_captured"} for r in rows),
               "metadata_only": sum(r["status"] == "metadata_only" for r in rows),
               "unavailable": sum(r["status"] == "unavailable" for r in rows), "scope": "external Cargo.lock candidates"}
    if any(r["status"] == "distributor_notice_captured" for r in rows):
        summary["distributor_notices"] = sum(r["status"] == "distributor_notice_captured" for r in rows)
    return CargoNotices(records, contents, raw, summary)
