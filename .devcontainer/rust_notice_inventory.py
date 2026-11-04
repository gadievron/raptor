"""Retain Rust standard-library notice candidates for a source-declared release.

These texts cover the selected Rust release, not verified compiled membership
or correspondence between the installed executable and a compiler build.
No toolchain is installed and no archive member is executed or extracted.
"""
import hashlib
import http.client
import io
import json
import lzma
from pathlib import PurePosixPath
import re
import tarfile
import tomllib
import urllib.parse

MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_TEXT = 512 * 1024
MAX_MANIFEST = 4 * 1024 * 1024
TARGET = "x86_64-unknown-linux-gnu"


def collect_rust_notices(declaration, fetch):
    receipt = {"status": "unavailable", "scope": "source-declared Rust release standard-library notices; not compiled membership or build correspondence"}
    records, contents = [], {}
    try:
        channel = tomllib.loads(declaration.decode("utf-8"))["toolchain"]["channel"]
        if not isinstance(channel, str) or not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", channel):
            raise ValueError("Rust toolchain must declare a numeric release")
        receipt.update(channel=channel, declaration_sha256=hashlib.sha256(declaration).hexdigest())
        url = f"https://static.rust-lang.org/dist/channel-rust-{channel}.toml"
        manifest = fetch(url, max_bytes=MAX_MANIFEST)
        if len(manifest) > MAX_MANIFEST:
            raise ValueError("Rust release manifest exceeds byte budget")
        package = tomllib.loads(manifest.decode("utf-8"))["pkg"]["rustc"]
        version = package["version"].split()[0]
        if (not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
                or (channel.count(".") == 2 and version != channel)
                or (channel.count(".") == 1 and not version.startswith(channel + "."))):
            raise ValueError("Rust release manifest identifies a different compiler")
        receipt["version"] = version
        target = package["target"][TARGET]
        archive_url, expected = target["xz_url"], target["xz_hash"]
        parsed = urllib.parse.urlsplit(archive_url)
        filename = f"rustc-{version}-{TARGET}.tar.xz"
        if (target.get("available") is not True or parsed.scheme != "https" or parsed.netloc != "static.rust-lang.org"
                or parsed.query or parsed.fragment or not re.fullmatch(r"/dist/(?:[0-9]{4}-[0-9]{2}-[0-9]{2}/)?" + re.escape(filename), parsed.path)
                or not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected)):
            raise ValueError("invalid Rust release archive identity")
        raw = fetch(archive_url, max_bytes=MAX_ARCHIVE)
        if len(raw) > MAX_ARCHIVE or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("Rust archive differs from release checksum or exceeds budget")
        receipt.update(manifest_url=url, manifest_sha256=hashlib.sha256(manifest).hexdigest(), archive_url=archive_url, archive_sha256=expected)
        prefix = f"rustc-{version}-{TARGET}/"
        required = {"LICENSE-APACHE", "LICENSE-MIT", "COPYRIGHT", "rustc/share/doc/rust/COPYRIGHT-library.html"}
        found, seen, total = set(), set(), 0
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r|xz") as archive:
            for index, member in enumerate(archive):
                total += member.size
                name = member.name.rstrip("/")
                path = PurePosixPath(name)
                if (index >= 1000 or total > MAX_EXPANDED or path.is_absolute() or ".." in path.parts
                        or "\\" in name or str(path) != name or not (name.startswith(prefix) or (member.isdir() and name == prefix.rstrip("/"))) or name in seen):
                    raise ValueError("unsafe, ambiguous or oversized Rust archive")
                seen.add(name)
                relative = name[len(prefix):]
                if relative not in required:
                    continue
                if not member.isfile() or member.size > MAX_TEXT:
                    raise ValueError("Rust library notice is not a bounded regular file")
                with archive.extractfile(member) as stream:
                    body = stream.read(MAX_TEXT + 1)
                body.decode("utf-8")
                if not body.strip() or b"\x00" in body or len(body) > MAX_TEXT:
                    raise ValueError("invalid Rust library notice text")
                sha = hashlib.sha256(body).hexdigest()
                filename = "LICENSE-" + sha + ".txt"
                records.append({"file": filename, "sha256": sha, "source_member": relative,
                                "notice_origin": "rust_release_library_notice", "source_url": archive_url,
                                "source_archive_sha256": expected})
                contents[filename] = body
                found.add(relative)
        if found != required:
            raise ValueError("Rust release lacks required standard-library notice files")
        evidence = json.dumps({"format": "raptor-rust-release-evidence", "version": 1,
                               "manifest_url": url, "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                               "manifest_toml": manifest.decode("utf-8")}, ensure_ascii=True).encode()
        if len(evidence) > MAX_MANIFEST:
            raise ValueError("retained Rust release evidence exceeds byte budget")
        sha = hashlib.sha256(evidence).hexdigest()
        filename = "NOTICE-SOURCE-SBOM-" + sha + ".json"
        records.append({"file": filename, "sha256": sha, "content_kind": "source_sbom",
                        "scope": "Rust release metadata, not installed package inventory"})
        contents[filename] = evidence
        receipt.update(status="release_library_notices_captured", notice_files=len(found))
        return records, contents, receipt
    except (OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, tarfile.TarError, EOFError, lzma.LZMAError, http.client.HTTPException) as error:
        receipt["error"] = type(error).__name__ + ": " + str(error)[:500]
        return [], {}, receipt
