"""Verified upstream declarations and standard reference copies stay distinct."""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("npm_reference_refresh", ROOT / ".devcontainer/refresh-npm-notices.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def setup(tmp_path, monkeypatch, version="1.0.0", license="ISC"):
    installed = {"name": "@npmcli/agent", "version": version, "license": license, "author": "GitHub Inc."}
    raw = json.dumps(installed).encode()
    (tmp_path / "package.json").write_bytes(raw)
    source = {"package/package.json": raw}
    metadata = {**installed, "dist": {"tarball": "https://registry.npmjs.org/agent.tgz", "integrity": "checked"}, "gitHead": "a" * 40}
    reference = json.dumps({"licenseId": "ISC", "licenseText": "Verbatim standard reference text."}).encode()
    entry = {"name": "@npmcli/agent", "version": "1.0.0", "license": "ISC", "status": "unresolved",
             "source_kind": "declared_spdx_reference", "reference_license_id": "ISC",
             "installed_filename": "NOTICE", "license_reference_url": "https://raw.githubusercontent.com/spdx/reference",
             "license_reference_sha256": hashlib.sha256(reference).hexdigest()}
    monkeypatch.setattr(tool, "fetch", lambda url: reference if url == entry["license_reference_url"] else json.dumps(metadata).encode())
    monkeypatch.setattr(tool, "checked_release", lambda data: (b"release", source))
    return entry, installed, source, metadata


@pytest.mark.parametrize("version", ["1.0.0", "1.0.1"])
def test_reference_refreshes_versions_with_original_attribution(tmp_path, monkeypatch, version):
    entry, installed, _, _ = setup(tmp_path, monkeypatch, version)
    updated, notice = tool.refresh_entry(entry, tmp_path, installed)
    assert updated["status"] == "declaration_and_standard_text_retained"
    assert updated["version"] == version
    assert updated["verified_installed_files"] == 1
    assert updated["sha256"] == hashlib.sha256(notice).hexdigest()
    assert b"GitHub Inc." in notice
    assert b"not an\nupstream-authored package notice" in notice
    assert notice.endswith(b"Verbatim standard reference text.")
    assert "upstream-authored package notice" in updated["scope"]


def test_changed_license_becomes_an_explicit_gap_without_reusing_isc(tmp_path, monkeypatch):
    entry, installed, _, _ = setup(tmp_path, monkeypatch, "2.0.0", "MIT")
    updated, notice = tool.refresh_entry(entry, tmp_path, installed)
    assert notice is None
    assert updated["license"] == "MIT" and updated["status"] == "unresolved"
    assert "Declaration changed" in updated["reason"]


def test_modified_payload_is_refused_before_reference_is_added(tmp_path, monkeypatch):
    entry, installed, source, _ = setup(tmp_path, monkeypatch)
    (tmp_path / "index.js").write_text("modified")
    source["package/index.js"] = b"original"
    with pytest.raises(ValueError, match="payload differs"):
        tool.refresh_entry(entry, tmp_path, installed)


def test_wrong_reference_hash_is_refused(tmp_path, monkeypatch):
    entry, installed, _, _ = setup(tmp_path, monkeypatch)
    entry["license_reference_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="reference checksum"):
        tool.refresh_entry(entry, tmp_path, installed)


def test_wrong_reference_identifier_is_refused(tmp_path, monkeypatch):
    entry, _, _, metadata = setup(tmp_path, monkeypatch)
    reference = json.dumps({"licenseId": "MIT", "licenseText": "Wrong terms"}).encode()
    entry["license_reference_sha256"] = hashlib.sha256(reference).hexdigest()
    monkeypatch.setattr(tool, "fetch", lambda url: reference)
    with pytest.raises(ValueError, match="differs from upstream"):
        tool.declared_reference_notice(entry, metadata, metadata)
