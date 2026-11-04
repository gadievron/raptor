"""Native publisher archives are streamed, integrity checked and never extracted."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("npm_native", ROOT / ".devcontainer/collect-npm-native-notices.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
PACKAGE = {"name": "@anthropic-ai/claude-code-linux-x64", "version": "1.0.0", "license": "SEE LICENSE IN LICENSE.md"}
PAYLOAD = b"\x7fELF" + b"native payload" * 100


def archive(extra=()):
    result = io.BytesIO()
    rows = [("package/package.json", json.dumps(PACKAGE).encode()),
            ("package/LICENSE.md", b"publisher license grant"), ("package/claude", PAYLOAD), *extra]
    with tarfile.open(fileobj=result, mode="w:gz") as tar:
        for name, body in rows:
            entry = tarfile.TarInfo(name)
            entry.size = len(body)
            tar.addfile(entry, io.BytesIO(body))
    return result.getvalue()


def sri(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def test_release_returns_payload_hash_and_notices_without_retaining_binary():
    data = archive()
    files, notices, metadata, digest = tool.release(io.BytesIO(data), sri(data))
    assert metadata == PACKAGE
    assert files["claude"]["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
    assert files["claude"]["elf"]
    assert list(notices) == ["LICENSE.md"]
    assert digest == hashlib.sha256(data).hexdigest()
    assert all(not isinstance(value, bytes) for value in files["claude"].values())


@pytest.mark.parametrize("change", ["integrity", "trailing", "duplicate", "traversal", "archive_budget", "expansion_budget"])
def test_bad_archives_never_produce_identity_evidence(change, monkeypatch):
    data = archive()
    integrity = sri(data)
    if change == "integrity":
        integrity = sri(b"different release")
    elif change == "trailing":
        data += b"changed trailing bytes" * 1000
    elif change == "duplicate":
        data = archive([("package/claude", b"different")])
        integrity = sri(data)
    elif change == "traversal":
        data = archive([("package/../outside", b"data")])
        integrity = sri(data)
    elif change == "archive_budget":
        monkeypatch.setattr(tool, "MAX_ARCHIVE", 10)
    else:
        monkeypatch.setattr(tool, "MAX_EXPANDED", 10)
    with pytest.raises(ValueError):
        tool.release(io.BytesIO(data), integrity)


@pytest.mark.parametrize("changed", [False, True])
def test_installed_payload_must_match_release_and_stale_evidence_is_cleared(tmp_path, monkeypatch, changed):
    root = tmp_path / "claude-code-linux-x64"
    root.mkdir()
    (root / "package.json").write_text(json.dumps(PACKAGE))
    (root / "claude").write_bytes(b"modified payload" if changed else PAYLOAD)
    data = archive()
    registry = dict(PACKAGE, dist={"tarball": "https://registry.npmjs.org/package.tgz", "integrity": sri(data)})
    monkeypatch.setattr(tool, "metadata", lambda url: registry)
    monkeypatch.setattr(tool.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(data))
    output = tmp_path / "notices"
    destination = output / root.name
    destination.mkdir(parents=True)
    (destination / "LICENSE-old.txt").write_text("stale")
    result = tool.collect(root, output)
    assert result["status"] == ("unavailable" if changed else "release_notice_candidates_captured")
    assert not (destination / "LICENSE-old.txt").exists()
    if changed:
        assert not result["files"]
    else:
        assert result["binary_sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
