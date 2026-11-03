"""Publication tooling is checksum-pinned and never extracts archive paths."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("install_sbom_tools", ROOT / ".github/scripts/install_sbom_tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLS)


def archive(*, duplicate=False, symlink=False):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as output:
        for _ in range(2 if duplicate else 1):
            info = tarfile.TarInfo("syft")
            payload = b"verified executable bytes"
            info.size = len(payload)
            if symlink:
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                info.size = 0
            output.addfile(info, io.BytesIO(payload))
    return stream.getvalue()


def pins(raw):
    return {"schema_version": 1, "syft": {"url": "https://example.invalid/syft.tgz",
            "sha256": hashlib.sha256(raw).hexdigest(), "member": "syft"}}


def test_valid_archive_installs_only_verified_executable(tmp_path, monkeypatch):
    raw = archive()
    monkeypatch.setattr(TOOLS, "urlopen", lambda *args, **kwargs: io.BytesIO(raw))
    out = tmp_path / "tools"
    TOOLS.install(pins(raw), out)
    assert list(out.iterdir()) == [out / "syft"]
    assert (out / "syft").read_bytes() == b"verified executable bytes"
    assert (out / "syft").stat().st_mode & 0o777 == 0o755


@pytest.mark.parametrize("problem", ["transport", "hash", "member", "schema"])
def test_invalid_pins_never_download_or_create_outputs(tmp_path, monkeypatch, problem):
    source = pins(archive())
    if problem == "transport": source["syft"]["url"] = "http://example.invalid/syft.tgz"
    elif problem == "hash": source["syft"]["sha256"] = "bad"
    elif problem == "member": source["syft"]["member"] = "../syft"
    else: source["schema_version"] = True
    monkeypatch.setattr(TOOLS, "urlopen", lambda *args, **kwargs: pytest.fail("must not download"))
    out = tmp_path / "tools"
    with pytest.raises(ValueError): TOOLS.install(source, out)
    assert not out.exists()


@pytest.mark.parametrize("problem", ["tampered", "oversize", "duplicate", "symlink", "existing"])
def test_invalid_archives_leave_no_partial_tool(tmp_path, monkeypatch, problem):
    raw = archive(duplicate=problem == "duplicate", symlink=problem == "symlink")
    source = pins(raw)
    if problem == "tampered": raw += b"changed"
    elif problem == "oversize": monkeypatch.setattr(TOOLS, "MAX_BYTES", 8)
    monkeypatch.setattr(TOOLS, "urlopen", lambda *args, **kwargs: io.BytesIO(raw))
    out = tmp_path / "tools"
    if problem == "existing": out.mkdir()
    with pytest.raises(ValueError): TOOLS.install(source, out)
    assert not (out / "syft").exists()
