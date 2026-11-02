"""Bundled Node notices track verified release bytes across upgrades."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "refresh_node_notices", ROOT / ".devcontainer/refresh-node-notices.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def release(
    binary=b"new node",
    notice=b"new complete notices",
    *,
    kind="regular",
    alias=False,
    extra=b"",
):
    stream = io.BytesIO()
    prefix = "node-v24.16.0-linux-x64/"
    with tarfile.open(fileobj=stream, mode="w:xz") as archive:
        for name, data in [("bin/node", binary), ("LICENSE", notice), ("extra", extra)]:
            path = prefix + name
            if alias and name == "LICENSE":
                path = prefix + "./LICENSE"
            member = tarfile.TarInfo(path)
            member.size = len(data)
            if name == "LICENSE" and kind == "symlink":
                member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
                member.size = 0
            if name == "LICENSE" and kind == "missing":
                continue
            archive.addfile(member, io.BytesIO(data))
            if name == "LICENSE" and kind == "duplicate":
                archive.addfile(member, io.BytesIO(data))
    return stream.getvalue()


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    node = tmp_path / "playwright/driver/node"
    node.parent.mkdir(parents=True)
    node.write_bytes(b"old node")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    notice = b"old complete notices including third-party terms"
    (evidence / "LICENSE").write_bytes(notice)
    url, sums = MODULE.urls("24.15.0", "linux-x64")
    receipt = {
        "schema_version": 1,
        "name": "node",
        "version": "24.15.0",
        "platform": "linux-x64",
        "binary_sha256": sha(b"old node"),
        "notice_sha256": sha(notice),
        "source_archive_sha256": "b" * 64,
        "source_archive_url": url,
        "checksums_url": sums,
    }
    (evidence / "provenance.json").write_text(json.dumps(receipt))
    monkeypatch.setattr(MODULE, "runtime_platform", lambda: "linux-x64")

    def forbidden(*args, **kwargs):
        pytest.fail("unchanged evidence must not execute Node or access the network")

    monkeypatch.setattr(MODULE, "fetch", forbidden)
    monkeypatch.setattr(MODULE, "node_version", forbidden)
    return node, evidence, receipt


def updated(fixture, monkeypatch, *, archive=None, sums=None):
    node, evidence, receipt = fixture
    node.write_bytes(b"new node")
    monkeypatch.setattr(MODULE, "node_version", lambda path: "24.16.0")
    data = archive if archive is not None else release()
    url, checksums = MODULE.urls("24.16.0", "linux-x64")
    text = (
        sums
        if sums is not None
        else (sha(data) + "  " + url.rsplit("/", 1)[-1] + "\n").encode()
    )
    calls = []

    def fetch(url_arg, limit):
        calls.append(url_arg)
        return text if url_arg == checksums else data

    monkeypatch.setattr(MODULE, "fetch", fetch)
    return calls


def test_unchanged_evidence_installs_full_notice_without_network_or_execution(fixture):
    node, evidence, _ = fixture
    assert MODULE.refresh(node, evidence) == "cached"
    assert (
        node.with_name("LICENSE.node").read_bytes()
        == (evidence / "LICENSE").read_bytes()
    )
    assert MODULE.refresh(node, evidence) == "cached"


def test_upgrade_verifies_release_and_reuses_refreshed_evidence(fixture, monkeypatch):
    node, evidence, receipt = fixture
    node.with_name("LICENSE.node").write_bytes((evidence / "LICENSE").read_bytes())
    calls = updated(fixture, monkeypatch)
    assert MODULE.refresh(node, evidence) == "refreshed"
    assert len(calls) == 2
    after = json.loads((evidence / "provenance.json").read_text())
    assert after["version"] == "24.16.0" and after["binary_sha256"] == sha(b"new node")
    assert after["source_archive_sha256"] == sha(release())
    assert node.with_name("LICENSE.node").read_bytes() == b"new complete notices"

    def forbidden(*args, **kwargs):
        pytest.fail("refreshed evidence should be reusable offline")

    monkeypatch.setattr(MODULE, "fetch", forbidden)
    monkeypatch.setattr(MODULE, "node_version", forbidden)
    assert MODULE.refresh(node, evidence) == "cached"


@pytest.mark.parametrize("kind", ["missing", "symlink", "duplicate"])
def test_bad_release_notice_never_changes_seed_or_installs_output(
    fixture, monkeypatch, kind
):
    node, evidence, _ = fixture
    before = (evidence / "provenance.json").read_bytes()
    updated(fixture, monkeypatch, archive=release(kind=kind))
    with pytest.raises(ValueError):
        MODULE.refresh(node, evidence)
    assert (evidence / "provenance.json").read_bytes() == before
    assert not node.with_name("LICENSE.node").exists()


@pytest.mark.parametrize(
    "change",
    [
        "archive-sha",
        "binary-sha",
        "alias",
        "missing-sum",
        "duplicate-sum",
        "empty-license",
    ],
)
def test_unverified_release_evidence_is_refused(fixture, monkeypatch, change):
    data = release(
        binary=b"other node" if change == "binary-sha" else b"new node",
        notice=b"" if change == "empty-license" else b"new complete notices",
        alias=change == "alias",
    )
    line = (sha(data) + "  node-v24.16.0-linux-x64.tar.xz\n").encode()
    sums = {
        "archive-sha": b"a" * 64 + b"  node-v24.16.0-linux-x64.tar.xz\n",
        "missing-sum": b"",
        "duplicate-sum": line + line,
    }.get(change)
    updated(fixture, monkeypatch, archive=data, sums=sums)
    with pytest.raises(ValueError):
        MODULE.refresh(fixture[0], fixture[1])
    assert not fixture[0].with_name("LICENSE.node").exists()


@pytest.mark.parametrize(
    "change",
    [
        "notice",
        "schema",
        "url",
        "sha-format",
        "missing-field",
        "symlink-input",
        "symlink-output",
        "conflicting-output",
    ],
)
def test_invalid_cache_or_destination_is_refused_without_network(fixture, change):
    node, evidence, receipt = fixture
    if change == "notice":
        (evidence / "LICENSE").write_bytes(b"tampered")
    elif change == "schema":
        receipt["schema_version"] = True
    elif change == "url":
        receipt["source_archive_url"] = "https://evil.invalid/node.tar.xz"
    elif change == "sha-format":
        receipt["binary_sha256"] = "not a digest"
    elif change == "missing-field":
        receipt.pop("version")
    elif change == "symlink-input":
        data = (evidence / "LICENSE").read_bytes()
        (evidence / "elsewhere").write_bytes(data)
        (evidence / "LICENSE").unlink()
        (evidence / "LICENSE").symlink_to(evidence / "elsewhere")
    elif change == "symlink-output":
        node.with_name("LICENSE.node").symlink_to(evidence / "LICENSE")
    else:
        node.with_name("LICENSE.node").write_bytes(b"unreviewed notice")
    (evidence / "provenance.json").write_text(json.dumps(receipt))
    with pytest.raises((ValueError, OSError)):
        MODULE.refresh(node, evidence)


def test_runtime_change_during_refresh_is_refused(fixture, monkeypatch):
    node, evidence, _ = fixture
    updated(fixture, monkeypatch)
    fetch = MODULE.fetch

    def changed(url, limit):
        result = fetch(url, limit)
        if url.endswith(".tar.xz"):
            node.write_bytes(b"changed during refresh")
        return result

    monkeypatch.setattr(MODULE, "fetch", changed)
    with pytest.raises(ValueError, match="changed before"):
        MODULE.refresh(node, evidence)
    assert not node.with_name("LICENSE.node").exists()


def test_expansion_budget_covers_members_after_selected_evidence(monkeypatch):
    data = release(extra=b"x" * 200000)
    monkeypatch.setattr(MODULE, "MAX_EXPANDED", 64000)
    with pytest.raises(ValueError, match="expanded"):
        MODULE.release_evidence(data, "24.16.0", "linux-x64")


@pytest.mark.parametrize(
    "url",
    [
        "http://nodejs.org/dist/x",
        "https://evil.invalid/dist/x",
        "https://nodejs.org:444/dist/x",
        "https://user@nodejs.org/dist/x",
        "https://nodejs.org/dist/x?redirect=elsewhere",
        "https://nodejs.org/elsewhere",
    ],
)
def test_redirects_and_downloads_are_confined_to_official_distribution_host(url):
    with pytest.raises(ValueError):
        MODULE.checked_url(url)
    with pytest.raises(ValueError):
        MODULE.NodeRedirect().redirect_request(None, None, 302, "", {}, url)


def test_docker_notice_installation_shares_runtime_install_layer():
    dockerfile = (ROOT / ".devcontainer/Dockerfile").read_text()
    block = next(
        block for block in dockerfile.split("\nRUN ") if "uv export --locked" in block
    )
    assert "/usr/local/libexec/refresh-node-notices.py" in block
    assert "--evidence /usr/share/doc/raptor-node-notices" in block
    assert "COPY .devcontainer/node-notices/" in dockerfile.split("\nRUN ")[
        0
    ] or dockerfile.index("COPY .devcontainer/node-notices/") < dockerfile.index(
        "uv export --locked"
    )


def test_release_version_is_read_from_embedded_metadata_without_execution(tmp_path):
    node = tmp_path / "node"
    node.write_bytes(
        b"binary https://nodejs.org/download/release/v24.15.0/node-v24.15.0.tar.gz\0 payload"
    )
    node.chmod(0o644)
    assert MODULE.node_version(node) == "24.15.0"


@pytest.mark.parametrize(
    "data",
    [
        b"no release metadata",
        b"https://nodejs.org/download/release/v24.15.0/node-v24.16.0.tar.gz\0",
        b"https://nodejs.org/dist/v24.15.0/node-v24.15.0.tar.gz\0https://nodejs.org/dist/v24.16.0/node-v24.16.0.tar.gz\0",
    ],
)
def test_missing_or_conflicting_embedded_release_identity_is_refused(tmp_path, data):
    node = tmp_path / "node"
    node.write_bytes(data)
    with pytest.raises(ValueError, match="metadata"):
        MODULE.node_version(node)
