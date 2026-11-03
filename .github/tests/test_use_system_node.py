"""Container runtime cleanup preserves Playwright and installation integrity."""
import base64
import csv
import hashlib
import importlib.util
import io
from pathlib import Path, PurePosixPath
import subprocess
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("use_system_node", ROOT / ".devcontainer/use-system-node.py")
NODE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NODE)


@pytest.fixture(autouse=True)
def linux_image_policy(monkeypatch):
    monkeypatch.setattr(NODE, "sys", SimpleNamespace(platform="linux"))


@pytest.fixture
def installation(tmp_path, monkeypatch):
    executable = tmp_path / "playwright/driver/node"
    executable.parent.mkdir(parents=True)
    payload = b"\x7fELFexample node runtime"
    executable.write_bytes(payload)
    cli = executable.parent / "package/cli.js"
    cli.parent.mkdir()
    cli.write_text("driver")
    record = tmp_path / "playwright-1.dist-info/RECORD"
    record.parent.mkdir()
    digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
    out = io.StringIO(newline="")
    csv.writer(out).writerows([
        ["playwright/driver/node", "sha256=" + digest, str(len(payload))],
        ["playwright/driver/package/cli.js", "retained", "6"],
        ["playwright-1.dist-info/RECORD", "", ""],
    ])
    record.write_text(out.getvalue())
    dist = SimpleNamespace(locate_file=lambda path: tmp_path / str(path),
                           files=[PurePosixPath("playwright-1.dist-info/RECORD")])
    calls = []
    monkeypatch.setenv("PLAYWRIGHT_NODEJS_PATH", "/usr/bin/node")
    monkeypatch.setattr(NODE.subprocess, "run", lambda *args, **kwargs: calls.append((args, kwargs)))
    return dist, executable, record, cli, calls


def test_removes_only_verified_binary_and_record_row(installation):
    dist, executable, record, cli, calls = installation
    mode = record.stat().st_mode
    NODE.configure(dist)
    assert not executable.exists()
    assert cli.read_text() == "driver"
    assert list(csv.reader(io.StringIO(record.read_text()))) == [
        ["playwright/driver/package/cli.js", "retained", "6"],
        ["playwright-1.dist-info/RECORD", "", ""],
    ]
    assert record.stat().st_mode == mode
    assert calls[0][0][0] == ["/usr/bin/node", str(cli), "--version"]
    assert calls[0][1] == {"check": True, "timeout": 30}
    NODE.configure(dist, check=True)
    NODE.configure(dist)
    assert not list(record.parent.glob(".playwright-record-*"))


@pytest.mark.parametrize("problem", ["changed", "missing", "duplicate", "symlink", "not-elf", "check"])
def test_refuses_unverified_or_remaining_binary_without_changes(installation, problem):
    dist, executable, record, _, _ = installation
    if problem == "changed":
        executable.write_bytes(b"\x7fELFchanged")
    elif problem == "missing":
        executable.unlink()
    elif problem == "duplicate":
        record.write_text(record.read_text() * 2)
    elif problem == "symlink":
        target = executable.with_suffix(".other")
        executable.rename(target)
        executable.symlink_to(target)
    elif problem == "not-elf":
        executable.write_bytes(b"not an executable")
    before = record.read_bytes()
    with pytest.raises(ValueError):
        NODE.configure(dist, check=problem == "check")
    assert record.read_bytes() == before
    if problem != "missing":
        assert executable.exists()


@pytest.mark.parametrize("problem", ["windows", "override", "driver"])
def test_failed_runtime_validation_preserves_bundle(installation, monkeypatch, problem):
    dist, executable, record, _, _ = installation
    before = record.read_bytes()
    if problem == "windows":
        monkeypatch.setattr(NODE.sys, "platform", "win32")
    elif problem == "override":
        monkeypatch.delenv("PLAYWRIGHT_NODEJS_PATH")
    else:
        def fail(*args, **kwargs):
            raise subprocess.CalledProcessError(1, args[0])
        monkeypatch.setattr(NODE.subprocess, "run", fail)
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        NODE.configure(dist)
    assert executable.exists()
    assert record.read_bytes() == before


def test_build_and_publication_keep_override_and_check_candidate():
    dockerfile = (ROOT / ".devcontainer/Dockerfile").read_text()
    configured = dockerfile.index("ENV PLAYWRIGHT_NODEJS_PATH=/usr/bin/node")
    assert dockerfile.index("nodejs=") < configured
    assert configured < dockerfile.index("RUN python3 /usr/local/libexec/use-system-node.py")
    assert "refresh-node-notices.py" not in dockerfile
    workflow = (ROOT / ".github/workflows/dockerhub-publish.yml").read_text()
    assert workflow.index("use-system-node.py --check") < workflow.index("- name: Publish verified image")
