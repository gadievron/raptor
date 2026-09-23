"""CLI tests for libexec/raptor-stage-hints.

The helper PRINTS staging commands for the operator and verifies a
staged copy — it must never execute privilege escalation, and every
filesystem-derived path it prints must be rendered escaped.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-stage-hints"


def _run(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, env=env, timeout=60,
    )


def test_script_never_shells_out():
    # Static containment pin: the helper prints commands, it must
    # not grow a code path that runs them (no subprocess / os.system
    # / exec family anywhere in the script).
    text = SCRIPT.read_text()
    for banned in ("subprocess", "os.system", "os.exec",
                   "os.spawn", "pty.", "popen"):
        assert banned not in text, banned


def test_readable_path_reports_no_staging(tmp_path):
    target = tmp_path / "bin"
    target.mkdir()
    (target / "a").write_bytes(b"x")
    proc = _run(str(target))
    assert proc.returncode == 0
    assert "no staging needed" in proc.stdout


def test_missing_path_is_a_usage_error(tmp_path):
    proc = _run(str(tmp_path / "nope"))
    assert proc.returncode == 2
    assert "no such path" in proc.stdout


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads everything")
def test_unreadable_path_prints_recipe_and_never_executes(tmp_path):
    target = tmp_path / "locked"
    target.mkdir()
    (target / "f").write_bytes(b"x")
    target.chmod(0o000)
    try:
        proc = _run(str(target), "--dest", str(tmp_path / "durable"))
    finally:
        target.chmod(0o755)
    assert proc.returncode == 0
    assert "sudo cp -a --" in proc.stdout
    assert "sudo chown -R" in proc.stdout
    assert "never executes" in proc.stdout
    # printing, not doing: nothing was staged
    assert not (tmp_path / "durable").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads everything")
def test_hostile_path_bytes_are_escaped(tmp_path):
    name = "evil\x1b[31m"
    target = tmp_path / name
    target.mkdir()
    target.chmod(0o000)
    try:
        proc = _run(str(target))
    finally:
        target.chmod(0o755)
    assert "\x1b[31m" not in proc.stdout
    assert "\\x1b" in proc.stdout
    assert "non-printable" in proc.stdout


def test_verify_complete_copy(tmp_path):
    original = tmp_path / "orig"
    (original / "sub").mkdir(parents=True)
    (original / "a.bin").write_bytes(b"12345")
    (original / "sub" / "b.bin").write_bytes(b"67")
    staged = tmp_path / "staged"
    import shutil
    shutil.copytree(original, staged)
    proc = _run(str(original), "--verify", str(staged))
    assert proc.returncode == 0
    assert "covers every readable original entry" in proc.stdout


def test_verify_reports_missing_and_mismatched(tmp_path):
    original = tmp_path / "orig"
    original.mkdir()
    (original / "a.bin").write_bytes(b"12345")
    (original / "b.bin").write_bytes(b"999")
    staged = tmp_path / "staged"
    staged.mkdir()
    (staged / "b.bin").write_bytes(b"9")  # truncated copy
    proc = _run(str(original), "--verify", str(staged))
    assert proc.returncode == 1
    assert "missing in staged copy: a.bin" in proc.stdout
    assert "size mismatch: b.bin" in proc.stdout
    assert "INCOMPLETE" in proc.stdout


def test_verify_single_file_by_size(tmp_path):
    # Basenames legitimately differ for single-file staging; the
    # comparison is size-level.
    original = tmp_path / "one.bin"
    original.write_bytes(b"abc")
    staged = tmp_path / "copy.bin"
    staged.write_bytes(b"abc")
    proc = _run(str(original), "--verify", str(staged))
    assert proc.returncode == 0
    assert "matches the original size" in proc.stdout

    staged.write_bytes(b"a")
    proc = _run(str(original), "--verify", str(staged))
    assert proc.returncode == 1
    assert "INCOMPLETE" in proc.stdout


def test_fifo_probe_never_blocks_or_stages(tmp_path):
    # open()+read(1) on a FIFO blocks forever; the probe must
    # lstat-classify and refuse without opening. The subprocess
    # timeout is the hang oracle.
    fifo = tmp_path / "pipe"
    try:
        os.mkfifo(fifo)
    except (OSError, AttributeError):
        pytest.skip("mkfifo unavailable")
    proc = _run(str(fifo))
    assert proc.returncode == 2
    assert "not a regular file" in proc.stdout
    assert "staging does not apply" in proc.stdout


def test_verify_refuses_symlinked_staged_root(tmp_path):
    original = tmp_path / "orig"
    original.mkdir()
    (original / "a").write_bytes(b"x")
    real = tmp_path / "real"
    real.mkdir()
    (real / "a").write_bytes(b"x")
    staged = tmp_path / "staged"
    staged.symlink_to(real)
    proc = _run(str(original), "--verify", str(staged))
    assert proc.returncode == 2
    assert "symlink" in proc.stdout
    assert "refusing" in proc.stdout


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads everything")
def test_symlink_target_gets_link_hint(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o000)
    link = tmp_path / "link"
    link.symlink_to(locked)
    try:
        proc = _run(str(link), "--dest", str(tmp_path / "d"))
    finally:
        locked.chmod(0o755)
    assert proc.returncode == 0
    assert "SYMLINK" in proc.stdout
    assert "stages the link" in proc.stdout


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads everything")
def test_recipe_uses_no_dereference_chown_and_notes_toctou(tmp_path):
    target = tmp_path / "locked"
    target.mkdir()
    target.chmod(0o000)
    try:
        proc = _run(str(target), "--dest", str(tmp_path / "d"))
    finally:
        target.chmod(0o755)
    # -h: a symlink inside the staged hostile tree must never steer
    # ownership changes onto its target outside the tree.
    assert "chown -R -h" in proc.stdout
    assert "TOCTOU" in proc.stdout


def test_verify_counts_staged_extras(tmp_path):
    original = tmp_path / "orig"
    original.mkdir()
    (original / "a").write_bytes(b"x")
    staged = tmp_path / "staged"
    staged.mkdir()
    (staged / "a").write_bytes(b"x")
    (staged / "planted").write_bytes(b"y")
    proc = _run(str(original), "--verify", str(staged))
    assert proc.returncode == 0
    assert "1 entr(ies) not present in the readable original" in proc.stdout


def test_verify_unreadable_original_degrades_honestly(tmp_path):
    staged = tmp_path / "staged"
    staged.mkdir()
    (staged / "a").write_bytes(b"x")
    proc = _run(str(tmp_path / "gone"), "--verify", str(staged))
    assert proc.returncode == 0
    assert "cannot compare" in proc.stdout
    assert "best-effort" in proc.stdout
