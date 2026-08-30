"""Tests for ``libexec/raptor-zkpox`` — the operator CLI for
Tier 0/1 bundle assembly + Tier 1.5 reproduction.

Trust-marker rejection, error-path handling (missing/corrupt/
incomplete manifest, non-store dir), and a happy-path
bundle→reproduce walk via the FUZZ replay mode (real binary).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# packages/zkpox/tests/test_libexec_raptor_zkpox.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))


def _mount_ns_usable() -> bool:
    if sys.platform != "linux":
        return False
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl.exists() and sysctl.read_text().strip() == "1":
        return False
    return True


_needs_sandbox = pytest.mark.skipif(
    not _mount_ns_usable(),
    reason="reproduce needs mount-ns sandbox (uidmap + apparmor userns=0)",
)

SCRIPT = REPO / "libexec" / "raptor-zkpox"


def _clean_env() -> dict:
    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDECODE", "_RAPTOR_TRUSTED")}
    env["RAPTOR_DIR"] = str(REPO)
    return env


def _trusted_env() -> dict:
    env = _clean_env()
    env["_RAPTOR_TRUSTED"] = "1"
    return env


def _run(args, env=None):
    return subprocess.run(
        [str(SCRIPT), *args],
        env=env or _trusted_env(),
        capture_output=True, text=True, timeout=60, check=False,
    )


# ----------------------------------------------------------------------
# Trust marker
# ----------------------------------------------------------------------


def test_trust_marker_rejects_clean_env():
    r = _run(["bundle", "x", "y", "--out", "z"], env=_clean_env())
    assert r.returncode == 2
    assert "internal dispatch script" in r.stderr


# ----------------------------------------------------------------------
# reproduce error paths
# ----------------------------------------------------------------------


def test_reproduce_missing_dir(tmp_path):
    r = _run(["reproduce", str(tmp_path / "nope")])
    assert r.returncode == 2
    assert "no manifest.json" in r.stderr


def test_reproduce_no_witness_bin(tmp_path):
    d = tmp_path / "b"
    d.mkdir()
    (d / "manifest.json").write_text("{}")
    r = _run(["reproduce", str(d)])
    assert r.returncode == 2
    assert "no witness.bin" in r.stderr


def test_reproduce_corrupt_manifest(tmp_path):
    """Pre-fix: json.loads raised JSONDecodeError uncaught →
    traceback. Post-fix: clean rc=2 message."""
    d = tmp_path / "b"
    d.mkdir()
    (d / "manifest.json").write_text("{not valid json")
    (d / "witness.bin").write_bytes(b"x")
    r = _run(["reproduce", str(d)])
    assert r.returncode == 2
    assert "not valid JSON" in r.stderr
    assert "Traceback" not in r.stderr


def test_reproduce_incomplete_manifest(tmp_path):
    """Valid JSON but missing the load-bearing fields → rc=2,
    not a KeyError traceback."""
    d = tmp_path / "b"
    d.mkdir()
    (d / "manifest.json").write_text(json.dumps({"witness_hash": "abc"}))
    (d / "witness.bin").write_bytes(b"x")
    r = _run(["reproduce", str(d)])
    assert r.returncode == 2
    assert "missing required field" in r.stderr
    assert "Traceback" not in r.stderr


def test_reproduce_witness_hash_mismatch(tmp_path):
    """witness.bin doesn't hash to the manifest's witness_hash →
    rc=2, no reproduction attempted."""
    from core.witness.types import compute_bytes_hash
    d = tmp_path / "b"
    d.mkdir()
    (d / "manifest.json").write_text(json.dumps({
        "witness_hash": compute_bytes_hash(b"original witness"),
        "witness_len": len(b"original witness"),
        "source": "fuzz",
        "observed_outcome": "exit_signal",
    }))
    (d / "witness.bin").write_bytes(b"tampered witness")
    r = _run(["reproduce", str(d)])
    assert r.returncode == 2
    assert "hash mismatch" in r.stderr
    assert "Traceback" not in r.stderr


def test_reproduce_witness_len_mismatch(tmp_path):
    """Matching hash but wrong witness_len (inconsistent manifest) →
    rc=2. Belt-and-braces alongside the hash check."""
    from core.witness.types import compute_bytes_hash
    data = b"witness bytes"
    d = tmp_path / "b"
    d.mkdir()
    (d / "manifest.json").write_text(json.dumps({
        "witness_hash": compute_bytes_hash(data),
        "witness_len": len(data) + 1,
        "source": "fuzz",
        "observed_outcome": "exit_signal",
    }))
    (d / "witness.bin").write_bytes(data)
    r = _run(["reproduce", str(d)])
    assert r.returncode == 2
    assert "length mismatch" in r.stderr
    assert "Traceback" not in r.stderr


# ----------------------------------------------------------------------
# bundle error paths
# ----------------------------------------------------------------------


def test_bundle_non_store_dir(tmp_path):
    r = _run(["bundle", str(tmp_path / "nostore"), "abc",
              "--out", str(tmp_path / "out")])
    assert r.returncode == 2
    assert "not a witness store" in r.stderr


def test_bundle_witness_not_in_store(tmp_path):
    """Store exists but the hash isn't present."""
    from core.witness.store import WitnessStore
    from core.witness.types import (
        Witness,
        WitnessOutcome,
        WitnessSource,
        compute_bytes_hash,
    )
    store = WitnessStore(tmp_path / "w")
    d = b"present"
    store.put(Witness(
        bytes_hash=compute_bytes_hash(d), bytes_len=len(d),
        source=WitnessSource.FUZZ, observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        outcome_detail={}, target_binary_hash="a" * 64,
    ), d)
    r = _run(["bundle", str(tmp_path / "w"), "f" * 64,
              "--out", str(tmp_path / "out")])
    assert r.returncode == 2


# ----------------------------------------------------------------------
# Happy path: bundle → reproduce (FUZZ replay, real binary)
# ----------------------------------------------------------------------


# Deterministic on delivered input: the null write cannot depend on
# scheduling or ASLR, and the read retries EINTR so a signal landing
# mid-read cannot turn a crash run into a clean exit.
_CRASHER = (
    "#include <errno.h>\n"
    "#include <unistd.h>\n"
    "int main(void){char b[64]; ssize_t n;\n"
    "do { n = read(0, b, 63); } while (n < 0 && errno == EINTR);\n"
    "if (n > 0 && b[0]=='B'){ int *p = 0; *p = 42; } return 0;}\n"
)


@_needs_sandbox
@pytest.mark.skipif(
    shutil.which("cc") is None and shutil.which("gcc") is None,
    reason="no C compiler",
)
def test_bundle_then_reproduce_happy_path(tmp_path):
    from core.hash import sha256_file
    from core.witness.store import WitnessStore
    from core.witness.types import (
        Witness,
        WitnessOutcome,
        WitnessSource,
        compute_bytes_hash,
    )

    cc = shutil.which("cc") or shutil.which("gcc")
    src = tmp_path / "crasher.c"
    src.write_text(_CRASHER)
    binary = tmp_path / "crasher"
    subprocess.run([cc, "-O0", "-o", str(binary), str(src)],
                   check=True, timeout=30)

    crash_input = b"B" + b"\x00" * 8
    store = WitnessStore(tmp_path / "w")
    store.put(Witness(
        bytes_hash=compute_bytes_hash(crash_input),
        bytes_len=len(crash_input),
        source=WitnessSource.FUZZ,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        outcome_detail={"finding_id": "F1"},
        target_binary_hash=sha256_file(binary),
    ), crash_input)
    wh = compute_bytes_hash(crash_input)

    # bundle
    out = tmp_path / "out"
    r = _run(["bundle", str(tmp_path / "w"), wh, "--out", str(out)])
    assert r.returncode == 0, r.stderr
    bundle_dir = out / "zkpox" / wh
    assert (bundle_dir / "manifest.json").is_file()
    assert json.loads((bundle_dir / "manifest.json").read_text())["tier"] == "0/1"

    # reproduce
    r = _run(["reproduce", str(bundle_dir), "--binary", str(binary), "--n", "3"])
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    assert manifest["tier"] == "1.5"  # bumped
    assert manifest["reproduction"]["reproduced"] is True
    assert manifest["reproduction"]["runs"] == 3
    # Per-run diagnostics recorded for every EXECUTED run: on a
    # divergent run the manifest (and the CLI report echoed on
    # failure) names the shape — returncode, signal, isolation
    # degradation — instead of a bare outcome string. The host may
    # interleave retried spawn_failure attempt records (a transient
    # exec failure, classified and retried — the spawn-failure
    # machinery working, not a reproduction problem); the assertions
    # here are about the executed outcomes.
    run_details = manifest["reproduction"]["run_details"]
    executed = [rec for rec in run_details
                if rec["outcome"] != "spawn_failure"]
    assert [rec["run"] for rec in executed] == [1, 2, 3], (
        f"expected all 3 runs to execute (spawn_failure attempt "
        f"records excluded): {run_details}")
    for rec in executed:
        assert rec["outcome"] == "exit_signal"
        assert "returncode" in rec
    for rec in run_details:
        if rec["outcome"] == "spawn_failure":
            # Environment-supplied transient, retried by design —
            # its provenance must be on the record.
            assert "spawn_failure" in rec, rec


@_needs_sandbox
@pytest.mark.skipif(
    shutil.which("cc") is None and shutil.which("gcc") is None,
    reason="no C compiler",
)
def test_reproduce_first_run_silent_exit_126_is_spawn_failure(tmp_path):
    """A first replay run that exits 126 with no output, no crash
    evidence, and no exec-status category — the shape a lost/absent
    setup status leaves behind — must classify as a spawn failure and
    retry, not enter the verdict as an observed outcome.

    Driven through the REAL CLI: the target's first execution inside
    the sandbox exits 126 silently (exec succeeds, so the exec-status
    pipe reports EOF exactly like a lost status byte does); every
    later execution dies by SIGSEGV. Pre-fix the 126 was counted as
    no_obvious_effect and one such run flipped a deterministic
    SIGSEGV witness to "non-deterministic", reproduced=False.

    The host environment can add ITS OWN spawn failures on top of the
    injected one (the very race this machinery exists for) — including
    on run 1's retry, which then excludes run 1 entirely. Under the
    executed-runs verdict that is still reproduced=True / exit 0; the
    assertions below distinguish the injected record (run 1, attempt
    1, returncode 126) from environment-supplied ones and pin only
    what the injection guarantees.
    """
    from core.hash import sha256_file
    from core.witness.store import WitnessStore
    from core.witness.types import (
        Witness,
        WitnessOutcome,
        WitnessSource,
        compute_bytes_hash,
    )

    cc = shutil.which("cc") or shutil.which("gcc")
    src = tmp_path / "segv.c"
    src.write_text("int main(void){int *p = 0; *p = 42; return 0;}\n")
    helper = tmp_path / "segv-helper"
    subprocess.run([cc, "-O0", "-o", str(helper), str(src)],
                   check=True, timeout=30)
    # The pinned target: first run drops a marker in its own (writable
    # output) dir and exits 126 writing nothing — the silent
    # exec-failure shape; later runs exec a genuine SIGSEGV. The crash
    # must be a real fault (not kill(2)): the target runs as the
    # pid-namespace init, which ignores kill-raised signals without a
    # handler, while kernel-generated faults are always delivered.
    crasher = tmp_path / "crasher"
    crasher.write_text(
        "#!/bin/sh\n"
        'd=$(dirname "$0")\n'
        'if [ ! -e "$d/.spawned-once" ]; then\n'
        '  : > "$d/.spawned-once" 2>/dev/null\n'
        "  exit 126\n"
        "fi\n"
        'exec "$d/segv-helper"\n'
    )
    crasher.chmod(0o755)

    crash_input = b"B" + b"\x00" * 8
    store = WitnessStore(tmp_path / "w")
    store.put(Witness(
        bytes_hash=compute_bytes_hash(crash_input),
        bytes_len=len(crash_input),
        source=WitnessSource.FUZZ,
        observed_outcome=WitnessOutcome.EXIT_SIGNAL,
        outcome_detail={"finding_id": "F1"},
        target_binary_hash=sha256_file(crasher),
    ), crash_input)
    wh = compute_bytes_hash(crash_input)

    out = tmp_path / "out"
    r = _run(["bundle", str(tmp_path / "w"), wh, "--out", str(out)])
    assert r.returncode == 0, r.stderr
    bundle_dir = out / "zkpox" / wh

    r = _run(["reproduce", str(bundle_dir), "--binary", str(crasher),
              "--n", "3"])
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    rep = manifest["reproduction"]
    sf = [d for d in rep["run_details"]
          if d.get("outcome") == "spawn_failure"]
    # The INJECTED spawn failure: the scripted silent exit 126 lands
    # on run 1 — attempt 1 normally, or attempt 2 when the
    # environment's own race consumed attempt 1 before the script
    # ever ran. Either way a run-1 spawn_failure record with
    # returncode 126 must exist.
    injected = [d for d in sf
                if d["run"] == 1 and d.get("returncode") == 126]
    assert injected, (
        f"the injected run-1 silent 126 was not classified as a "
        f"spawn failure: {rep['run_details']}")
    # Any record beyond the injected one is the ENVIRONMENT's own
    # spawn failure (the host race this machinery exists for) —
    # legal on any run/attempt; environment X-category records carry
    # no returncode. Every record must carry its provenance reason.
    environment = [d for d in sf if d is not injected[0]]
    for d in environment:
        assert "spawn_failure" in d, (
            f"environment spawn-failure record lacks provenance: {d}")
    assert rep["spawn_failures"] == len(sf) >= 1
    # Verdict over EXECUTED runs: every executed run must be the
    # recorded SIGSEGV outcome. Normally the retry executes and all
    # 3 runs are observed; an environment spawn failure on a retry
    # excludes that run — still reproduced=True over the remainder.
    assert rep["reproduced"] is True
    executed = rep["observed_outcomes"]
    assert 1 <= len(executed) <= 3
    assert executed == ["exit_signal"] * len(executed), (
        f"an executed run diverged from the recorded outcome "
        f"(this would be a real reproduction failure, not the "
        f"environment race): {rep}")
    assert manifest["tier"] == "1.5"
