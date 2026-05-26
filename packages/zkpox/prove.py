"""
Locate the zkpox-prove binary and drive it against a witness.

Phase 1.1: thin wrapper. Phase 1.5 will route this through RAPTOR's
run-lifecycle (`libexec/raptor-run-lifecycle`) so prove invocations
appear in the project's run history.

The prover binary is the `zkpox-prove` workspace member at
`core/zkpox/prover/`; we expect it built via
`cargo build --release --manifest-path core/zkpox/Cargo.toml`.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from core.sandbox import run_untrusted

from packages.zkpox.proving_deps import require_proving_stack


# Repo root resolution. The Rust workspace lives at <repo>/core/zkpox/.
# Fall back to walking up from this file's location so the package works
# regardless of whether RAPTOR_DIR is set (it is for runtime; not always
# in tests / one-off CLI use).
def _repo_root() -> Path:
    if "RAPTOR_DIR" in os.environ:
        return Path(os.environ["RAPTOR_DIR"])
    here = Path(__file__).resolve()
    # packages/zkpox/prove.py → repo root is two parents up.
    return here.parent.parent.parent


def _default_binary() -> Path:
    return _repo_root() / "core" / "zkpox" / "target" / "release" / "zkpox-prove"


@dataclass(frozen=True)
class Verdicts:
    """Public-values shape committed by the SP1 guest.

    Phase 1.6 added `target_id` as the first committed value so the
    bundle records which C target was proven against.
    """

    target_id: int
    crash_only_crashed: bool
    oob_detected: bool
    oob_count: int
    oob_first_offset: int


@dataclass(frozen=True)
class ProveResult:
    """Result of one prover invocation. Mirrors the JSON record the
    Rust binary emits; see core/zkpox/prover/src/main.rs for the
    canonical schema."""

    tag: str
    witness: Path
    witness_bytes: int
    mode: str  # "execute" | "prove"
    verdicts: Verdicts
    cycles: int | None
    wall_secs: float
    proof_bytes: int | None
    verified: bool | None


class ProverError(Exception):
    """Raised when the prover binary fails or its output is unparseable."""


def run(
    witness: Path,
    *,
    mode: str = "execute",
    binary: Path | None = None,
    tag: str | None = None,
    timeout: float | None = None,
) -> ProveResult:
    """Invoke `zkpox-prove` and parse the result.

    `mode`: ``"execute"`` (fast, no proof) or ``"prove"`` (full STARK).
    `binary`: override path; defaults to the workspace's release binary.
    `tag`: bench-record tag echoed in the JSON output.
    `timeout`: subprocess timeout in seconds; None = unlimited.
    """
    if mode not in ("execute", "prove"):
        raise ValueError(f"mode must be 'execute' or 'prove', got {mode!r}")
    # Gate the *default* path on the proving stack so a bare box gets
    # the actionable ProvingStackUnavailable message rather than a vague
    # "binary not found". An explicit ``binary=`` overrides — tests
    # (and any future stub-prover use) supply their own path and
    # legitimately don't need cargo-prove / SP1 installed.
    if binary is None:
        require_proving_stack()
    bin_path = Path(binary) if binary else _default_binary()
    if not bin_path.exists():
        raise ProverError(
            f"prover binary not found: {bin_path}\n"
            f"build it with: cargo build --release "
            f"--manifest-path core/zkpox/Cargo.toml"
        )

    cmd: list[str] = [
        str(bin_path),
        "--witness", str(witness),
        f"--{mode}",
    ]
    if tag is not None:
        cmd += ["--tag", tag]

    # Sandboxed via run_untrusted: full env hygiene, Landlock-scoped FS
    # (witness read-only, per-call temp dir for SP1 scratch), no network.
    # The prover lives under core/zkpox/target/release/ which is not on
    # the default safe-bin path, so tool_paths is mandatory here.
    witness_dir = Path(witness).resolve().parent
    sandbox_workdir = tempfile.mkdtemp(prefix="zkpox-prove-")
    try:
        completed = run_untrusted(
            cmd,
            target=str(witness_dir),
            output=sandbox_workdir,
            readable_paths=[str(witness_dir)],
            tool_paths=[str(bin_path.parent)],
            caller_label="zkpox-prove",
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    finally:
        shutil.rmtree(sandbox_workdir, ignore_errors=True)
    if completed.returncode != 0:
        raise ProverError(
            f"zkpox-prove exited {completed.returncode}\n"
            f"stderr:\n{completed.stderr}"
        )
    try:
        record = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ProverError(
            f"could not parse prover output as JSON: {exc}\n"
            f"stdout:\n{completed.stdout}"
        )

    v = record.get("verdicts") or {}
    return ProveResult(
        tag=record["tag"],
        witness=Path(record["witness"]),
        witness_bytes=int(record["witness_bytes"]),
        mode=record["mode"],
        verdicts=Verdicts(
            target_id=int(v.get("target_id", 0x01)),  # default 01 for pre-1.6 records
            crash_only_crashed=bool(v["crash_only_crashed"]),
            oob_detected=bool(v["oob_detected"]),
            oob_count=int(v["oob_count"]),
            oob_first_offset=int(v["oob_first_offset"]),
        ),
        cycles=record.get("cycles"),
        wall_secs=float(record["wall_secs"]),
        proof_bytes=record.get("proof_bytes"),
        verified=record.get("verified"),
    )
