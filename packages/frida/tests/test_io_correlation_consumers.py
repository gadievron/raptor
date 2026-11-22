"""Consumer census for the io-correlation artifact and its receipt stamp.

``io-correlation.json`` (packages.frida.correlate) carries
``receipt_stamp: "frida:token-at-sink"`` — a VERIFICATION-role spelling
in the exact-spelling registry. The stamp in the artifact is an
annotation for the OPERATOR's G2 recording decision (`raptor-audit
record --evidence-tool frida:token-at-sink`, gated on a confirmed sweep
receipt): no automated consumer may promote it into
``outcome.evidence_tool``. A scanned repo cannot forge the in-process
observation seam the orchestrator consumes
(``core.audit.frida_observe``), but a hostile run directory CAN contain
a planted ``io-correlation.json`` — an automated artifact→evidence_tool
promotion would turn that file write into a confirmed finding.

These censuses turn the invariant from "no consumer happens to exist"
into "adding one fails CI": any new runtime file touching the artifact
or the stamp key must be added to the allowlist here, in a change that
confronts this doctrine.
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]

# Runtime code only — tests may mention the artifact freely.
_RUNTIME_ROOTS = ("core", "packages", "libexec")

# Files allowed to carry the "io-correlation" literal:
#   correlate.py — the writer (mints the artifact and its stamp).
#   runner.py    — docstring pointer at the post-processor join.
#   reporting.py — lists the artifact among a run's outputs.
#   cli.py       — prints the artifact path / the skip notice.
#   evidence_grade.py — describes the receipt in the registry comment
#                  and the evidence-chain text; never reads the file.
_IO_CORRELATION_READERS = frozenset({
    "packages/frida/correlate.py",
    "packages/frida/runner.py",
    "packages/frida/reporting.py",
    "packages/frida/cli.py",
    "core/audit/evidence_grade.py",
})

# Files allowed to carry the "receipt_stamp" key:
#   correlate.py / patch_oracle.py — artifact writers (token-at-sink /
#                  sink-observed annotations on their own reports).
#   frida_observe.py — the in-process observation dataclass
#                  (frida:runtime, detection role).
#   frida_validation_bridge.py — /validate's bridge record
#                  (RUNTIME_OBSERVATION_STAMP, detection role).
#   orchestrator.py — the ONE automated reader: consumes the
#                  in-process FridaObservation only (and only onto
#                  non-sanitizer detection paths); it must never
#                  appear in the io-correlation census above.
_RECEIPT_STAMP_FILES = frozenset({
    "packages/frida/correlate.py",
    "packages/frida/patch_oracle.py",
    "core/audit/frida_observe.py",
    "core/orchestration/frida_validation_bridge.py",
    "core/audit/orchestrator.py",
})


def _runtime_files():
    for root in _RUNTIME_ROOTS:
        base = _REPO_ROOT / root
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            parts = path.relative_to(_REPO_ROOT).parts
            if "tests" in parts or "__pycache__" in parts:
                continue
            if path.suffix == ".py" or (
                    parts[0] == "libexec" and path.name.startswith("raptor-")):
                yield path


def _census(needle: str) -> set[str]:
    hits: set[str] = set()
    for path in _runtime_files():
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if needle in text:
            hits.add(path.relative_to(_REPO_ROOT).as_posix())
    return hits


def test_io_correlation_artifact_consumers_are_closed():
    hits = _census("io-correlation")
    unexpected = hits - _IO_CORRELATION_READERS
    assert not unexpected, (
        "new runtime consumer(s) of io-correlation.json: "
        f"{sorted(unexpected)}. The artifact's receipt_stamp is an "
        "operator-facing annotation — automated code must not read it "
        "back, and must NEVER promote it into outcome.evidence_tool "
        "(a hostile run dir can plant the file). If the new consumer "
        "is legitimate and non-promoting, extend the allowlist here "
        "with a comment saying what it reads and why."
    )
    # Drift guard in the other direction: an allowlisted file that no
    # longer mentions the artifact should be pruned, not grandfathered.
    stale = _IO_CORRELATION_READERS - hits
    assert not stale, f"allowlisted non-consumers to prune: {sorted(stale)}"


def test_receipt_stamp_key_consumers_are_closed():
    hits = _census("receipt_stamp")
    unexpected = hits - _RECEIPT_STAMP_FILES
    assert not unexpected, (
        "new runtime consumer(s) of the receipt_stamp key: "
        f"{sorted(unexpected)}. Receipt stamps on frida artifacts are "
        "role-graded by the exact-spelling registry and must reach "
        "outcome.evidence_tool only through the orchestrator's "
        "in-process observation seam — never parsed back from an "
        "artifact a scanned repo or hostile run dir can write."
    )
    stale = _RECEIPT_STAMP_FILES - hits
    assert not stale, f"allowlisted non-consumers to prune: {sorted(stale)}"


def test_the_evidence_tool_promoter_never_reads_the_artifact():
    """The orchestrator is the only receipt_stamp reader that writes
    outcome.evidence_tool; it must stay out of the io-correlation
    census so the artifact can never become the stamp's source."""
    orchestrator = (
        _REPO_ROOT / "core" / "audit" / "orchestrator.py"
    ).read_text(errors="replace")
    assert "receipt_stamp" in orchestrator
    assert "io-correlation" not in orchestrator
    assert "io_correlation" not in orchestrator
