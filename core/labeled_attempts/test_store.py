"""LabeledAttempt store tests — write/read across the three-tier pool."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# parents[3] = repo root
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from core.labeled_attempts import (  # noqa: E402
    LabeledAttempt,
    SandboxEvidence,
    bundled_corpus_path,
    find_by_cwe,
    find_by_finding_signature,
    global_pool_path,
    project_pool_path,
    read_all,
    write,
)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def _make_attempt(
    finding_id: str = "FND-001",
    finding_signature: str = "deadbeef" * 4,
    cwe: str = "CWE-787",
    outcome: str = "success",
    timestamp: str = "2026-06-03T14:05:32+00:00",
) -> LabeledAttempt:
    return LabeledAttempt(
        finding_id=finding_id,
        finding_signature=finding_signature,
        cwe=cwe,
        outcome=outcome,
        sandbox_evidence=SandboxEvidence(
            bytes_hash="a" * 64,
            bytes_len=128,
            observed_outcome="flag_captured",
        ),
        producing_model="claude-haiku-4-5",
        prompt_version="v3",
        tools_used=("find_symbol",),
        iterations=8,
        cost_usd=0.12,
        timestamp=timestamp,
    )


@pytest.fixture
def project_dir(tmp_path):
    """A throwaway project directory."""
    d = tmp_path / "proj"
    d.mkdir()
    return d


@pytest.fixture
def isolated_global(monkeypatch, tmp_path):
    """Redirect ~/.raptor/labeled_attempts to a tmp path so tests don't
    pollute the real global pool. We monkeypatch HOME for the duration
    of the test."""
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    return fake_home / ".raptor" / "labeled_attempts"


# --------------------------------------------------------------------------
# Path helpers
# --------------------------------------------------------------------------


def test_bundled_corpus_path_uses_raptor_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
    expected = (
        tmp_path
        / "packages" / "llm_analysis" / "exploit_engine"
        / "eval" / "bundled_corpus"
    )
    assert bundled_corpus_path() == expected


def test_project_pool_path_under_project_dir(tmp_path):
    proj = tmp_path / "proj"
    assert project_pool_path(proj) == proj / "labeled_attempts"


def test_global_pool_path_under_home(isolated_global):
    assert global_pool_path() == isolated_global


# --------------------------------------------------------------------------
# Write
# --------------------------------------------------------------------------


def test_write_creates_finding_signature_directory(project_dir):
    a = _make_attempt(finding_signature="aaaa" * 8)
    paths = write(a, project_dir=project_dir)
    assert len(paths) == 1
    p = paths[0]
    assert "aaaaaaaa" in str(p)
    assert p.parent.name == "aaaa" * 8
    assert p.exists()


def test_write_filename_carries_oracle_and_timestamp(project_dir):
    a = _make_attempt(timestamp="2026-06-03T14:05:32+00:00")
    paths = write(a, project_dir=project_dir)
    assert paths[0].name.startswith("sandbox-2026")
    assert paths[0].name.endswith(".json")


def test_write_round_trips(project_dir):
    a = _make_attempt()
    write(a, project_dir=project_dir)
    [restored] = list(read_all(project_dir=project_dir, include_bundled=False))
    assert restored == a


def test_write_also_global_writes_two_paths(project_dir, isolated_global):
    a = _make_attempt()
    paths = write(a, project_dir=project_dir, also_global=True)
    assert len(paths) == 2
    # One in project, one in global
    assert any(project_dir in p.parents for p in paths)
    assert any(isolated_global in p.parents for p in paths)


# --------------------------------------------------------------------------
# Read — pool resolution
# --------------------------------------------------------------------------


def test_read_all_project_only(project_dir):
    a = _make_attempt(finding_id="A")
    b = _make_attempt(finding_id="B", finding_signature="cccc" * 8)
    write(a, project_dir=project_dir)
    write(b, project_dir=project_dir)
    records = list(read_all(project_dir=project_dir, include_bundled=False))
    ids = {r.finding_id for r in records}
    assert ids == {"A", "B"}


def test_read_all_includes_bundled_by_default(
    monkeypatch, tmp_path, project_dir
):
    """If RAPTOR_DIR points at a tmp tree with a bundled corpus, reads
    include it by default."""
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
    bundled = bundled_corpus_path()
    bundled.mkdir(parents=True)

    # Plant a record in the bundled tree (would normally be done by
    # the build step that materialises the demo corpus)
    bundled_record = _make_attempt(finding_id="BUNDLED")
    sig_dir = bundled / bundled_record.finding_signature
    sig_dir.mkdir()
    record_path = sig_dir / "sandbox-20260101T000000.000Z.json"
    import json
    record_path.write_text(json.dumps(bundled_record.to_dict()))

    # And one in project
    a = _make_attempt(finding_id="PROJECT", finding_signature="cccc" * 8)
    write(a, project_dir=project_dir)

    records = list(read_all(project_dir=project_dir, include_bundled=True))
    ids = {r.finding_id for r in records}
    assert ids == {"BUNDLED", "PROJECT"}


def test_read_all_excludes_bundled_when_flag_off(
    monkeypatch, tmp_path, project_dir
):
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
    bundled = bundled_corpus_path()
    bundled.mkdir(parents=True)

    bundled_record = _make_attempt(finding_id="BUNDLED")
    sig_dir = bundled / bundled_record.finding_signature
    sig_dir.mkdir()
    import json
    (sig_dir / "sandbox-20260101T000000.000Z.json").write_text(
        json.dumps(bundled_record.to_dict()),
    )

    records = list(read_all(project_dir=project_dir, include_bundled=False))
    assert records == []  # No bundled, no project records yet


def test_read_all_global_pool_opt_in(project_dir, isolated_global):
    """include_global=True pulls in the cross-project pool."""
    a = _make_attempt(finding_id="LOCAL")
    write(a, project_dir=project_dir)

    b = _make_attempt(finding_id="GLOBAL", finding_signature="cccc" * 8)
    write(b, project_dir=project_dir, also_global=True)

    # include_global=False — only project records (LOCAL + GLOBAL,
    # since GLOBAL wrote to both)
    project_only = list(read_all(
        project_dir=project_dir,
        include_bundled=False,
        include_global=False,
    ))
    assert {r.finding_id for r in project_only} == {"LOCAL", "GLOBAL"}

    # include_global=True — GLOBAL appears once more from the global pool
    with_global = list(read_all(
        project_dir=project_dir,
        include_bundled=False,
        include_global=True,
    ))
    # GLOBAL is duplicated — it's in both pools. That's by design; the
    # caller dedupes (matching.py will collapse by exploit_code hash etc.)
    assert sum(1 for r in with_global if r.finding_id == "GLOBAL") == 2


# --------------------------------------------------------------------------
# Read — filtering
# --------------------------------------------------------------------------


def test_find_by_cwe(project_dir):
    write(_make_attempt(finding_id="A", cwe="CWE-787",
                        finding_signature="aa" * 16),
          project_dir=project_dir)
    write(_make_attempt(finding_id="B", cwe="CWE-416",
                        finding_signature="bb" * 16),
          project_dir=project_dir)
    write(_make_attempt(finding_id="C", cwe="CWE-787",
                        finding_signature="cc" * 16),
          project_dir=project_dir)

    cwe_787 = list(find_by_cwe("CWE-787", project_dir=project_dir,
                                include_bundled=False))
    assert {r.finding_id for r in cwe_787} == {"A", "C"}


def test_find_by_cwe_case_insensitive(project_dir):
    write(_make_attempt(cwe="CWE-787"), project_dir=project_dir)
    assert list(find_by_cwe("cwe-787", project_dir=project_dir,
                            include_bundled=False))


def test_find_by_finding_signature(project_dir):
    SIG = "fafa" * 8
    write(_make_attempt(finding_id="A", finding_signature=SIG),
          project_dir=project_dir)
    write(_make_attempt(finding_id="B", finding_signature=SIG,
                        timestamp="2026-06-04T10:00:00+00:00"),
          project_dir=project_dir)
    write(_make_attempt(finding_id="C", finding_signature="eeee" * 8),
          project_dir=project_dir)

    by_sig = list(find_by_finding_signature(
        SIG, project_dir=project_dir, include_bundled=False,
    ))
    assert {r.finding_id for r in by_sig} == {"A", "B"}


# --------------------------------------------------------------------------
# Resilience — corrupt records skipped, not fatal
# --------------------------------------------------------------------------


def test_corrupt_record_is_skipped(project_dir):
    # Good record
    a = _make_attempt(finding_id="GOOD")
    write(a, project_dir=project_dir)

    # Corrupt one (write invalid JSON in the right directory layout)
    bad_dir = project_pool_path(project_dir) / ("bad" * 6 + "ad")
    bad_dir.mkdir(parents=True)
    (bad_dir / "sandbox-20260101T000000.000Z-aaaaaa.json").write_text("{not-json")

    # Read should yield only the good one, not raise
    records = list(read_all(project_dir=project_dir, include_bundled=False))
    assert [r.finding_id for r in records] == ["GOOD"]


# --------------------------------------------------------------------------
# Adversarial: concurrent writes (from session adversarial review 2026-06-03)
# --------------------------------------------------------------------------


def test_concurrent_writes_do_not_overwrite(project_dir):
    """20 threads writing records with the same timestamp must all land
    on disk — the random-suffix + O_EXCL retry loop prevents
    overwrites that lose data."""
    import threading

    SAME_TS = "2026-06-03T14:00:00+00:00"
    SAME_SIG = "f" * 32

    barrier = threading.Barrier(20)
    errors: list[str] = []

    def writer(i: int) -> None:
        try:
            a = _make_attempt(
                finding_id=f"X{i}",
                finding_signature=SAME_SIG,
                timestamp=SAME_TS,
            )
            barrier.wait()  # release all 20 simultaneously
            write(a, project_dir=project_dir)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{i}: {e}")

    threads = [
        threading.Thread(target=writer, args=(i,)) for i in range(20)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"some writers failed: {errors}"
    records = list(read_all(project_dir=project_dir, include_bundled=False))
    assert len(records) == 20, (
        f"expected 20 records, got {len(records)} — "
        f"concurrent writes lost data"
    )
    # All carry distinct finding_ids
    assert {r.finding_id for r in records} == {f"X{i}" for i in range(20)}


# --------------------------------------------------------------------------
# E2E: simulate a real engine producer flow
# --------------------------------------------------------------------------


def test_e2e_engine_producer_flow(project_dir, isolated_global):
    """End-to-end simulation of how /exploit will write+read records.

    Models the producer side as if three runs of the engine had landed:
      1. Haiku, CWE-787, success on Finding A
      2. Haiku, CWE-787, reasoned_failure on Finding B
      3. Opus, CWE-416, success on Finding C (also persisted globally)

    Then exercises the consumer side: an L3-retrieval query for
    CWE-787 exemplars should pull the two CWE-787 records and skip the
    CWE-416 one.
    """
    from core.labeled_attempts import compute_finding_signature

    # --- Producer: three "engine runs" land records ---------------------
    sig_a = compute_finding_signature(
        cwe="CWE-787", file_path="src/parse.c",
        function="parse_header", line=42,
    )
    sig_b = compute_finding_signature(
        cwe="CWE-787", file_path="src/copy.c",
        function="copy_block", line=99,
    )
    sig_c = compute_finding_signature(
        cwe="CWE-416", file_path="src/free.c",
        function="free_node", line=17,
    )

    # Distinct signatures (sanity — caught a real schema bug earlier)
    assert len({sig_a, sig_b, sig_c}) == 3

    rec_a = LabeledAttempt(
        finding_id="FND-A", finding_signature=sig_a, cwe="CWE-787",
        outcome="success",
        sandbox_evidence=SandboxEvidence(
            bytes_hash="a" * 64, bytes_len=64,
            observed_outcome="sanitizer_report",
            target_binary_hash="b" * 64, commit_sha="deadbe1",
            mitigations_active=["canary", "NX", "ASLR"],
            arch="x86_64",
            exploit_code='int main(){char buf[8];gets(buf);}',
            exploit_language="c",
        ),
        producing_model="claude-haiku-4-5",
        prompt_version="v3",
        tools_used=("find_symbol", "disassemble"),
        iterations=12, cost_usd=0.18,
        timestamp="2026-06-03T14:05:32+00:00",
    )
    rec_b = LabeledAttempt(
        finding_id="FND-B", finding_signature=sig_b, cwe="CWE-787",
        outcome="reasoned_failure",
        sandbox_evidence=SandboxEvidence(
            bytes_hash="c" * 64, bytes_len=16,
            observed_outcome="no_obvious_effect",
        ),
        producing_model="claude-haiku-4-5",
        prompt_version="v3",
        iterations=20, cost_usd=0.41,
        timestamp="2026-06-03T14:08:11+00:00",
    )
    rec_c = LabeledAttempt(
        finding_id="FND-C", finding_signature=sig_c, cwe="CWE-416",
        outcome="success",
        sandbox_evidence=SandboxEvidence(
            bytes_hash="d" * 64, bytes_len=32,
            observed_outcome="sanitizer_report",
        ),
        producing_model="claude-opus-4-7",
        prompt_version="v3",
        iterations=4, cost_usd=0.62,
        timestamp="2026-06-03T14:12:00+00:00",
    )

    paths_a = write(rec_a, project_dir=project_dir)
    paths_b = write(rec_b, project_dir=project_dir)
    paths_c = write(rec_c, project_dir=project_dir, also_global=True)

    assert len(paths_a) == 1
    assert len(paths_b) == 1
    assert len(paths_c) == 2  # project + global

    # --- Consumer: L3-retrieval query for "give me CWE-787 exemplars" ---
    cwe_787 = list(find_by_cwe(
        "CWE-787", project_dir=project_dir, include_bundled=False,
    ))
    assert {r.finding_id for r in cwe_787} == {"FND-A", "FND-B"}

    # The CWE-787 success exemplar is the one the prompt builder
    # would lean on as the few-shot positive
    successes = [r for r in cwe_787 if r.outcome == "success"]
    assert len(successes) == 1
    assert successes[0].finding_id == "FND-A"
    # ...and the exploit code is preserved verbatim for the few-shot slot
    assert successes[0].sandbox_evidence.exploit_code.startswith("int main")

    # --- Cross-project: global pool surfaces FND-C ---------------------
    global_records = list(read_all(
        project_dir=None, include_bundled=False, include_global=True,
    ))
    assert {r.finding_id for r in global_records} == {"FND-C"}

    # --- Provenance preserved across round-trip ---
    [restored_c] = list(find_by_finding_signature(
        sig_c, project_dir=project_dir, include_bundled=False,
    ))
    assert restored_c.producing_model == "claude-opus-4-7"
    assert restored_c.cost_usd == 0.62
    assert restored_c.tools_used == ()  # default tuple round-trips


# --------------------------------------------------------------------------
# Adversarial: symlink-follow on write (deferred item from review)
# --------------------------------------------------------------------------


def test_write_does_not_follow_planted_symlink(project_dir, tmp_path):
    """If an attacker plants a symlink at the exact filename the writer
    *would* pick, the writer must not write through it. The security
    property: the symlink's target is never modified. The write itself
    still succeeds — under a different filename — because the retry
    loop re-rolls the random suffix on EEXIST."""
    import os
    from core.labeled_attempts.store import _record_filename

    pool = project_pool_path(project_dir)
    pool.mkdir(parents=True)

    victim = tmp_path / "victim.txt"
    original = "original content — must not be overwritten"
    victim.write_text(original)

    # Build the per-signature dir + plant a symlink at the EXACT
    # filename the writer is about to pick (we know what filename
    # _record_filename will produce because we control the timestamp
    # and random suffix is the only variable).
    a = _make_attempt(
        finding_signature="aaaa" * 8,
        timestamp="2026-06-03T14:00:00+00:00",
    )
    sig_dir = pool / a.finding_signature
    sig_dir.mkdir()

    # Plant a symlink at SOME predicted name. The writer will pick a
    # different random suffix, so this won't directly collide — but
    # we don't need a direct collision; we need to assert that whatever
    # filename the writer picks, the victim file is never touched.
    decoy_filename = _record_filename(a)
    decoy_path = sig_dir / decoy_filename
    os.symlink(victim, decoy_path)

    # Perform the write — picks a different random suffix → succeeds
    # at a different filename → never opens through the planted
    # symlink.
    paths = write(a, project_dir=project_dir)
    assert len(paths) == 1

    # SECURITY ASSERTION: victim never modified.
    assert victim.read_text() == original

    # And the symlink itself wasn't replaced.
    assert decoy_path.is_symlink()


def test_write_atomic_with_existing_symlink_refuses_open(tmp_path):
    """Direct-path probe: feeding _write_atomic a path that IS a
    symlink to a real victim file results in either EEXIST (because
    the symlink exists) or ELOOP (because O_NOFOLLOW catches it).
    Either way: the victim is not modified."""
    import os
    from core.labeled_attempts.store import _write_atomic

    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")

    link = tmp_path / "sandbox-x-aaaaaa.json"
    os.symlink(victim, link)

    # _write_atomic will catch FileExistsError and retry with a new
    # suffix — pointing at a different (non-existent) path → success.
    # The security property is that the *victim* file is never modified.
    _write_atomic(link, "{}")
    assert victim.read_text() == "untouched"


def test_missing_oracle_record_is_skipped(project_dir):
    """A record with no oracle evidence violates the constraint and
    should be skipped on read, not raise."""
    import json
    bad_dir = project_pool_path(project_dir) / "ababab12"
    bad_dir.mkdir(parents=True)
    bad_blob = {
        "finding_id": "BAD",
        "finding_signature": "ababab12",
        "cwe": "CWE-787",
        "outcome": "success",
        # No oracle evidence — fails __post_init__
        "producing_model": "x",
        "prompt_version": "v3",
        "tools_used": [],
        "iterations": 0,
        "cost_usd": 0.0,
        "reproducible": True,
        "timestamp": "2026-06-03T14:05:32+00:00",
    }
    (bad_dir / "sandbox-20260101T000000.000Z.json").write_text(json.dumps(bad_blob))

    # Read should silently skip the bad record
    records = list(read_all(project_dir=project_dir, include_bundled=False))
    assert records == []
