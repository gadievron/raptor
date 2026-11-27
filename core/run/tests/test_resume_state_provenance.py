"""Authorship tokens over resume-state fields (worker liveness +
persisted cost caps) — mint/verify round trips, tamper rejection, and
the demote-never-error degrade shapes readers rely on."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.run import resume_state_provenance as rsp


@pytest.fixture(autouse=True)
def _key_in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Innermost XDG pin: every test mints against a private key."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


class TestWorkerRecord:
    def test_stamp_then_verify(self, tmp_path: Path):
        record = {"tool_pid": 4242, "tool_pid_start": "123456"}
        rsp.stamp_worker_record(record, tmp_path)
        assert rsp.WORKER_PROVENANCE_KEY in record
        assert rsp.verify_worker_record(record, tmp_path)

    def test_json_round_trip_verifies(self, tmp_path: Path):
        # The on-disk read-back is JSON-decoded: ints survive, and the
        # canonical encoding must reproduce the mint side from it.
        import json
        record = {"tool_pid": 4242, "tool_pid_start": "123456"}
        rsp.stamp_worker_record(record, tmp_path)
        assert rsp.verify_worker_record(
            json.loads(json.dumps(record)), tmp_path)

    def test_bare_pid_record_stamps(self, tmp_path: Path):
        # Off-Linux writers record no starttime; the token still binds
        # the (pid, "") tuple.
        record = {"tool_pid": 4242}
        rsp.stamp_worker_record(record, tmp_path)
        assert rsp.verify_worker_record(record, tmp_path)

    def test_tampered_pid_fails(self, tmp_path: Path):
        record = {"tool_pid": 4242, "tool_pid_start": "123456"}
        rsp.stamp_worker_record(record, tmp_path)
        record["tool_pid"] = 4243
        assert not rsp.verify_worker_record(record, tmp_path)

    def test_tampered_starttime_fails(self, tmp_path: Path):
        record = {"tool_pid": 4242, "tool_pid_start": "123456"}
        rsp.stamp_worker_record(record, tmp_path)
        record["tool_pid_start"] = "123457"
        assert not rsp.verify_worker_record(record, tmp_path)

    def test_stripped_starttime_fails(self, tmp_path: Path):
        record = {"tool_pid": 4242, "tool_pid_start": "123456"}
        rsp.stamp_worker_record(record, tmp_path)
        del record["tool_pid_start"]
        assert not rsp.verify_worker_record(record, tmp_path)

    def test_cross_run_replay_fails(self, tmp_path: Path):
        # The replay B-class: a record stamped for run A copied into
        # run B's metadata must not read as run B's live worker (an
        # unbound token over a long-lived pid was a standing
        # denial-of-resume for any run dir it was copied into).
        record = {"tool_pid": 4242, "tool_pid_start": "123456"}
        rsp.stamp_worker_record(record, tmp_path / "run-a")
        assert rsp.verify_worker_record(record, tmp_path / "run-a")
        assert not rsp.verify_worker_record(record, tmp_path / "run-b")

    def test_legacy_unbound_token_verifies_in_any_dir(
        self, tmp_path: Path,
    ):
        # Records minted before run binding existed carry no run_dir
        # in the MAC'd fields; the fallback keeps those runs verifying
        # across the upgrade. The window self-expires with the stamped
        # worker process — no NEW token is ever minted in this shape.
        record = {"tool_pid": 4242, "tool_pid_start": "123456"}
        token = rsp._mint(rsp._worker_fields(record))
        assert token
        record[rsp.WORKER_PROVENANCE_KEY] = token
        assert rsp.verify_worker_record(record, tmp_path / "anywhere")

    def test_legacy_unstamped_fails_quietly(self, tmp_path: Path):
        # Degrade, never error: the pre-stamp record shape.
        assert not rsp.verify_worker_record(
            {"tool_pid": 4242, "tool_pid_start": "123456"}, tmp_path)

    def test_garbage_token_fails_quietly(self, tmp_path: Path):
        record = {"tool_pid": 4242, "tool_pid_start": "123456",
                  rsp.WORKER_PROVENANCE_KEY: "zz-not-hex"}
        assert not rsp.verify_worker_record(record, tmp_path)
        record[rsp.WORKER_PROVENANCE_KEY] = ["list"]
        assert not rsp.verify_worker_record(record, tmp_path)

    def test_non_mapping_fails_quietly(self, tmp_path: Path):
        assert not rsp.verify_worker_record(
            None, tmp_path)  # type: ignore[arg-type]

    def test_pidless_record_never_stamped(self, tmp_path: Path):
        record = {"status": "running",
                  rsp.WORKER_PROVENANCE_KEY: "stale-token"}
        rsp.stamp_worker_record(record, tmp_path)
        assert rsp.WORKER_PROVENANCE_KEY not in record

    def test_restamp_replaces_stale_token(self, tmp_path: Path):
        record = {"tool_pid": 4242, "tool_pid_start": "1"}
        rsp.stamp_worker_record(record, tmp_path)
        record["tool_pid_start"] = "2"
        rsp.stamp_worker_record(record, tmp_path)
        assert rsp.verify_worker_record(record, tmp_path)


class TestCostCap:
    def test_stamp_then_verify(self, tmp_path: Path):
        cfg = {"max_cost_usd": 25.0}
        rsp.stamp_cost_cap(cfg, tmp_path)
        assert rsp.verify_cost_cap(cfg, tmp_path)

    def test_uncapped_none_stamps_and_verifies(self, tmp_path: Path):
        cfg: dict = {}
        rsp.stamp_cost_cap(cfg, tmp_path)
        assert rsp.COST_CAP_PROVENANCE_KEY in cfg
        assert rsp.verify_cost_cap(cfg, tmp_path)

    def test_int_float_same_value_cross_verify(self, tmp_path: Path):
        # JSON may hand back 25 for a persisted 25.0: the canonical
        # form goes through float(), so the numeric value — not its
        # spelling — is what the token binds.
        cfg = {"max_cost_usd": 25.0}
        rsp.stamp_cost_cap(cfg, tmp_path)
        cfg["max_cost_usd"] = 25
        assert rsp.verify_cost_cap(cfg, tmp_path)

    def test_tampered_value_fails(self, tmp_path: Path):
        cfg = {"max_cost_usd": 10.0}
        rsp.stamp_cost_cap(cfg, tmp_path)
        cfg["max_cost_usd"] = 0.0
        assert not rsp.verify_cost_cap(cfg, tmp_path)

    def test_distinct_non_numeric_values_never_cross_verify(
        self, tmp_path: Path,
    ):
        # No current writer persists non-numeric caps, but the resume
        # reader coerces via float(), which accepts numeric STRINGS —
        # a shared non-numeric sentinel would let a stamp minted over
        # "5" verify for "999999". Each non-numeric value must bind
        # its own canonical.
        cfg: dict = {"max_cost_usd": "5"}
        rsp.stamp_cost_cap(cfg, tmp_path)
        assert rsp.verify_cost_cap(cfg, tmp_path)
        cfg["max_cost_usd"] = "999999"
        assert not rsp.verify_cost_cap(cfg, tmp_path)
        # Cross-type non-numerics stay distinct too.
        assert rsp._cap_canonical("5") != rsp._cap_canonical(["5"])
        assert rsp._cap_canonical(True) != rsp._cap_canonical("True")

    def test_deleted_value_fails(self, tmp_path: Path):
        # "Uncapped" is a stampable value of its own: deleting the key
        # from a capped config must not verify as uncapped.
        cfg = {"max_cost_usd": 10.0}
        rsp.stamp_cost_cap(cfg, tmp_path)
        del cfg["max_cost_usd"]
        assert not rsp.verify_cost_cap(cfg, tmp_path)

    def test_bound_to_run_dir(self, tmp_path: Path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        cfg: dict = {}
        rsp.stamp_cost_cap(cfg, dir_a)
        assert rsp.verify_cost_cap(cfg, dir_a)
        assert not rsp.verify_cost_cap(cfg, dir_b)

    def test_legacy_unstamped_fails_quietly(self, tmp_path: Path):
        assert not rsp.verify_cost_cap({"max_cost_usd": 10.0}, tmp_path)
        assert not rsp.verify_cost_cap({}, tmp_path)

    def test_worker_token_never_cross_verifies(self, tmp_path: Path):
        # Shared key, distinct kinds: a worker token replayed into the
        # cost-cap slot (or vice versa) must not verify — even when
        # both bind the SAME run dir, the kind field separates them.
        record = {"tool_pid": 4242, "tool_pid_start": "1"}
        rsp.stamp_worker_record(record, tmp_path)
        cfg = {"max_cost_usd": None,
               rsp.COST_CAP_PROVENANCE_KEY:
                   record[rsp.WORKER_PROVENANCE_KEY]}
        assert not rsp.verify_cost_cap(cfg, tmp_path)


class TestKeyHandling:
    def test_key_usable_creates_key(self):
        assert rsp.key_usable()
        assert rsp._key_path().is_file()

    def test_unusable_key_degrades_to_unstamped(self, tmp_path: Path):
        # A symlinked key file is refused by the shared fd-fstat
        # discipline (O_NOFOLLOW at open): writers persist unstamped,
        # readers degrade — never an exception.
        import os
        xdg = Path(os.environ["XDG_DATA_HOME"])
        key_dir = xdg / "raptor"
        key_dir.mkdir(parents=True)
        real = tmp_path / "elsewhere.key"
        real.write_bytes(b"k" * 32)
        (key_dir / "resume-state-mac.key").symlink_to(real)
        record = {"tool_pid": 4242, "tool_pid_start": "1"}
        rsp.stamp_worker_record(record, tmp_path)
        assert rsp.WORKER_PROVENANCE_KEY not in record
        assert not rsp.verify_worker_record(record, tmp_path)
        cfg = {"max_cost_usd": 5.0}
        rsp.stamp_cost_cap(cfg, tmp_path)
        assert rsp.COST_CAP_PROVENANCE_KEY not in cfg
        assert not rsp.key_usable()
