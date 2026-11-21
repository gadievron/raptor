"""Tests for the audit's symbolic (angr) sweep channel."""

from unittest.mock import patch

from core.audit.sweep import run_symbolic_sweep, symbolic_applicable


class _Info:
    """load_binary stub."""

    def __init__(self, symbols=None, is_pie=False):
        self.symbols = symbols or {"f": 0x1000}
        self.is_pie = is_pie


class TestApplicability:
    def test_source_items_never_applicable(self):
        assert not symbolic_applicable("CWE-121", "src/main.c")

    def test_binary_items_gated_on_angr(self):
        with patch(
            "core.symbolic._availability.angr_available",
            return_value=False,
        ):
            assert not symbolic_applicable("CWE-121", "binary:t")


class TestRunnerErrors:
    def test_source_file_errors(self, tmp_path):
        res = run_symbolic_sweep(
            target_path=tmp_path, file_path="src/a.c",
            function_name="f", out_dir=tmp_path,
        )
        assert res.outcome == "error"
        assert "binary:" in res.errors[0]

    def test_angr_absent_errors_cleanly(self, tmp_path):
        with patch(
            "core.symbolic._availability.angr_available",
            return_value=False,
        ):
            res = run_symbolic_sweep(
                target_path=tmp_path / "b", file_path="binary:b",
                function_name="f", out_dir=tmp_path,
            )
        assert res.outcome == "error"
        assert "angr" in res.errors[0]

    def test_no_witness_is_inconclusive_never_refuted(self, tmp_path):
        binary = tmp_path / "b"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 60)

        class _R:
            succeeded = False
            concrete_input = None
            reason = "budget exhausted"

        with (
            patch(
                "core.symbolic._availability.angr_available",
                return_value=True,
            ),
            patch("core.symbolic.load_binary", return_value=_Info()),
            patch(
                "core.symbolic.find_reaching_input", return_value=_R(),
            ),
        ):
            res = run_symbolic_sweep(
                target_path=binary, file_path="binary:b",
                function_name="f", out_dir=tmp_path,
                address=0x1000, cwe="CWE-79",
            )
        assert res.outcome == "inconclusive"
        assert "not a refutation" in (res.details or {}).get("reason", "")

    def _reach_with_replay(self, tmp_path, replay_record):
        binary = tmp_path / "b"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 60)

        class _R:
            succeeded = True
            concrete_input = b"A" * 32
            reason = ""
            wall_seconds = 1.0

        with (
            patch(
                "core.symbolic._availability.angr_available",
                return_value=True,
            ),
            patch("core.symbolic.load_binary", return_value=_Info()),
            patch(
                "core.symbolic.find_reaching_input", return_value=_R(),
            ),
            patch(
                "packages.exploitability_validation.symbolic_witness"
                ".replay_witness",
                return_value=dict(replay_record),
            ),
            patch(
                "packages.exploitability_validation.symbolic_witness"
                ".store_witness",
                return_value="0" * 64,
            ),
        ):
            return run_symbolic_sweep(
                target_path=binary, file_path="binary:b",
                function_name="f", out_dir=tmp_path,
                address=0x1000, cwe="CWE-79", replay=True,
            )

    def test_waitstatus_crash_upgrades_to_crash_grade(self, tmp_path):
        res = self._reach_with_replay(tmp_path, {
            "replay_outcome": "exit_signal",
            "replay_signal": 11,
            "signal_provenance": "waitstatus",
            "evidence_grade": "mechanical",
        })
        assert res.outcome == "confirmed"
        assert res.rule_id == "symbolic-reach-crash"
        details = res.details or {}
        assert details.get("signal_provenance") == "waitstatus"
        assert details.get("evidence_grade") == "mechanical"
        assert "crashed with signal 11" in res.matches[0]["message"]

    def test_exitcode_decoded_signal_never_crash_grade(self, tmp_path):
        # A target calling exit(139) produces the exitcode/heuristic
        # stamps; the forgeable signal must not mint the crash rule.
        res = self._reach_with_replay(tmp_path, {
            "replay_outcome": "exit_signal",
            "replay_signal": 11,
            "signal_provenance": "exitcode",
            "evidence_grade": "heuristic",
        })
        assert res.outcome == "confirmed"
        assert res.rule_id == "symbolic-reach"
        details = res.details or {}
        assert details.get("signal_provenance") == "exitcode"
        assert details.get("evidence_grade") == "heuristic"
        message = res.matches[0]["message"]
        assert "crashed with signal" not in message
        assert "target-forgeable" in message

    def _hijack_sweep(self, tmp_path, result_cls):
        binary = tmp_path / "b"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
        with (
            patch(
                "core.symbolic._availability.angr_available",
                return_value=True,
            ),
            patch("core.symbolic.load_binary", return_value=_Info()),
            patch(
                "core.symbolic.find_overflow_reaching_input",
                return_value=result_cls(),
            ),
        ):
            return run_symbolic_sweep(
                target_path=binary, file_path="binary:b",
                function_name="f", out_dir=tmp_path,
                address=0x1000, cwe="CWE-121",
            )

    def test_witness_confirms(self, tmp_path):
        class _R:
            succeeded = True
            concrete_input = b"A" * 32
            reason = ""
            wall_seconds = 1.0
            metadata = {"hijack_sites": [
                {"address": 0x1040, "symbol": "f"},
                {"address": 0x1010, "symbol": "f"},
            ]}

        res = self._hijack_sweep(tmp_path, _R)
        assert res.outcome == "confirmed"
        assert res.rule_id == "symbolic-pc-hijack"
        assert (res.details or {}).get("hijack_sites")
        entry = res.to_log_entry()
        assert entry["key"] == "binary:b:f"

    def test_hijack_site_elsewhere_is_inconclusive(self, tmp_path):
        # The witness steers PC to f's address, but the frame that
        # leaked control belongs to other_func — confirming f's
        # finding from this witness would be a false conclusion.
        class _R:
            succeeded = True
            concrete_input = b"A" * 32
            reason = ""
            wall_seconds = 1.0
            metadata = {"hijack_sites": [
                {"address": 0x2040, "symbol": "other_func"},
            ]}

        res = self._hijack_sweep(tmp_path, _R)
        assert res.outcome == "inconclusive"
        assert res.rule_id == "symbolic-pc-hijack"
        reason = (res.details or {}).get("reason", "")
        assert "other_func" in reason
        assert "unconfirmed" in reason

    def test_hijack_without_attribution_is_inconclusive(self, tmp_path):
        # No metadata at all (solver stub / legacy result): the site
        # is unknown, so the per-function claim stays unconfirmed.
        class _R:
            succeeded = True
            concrete_input = b"A" * 32
            reason = ""
            wall_seconds = 1.0

        res = self._hijack_sweep(tmp_path, _R)
        assert res.outcome == "inconclusive"
        reason = (res.details or {}).get("reason", "")
        assert "could not be attributed" in reason

    def test_hijack_hostile_symbol_rendered_inert(self, tmp_path):
        # Symbol names are attacker-chosen bytes from the analysed
        # binary; the inconclusive reason must carry escapes, not
        # raw control characters.
        class _R:
            succeeded = True
            concrete_input = b"A" * 32
            reason = ""
            wall_seconds = 1.0
            metadata = {"hijack_sites": [
                {"address": 0x2040, "symbol": "evil\x1b[2Jname"},
            ]}

        res = self._hijack_sweep(tmp_path, _R)
        assert res.outcome == "inconclusive"
        reason = (res.details or {}).get("reason", "")
        assert "\x1b" not in reason
        assert "evil" in reason


class TestCanaryCaveat:
    """A hijack witness against a stack-protector build is
    model-optimistic — the solver chose the guard value, which a real
    attacker cannot. A confirmed symbolic-pc-hijack must never ship
    without the caveat on such a build."""

    def _hijack_sweep(self, tmp_path, result_cls, store_capture=None):
        binary = tmp_path / "b"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 60)

        def _capture(finding, record, binary_path, out_dir):
            if store_capture is not None:
                store_capture.update(record)
            return "0" * 64

        with (
            patch(
                "core.symbolic._availability.angr_available",
                return_value=True,
            ),
            patch("core.symbolic.load_binary", return_value=_Info()),
            patch(
                "core.symbolic.find_overflow_reaching_input",
                return_value=result_cls(),
            ),
            patch(
                "packages.exploitability_validation.symbolic_witness"
                ".store_witness",
                side_effect=_capture,
            ),
        ):
            return run_symbolic_sweep(
                target_path=binary, file_path="binary:b",
                function_name="f", out_dir=tmp_path,
                address=0x1000, cwe="CWE-121",
            )

    @staticmethod
    def _result(canary):
        class _R:
            succeeded = True
            concrete_input = b"A" * 32
            reason = ""
            wall_seconds = 1.0
            metadata = {
                "hijack_sites": [{"address": 0x1040, "symbol": "f"}],
                "canary_present": canary,
            }
        return _R

    def test_protector_build_confirmation_carries_caveat(self, tmp_path):
        from packages.exploitability_validation.symbolic_witness import (
            CANARY_CAVEAT,
        )
        res = self._hijack_sweep(tmp_path, self._result(True))
        assert res.outcome == "confirmed"
        assert res.rule_id == "symbolic-pc-hijack"
        assert (res.details or {}).get("canary_caveat") == CANARY_CAVEAT
        assert "stack protector" in res.matches[0]["message"]
        assert "model-optimistic" in res.matches[0]["message"]

    def test_protector_caveat_reaches_stored_witness_record(self, tmp_path):
        captured = {}
        self._hijack_sweep(tmp_path, self._result(True),
                           store_capture=captured)
        assert "stack protector" in captured.get("canary_caveat", "")

    def test_unprotected_build_has_no_caveat(self, tmp_path):
        captured = {}
        res = self._hijack_sweep(tmp_path, self._result(False),
                                 store_capture=captured)
        assert res.outcome == "confirmed"
        assert "canary_caveat" not in (res.details or {})
        assert "stack protector" not in res.matches[0]["message"]
        assert "canary_caveat" not in captured

    def test_inconclusive_hijack_still_carries_caveat(self, tmp_path):
        # Site attribution fails (control lost elsewhere) — the kept
        # witness details must still say the guard was solver-chosen.
        class _R:
            succeeded = True
            concrete_input = b"A" * 32
            reason = ""
            wall_seconds = 1.0
            metadata = {
                "hijack_sites": [{"address": 0x2040,
                                  "symbol": "other_func"}],
                "canary_present": True,
            }

        res = self._hijack_sweep(tmp_path, _R)
        assert res.outcome == "inconclusive"
        assert "stack protector" in (res.details or {}).get(
            "canary_caveat", "")

    def test_reach_mode_never_caveats(self, tmp_path):
        # canary_present is hijack metadata; plain reachability on a
        # protector build is not model-optimistic.
        binary = tmp_path / "b"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 60)

        class _R:
            succeeded = True
            concrete_input = b"A" * 32
            reason = ""
            wall_seconds = 1.0
            metadata = {"canary_present": True}

        with (
            patch(
                "core.symbolic._availability.angr_available",
                return_value=True,
            ),
            patch("core.symbolic.load_binary", return_value=_Info()),
            patch(
                "core.symbolic.find_reaching_input", return_value=_R(),
            ),
            patch(
                "packages.exploitability_validation.symbolic_witness"
                ".store_witness",
                return_value="0" * 64,
            ),
        ):
            res = run_symbolic_sweep(
                target_path=binary, file_path="binary:b",
                function_name="f", out_dir=tmp_path,
                address=0x1000, cwe="CWE-79",
            )
        assert res.outcome == "confirmed"
        assert "canary_caveat" not in (res.details or {})
