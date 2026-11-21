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

    def test_witness_confirms(self, tmp_path):
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
                "core.symbolic.find_overflow_reaching_input",
                return_value=_R(),
            ),
        ):
            res = run_symbolic_sweep(
                target_path=binary, file_path="binary:b",
                function_name="f", out_dir=tmp_path,
                address=0x1000, cwe="CWE-121",
            )
        assert res.outcome == "confirmed"
        assert res.rule_id == "symbolic-pc-hijack"
        entry = res.to_log_entry()
        assert entry["key"] == "binary:b:f"
