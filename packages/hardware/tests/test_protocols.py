"""Hermetic tests for the hardware enumeration pipeline.

No Glasgow device or binary required: a fake runner records the exact
argv each stage produces, and the parsers are fed output shaped like
current upstream glasgow (audited against GlasgowEmbedded/glasgow).
These pin the CLI contract — applet names, pin flag forms, which
stream results land on — so a silent drift becomes a red test, not a
degraded field run. Real-process tests for run_timed use throwaway
python children (no device involved).
"""

from __future__ import annotations

import sys

import pytest

from packages.hardware.enumerator import (
    _load_noise_floor,
    _make_recommendations,
    _parse_pin_range,
)
from packages.hardware.glasgow_runner import GlasgowRunner
from packages.hardware.protocols.i2c import _parse_i2c_scan, detect_i2c
from packages.hardware.protocols.jtag import _parse_pinout_output, detect_jtag
from packages.hardware.protocols.passive import (
    _capture_vcd,
    _parse_vcd,
    filter_pins_by_noise_floor,
)
from packages.hardware.protocols.uart import _finding_from_result, detect_uart


def _res(returncode: int = 0, stdout: str = "", stderr: str = "",
         stdout_bytes: bytes | None = None) -> dict:
    """Result dict in the GlasgowRunner shape."""
    return {
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_bytes": stdout_bytes if stdout_bytes is not None
        else stdout.encode(),
        "command": "",
    }


class FakeRunner:
    """Duck-typed GlasgowRunner: records argv, replays canned results."""

    def __init__(self, results: list[dict] | None = None):
        self.calls: list[list[str]] = []
        self._results = list(results or [])

    def _next(self) -> dict:
        if self._results:
            return self._results.pop(0)
        return _res()

    def run(self, args: list[str], timeout: int | None = None,
            capture_output: bool = True) -> dict:
        self.calls.append(list(args))
        return self._next()

    def run_timed(self, args: list[str], duration: int,
                  grace: int = 5) -> dict:
        self.calls.append(list(args))
        return self._next()


def _real_runner(binary: str = "glasgow") -> GlasgowRunner:
    """A GlasgowRunner without the PATH probe, pointed at ``binary``."""
    r = GlasgowRunner.__new__(GlasgowRunner)
    r.timeout = 30
    r._glasgow_path = binary
    return r


# ---------------------------------------------------------------------------
# Passive capture
# ---------------------------------------------------------------------------


class TestPassive:
    def test_capture_invocation_shape(self, tmp_path):
        """The analyzer applet contract: name 'analyzer', pins as one
        --i list in A<n> form, explicit --pin-names labels, positional
        VCD path."""
        fake = FakeRunner()
        vcd = tmp_path / "cap.vcd"
        _capture_vcd(fake, [0, 2, 5], vcd, 3.3, duration=10)
        assert fake.calls == [[
            "run", "analyzer", "-V", "3.3",
            "--i", "A0,A2,A5",
            "--pin-names", "pin0,pin2,pin5",
            str(vcd),
        ]]

    def test_parse_vcd_counts_by_physical_pin(self, tmp_path):
        vcd = tmp_path / "t.vcd"
        vcd.write_text(
            "$timescale 1 ns $end\n"
            "$scope module glasgow $end\n"
            "$var wire 1 ! pin2 $end\n"
            "$var wire 1 \" pin5 $end\n"
            "$enddefinitions $end\n"
            "#0\n0!\n0\"\n"
            "#10\n1!\n"
            "#20\n0!\n"
            "#30\n1\"\n"
        )
        counts = _parse_vcd(vcd)
        assert counts == {2: 3, 5: 2}

    def test_parse_vcd_missing_or_empty(self, tmp_path):
        assert _parse_vcd(tmp_path / "absent.vcd") == {}
        empty = tmp_path / "empty.vcd"
        empty.write_bytes(b"")
        assert _parse_vcd(empty) == {}

    def test_noise_floor_filter(self):
        real, noise = filter_pins_by_noise_floor(
            signal_counts={1: 1000, 2: 12, 3: 500},
            noise_counts={1: 5, 2: 10},
            snr_threshold=10.0,
        )
        # pin 1: SNR 200 → real; pin 2: SNR 1.2 → noise;
        # pin 3: zero noise floor → always real
        assert real == [1, 3]
        assert noise == [2]


# ---------------------------------------------------------------------------
# I2C
# ---------------------------------------------------------------------------


class TestI2C:
    def test_parse_current_upstream_format(self):
        out = (
            "I: g.applet.interface.i2c_controller: scan found address 0b0101000/0x28\n"
            "I: g.applet.interface.i2c_controller: scan found address 0b1010000/0x50\n"
        )
        assert _parse_i2c_scan(out) == ["0x28", "0x50"]

    def test_parse_legacy_formats_and_dedupe(self):
        out = "0x48: present\ndevice at 0x48\ndevice at 0x50\n"
        assert _parse_i2c_scan(out) == ["0x48", "0x50"]

    def test_detect_invocation_and_stderr_results(self, tmp_path):
        hit = _res(stderr="I: scan found address 0b1010000/0x50\n")
        fake = FakeRunner(results=[hit])
        findings = detect_i2c(fake, [0, 1], tmp_path, voltage=3.3)
        assert fake.calls[0] == [
            "run", "i2c-controller", "--voltage", "3.3",
            "--scl", "A0", "--sda", "A1", "scan",
        ]
        assert findings[0]["protocol"] == "i2c"
        assert findings[0]["devices"] == ["0x50"]


# ---------------------------------------------------------------------------
# UART
# ---------------------------------------------------------------------------


class TestUART:
    def test_auto_baud_first_then_fallback(self, tmp_path):
        boot = "U-Boot 2023.01 (RAPTOR)\nHit any key to stop autoboot\n"
        auto_hit = _res(
            stdout=boot,
            stderr="I: g.applet.interface.uart: switched to 57600 baud\n",
        )
        fake = FakeRunner(results=[auto_hit])
        findings = detect_uart(fake, [1], tmp_path, voltage=3.3)
        assert fake.calls[0] == [
            "run", "uart", "--voltage", "3.3", "--auto-baud",
            "--rx", "A1", "tty", "--stream",
        ]
        assert len(fake.calls) == 1  # auto-baud hit → no fixed-rate sweep
        assert findings[0]["baud_rate"] == 57600
        assert findings[0]["notes"] == "U-Boot boot log detected"

    def test_auto_baud_without_switched_line_is_none(self, tmp_path):
        """Auto-baud confirmed the pin but never logged a rate —
        baud_rate must be None (rendered 'auto'), never 0."""
        hit = _res(stdout="BusyBox v1.36 built-in shell\n# ")
        finding = _finding_from_result(hit, 1, None, tmp_path / "c.bin")
        assert finding is not None
        assert finding["baud_rate"] is None

    def test_fallback_iterates_fixed_rates(self, tmp_path):
        silent = _res(returncode=1)
        shell = _res(stdout="BusyBox v1.36 built-in shell\n# ")
        fake = FakeRunner(results=[silent, shell])
        findings = detect_uart(fake, [3], tmp_path, voltage=3.3)
        assert fake.calls[1][:6] == [
            "run", "uart", "--voltage", "3.3", "--baud", "115200",
        ]
        assert findings[0]["baud_rate"] == 115200

    def test_raw_noise_rejected_even_when_decoded_lossy(self, tmp_path):
        """Scoring runs on RAW bytes: undecodable noise whose lossy
        decode is all printable replacement chars must NOT score as
        UART."""
        noise = bytes(range(0x80, 0xC0)) * 4
        garbage = _res(
            stdout=noise.decode("utf-8", errors="replace"),
            stdout_bytes=noise,
        )
        assert _finding_from_result(garbage, 0, 9600, tmp_path / "c.bin") is None

    def test_sample_display_sanitized(self, tmp_path):
        """Control bytes (e.g. ESC) from a hostile target must not reach
        reports/terminal verbatim."""
        payload = b"login: \x1b]0;pwned\x07\r\n"
        hit = _res(stdout_bytes=payload + b" " * 40)
        finding = _finding_from_result(hit, 2, 9600, tmp_path / "c.bin")
        assert finding is not None
        assert "\x1b" not in finding["sample_bytes"]
        assert "login:" in finding["sample_bytes"]


# ---------------------------------------------------------------------------
# JTAG (jtag-pinout)
# ---------------------------------------------------------------------------

_PINOUT_HIT = (
    "I: g.applet.interface.jtag_pinout: detecting TCK, TMS, and TDO\n"
    "I: g.applet.interface.jtag_pinout: JTAG interface with reset detected\n"
    "I: g.applet.interface.jtag_pinout: use `jtag-probe -V 3.3 --tck A0 "
    "--tms A1 --tdi B2 --tdo A3 --trst A4` as arguments\n"
)


class TestJTAG:
    def test_parse_pinout_roles_keep_port(self):
        roles = _parse_pinout_output(_PINOUT_HIT)
        # Full pin names — dropping the port letter would misreport B2.
        assert roles == {
            "tck": "A0", "tms": "A1", "tdi": "B2", "tdo": "A3", "trst": "A4",
        }

    def test_parse_no_interface(self):
        assert _parse_pinout_output("W: no JTAG interface detected\n") is None

    def test_parse_multi_interface_is_no_result(self):
        out = (
            "W: more than one JTAG interface detected; this is likely a "
            "false positive\n" + _PINOUT_HIT
        )
        assert _parse_pinout_output(out) is None

    def test_detect_invocation_and_finding(self, tmp_path):
        hit = _res(stderr=_PINOUT_HIT)
        fake = FakeRunner(results=[hit])
        findings = detect_jtag(fake, [0, 1, 2, 3, 4], tmp_path, voltage=3.3)
        assert fake.calls == [[
            "run", "jtag-pinout", "-V", "3.3", "--pins", "A0,A1,A2,A3,A4",
        ]]
        assert findings[0]["pins"]["tck"] == "A0"
        assert findings[0]["pins"]["tdi"] == "B2"
        assert findings[0]["confidence"] == "confirmed"

    def test_too_few_pins_skips(self, tmp_path):
        fake = FakeRunner()
        assert detect_jtag(fake, [0, 1, 2], tmp_path) == []
        assert fake.calls == []


# ---------------------------------------------------------------------------
# Enumerator helpers
# ---------------------------------------------------------------------------


class TestParsePinRange:
    def test_valid_forms(self):
        assert _parse_pin_range("0-7") == [0, 1, 2, 3, 4, 5, 6, 7]
        assert _parse_pin_range("0,3,5") == [0, 3, 5]
        assert _parse_pin_range("0-2,6") == [0, 1, 2, 6]

    @pytest.mark.parametrize("bad", ["3-", "-1", "1,,2", "a", "", "7-0", "0-9"])
    def test_malformed_rejected(self, bad):
        with pytest.raises(ValueError):
            _parse_pin_range(bad)


class TestLoadNoiseFloor:
    def test_valid(self, tmp_path):
        p = tmp_path / "nf.json"
        p.write_text('{"0": 5, "3": 12}')
        assert _load_noise_floor(str(p)) == {0: 5, 3: 12}

    @pytest.mark.parametrize("content", [
        '{"0": "not-a-count"}', '{"x": 1}', "[]", "not json",
    ])
    def test_malformed_disables_filtering(self, tmp_path, content, capsys):
        p = tmp_path / "nf.json"
        p.write_text(content)
        assert _load_noise_floor(str(p)) == {}
        assert "noise filtering disabled" in capsys.readouterr().out

    def test_missing_file_disables_filtering(self, tmp_path):
        assert _load_noise_floor(str(tmp_path / "absent.json")) == {}


class TestRecommendations:
    def test_jtag_completed_scan_not_resuggested(self):
        """A finished-but-empty JTAG scan appends plain 'jtag' — the
        're-run with --jtag' hint must fire only for 'jtag (not
        scanned)'."""
        recs = _make_recommendations([], ["i2c", "uart", "jtag"])
        assert not any("--jtag" in r for r in recs)
        recs = _make_recommendations([], ["i2c", "jtag (not scanned)"])
        assert any("--jtag" in r for r in recs)

    def test_uart_auto_baud_none_renders_auto(self):
        recs = _make_recommendations([{
            "protocol": "uart", "baud_rate": None,
            "pins": {"rx": 1}, "notes": "",
        }], [])
        assert "--auto-baud" in recs[0]
        assert "--baud 0" not in recs[0]
        assert "None" not in recs[0]

    def test_jtag_pins_used_verbatim(self):
        recs = _make_recommendations([{
            "protocol": "jtag",
            "pins": {"tck": "A0", "tms": "A1", "tdi": "B2", "tdo": "A3"},
        }], [])
        assert "--tdi B2" in recs[0]
        assert "AB2" not in recs[0] and "AA0" not in recs[0]


# ---------------------------------------------------------------------------
# GlasgowRunner: applet probe, identify, timed captures
# ---------------------------------------------------------------------------


class TestCheckApplet:
    def _runner_with(self, results: list[dict]) -> GlasgowRunner:
        r = _real_runner()
        fake = FakeRunner(results=results)
        r.run = fake.run  # type: ignore[method-assign]
        return r

    def test_compatible(self):
        ok = _res(stdout="usage: ... --scl PIN --sda PIN")
        r = self._runner_with([ok])
        assert r.check_applet("i2c-controller", ["--scl", "--sda"]) is None

    def test_missing_flag_reported(self):
        old = _res(stdout="usage: ... --pins-scl N")
        r = self._runner_with([old])
        problem = r.check_applet("i2c-controller", ["--scl", "--sda"])
        assert problem is not None and "--scl" in problem

    def test_short_flag_not_satisfied_by_longer_flag(self):
        """Word-boundary matching: help text offering only --io must not
        satisfy an expected --i."""
        lookalike = _res(stdout="usage: ... --io PINS --input FILE")
        r = self._runner_with([lookalike])
        problem = r.check_applet("analyzer", ["--i"])
        assert problem is not None and "--i" in problem

    def test_unknown_applet_reported(self):
        err = _res(returncode=2,
                   stderr="error: unknown applet 'logic-analyzer'")
        r = self._runner_with([err])
        problem = r.check_applet("logic-analyzer", ["--pins"])
        assert problem is not None and "not available" in problem


class TestIdentify:
    def test_serial_to_revision(self):
        r = _real_runner()
        fake = FakeRunner(results=[_res(stdout="C3-20240527T113341Z\n")])
        r.run = fake.run  # type: ignore[method-assign]
        info = r.identify()
        assert info == {
            "found": True, "version": "revC3",
            "serial": "C3-20240527T113341Z", "raw": "C3-20240527T113341Z",
        }

    def test_no_device(self):
        r = _real_runner()
        fake = FakeRunner(results=[_res(stderr="W: no devices available\n")])
        r.run = fake.run  # type: ignore[method-assign]
        assert r.identify()["found"] is False


class TestRunTimed:
    """Real-process tests: throwaway python children stand in for the
    glasgow CLI. Durations are kept tiny."""

    def test_window_elapses_and_sigint_collects_output(self):
        r = _real_runner(sys.executable)
        result = r.run_timed(
            ["-u", "-c",
             "import time,sys\n"
             "sys.stdout.write('captured')\n"
             "sys.stdout.flush()\n"
             "time.sleep(30)"],
            duration=1, grace=3,
        )
        assert result["stdout"] == "captured"
        assert result["stdout_bytes"] == b"captured"

    def test_binary_noise_does_not_crash(self):
        """Non-UTF-8 device bytes must come back decoded lossily, not
        raise UnicodeDecodeError out of communicate()."""
        r = _real_runner(sys.executable)
        result = r.run_timed(
            ["-u", "-c",
             "import sys,time\n"
             "sys.stdout.buffer.write(b'\\xff\\xfe\\x80ok')\n"
             "sys.stdout.flush()\n"
             "time.sleep(30)"],
            duration=1, grace=3,
        )
        assert result["stdout_bytes"] == b"\xff\xfe\x80ok"
        assert "ok" in result["stdout"]

    def test_sigint_ignorer_is_killed_and_reaped(self):
        """A child that ignores SIGINT must be SIGKILLed within the
        grace budget instead of hanging the pipeline."""
        r = _real_runner(sys.executable)
        result = r.run_timed(
            ["-u", "-c",
             "import signal,time\n"
             "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
             "time.sleep(60)"],
            duration=1, grace=1,
        )
        assert result["returncode"] != 0

    def test_missing_binary(self):
        r = _real_runner("/nonexistent/glasgow-binary")
        result = r.run_timed(["run", "analyzer"], duration=1)
        assert result["returncode"] == -1
        assert "not found" in result["stderr"]
