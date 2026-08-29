#!/usr/bin/env python3
"""
Passive logic capture and VCD analysis.

Captures signals on up to 8 pins while the user power-cycles the target.
Identifies which pins have signal transitions (active pins) by parsing the VCD.
"""

import json
import re
from pathlib import Path

from core.logging import get_logger
from packages.hardware.glasgow_runner import GlasgowRunner

logger = get_logger()

CAPTURE_DURATION = 10   # seconds
BASELINE_DURATION = 5   # seconds for noise floor capture


def _parse_vcd(vcd_path: Path) -> dict[int, int]:
    """
    Parse a VCD file and return transition counts per pin.

    Scans value-change lines after $enddefinitions. A line matching
    [01xz][!-~] (value + signal-id character) indicates a state change.

    Args:
        vcd_path: Path to the .vcd file

    Returns:
        dict mapping pin_number -> transition_count for pins with any transitions
    """
    counts: dict[int, int] = {}
    signal_map: dict[str, int] = {}   # VCD signal-id character -> pin number
    # Signal names come from the --pin-names labels the capture passes
    # ("pin<N>" by physical pin number). Without that flag the analyzer
    # applet defaults to positional "pin[0]", "pin[1]", ... names, whose
    # first integer is the LIST INDEX, not the pin — always capture with
    # explicit labels.

    if not vcd_path.exists() or vcd_path.stat().st_size == 0:
        return counts

    past_definitions = False

    try:
        with open(vcd_path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()

                # Map $var declarations to pin numbers
                # e.g.  $var wire 1 ! pin0 $end
                if "$var" in line:
                    m = re.search(r'\$var\s+\S+\s+\d+\s+(\S+)\s+(\S+)', line)
                    if m:
                        sig_id = m.group(1)
                        sig_name = m.group(2).strip().removesuffix("$end").strip()
                        nm = re.search(r'(\d+)', sig_name)
                        if nm:
                            signal_map[sig_id] = int(nm.group(1))

                if "$enddefinitions" in line:
                    past_definitions = True
                    continue

                if not past_definitions:
                    continue

                # Value-change lines: [01xzXZ][printable]
                m = re.match(r'^([01xzXZ])([!-~])$', line)
                if m:
                    value = m.group(1)
                    sig_id = m.group(2)
                    if value in ('0', '1') and sig_id in signal_map:
                        pin = signal_map[sig_id]
                        counts[pin] = counts.get(pin, 0) + 1

    except Exception as e:
        logger.warning(f"VCD parse error: {e}")

    return counts


def _hint_if_bitstream_build(result: dict) -> None:
    """On a fresh install glasgow synthesizes the applet's FPGA
    bitstream INSIDE the first capture window (minutes vs a 5-10s
    window) — the capture then looks empty. Tell the operator what
    actually happened instead of leaving a silent false negative."""
    stderr = result.get("stderr", "")
    if "toolchain" in stderr or "bitstream" in stderr or "yosys" in stderr:
        print(
            "  [!] glasgow appears to be building the applet bitstream "
            "(first run on this install) — the capture window elapsed "
            "during the build. Re-run once, or pre-build with "
            "`glasgow build --rev <rev> <applet> ...`"
        )


def _capture_vcd(
    glasgow: GlasgowRunner,
    pins: list[int],
    vcd_path: Path,
    voltage: float,
    duration: int,
) -> dict:
    """Capture ``duration`` seconds of logic activity on ``pins`` into
    ``vcd_path`` using the ``analyzer`` applet.

    The applet streams until interrupted (it has no duration option), so
    the capture runs under :meth:`GlasgowRunner.run_timed` — SIGINT after
    the window lets the applet close the VCD file cleanly. Pins are
    passed as one ``--i`` list in Glasgow ``A<n>`` notation, and
    ``--pin-names`` labels each signal ``pin<n>`` by PHYSICAL pin number
    so ``_parse_vcd`` recovers real pins (the applet's default names are
    positional indices).

    Success is judged by the caller on the VCD artifact, not the exit
    code — an interrupted capture exits non-zero by design.
    """
    pin_list = ",".join(f"A{p}" for p in pins)
    pin_names = ",".join(f"pin{p}" for p in pins)
    return glasgow.run_timed(
        [
            "run", "analyzer",
            "-V", str(voltage),
            "--i", pin_list,
            "--pin-names", pin_names,
            str(vcd_path),
        ],
        duration=duration,
    )


def run_noise_baseline(
    glasgow: GlasgowRunner,
    pins: list[int],
    out_dir: Path,
    voltage: float,
    duration: int = BASELINE_DURATION,
) -> dict[int, int]:
    """
    Capture a noise floor baseline with the target powered OFF.

    Prompts the user to power off the target, runs a short VCD capture,
    and returns transition counts per pin as the noise floor.

    Args:
        glasgow: GlasgowRunner instance
        pins: Pin numbers to capture
        out_dir: Directory to write noise-baseline.vcd and noise-baseline.json
        voltage: I/O voltage
        duration: Capture duration in seconds (default 5)

    Returns:
        dict mapping pin_number -> transition_count (the noise floor).
        Empty dict if capture fails (disables noise filtering).
    """
    vcd_path = out_dir / "noise-baseline.vcd"
    json_path = out_dir / "noise-baseline.json"
    pins_str = ",".join(str(p) for p in pins)

    print(f"\n[Stage 0.5] Noise baseline capture...")
    print(f"  >>> POWER OFF YOUR TARGET NOW <<<")
    input(f"  Press Enter when target is OFF to begin {duration}s baseline capture...")
    print(f"  Capturing {duration}-second baseline on pins {pins_str}...")
    print(f"  (Any transitions now are electrical noise)\n")

    result = _capture_vcd(glasgow, pins, vcd_path, voltage, duration)

    if not vcd_path.exists() or vcd_path.stat().st_size == 0:
        logger.warning(f"Noise baseline capture failed: {result['stderr']}")
        print(f"  [!] Baseline capture failed — noise filtering disabled")
        _hint_if_bitstream_build(result)
        return {}

    noise_counts = _parse_vcd(vcd_path)

    # Save to JSON for reuse with --noise-floor on subsequent runs
    with open(json_path, "w") as f:
        json.dump({str(k): v for k, v in noise_counts.items()}, f, indent=2)

    if noise_counts:
        print(f"  Noise floor: { {p: c for p, c in sorted(noise_counts.items())} }")
    else:
        print(f"  Noise floor: clean (no transitions observed)")
    print(f"  Saved to: {json_path}")

    return noise_counts


def filter_pins_by_noise_floor(
    signal_counts: dict[int, int],
    noise_counts: dict[int, int],
    snr_threshold: float = 10.0,
) -> tuple[list[int], list[int]]:
    """
    Filter active pins by comparing signal transitions against noise baseline.

    A pin passes if its signal count divided by noise count meets the threshold.
    Pins with zero noise transitions always pass (no floor to compare against).

    Args:
        signal_counts: {pin: count} from main capture (device on)
        noise_counts: {pin: count} from baseline capture (device off)
        snr_threshold: Minimum signal/noise ratio to treat pin as real (default 10)

    Returns:
        (real_pins, noise_pins) — sorted lists of pin numbers
    """
    real_pins: list[int] = []
    noise_pins: list[int] = []

    for pin, sig_count in signal_counts.items():
        floor = noise_counts.get(pin, 0)
        snr = sig_count / max(1, floor)
        if floor == 0 or snr >= snr_threshold:
            real_pins.append(pin)
        else:
            logger.info(
                f"Pin {pin}: SNR={snr:.1f}x "
                f"(signal={sig_count}, noise={floor}) — excluded as noise"
            )
            noise_pins.append(pin)

    return sorted(real_pins), sorted(noise_pins)


def run_passive_capture(
    glasgow: GlasgowRunner,
    pins: list[int],
    out_dir: Path,
    voltage: float = 3.3,
) -> dict:
    """
    Run passive logic capture on specified pins.

    Prompts the user to power-cycle the target, records for CAPTURE_DURATION
    seconds, then parses which pins showed transitions.

    Args:
        glasgow: GlasgowRunner instance
        pins: Pin numbers to monitor (e.g. [0,1,2,3,4,5,6,7])
        out_dir: Directory to write passive.vcd
        voltage: I/O voltage (default 3.3V)

    Returns:
        dict with keys:
            active_pins (list): Pins with signal transitions
            signal_counts (dict): {pin: transition_count} from VCD parse
            vcd_path (str): Path to recorded VCD file
            success (bool): Whether capture completed
            skipped (bool): True if capture failed (fallback: all pins active)
    """
    vcd_path = out_dir / "passive.vcd"
    pins_str = ",".join(str(p) for p in pins)

    print(f"\n[*] Passive logic capture on pins {pins_str} ({CAPTURE_DURATION}s)")
    print(f"    >>> POWER-CYCLE YOUR TARGET NOW <<<")
    print(f"    Capturing for {CAPTURE_DURATION} seconds...\n")

    result = _capture_vcd(glasgow, pins, vcd_path, voltage, CAPTURE_DURATION)

    if not vcd_path.exists() or vcd_path.stat().st_size == 0:
        logger.warning(f"Passive capture failed: {result['stderr']}")
        print(f"  [!] Passive capture failed — treating all pins as active")
        _hint_if_bitstream_build(result)
        return {
            "active_pins": pins,
            "signal_counts": {},
            "vcd_path": str(vcd_path),
            "success": False,
            "skipped": True,
        }

    signal_counts = _parse_vcd(vcd_path)
    active_pins = sorted(signal_counts.keys())

    if not active_pins:
        # No transitions detected — could be a flat/idle bus; probe all pins
        logger.info("No transitions in VCD — treating all probed pins as active")
        active_pins = pins

    logger.info(f"Passive capture complete. Active pins: {active_pins}")
    print(f"  Active pins detected: {active_pins}")

    return {
        "active_pins": active_pins,
        "signal_counts": signal_counts,
        "vcd_path": str(vcd_path),
        "success": True,
        "skipped": False,
    }
