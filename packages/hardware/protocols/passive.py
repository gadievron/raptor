#!/usr/bin/env python3
"""
Passive logic capture and VCD analysis.

Captures signals on up to 8 pins while the user power-cycles the target.
Identifies which pins have signal transitions (active pins) by parsing the VCD.
"""

import json
import re
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from core.logging import get_logger
from packages.hardware.glasgow_runner import GlasgowRunner

logger = get_logger()

CAPTURE_DURATION = 10   # seconds
BASELINE_DURATION = 5   # seconds for noise floor capture
SAMPLE_RATE = "10e6"    # 10 MHz


def _parse_vcd(vcd_path: Path) -> dict:
    """
    Parse a VCD file and return transition counts per pin.

    Scans value-change lines after $enddefinitions. A line matching
    [01xz][!-~] (value + signal-id character) indicates a state change.

    Args:
        vcd_path: Path to the .vcd file

    Returns:
        dict mapping pin_number -> transition_count for pins with any transitions
    """
    counts: dict = {}
    signal_map: dict = {}   # VCD signal-id character -> pin number

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
                        sig_name = m.group(2).rstrip("$end").strip()
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


def run_noise_baseline(
    glasgow: GlasgowRunner,
    pins: list,
    out_dir: Path,
    voltage: float,
    duration: int = BASELINE_DURATION,
) -> dict:
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

    result = glasgow.run(
        [
            "run", "logic-analyzer",
            f"-V{voltage}",
            "--pins", pins_str,
            "--sample-rate", SAMPLE_RATE,
            "record", str(vcd_path),
        ],
        timeout=duration + 15,
    )

    if result["returncode"] != 0 or not vcd_path.exists():
        logger.warning(f"Noise baseline capture failed: {result['stderr']}")
        print(f"  [!] Baseline capture failed — noise filtering disabled")
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
    signal_counts: dict,
    noise_counts: dict,
    snr_threshold: float = 10.0,
) -> tuple:
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
    real_pins = []
    noise_pins = []

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
    pins: list,
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

    result = glasgow.run(
        [
            "run", "logic-analyzer",
            f"-V{voltage}",
            "--pins", pins_str,
            "--sample-rate", SAMPLE_RATE,
            "record", str(vcd_path),
        ],
        timeout=CAPTURE_DURATION + 15,
    )

    if result["returncode"] != 0 or not vcd_path.exists():
        logger.warning(f"Passive capture failed: {result['stderr']}")
        print(f"  [!] Passive capture failed — treating all pins as active")
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
