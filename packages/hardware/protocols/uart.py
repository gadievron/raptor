#!/usr/bin/env python3
"""
UART pin and baud rate detection.

For each active pin (potential TX/RX), tries common baud rates and checks
for printable ASCII content in the captured bytes.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from core.logging import get_logger
from packages.hardware.glasgow_runner import GlasgowRunner

logger = get_logger()

# Baud rates to try, most-common first
BAUD_RATES = [115200, 57600, 38400, 19200, 9600]

# Capture window per attempt (seconds)
CAPTURE_DURATION = 3

# Minimum ratio of printable bytes to consider UART confirmed
MIN_PRINTABLE_RATIO = 0.6


def _score_bytes(data: bytes) -> float:
    """Return fraction of printable ASCII bytes (tabs, newlines, 0x20-0x7E)."""
    if not data:
        return 0.0
    printable = sum(
        1 for b in data
        if (0x09 <= b <= 0x0D) or (0x20 <= b <= 0x7E)
    )
    return printable / len(data)


def _read_sample(path: Path, max_bytes: int = 128) -> bytes:
    """Read up to max_bytes from a capture file."""
    if not path.exists() or path.stat().st_size == 0:
        return b""
    with open(path, "rb") as f:
        return f.read(max_bytes)


def detect_uart(
    glasgow: GlasgowRunner,
    active_pins: list,
    out_dir: Path,
    voltage: float = 3.3,
) -> list:
    """
    Try each active pin as UART RX at common baud rates.

    Args:
        glasgow: GlasgowRunner instance
        active_pins: Pins that showed signal activity
        out_dir: Directory to write per-pin capture files
        voltage: I/O voltage

    Returns:
        List of finding dicts for confirmed UART channels
    """
    findings = []

    for pin in active_pins:
        for baud in BAUD_RATES:
            capture_file = out_dir / f"uart-{pin}-{baud}.bin"

            result = glasgow.run(
                [
                    "run", "uart",
                    f"-V{voltage}",
                    "--baud", str(baud),
                    "--pins-rx", str(pin),
                    "record", str(capture_file),
                ],
                timeout=CAPTURE_DURATION + 5,
            )

            sample = _read_sample(capture_file)
            if not sample:
                continue

            ratio = _score_bytes(sample)
            if ratio < MIN_PRINTABLE_RATIO:
                continue

            # Readable UART output found
            sample_text = sample.decode("ascii", errors="replace").strip()[:80]
            confidence = "high" if ratio > 0.8 else "medium"

            notes = ""
            sample_lower = sample_text.lower()
            if "u-boot" in sample_lower:
                notes = "U-Boot boot log detected"
            elif "busybox" in sample_lower or sample_text.endswith("$ ") or sample_text.endswith("# "):
                notes = "Shell prompt detected"
            elif "login" in sample_lower:
                notes = "Login prompt detected"

            logger.info(f"UART detected: pin={pin}, baud={baud}, confidence={confidence}")
            findings.append({
                "protocol": "uart",
                "confidence": confidence,
                "pins": {"rx": pin},
                "baud_rate": baud,
                "sample_bytes": sample_text,
                "notes": notes,
                "capture_file": str(capture_file),
            })

            # Found at this baud rate — skip remaining rates for this pin
            break

    return findings
