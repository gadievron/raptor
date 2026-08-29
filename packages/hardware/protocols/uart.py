#!/usr/bin/env python3
"""
UART pin and baud rate detection.

For each active pin (potential target TX), first tries the uart
applet's hardware auto-baud (one capture), falling back to iterating
common baud rates. Confirms by printable-ASCII ratio of the captured
bytes.
"""

import re
from pathlib import Path
from typing import Optional

from core.logging import get_logger
from packages.hardware.glasgow_runner import GlasgowRunner

logger = get_logger()

# Fallback baud rates to try when auto-baud yields nothing, most-common first
BAUD_RATES = [115200, 57600, 38400, 19200, 9600]

# Capture window per attempt (seconds)
CAPTURE_DURATION = 3

# Minimum ratio of printable bytes to consider UART confirmed
MIN_PRINTABLE_RATIO = 0.6

# Auto-baud reports the measured rate via the logger:
# "switched to 115200 baud"
_AUTO_BAUD_RE = re.compile(r"switched to (\d+) baud")


def _score_bytes(data: bytes) -> float:
    """Return fraction of printable ASCII bytes (tabs, newlines, 0x20-0x7E)."""
    if not data:
        return 0.0
    printable = sum(
        1 for b in data
        if (0x09 <= b <= 0x0D) or (0x20 <= b <= 0x7E)
    )
    return printable / len(data)


def _capture(
    glasgow: GlasgowRunner, pin: int, voltage: float, baud_args: list[str],
) -> dict:
    """One tty capture attempt on ``pin``. The tty subcommand streams
    until interrupted, so this runs under run_timed."""
    return glasgow.run_timed(
        [
            "run", "uart",
            "--voltage", str(voltage),
            *baud_args,
            "--rx", f"A{pin}",
            "tty", "--stream",
        ],
        duration=CAPTURE_DURATION,
    )


def _classify_sample(sample_text: str) -> str:
    """Human note for recognisable UART content."""
    sample_lower = sample_text.lower()
    if "u-boot" in sample_lower:
        return "U-Boot boot log detected"
    if "busybox" in sample_lower or sample_text.endswith("$ ") or sample_text.endswith("# "):
        return "Shell prompt detected"
    if "login" in sample_lower:
        return "Login prompt detected"
    return ""


def _display_text(sample: bytes) -> str:
    """Render captured device bytes for reports/terminal: printable
    ASCII kept, everything else (including ESC — a hostile target could
    otherwise inject terminal escape sequences into the operator's
    session) replaced with '.'."""
    return "".join(
        chr(b) if 0x20 <= b <= 0x7E else "."
        for b in sample
    ).strip()[:80]


def _finding_from_result(
    result: dict, pin: int, baud: Optional[int], capture_file: Path,
) -> Optional[dict]:
    """Score one capture; return a finding dict when it looks like UART.

    Scoring runs on the RAW capture bytes (``stdout_bytes``): any
    decode→re-encode round trip maps undecodable noise to printable
    replacement characters and turns electrically noisy pins into
    false-positive "UART confirmed" findings.
    """
    sample = result.get("stdout_bytes", b"")[:128]
    if not sample:
        return None
    ratio = _score_bytes(sample)
    if ratio < MIN_PRINTABLE_RATIO:
        return None
    capture_file.write_bytes(sample)

    if baud is None:
        # Auto-baud: the measured rate is logger output (stderr). None
        # when the applet never reported a rate — consumers render that
        # as "auto", never "--baud 0".
        m = _AUTO_BAUD_RE.search(result.get("stderr", ""))
        baud = int(m.group(1)) if m else None

    sample_text = _display_text(sample)
    confidence = "high" if ratio > 0.8 else "medium"
    logger.info(f"UART detected: pin={pin}, baud={baud}, confidence={confidence}")
    return {
        "protocol": "uart",
        "confidence": confidence,
        "pins": {"rx": pin},
        "baud_rate": baud,
        "sample_bytes": sample_text,
        "notes": _classify_sample(sample_text),
        "capture_file": str(capture_file),
    }


def detect_uart(
    glasgow: GlasgowRunner,
    active_pins: list[int],
    out_dir: Path,
    voltage: float = 3.3,
) -> list[dict]:
    """
    Try each active pin as UART RX: hardware auto-baud first, then the
    common fixed rates.

    Args:
        glasgow: GlasgowRunner instance
        active_pins: Pins that showed signal activity
        out_dir: Directory to write per-pin capture files
        voltage: I/O voltage

    Returns:
        List of finding dicts for confirmed UART channels
    """
    findings: list[dict] = []

    for pin in active_pins:
        # Attempt 1: hardware auto-baud — one capture window instead of
        # len(BAUD_RATES).
        result = _capture(glasgow, pin, voltage, ["--auto-baud"])
        finding = _finding_from_result(
            result, pin, None, out_dir / f"uart-{pin}-auto.bin",
        )
        if finding is not None:
            findings.append(finding)
            continue

        # Fallback: iterate fixed rates (older glasgow without
        # --auto-baud errors the first attempt; these still work).
        for baud in BAUD_RATES:
            result = _capture(glasgow, pin, voltage, ["--baud", str(baud)])
            finding = _finding_from_result(
                result, pin, baud, out_dir / f"uart-{pin}-{baud}.bin",
            )
            if finding is not None:
                findings.append(finding)
                break

    return findings
