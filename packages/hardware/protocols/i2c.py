#!/usr/bin/env python3
"""
I2C bus scan on candidate pin pairs.

Tries adjacent pin pairs from active_pins as SCL/SDA (both orderings).
Looks for ACK responses indicating I2C devices are present.
"""

import re
from pathlib import Path

from core.logging import get_logger
from packages.hardware.glasgow_runner import GlasgowRunner

logger = get_logger()


def _parse_i2c_scan(output: str) -> list[str]:
    """
    Parse 'glasgow run i2c-controller scan' output for device addresses.

    Current upstream reports hits via the logger (stderr) as
    "scan found address 0b0101000/0x28"; older releases printed
    "0x48: present" / "device at 0x48". All three shapes are matched.
    Returns list of hex address strings.
    """
    addresses: list[str] = []
    for line in output.splitlines():
        for pattern in (
            r'scan found address\s+\S*/(0x[0-9a-fA-F]{2})',
            r'(0x[0-9a-fA-F]{2})[:\s]+present',
            r'device\s+at\s+(0x[0-9a-fA-F]{2})',
        ):
            m = re.search(pattern, line, re.IGNORECASE)
            if m and m.group(1) not in addresses:
                addresses.append(m.group(1))
    return addresses


def detect_i2c(
    glasgow: GlasgowRunner,
    active_pins: list[int],
    out_dir: Path,
    voltage: float = 3.3,
) -> list[dict]:
    """
    Scan adjacent pin pairs from active_pins for I2C devices.

    Args:
        glasgow: GlasgowRunner instance
        active_pins: Pins that showed signal activity
        out_dir: Unused
        voltage: I/O voltage

    Returns:
        List of finding dicts for I2C buses with responding devices
    """
    findings: list[dict] = []
    tried: set[tuple[int, int]] = set()
    build_hinted = False

    # Try both orderings (SCL, SDA) and (SDA, SCL) for each adjacent pair
    for i in range(len(active_pins) - 1):
        for scl, sda in [
            (active_pins[i], active_pins[i + 1]),
            (active_pins[i + 1], active_pins[i]),
        ]:
            pair = (scl, sda)
            if pair in tried:
                continue
            tried.add(pair)

            result = glasgow.run(
                [
                    "run", "i2c-controller",
                    "--voltage", str(voltage),
                    "--scl", f"A{scl}",
                    "--sda", f"A{sda}",
                    "scan",
                ],
                timeout=8,
            )

            # Hits are logger output (stderr) on current glasgow; older
            # releases printed to stdout. Parse both.
            addresses = _parse_i2c_scan(result["stdout"] + "\n" + result["stderr"])
            if not addresses:
                # A first-run bitstream build consumes the scan window —
                # that pair's "no devices" is then meaningless. Say so
                # once instead of leaving a silent false negative.
                stderr = result["stderr"]
                if not build_hinted and (
                    "toolchain" in stderr or "bitstream" in stderr
                    or "yosys" in stderr
                ):
                    print(
                        "  [!] glasgow appears to be building the applet "
                        "bitstream — this pair's scan window elapsed "
                        "during the build; re-run, or use --warm-cache"
                    )
                    build_hinted = True
                continue

            logger.info(f"I2C at SCL={scl} SDA={sda}: {addresses}")
            findings.append({
                "protocol": "i2c",
                "confidence": "confirmed",
                "pins": {"scl": scl, "sda": sda},
                "devices": addresses,
                "notes": f"{len(addresses)} device(s) found",
            })

    return findings
