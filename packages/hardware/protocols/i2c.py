#!/usr/bin/env python3
"""
I2C bus scan on candidate pin pairs.

Tries adjacent pin pairs from active_pins as SCL/SDA (both orderings).
Looks for ACK responses indicating I2C devices are present.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from core.logging import get_logger
from packages.hardware.glasgow_runner import GlasgowRunner

logger = get_logger()


def _parse_i2c_scan(stdout: str) -> list:
    """
    Parse 'glasgow run i2c-initiator scan' output for device addresses.

    Matches:  "0x48: present"  /  "device at 0x48"
    Returns list of hex address strings.
    """
    addresses = []
    for line in stdout.splitlines():
        m = re.search(r'(0x[0-9a-fA-F]{2})[:\s]+present', line, re.IGNORECASE)
        if m:
            addresses.append(m.group(1))
        m2 = re.search(r'device\s+at\s+(0x[0-9a-fA-F]{2})', line, re.IGNORECASE)
        if m2:
            addr = m2.group(1)
            if addr not in addresses:
                addresses.append(addr)
    return addresses


def detect_i2c(
    glasgow: GlasgowRunner,
    active_pins: list,
    out_dir: Path,
    voltage: float = 3.3,
) -> list:
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
    findings = []
    tried: set = set()

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

            addresses = _parse_i2c_scan(result["stdout"])
            if not addresses:
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
