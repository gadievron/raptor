#!/usr/bin/env python3
"""
JTAG chain enumeration via brute-force pin permutation.

Only runs when --jtag flag is passed. Tries all 4-pin permutations of
active_pins as TCK/TDI/TDO/TMS. Can take 5-10 minutes on 8 pins.
"""

import itertools
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from core.logging import get_logger
from packages.hardware.glasgow_runner import GlasgowRunner

logger = get_logger()

MAX_PERMUTATIONS = 2000


def _parse_jtag_output(stdout: str) -> list:
    """
    Parse glasgow jtag-probe scan output for devices in the chain.

    Looks for IDCODE values in the output.
    Returns list of device dicts.
    """
    devices = []
    for line in stdout.splitlines():
        m = re.search(r'idcode[:\s]+([0-9a-fA-Fx]+)', line, re.IGNORECASE)
        if m:
            devices.append({"idcode": m.group(1)})
    return devices


def detect_jtag(
    glasgow: GlasgowRunner,
    active_pins: list,
    out_dir: Path,
    voltage: float = 3.3,
) -> list:
    """
    Brute-force all 4-pin permutations from active_pins as JTAG TCK/TDI/TDO/TMS.

    This is intentionally slow (5-10 min for 8 pins) and should only be
    called when the user explicitly passes --jtag.

    Args:
        glasgow: GlasgowRunner instance
        active_pins: Pins that showed signal activity
        out_dir: Unused
        voltage: I/O voltage

    Returns:
        List of finding dicts for confirmed JTAG chains
    """
    findings = []
    perms = list(itertools.permutations(active_pins, 4))

    if len(perms) > MAX_PERMUTATIONS:
        logger.warning(f"Capping JTAG permutations at {MAX_PERMUTATIONS} (have {len(perms)})")
        perms = perms[:MAX_PERMUTATIONS]

    total = len(perms)
    print(f"\n[*] JTAG brute-force: {total} pin permutations to try...")

    for idx, (tck, tdi, tdo, tms) in enumerate(perms):
        if idx % 50 == 0:
            pct = 100 * idx // total
            print(f"    {idx}/{total} ({pct}%)", end="\r", flush=True)

        result = glasgow.run(
            [
                "run", "jtag-probe",
                "--voltage", str(voltage),
                "--tck", f"A{tck}",
                "--tdi", f"A{tdi}",
                "--tdo", f"A{tdo}",
                "--tms", f"A{tms}",
                "scan",
            ],
            timeout=8,
        )

        devices = _parse_jtag_output(result["stdout"])
        if not devices:
            continue

        logger.info(
            f"JTAG chain: TCK={tck} TDI={tdi} TDO={tdo} TMS={tms}, "
            f"devices={devices}"
        )
        print(f"\n  [+] JTAG chain found! TCK={tck} TDI={tdi} TDO={tdo} TMS={tms}")

        findings.append({
            "protocol": "jtag",
            "confidence": "confirmed",
            "pins": {"tck": tck, "tdi": tdi, "tdo": tdo, "tms": tms},
            "devices": devices,
            "notes": f"{len(devices)} device(s) in chain",
        })

    print()   # newline after progress line
    return findings
