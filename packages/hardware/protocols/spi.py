#!/usr/bin/env python3
"""
SPI flash detection via JEDEC ID probing.

Tries consecutive 4-pin groups from active pins using the 6 most common
CS/SCK/MOSI/MISO role assignments. Confirms with JEDEC identify.
"""

import itertools
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from core.logging import get_logger
from packages.hardware.glasgow_runner import GlasgowRunner

logger = get_logger()

# Chip name prefixes to look for in glasgow output
KNOWN_CHIPS = [
    "W25Q", "MX25L", "GD25Q", "S25FL", "MT25Q", "AT25",
    "IS25LP", "FM25Q", "XM25QH", "EN25",
]

# 6 most-likely role index orderings for a 4-pin group: (CS, SCK, MOSI, MISO)
ROLE_ORDERINGS = [
    (0, 1, 2, 3),   # natural
    (3, 0, 1, 2),   # CS at end
    (0, 2, 1, 3),   # MOSI/MISO swapped
    (1, 0, 2, 3),   # SCK first
    (0, 1, 3, 2),   # MISO/MOSI swapped
    (2, 0, 1, 3),   # CS second
]


def _parse_spi_output(stdout: str) -> dict:
    """
    Parse glasgow memory-25x identify output for chip name and capacity.

    Returns dict with chip, capacity_mb, jedec_id keys (any may be absent).
    """
    result = {}
    for line in stdout.splitlines():
        line_lower = line.lower()
        for chip in KNOWN_CHIPS:
            if chip.lower() in line_lower:
                result["chip"] = chip
                m = re.search(r'(\d+)\s*[Mm][Bb]', line)
                if m:
                    result["capacity_mb"] = int(m.group(1))
                break
        if "jedec" in line_lower and "id" in line_lower:
            m = re.search(r'jedec id[:\s]+([0-9a-f\s]+)', line_lower)
            if m:
                result["jedec_id"] = m.group(1).strip()
    return result


def detect_spi(
    glasgow: GlasgowRunner,
    active_pins: list,
    out_dir: Path,
    voltage: float = 3.3,
) -> list:
    """
    Try consecutive 4-pin groups from active_pins as SPI flash.

    For each group, tests up to 6 CS/SCK/MOSI/MISO role assignments.

    Args:
        glasgow: GlasgowRunner instance
        active_pins: Pins that showed signal activity
        out_dir: Unused (identify produces no output files)
        voltage: I/O voltage

    Returns:
        List of finding dicts for confirmed SPI flash chips
    """
    findings = []
    tried_groups: set = set()
    all_pins = list(active_pins)

    # Build candidate 4-pin groups: consecutive windows first, then all combos
    groups = []
    for i in range(len(all_pins) - 3):
        groups.append(tuple(all_pins[i:i + 4]))

    if len(all_pins) <= 8:
        for combo in itertools.combinations(all_pins, 4):
            if combo not in groups:
                groups.append(combo)

    for group in groups:
        group_key = frozenset(group)
        if group_key in tried_groups:
            continue
        tried_groups.add(group_key)

        for ordering in ROLE_ORDERINGS:
            cs, sck, mosi, miso = (group[i] for i in ordering)

            result = glasgow.run(
                [
                    "run", "memory-25x",
                    f"-V{voltage}",
                    "--pins-cs", str(cs),
                    "--pins-sck", str(sck),
                    "--pins-mosi", str(mosi),
                    "--pins-miso", str(miso),
                    "identify",
                ],
                timeout=10,
            )

            parsed = _parse_spi_output(result["stdout"])
            if not parsed:
                continue

            chip_name = parsed.get("chip", "Unknown SPI flash")
            logger.info(
                f"SPI flash: {chip_name} "
                f"CS={cs} SCK={sck} MOSI={mosi} MISO={miso}"
            )

            finding = {
                "protocol": "spi_flash",
                "confidence": "confirmed" if "chip" in parsed else "probable",
                "pins": {"cs": cs, "sck": sck, "mosi": mosi, "miso": miso},
                "chip": chip_name,
                "voltage_v": voltage,
            }
            if "capacity_mb" in parsed:
                finding["capacity_mb"] = parsed["capacity_mb"]
            if "jedec_id" in parsed:
                finding["jedec_id"] = parsed["jedec_id"]

            findings.append(finding)
            break   # Found for this group — stop trying role orderings

    return findings
