#!/usr/bin/env python3
"""
JTAG pin discovery via the glasgow ``jtag-pinout`` applet.

Only runs when --jtag is passed. jtag-pinout takes the full candidate
pin set (4-16 pins) and identifies the TCK/TMS/TDI/TDO (and TRST#)
assignment itself by driving IR shifts — minutes, not the hours a
naive 4-pin permutation brute-force of ``jtag-probe`` costs.
"""

import re
from pathlib import Path

from core.logging import get_logger
from packages.hardware.glasgow_runner import GlasgowRunner

logger = get_logger()

# jtag-pinout needs at least 4 candidate pins and accepts at most 16.
MIN_PINS = 4
MAX_PINS = 16

# Generous ceiling: pinout probing is interactive-speed per candidate
# set, but a slow target with many pins can take a few minutes.
PINOUT_TIMEOUT = 600

# Success line (logger output): "use `jtag-probe -V 3.3 --tck A0 --tms A1
# --tdi A2 --tdo A3 [--trst A4]` as arguments"
_ROLE_RE = re.compile(r"--(tck|tms|tdi|tdo|trst)\s+([A-Z]\d+)")


def _parse_pinout_output(output: str) -> dict[str, str] | None:
    """Extract the identified pin roles from jtag-pinout logger output.

    Returns {role: pin} with FULL pin names ("A0", "B3" — dropping the
    port letter would misreport any non-A pin), or None when no
    interface was found. A multi-interface warning is treated as no
    result (upstream flags it as a likely false positive).
    """
    if "no JTAG interface detected" in output:
        return None
    if "more than one JTAG interface detected" in output:
        return None
    use_line = next(
        (line for line in output.splitlines() if "as arguments" in line), None,
    )
    if use_line is None:
        return None
    roles = {m.group(1): m.group(2) for m in _ROLE_RE.finditer(use_line)}
    if not {"tck", "tms", "tdi", "tdo"} <= roles.keys():
        return None
    return roles


def detect_jtag(
    glasgow: GlasgowRunner,
    active_pins: list[int],
    out_dir: Path,
    voltage: float = 3.3,
) -> list[dict]:
    """Run jtag-pinout over the candidate pins to find a JTAG interface.

    Args:
        glasgow: GlasgowRunner instance
        active_pins: Pins that showed signal activity
        out_dir: Unused
        voltage: I/O voltage

    Returns:
        List with one finding dict when an interface is identified,
        else empty.
    """
    pins = list(active_pins)
    if len(pins) < MIN_PINS:
        print(
            f"\n[*] JTAG pinout needs at least {MIN_PINS} candidate pins "
            f"(have {len(pins)}) — skipping"
        )
        return []
    if len(pins) > MAX_PINS:
        logger.warning(
            f"Capping JTAG pinout candidates at {MAX_PINS} (have {len(pins)})"
        )
        pins = pins[:MAX_PINS]

    pin_list = ",".join(f"A{p}" for p in pins)
    print(f"\n[*] JTAG pin discovery (jtag-pinout) over pins {pin_list}...")

    result = glasgow.run(
        [
            "run", "jtag-pinout",
            "-V", str(voltage),
            "--pins", pin_list,
        ],
        timeout=PINOUT_TIMEOUT,
    )

    # Results are logger output (stderr); parse both streams.
    output = result["stdout"] + "\n" + result["stderr"]
    roles = _parse_pinout_output(output)
    if roles is None:
        if "more than one JTAG interface" in output:
            print("  [!] Multiple candidate interfaces reported — likely a "
                  "false positive; re-run with a narrower pin set")
        return []

    with_reset = "with reset detected" in output
    logger.info(f"JTAG interface identified: {roles}")
    print(
        "  [+] JTAG interface found! "
        + " ".join(f"{r.upper()}={p}" for r, p in sorted(roles.items()))
    )

    notes = "identified by jtag-pinout"
    if with_reset:
        notes += " (TRST# present)"

    return [{
        "protocol": "jtag",
        "confidence": "confirmed",
        "pins": roles,
        "devices": [],
        "notes": notes,
    }]
