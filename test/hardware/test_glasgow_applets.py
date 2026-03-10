#!/usr/bin/env python3
"""
RAPTOR Glasgow Applet Integration Tests
Kinda did this so I know all the applets are working as is the hardware. YMMV
Also figured an arduino and pi are the best test targets since they have a good mix of interfaces and are easy to reflash if we mess up the wiring

Usage:
    # Run all tests (requires Glasgow connected + Arduino target):
    python3 test/hardware/test_glasgow_applets.py

    # Dry-run (checks Glasgow is present, skips actual hardware):
    python3 test/hardware/test_glasgow_applets.py --dry-run

    # Test specific applet:
    python3 test/hardware/test_glasgow_applets.py --test uart
    python3 test/hardware/test_glasgow_applets.py --test i2c
    python3 test/hardware/test_glasgow_applets.py --test swd   # ARM target required

Wiring:
    UART test  → uart_target.ino on Arduino, Glasgow A0=RX A1=TX
    I2C test   → i2c_target.ino on Arduino, Glasgow A0=SCL A1=SDA
    SWD test   → Pi Pico or STM32 Blue Pill, Glasgow A0=SWCLK A1=SWDIO

See test/hardware/arduino_sketches/ for target firmware.
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

VOLTAGE = "3.3"
PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"

# Known venv locations to search if 'glasgow' is not on PATH
GLASGOW_SEARCH_PATHS = [
    Path.home() / "python_shit/glasgow-venv/bin/glasgow",
    Path.home() / ".local/bin/glasgow",
    Path("/opt/glasgow/bin/glasgow"),
]


def find_glasgow() -> str:
    """Return the glasgow binary path, checking PATH then known venv locations."""
    if path := shutil.which("glasgow"):
        return path
    for candidate in GLASGOW_SEARCH_PATHS:
        if candidate.exists():
            return str(candidate)
    return "glasgow"  # will fail gracefully in run_glasgow


GLASGOW_BIN = find_glasgow()


def run_glasgow(args: list, timeout: int = 10) -> dict:
    """Run a glasgow command and return result."""
    cmd = [GLASGOW_BIN] + args
    print(f"  $ {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "stdout": "", "stderr": "timed out"}
    except FileNotFoundError:
        return {"returncode": -1, "stdout": "", "stderr": "glasgow not found"}


def check_glasgow_present() -> bool:
    """Verify Glasgow binary exists and a device is connected."""
    result = run_glasgow(["list"], timeout=5)
    if result["returncode"] != 0 or not result["stdout"].strip():
        print(f"  Glasgow not found or no device: {result['stderr'].strip()}")
        return False
    print(f"  Glasgow detected: {result['stdout'].strip()[:80]}")
    return True


def test_uart(dry_run: bool = False) -> str:
    """
    Test: glasgow run uart --voltage 3.3 --rx A0 tty --stream
    Target: uart_target.ino at 115200 baud
    Expected: printable ASCII output including 'U-Boot' or shell prompt
    """
    print("\n[UART] Testing uart applet...")

    if dry_run:
        print("  dry-run: skipping hardware interaction")
        return SKIP

    # First verify the applet accepts the correct flags (--help should succeed)
    result = run_glasgow(["run", "uart", "--help"], timeout=5)
    if "--rx" not in result["stdout"] and "--rx" not in result["stderr"]:
        print(f"  FAIL: --rx flag not found in uart --help output")
        return FAIL
    print("  Flag check: --rx present in help output")

    # Capture a few seconds of UART output
    print("  Capturing UART output (3s)... power-cycle Arduino now if needed")
    result = run_glasgow([
        "run", "uart",
        "--voltage", VOLTAGE,
        "--baud", "115200",
        "--rx", "A0",
        "tty", "--stream",
    ], timeout=6)

    output = result["stdout"] + result["stderr"]
    if not output.strip():
        print("  FAIL: No output captured")
        return FAIL

    printable_ratio = sum(1 for c in output if c.isprintable() or c in '\r\n\t') / max(len(output), 1)
    print(f"  Captured {len(output)} bytes, printable ratio: {printable_ratio:.1%}")

    if printable_ratio < 0.5:
        print("  FAIL: Output mostly non-printable — wrong baud rate or wiring?")
        return FAIL

    if any(kw in output for kw in ["U-Boot", "BusyBox", "root", "Linux", "raptor"]):
        print(f"  PASS: Recognised UART output: {output[:60].strip()!r}")
        return PASS

    print(f"  PASS: Printable UART data received: {output[:60].strip()!r}")
    return PASS


def test_i2c(dry_run: bool = False) -> str:
    """
    Test: glasgow run i2c-controller --voltage 3.3 --scl A0 --sda A1 scan
    Target: i2c_target.ino (slave at 0x50)
    Expected: 0x50 present in scan output
    """
    print("\n[I2C] Testing i2c-controller applet...")

    if dry_run:
        print("  dry-run: skipping hardware interaction")
        return SKIP

    # Flag check
    result = run_glasgow(["run", "i2c-controller", "--help"], timeout=5)
    if "--scl" not in result["stdout"] and "--scl" not in result["stderr"]:
        print("  FAIL: --scl flag not found in i2c-controller --help")
        return FAIL
    print("  Flag check: --scl present in help output")

    # Run scan
    result = run_glasgow([
        "run", "i2c-controller",
        "--voltage", VOLTAGE,
        "--scl", "A0",
        "--sda", "A1",
        "scan",
    ], timeout=15)

    output = result["stdout"] + result["stderr"]
    print(f"  Scan output: {output.strip()[:120]}")

    if "0x50" in output or "0X50" in output.upper():
        print("  PASS: Found device at 0x50 (EEPROM target)")
        return PASS

    if result["returncode"] == 0 and ("present" in output.lower() or "device" in output.lower()):
        print("  PASS: I2C devices found (not 0x50 — check wiring)")
        return PASS

    if result["returncode"] != 0:
        print(f"  FAIL: applet returned error: {result['stderr'].strip()[:80]}")
        return FAIL

    print("  FAIL: No I2C devices found — check wiring and pull-ups")
    return FAIL


def test_swd(dry_run: bool = False) -> str:
    """
    Test: glasgow run swd-probe --voltage 3.3 --swclk A0 --swdio A1 dump-memory 0x20000000 64
    Target: Pi Pico (RP2040) or STM32 Blue Pill
    Expected: Non-empty memory dump, no error
    """
    print("\n[SWD] Testing swd-probe applet...")

    if dry_run:
        print("  dry-run: skipping hardware interaction")
        return SKIP

    # Flag check
    result = run_glasgow(["run", "swd-probe", "--help"], timeout=5)
    help_text = result["stdout"] + result["stderr"]
    if "--swclk" not in help_text:
        print("  FAIL: --swclk flag not found in swd-probe --help")
        return FAIL
    if "dump-memory" not in help_text:
        print("  FAIL: dump-memory subcommand not found in swd-probe --help")
        return FAIL
    print("  Flag check: --swclk and dump-memory present in help output")

    # Dump 64 bytes from SRAM start (should work on any unlocked ARM target)
    out_file = Path("/tmp/raptor-swd-test.bin")
    result = run_glasgow([
        "run", "swd-probe",
        "--voltage", VOLTAGE,
        "--swclk", "A0",
        "--swdio", "A1",
        "dump-memory", "0x20000000", "64",
        "-f", str(out_file),
    ], timeout=15)

    output = result["stdout"] + result["stderr"]
    print(f"  Output: {output.strip()[:120]}")

    if out_file.exists() and out_file.stat().st_size > 0:
        data = out_file.read_bytes()
        if data == b'\xff' * len(data) or data == b'\x00' * len(data):
            print(f"  WARN: Dump is all-0xFF or all-0x00 — target may be protected")
            return PASS  # applet worked, protection is a finding
        print(f"  PASS: Dumped {len(data)} bytes from 0x20000000: {data[:8].hex()}")
        return PASS

    if result["returncode"] != 0:
        print(f"  FAIL: {result['stderr'].strip()[:120]}")
        return FAIL

    print("  FAIL: No output file produced")
    return FAIL


def test_jtag_probe(dry_run: bool = False) -> str:
    """
    Test: glasgow run jtag-probe --voltage 3.3 --tck A0 --tdi A2 --tdo A3 --tms A1 scan
    Target: any JTAG-capable device (Arduino Due, STM32, FPGA dev board)
    Expected: IDCODE in output, returncode 0
    """
    print("\n[JTAG] Testing jtag-probe applet...")

    if dry_run:
        print("  dry-run: skipping hardware interaction")
        return SKIP

    # Flag check
    result = run_glasgow(["run", "jtag-probe", "--help"], timeout=5)
    help_text = result["stdout"] + result["stderr"]
    for flag in ["--tck", "--tdi", "--tdo", "--tms"]:
        if flag not in help_text:
            print(f"  FAIL: {flag} not found in jtag-probe --help")
            return FAIL
    print("  Flag check: --tck/--tdi/--tdo/--tms all present in help output")

    result = run_glasgow([
        "run", "jtag-probe",
        "--voltage", VOLTAGE,
        "--tck", "A0",
        "--tdi", "A2",
        "--tdo", "A3",
        "--tms", "A1",
        "scan",
    ], timeout=15)

    output = result["stdout"] + result["stderr"]
    print(f"  Output: {output.strip()[:120]}")

    if "idcode" in output.lower() or "0x" in output.lower():
        print("  PASS: JTAG chain detected")
        return PASS

    if result["returncode"] != 0:
        print(f"  FAIL: {result['stderr'].strip()[:80]}")
        return FAIL

    print("  WARN: No chain detected — check wiring or try --tck A0 --tdi A1 --tdo A2 --tms A3")
    return FAIL


def test_memory_25x(dry_run: bool = False) -> str:
    """
    Test: glasgow run memory-25x --voltage 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 identify
    Target: W25Q or similar SPI NOR flash chip (manual wiring required)
    Expected: Chip name and capacity in output
    """
    print("\n[SPI] Testing memory-25x applet (identify)...")
    print("  Note: Requires SPI flash chip wired to Glasgow")
    print("  Wiring: --cs A0 --sck A1 --io A2(COPI),A3(CIPO),A4(WP),A5(HOLD)")

    if dry_run:
        print("  dry-run: skipping hardware interaction")
        return SKIP

    # Flag check only — don't probe if no flash is wired
    result = run_glasgow(["run", "memory-25x", "--help"], timeout=5)
    help_text = result["stdout"] + result["stderr"]
    for flag in ["--cs", "--sck", "--io"]:
        if flag not in help_text:
            print(f"  FAIL: {flag} not found in memory-25x --help")
            return FAIL
    print("  Flag check: --cs, --sck, --io all present in help output")

    result = run_glasgow([
        "run", "memory-25x",
        "--voltage", VOLTAGE,
        "--cs", "A0",
        "--sck", "A1",
        "--io", "A2,A3,A4,A5",
        "identify",
    ], timeout=10)

    output = result["stdout"] + result["stderr"]
    print(f"  Output: {output.strip()[:120]}")

    if any(chip in output for chip in ["W25Q", "GD25Q", "MX25L", "MT25Q", "SST25"]):
        print(f"  PASS: SPI flash identified")
        return PASS

    if result["returncode"] == 0:
        print(f"  PASS: applet ran successfully: {output.strip()[:60]}")
        return PASS

    print(f"  SKIP: No SPI flash connected (or check wiring)")
    return SKIP


def main():
    parser = argparse.ArgumentParser(description="RAPTOR Glasgow Applet Integration Tests")
    parser.add_argument("--dry-run", action="store_true",
                        help="Skip hardware interaction, only verify Glasgow is present")
    parser.add_argument("--test", choices=["uart", "i2c", "swd", "jtag", "spi"],
                        help="Run only a specific test")
    args = parser.parse_args()

    print("=" * 60)
    print("RAPTOR Glasgow Applet Integration Tests")
    print("=" * 60)

    print("\n[0] Glasgow presence check...")
    if not check_glasgow_present():
        if args.dry_run:
            print("  dry-run: continuing without device")
        else:
            print("  Aborting — connect Glasgow and retry")
            sys.exit(1)

    tests = {
        "uart": test_uart,
        "i2c": test_i2c,
        "swd": test_swd,
        "jtag": test_jtag_probe,
        "spi": test_memory_25x,
    }

    if args.test:
        tests = {args.test: tests[args.test]}

    results = {}
    for name, fn in tests.items():
        results[name] = fn(dry_run=args.dry_run)

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    for name, result in results.items():
        indicator = "✓" if result == PASS else ("~" if result == SKIP else "✗")
        print(f"  {indicator} {name.upper():6s} {result}")

    failed = [n for n, r in results.items() if r == FAIL]
    if failed:
        print(f"\nFailed: {', '.join(failed)}")
        sys.exit(1)
    else:
        print("\nAll tests passed or skipped.")


if __name__ == "__main__":
    main()
