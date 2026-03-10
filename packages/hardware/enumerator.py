#!/usr/bin/env python3
"""
RAPTOR Hardware Security Enumerator

Automated interface discovery for unknown wired targets using Glasgow. This is still very much a WIP by me (danielcuthbert) but has proven to be useful.

Stages:
  0. Glasgow device check
  1. Passive logic capture (10s) — user power-cycles target
  2. I2C scan (adjacent pin pairs, safe ACK probing)
  3. UART detection (active pins × common baud rates)
  4. JTAG brute-force (opt-in via --jtag, 5-10 min)

Output: hardware-report.json written to the output directory.

Glasgow installation: https://glasgow-embedded.org/latest/install.html
Note: 'pip install glasgow' installs a placeholder (0.0.0) — install from source. We should help users with this error message if we detect the placeholder version and also help the project too.

Note: SPI flash detection and Vsense checks are intentionally excluded from automated
enumeration. SPI requires manual pin assignment to avoid false positives; Vsense
probing on incorrect wiring risks damaging the target on a one-shot opportunity.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.config import RaptorConfig
from core.logging import get_logger
from packages.hardware.glasgow_runner import GlasgowRunner, GLASGOW_INSTALL_URL
from packages.hardware.protocols.passive import (
    run_passive_capture,
    run_noise_baseline,
    filter_pins_by_noise_floor,
)
from packages.hardware.protocols.i2c import detect_i2c
from packages.hardware.protocols.uart import detect_uart
from packages.hardware.protocols.jtag import detect_jtag

logger = get_logger()


def _parse_pin_range(pins_arg: str) -> list:
    """
    Parse pin specification: '0-7', '0,1,2,3', or '0-3,6,7'.

    Returns sorted list of pin numbers.
    """
    pins: set = set()
    for part in pins_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            pins.update(range(int(start), int(end) + 1))
        else:
            pins.add(int(part))
    return sorted(pins)


def _make_recommendations(findings: list, not_detected: list) -> list:
    """Generate actionable next-step recommendations from findings."""
    recs = []
    for f in findings:
        proto = f.get("protocol", "")

        if proto == "uart":
            baud = f.get("baud_rate", "?")
            pin = f.get("pins", {}).get("rx", "?")
            notes = f.get("notes", "")
            recs.append(
                f"UART at {baud} baud on pin A{pin}"
                + (f" [{notes}]" if notes else "")
                + f" — connect with: glasgow run uart --voltage 3.3 --baud {baud} "
                f"--rx A{pin} --tx <TX_PIN> tty"
            )

        elif proto == "i2c":
            p = f.get("pins", {})
            devices = f.get("devices", [])
            recs.append(
                f"I2C bus SCL=A{p.get('scl','?')} SDA=A{p.get('sda','?')}, "
                f"devices: {', '.join(devices)} — "
                f"scan with: glasgow run i2c-controller --voltage 3.3 "
                f"--scl A{p.get('scl','?')} --sda A{p.get('sda','?')} scan"
            )

        elif proto == "jtag":
            p = f.get("pins", {})
            recs.append(
                f"JTAG chain: TCK=A{p.get('tck','?')} TDI=A{p.get('tdi','?')} "
                f"TDO=A{p.get('tdo','?')} TMS=A{p.get('tms','?')} — "
                f"enumerate with: glasgow run jtag-probe --voltage 3.3 "
                f"--tck A{p.get('tck','?')} --tdi A{p.get('tdi','?')} "
                f"--tdo A{p.get('tdo','?')} --tms A{p.get('tms','?')} scan — "
                f"then load jtag-exploitation skill"
            )

    if any("jtag" in s for s in not_detected):
        recs.append(
            "JTAG not scanned — re-run with --jtag to brute-force all pin permutations "
            "(adds ~5-10 minutes)"
        )

    return recs


class HardwareEnumerator:
    """Orchestrates the hardware interface discovery pipeline."""

    def __init__(
        self,
        pins: list,
        voltage: float,
        out_dir: Path,
        run_jtag: bool = False,
        skip_passive: bool = False,
        run_baseline: bool = False,
        noise_floor_file: Optional[str] = None,
        snr_threshold: float = 10.0,
    ):
        self.pins = pins
        self.voltage = voltage
        self.out_dir = out_dir
        self.run_jtag = run_jtag
        self.skip_passive = skip_passive
        self.run_baseline = run_baseline
        self.noise_floor_file = noise_floor_file
        self.snr_threshold = snr_threshold
        self.glasgow = GlasgowRunner()
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> dict:
        """
        Run the full discovery pipeline.

        Returns:
            hardware-report dict (also written to hardware-report.json)
        """
        start_time = time.time()

        print("\n" + "=" * 70)
        print("RAPTOR HARDWARE SECURITY ENUMERATOR")
        print("=" * 70)
        print(f"Voltage:   {self.voltage}V")
        print(f"Pins:      {self.pins}")
        print(f"Output:    {self.out_dir}")
        print(f"JTAG scan: {'yes' if self.run_jtag else 'no (--jtag to enable)'}")
        if self.run_baseline:
            print(f"Baseline:  yes (noise floor capture enabled, SNR threshold: {self.snr_threshold}x)")
        elif self.noise_floor_file:
            print(f"Baseline:  loaded from {self.noise_floor_file} (SNR threshold: {self.snr_threshold}x)")
        print("=" * 70 + "\n")

        # Validation state accumulated across stages
        validation = {
            "baseline_captured": False,
            "snr_threshold": self.snr_threshold,
            "noise_filtered_pins": [],
            "noise_floor": {},
        }

        # Stage 0: Glasgow device check
        print("[Stage 0] Glasgow device check...")
        glasgow_info = self.glasgow.identify()

        if not glasgow_info["found"]:
            error_msg = glasgow_info.get("error", "No device found")
            print(f"\n✗ Glasgow not found: {error_msg}")
            print(f"\nInstall Glasgow software from: {GLASGOW_INSTALL_URL}")
            print("Note: 'pip install glasgow' installs a placeholder (0.0.0) —")
            print("      install from source using the link above.")
            print("Then connect your Glasgow Interface Explorer via USB.\n")
            sys.exit(1)

        print(f"  Glasgow: {glasgow_info.get('version', 'detected')}")
        if glasgow_info.get("serial"):
            print(f"  Serial:  {glasgow_info['serial']}")

        # Stage 0.5: Noise baseline (opt-in)
        noise_counts: dict = {}
        if self.noise_floor_file:
            print(f"\n[Stage 0.5] Loading noise floor from {self.noise_floor_file}...")
            try:
                with open(self.noise_floor_file) as nf:
                    raw = json.load(nf)
                # JSON keys are strings; convert to int pin numbers
                noise_counts = {int(k): v for k, v in raw.items()}
                validation["baseline_captured"] = True
                validation["noise_floor"] = noise_counts
                print(f"  Noise floor loaded: { {p: c for p, c in sorted(noise_counts.items())} }")
            except Exception as e:
                print(f"  [!] Failed to load noise floor file: {e} — noise filtering disabled")
        elif self.run_baseline:
            noise_counts = run_noise_baseline(
                self.glasgow, self.pins, self.out_dir, self.voltage
            )
            if noise_counts:
                validation["baseline_captured"] = True
                validation["noise_floor"] = noise_counts

        # Stage 1: Passive logic capture
        active_pins = self.pins
        if not self.skip_passive:
            print("\n[Stage 1] Passive logic capture...")
            passive_result = run_passive_capture(
                self.glasgow, self.pins, self.out_dir, self.voltage
            )
            active_pins = passive_result["active_pins"]

            # Apply noise filtering if we have a baseline and real signal data
            signal_counts = passive_result.get("signal_counts", {})
            if noise_counts and signal_counts:
                real_pins, noise_pins = filter_pins_by_noise_floor(
                    signal_counts, noise_counts, self.snr_threshold
                )
                if noise_pins:
                    pin_labels = [f"A{p}" for p in noise_pins]
                    print(f"  Noise-filtered pins (excluded): {pin_labels}")
                    validation["noise_filtered_pins"] = noise_pins
                active_pins = real_pins if real_pins else active_pins
        else:
            print("\n[Stage 1] Skipping passive capture (--skip-passive)")
            passive_result = {"active_pins": self.pins, "signal_counts": {}, "skipped": True}

        print(f"  Pins for active probing: {active_pins}")

        # Stage 2: I2C scan
        print("\n[Stage 2] I2C bus scan...")
        i2c_findings = detect_i2c(self.glasgow, active_pins, self.out_dir, self.voltage)
        if i2c_findings:
            print(f"  Found {len(i2c_findings)} I2C bus(es)")
        else:
            print("  No I2C devices detected")

        # Stage 3: UART detection
        print("\n[Stage 3] UART detection...")
        uart_findings = detect_uart(self.glasgow, active_pins, self.out_dir, self.voltage)
        if uart_findings:
            for f in uart_findings:
                print(
                    f"  UART pin {f['pins']['rx']} @ {f['baud_rate']} baud "
                    f"[{f['confidence']}]"
                    + (f" — {f['notes']}" if f.get("notes") else "")
                )
        else:
            print("  No UART activity detected")

        # Stage 4: JTAG (opt-in)
        jtag_findings = []
        if self.run_jtag:
            print("\n[Stage 4] JTAG brute-force scan (this may take several minutes)...")
            jtag_findings = detect_jtag(
                self.glasgow, active_pins, self.out_dir, self.voltage
            )
            if jtag_findings:
                for f in jtag_findings:
                    print(f"  JTAG: {f['pins']} — {f.get('notes', '')}")
            else:
                print("  No JTAG chain detected")
        else:
            print("\n[Stage 4] JTAG scan skipped (use --jtag to enable)")

        # Compile report
        all_findings = i2c_findings + uart_findings + jtag_findings
        detected_protos = {f["protocol"] for f in all_findings}

        not_detected = [
            p for p in ["i2c", "uart"]
            if p not in detected_protos
        ]
        if self.run_jtag and "jtag" not in detected_protos:
            not_detected.append("jtag")
        elif not self.run_jtag:
            not_detected.append("jtag (not scanned)")

        duration = round(time.time() - start_time, 1)
        recommendations = _make_recommendations(all_findings, not_detected)

        report = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "glasgow": {
                "version": glasgow_info.get("version", ""),
                "serial": glasgow_info.get("serial", ""),
            },
            "voltage": self.voltage,
            "pins_probed": self.pins,
            "active_pins": active_pins,
            "findings": all_findings,
            "not_detected": not_detected,
            "recommendations": recommendations,
            "duration_seconds": duration,
            "validation": validation,
        }

        report_path = self.out_dir / "hardware-report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        # Summary
        print("\n" + "=" * 70)
        print("ENUMERATION COMPLETE")
        print("=" * 70)
        print(f"Duration:    {duration}s")
        print(f"Active pins: {active_pins}")
        print(f"Findings:    {len(all_findings)}")
        for finding in all_findings:
            confidence = finding.get("confidence", "")
            proto = finding.get("protocol", "")
            pins = finding.get("pins", {})
            print(f"  [{confidence}] {proto}: {pins}")
        if recommendations:
            print("\nNext steps:")
            for rec in recommendations:
                print(f"  • {rec}")
        print(f"\nReport: {report_path}")
        print("=" * 70 + "\n")

        return report


def main():
    """CLI entry point for hardware enumerator."""
    parser = argparse.ArgumentParser(
        description="RAPTOR Hardware Security Enumerator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Stages:
  0.   Glasgow device check
  0.5  Noise baseline (--baseline): capture with target OFF to establish noise floor
  1.   Passive logic capture (power-cycle target during this window)
  2.   I2C bus scan
  3.   UART baud-rate detection
  4.   JTAG brute-force (opt-in via --jtag)

Note: SPI flash detection is not automated — identify pins manually then use:
  glasgow run memory-25x -V3.3 --pins-cs <CS> --pins-sck <SCK> --pins-mosi <MOSI> --pins-miso <MISO> read flash.bin

Glasgow installation note:
  'pip install glasgow' installs a placeholder (0.0.0).
  Install the real software from: {GLASGOW_INSTALL_URL}

Examples:
  # Default: probe pins 0-7 at 3.3V
  python3 raptor.py hardware --voltage 3.3 --pins 0-7

  # Focus on known pin range at 1.8V with noise baseline
  python3 raptor.py hardware --voltage 1.8 --pins 0-7 --baseline

  # Reuse a previously captured baseline
  python3 raptor.py hardware --voltage 1.8 --pins 0-7 --noise-floor .out/hardware-xyz/noise-baseline.json

  # Skip passive capture and run JTAG brute-force
  python3 raptor.py hardware --skip-passive --jtag

  # Custom output directory
  python3 raptor.py hardware --out /tmp/my-target/
        """,
    )

    parser.add_argument(
        "--voltage", "-V",
        type=float,
        default=3.3,
        help="I/O voltage for all probing (default: 3.3V)",
    )
    parser.add_argument(
        "--pins",
        default="0-7",
        help="Pins to probe: '0-7' or '0,1,2,3' (default: 0-7)",
    )
    parser.add_argument(
        "--out",
        help="Output directory (default: .out/hardware-<timestamp>/)",
    )
    parser.add_argument(
        "--jtag",
        action="store_true",
        help="Enable JTAG brute-force scan (slow: 5-10 minutes)",
    )
    parser.add_argument(
        "--skip-passive",
        action="store_true",
        help="Skip passive logic capture, treat all --pins as active",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Capture noise baseline before main capture (prompts to power off target)",
    )
    parser.add_argument(
        "--noise-floor",
        metavar="FILE",
        help="Load pre-captured noise floor from JSON file (skips baseline capture)",
    )
    parser.add_argument(
        "--snr-threshold",
        type=float,
        default=10.0,
        metavar="N",
        help="Minimum signal-to-noise ratio to treat a pin as active (default: 10)",
    )
    args = parser.parse_args()

    if args.out:
        out_dir = Path(args.out)
    else:
        timestamp = int(time.time())
        out_dir = RaptorConfig.get_out_dir() / f"hardware-{timestamp}"

    pins = _parse_pin_range(args.pins)

    enumerator = HardwareEnumerator(
        pins=pins,
        voltage=args.voltage,
        out_dir=out_dir,
        run_jtag=args.jtag,
        skip_passive=args.skip_passive,
        run_baseline=args.baseline,
        noise_floor_file=args.noise_floor,
        snr_threshold=args.snr_threshold,
    )

    try:
        enumerator.run()
        return 0
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 130
    except SystemExit:
        raise
    except Exception as e:
        print(f"\n✗ Enumeration failed: {e}")
        logger.error(f"Hardware enumeration failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
