#!/usr/bin/env python3
"""
RAPTOR Hardware Security Enumerator

Automated interface discovery for unknown wired targets using the
Glasgow Interface Explorer.

Stages:
  0. Glasgow device check
  1. Passive logic capture (10s) — user power-cycles target
  2. I2C scan (adjacent pin pairs, safe ACK probing)
  3. UART detection (active pins × common baud rates)
  4. JTAG pin discovery via jtag-pinout (opt-in via --jtag)

Output: hardware-report.json written to the output directory.

Glasgow installation: https://glasgow-embedded.org/latest/install.html
Note: 'pip install glasgow' installs a placeholder (0.0.0) — install
from source.

Note: SPI flash detection and Vsense checks are intentionally excluded
from automated enumeration. SPI requires manual pin assignment to avoid
false positives; Vsense probing on incorrect wiring risks damaging the
target on a one-shot opportunity.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Optional

# Add repo root to path for imports
# packages/hardware/enumerator.py -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.config import RaptorConfig
from core.logging import get_logger
from core.run.output import unique_run_suffix
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

# The enumerator drives Glasgow port A only.
MAX_PIN = 7


class EnumerationSetupError(RuntimeError):
    """Setup precondition failed (no device, incompatible applet CLI).

    Raised — not sys.exit()ed — so programmatic embedders of
    HardwareEnumerator get an error instead of a dead process; the CLI
    entry point turns it into exit code 1.
    """


def _parse_pin_range(pins_arg: str) -> list[int]:
    """
    Parse pin specification: '0-7', '0,1,2,3', or '0-3,6,7'.

    Returns sorted list of pin numbers. Raises ValueError on malformed
    input, reversed/empty ranges, or pins outside port A (0-{MAX_PIN}).
    """
    pins: set[int] = set()
    for part in pins_arg.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"empty pin entry in {pins_arg!r}")
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            try:
                start, end = int(start_s), int(end_s)
            except ValueError:
                raise ValueError(
                    f"malformed pin range {part!r} (expected N-M)"
                ) from None
            if end < start:
                raise ValueError(f"reversed pin range {part!r}")
            pins.update(range(start, end + 1))
        else:
            try:
                pins.add(int(part))
            except ValueError:
                raise ValueError(f"malformed pin {part!r}") from None
    bad = sorted(p for p in pins if p < 0 or p > MAX_PIN)
    if bad:
        raise ValueError(
            f"pins out of range (port A is 0-{MAX_PIN}): {bad}"
        )
    if not pins:
        raise ValueError(f"no pins in {pins_arg!r}")
    return sorted(pins)


def _pin_range_arg(value: str) -> list[int]:
    """argparse type wrapper: malformed --pins becomes a usage error,
    not a traceback."""
    try:
        return _parse_pin_range(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def _load_noise_floor(path: str) -> dict[int, int]:
    """Load a --noise-floor JSON file as {pin: transition_count}.

    Keys AND values are validated as ints — a malformed file disables
    noise filtering (empty dict) rather than crashing mid-run.
    """
    try:
        with open(path) as nf:
            raw = json.load(nf)
        return {int(k): int(v) for k, v in raw.items()}
    except (OSError, ValueError, TypeError, AttributeError,
            json.JSONDecodeError) as e:
        print(f"  [!] Failed to load noise floor file: {e} — "
              f"noise filtering disabled")
        return {}


def _make_recommendations(
    findings: list[dict], not_detected: list[str],
) -> list[str]:
    """Generate actionable next-step recommendations from findings."""
    recs: list[str] = []
    for f in findings:
        proto = f.get("protocol", "")

        if proto == "uart":
            baud = f.get("baud_rate")
            pin = f.get("pins", {}).get("rx", "?")
            notes = f.get("notes", "")
            # baud None = auto-baud confirmed the pin but never logged a
            # rate; recommend --auto-baud rather than a nonsense --baud 0.
            baud_label = baud if baud else "auto"
            baud_flag = f"--baud {baud}" if baud else "--auto-baud"
            recs.append(
                f"UART at {baud_label} baud on pin A{pin}"
                + (f" [{notes}]" if notes else "")
                + f" — connect with: glasgow run uart --voltage 3.3 {baud_flag} "
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
            # jtag pins are full pin names ("A0") — jtag-pinout may
            # identify pins on either port.
            p = f.get("pins", {})
            probe_args = (
                f"--tck {p.get('tck','?')} --tms {p.get('tms','?')} "
                f"--tdi {p.get('tdi','?')} --tdo {p.get('tdo','?')}"
            )
            if "trst" in p:
                probe_args += f" --trst {p['trst']}"
            recs.append(
                f"JTAG interface: TCK={p.get('tck','?')} TMS={p.get('tms','?')} "
                f"TDI={p.get('tdi','?')} TDO={p.get('tdo','?')} — "
                f"enumerate the chain with: glasgow run jtag-probe --voltage 3.3 "
                f"{probe_args} scan — then load jtag-exploitation skill"
            )

    # Exact-match: a completed-but-empty JTAG scan appends plain "jtag",
    # which must NOT re-suggest scanning.
    if "jtag (not scanned)" in not_detected:
        recs.append(
            "JTAG not scanned — re-run with --jtag to run jtag-pinout pin "
            "discovery (adds a few minutes)"
        )

    return recs


class HardwareEnumerator:
    """Orchestrates the hardware interface discovery pipeline."""

    def __init__(
        self,
        pins: list[int],
        voltage: float,
        out_dir: Path,
        run_jtag: bool = False,
        skip_passive: bool = False,
        run_baseline: bool = False,
        noise_floor_file: Optional[str] = None,
        snr_threshold: float = 10.0,
        warm_cache: bool = False,
        glasgow: Optional[GlasgowRunner] = None,
    ):
        self.pins = pins
        self.voltage = voltage
        self.out_dir = out_dir
        self.run_jtag = run_jtag
        self.skip_passive = skip_passive
        self.run_baseline = run_baseline
        self.noise_floor_file = noise_floor_file
        self.snr_threshold = snr_threshold
        self.warm_cache = warm_cache
        self.glasgow = glasgow if glasgow is not None else GlasgowRunner()
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def _applet_checks(self) -> list[tuple[str, list[str]]]:
        """Applets this run will drive, with the flags it passes."""
        checks = [
            ("i2c-controller", ["--scl", "--sda"]),
            ("uart", ["--rx", "--baud", "--auto-baud"]),
        ]
        if not self.skip_passive or self.run_baseline:
            checks.append(("analyzer", ["--i", "--pin-names"]))
        if self.run_jtag:
            checks.append(("jtag-pinout", ["--pins"]))
        return checks

    def _warm_bitstream_cache(self, rev: str) -> None:
        """Pre-build the applet bitstreams (device-free ``glasgow build``)
        so first-run FPGA synthesis doesn't happen INSIDE the capture
        windows — a cold build takes minutes against 3-10s windows and
        turns into silent empty captures. Best-effort: a missing FPGA
        toolchain just warns."""
        pin_list = ",".join(f"A{p}" for p in self.pins)
        build_args: dict[str, list[str]] = {
            "analyzer": ["--i", pin_list, "--pin-names",
                         ",".join(f"pin{p}" for p in self.pins)],
            "uart": ["--rx", f"A{self.pins[0]}"],
            "i2c-controller": ["--scl", f"A{self.pins[0]}",
                               "--sda", f"A{self.pins[min(1, len(self.pins) - 1)]}"],
            "jtag-pinout": ["--pins", pin_list],
        }
        for applet, _flags in self._applet_checks():
            print(f"  Warming bitstream cache: {applet}...")
            result = self.glasgow.run(
                ["build", "--rev", rev, applet, *build_args.get(applet, [])],
                timeout=900,
            )
            if result["returncode"] != 0:
                print(f"  [!] {applet} build failed (continuing): "
                      f"{result['stderr'].strip().splitlines()[-1][:100] if result['stderr'].strip() else 'unknown'}")

    def run(self) -> dict:
        """
        Run the full discovery pipeline.

        Returns:
            hardware-report dict (also written to hardware-report.json)

        Raises:
            EnumerationSetupError: no device found or applet CLI mismatch.
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
            "noise_filter_overridden": False,
            "noise_floor": {},
        }

        # Stage 0: Glasgow device check
        print("[Stage 0] Glasgow device check...")
        glasgow_info = self.glasgow.identify()

        if not glasgow_info["found"]:
            error_msg = glasgow_info.get("error", "No device found")
            raise EnumerationSetupError(
                f"Glasgow not found: {error_msg}\n"
                f"Install Glasgow software from: {GLASGOW_INSTALL_URL}\n"
                "Note: 'pip install glasgow' installs a placeholder (0.0.0) — "
                "install from source using the link above.\n"
                "Then connect your Glasgow Interface Explorer via USB."
            )

        print(f"  Glasgow: {glasgow_info.get('version', 'detected')}")
        if glasgow_info.get("serial"):
            print(f"  Serial:  {glasgow_info['serial']}")

        # Still Stage 0: applet CLI compatibility probe. Glasgow renames
        # applets and pin flags across releases; a mismatch must fail
        # loud here, not degrade into silent all-clear captures later.
        problems = [
            problem
            for applet, flags in self._applet_checks()
            if (problem := self.glasgow.check_applet(applet, flags))
        ]
        if problems:
            detail = "\n".join(f"  - {p}" for p in problems)
            raise EnumerationSetupError(
                "Glasgow applet CLI mismatch:\n" + detail + "\n"
                "This glasgow install's CLI differs from what the "
                "enumerator drives. Update glasgow (install from source) "
                "or update packages/hardware/ to match."
            )
        print("  Applet CLI check: ok")

        # Optional bitstream warmup (--warm-cache): device revision
        # comes from the serial prefix parsed by identify() ("revC3").
        if self.warm_cache:
            rev = glasgow_info.get("version", "").removeprefix("rev")
            if rev:
                print("  Pre-building applet bitstreams (--warm-cache; "
                      "first run can take minutes)...")
                self._warm_bitstream_cache(rev)
            else:
                print("  [!] --warm-cache: could not determine device "
                      "revision from serial; skipping warmup")

        # Stage 0.5: Noise baseline (opt-in)
        noise_counts: dict[int, int] = {}
        if self.noise_floor_file:
            print(f"\n[Stage 0.5] Loading noise floor from {self.noise_floor_file}...")
            noise_counts = _load_noise_floor(self.noise_floor_file)
            if noise_counts:
                validation["baseline_captured"] = True
                validation["noise_floor"] = noise_counts
                print(f"  Noise floor loaded: { {p: c for p, c in sorted(noise_counts.items())} }")
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
                if real_pins:
                    active_pins = real_pins
                elif noise_pins:
                    # Every active pin scored below the noise floor —
                    # probing nothing helps nobody, so probe them all,
                    # but say so and record it (the report must not
                    # claim pins were excluded that were then probed).
                    print("  [!] All pins fell below the noise floor — "
                          "probing all of them anyway (recorded as "
                          "noise_filter_overridden)")
                    validation["noise_filter_overridden"] = True
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
                    f"  UART pin {f['pins']['rx']} @ {f['baud_rate'] or 'auto'} baud "
                    f"[{f['confidence']}]"
                    + (f" — {f['notes']}" if f.get("notes") else "")
                )
        else:
            print("  No UART activity detected")

        # Stage 4: JTAG (opt-in)
        jtag_findings = []
        if self.run_jtag:
            print("\n[Stage 4] JTAG pin discovery (jtag-pinout, may take a few minutes)...")
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


def main() -> int:
    """CLI entry point for hardware enumerator."""
    parser = argparse.ArgumentParser(
        description="RAPTOR Hardware Security Enumerator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Stages:
  0.   Glasgow device check + applet CLI compatibility probe
  0.5  Noise baseline (--baseline): capture with target OFF to establish noise floor
  1.   Passive logic capture (power-cycle target during this window)
  2.   I2C bus scan
  3.   UART baud-rate detection
  4.   JTAG pin discovery via jtag-pinout (opt-in via --jtag)

Note: SPI flash detection is not automated — identify pins manually then use:
  glasgow run memory-25x -V 3.3 --cs <CS> --sck <SCK> --io <COPI>,<CIPO>,<WP>,<HOLD> read 0 <LENGTH> -f flash.bin

Glasgow installation note:
  'pip install glasgow' installs a placeholder (0.0.0).
  Install the real software from: {GLASGOW_INSTALL_URL}

Examples:
  # Default: probe pins 0-7 at 3.3V
  python3 raptor.py hardware --voltage 3.3 --pins 0-7

  # Focus on known pin range at 1.8V with noise baseline
  python3 raptor.py hardware --voltage 1.8 --pins 0-7 --baseline

  # Reuse a previously captured baseline
  python3 raptor.py hardware --voltage 1.8 --pins 0-7 --noise-floor out/hardware_<run>/noise-baseline.json

  # Skip passive capture and run JTAG pin discovery
  python3 raptor.py hardware --skip-passive --jtag

  # Fresh install: pre-build the FPGA bitstreams before the capture windows
  python3 raptor.py hardware --warm-cache

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
        type=_pin_range_arg,
        default="0-7",
        help=f"Pins to probe on port A (0-{MAX_PIN}): '0-7' or '0,1,2,3' (default: 0-7)",
    )
    parser.add_argument(
        "--out",
        help="Output directory (default: out/hardware_<run suffix>/)",
    )
    parser.add_argument(
        "--jtag",
        action="store_true",
        help="Enable JTAG pin discovery via jtag-pinout (adds a few minutes)",
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
    parser.add_argument(
        "--warm-cache",
        action="store_true",
        help="Pre-build applet FPGA bitstreams before probing (first run on "
             "a fresh install otherwise builds them inside the capture "
             "windows, producing empty captures)",
    )
    args = parser.parse_args()

    if args.out:
        out_dir = Path(args.out)
    else:
        # Collision-prevention via unique_run_suffix — see core/run/output.py.
        out_dir = RaptorConfig.get_out_dir() / f"hardware_{unique_run_suffix('_')}"

    # argparse only applies type= to operator-supplied values; the
    # default is a string and parses here.
    pins = args.pins if isinstance(args.pins, list) else _parse_pin_range(args.pins)

    enumerator = HardwareEnumerator(
        pins=pins,
        voltage=args.voltage,
        out_dir=out_dir,
        run_jtag=args.jtag,
        skip_passive=args.skip_passive,
        run_baseline=args.baseline,
        noise_floor_file=args.noise_floor,
        snr_threshold=args.snr_threshold,
        warm_cache=args.warm_cache,
    )

    try:
        enumerator.run()
        return 0
    except EnumerationSetupError as e:
        print(f"\n✗ {e}\n")
        return 1
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
