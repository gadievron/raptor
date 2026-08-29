---
name: glasgow-interaction
description: Glasgow Interface Explorer Python API patterns. How to invoke applets, use the programmatic interface, build custom applets, and integrate Glasgow into automated hardware security workflows.
user-invocable: false
---

# Glasgow Interaction Skill

Glasgow Interface Explorer is a Python-native FPGA-based multi-protocol interface tool. All hardware interaction skills in this directory build on top of it.

Documentation: https://glasgow-embedded.org/latest/intro.html

---

## Device setup and identification

```bash
# Check Glasgow is attached and recognised (prints one serial per line)
glasgow list

# List available applets
glasgow run --help

# Query I/O port voltage configuration and live measurements
glasgow voltage

# Safety: turn off all I/O port voltage regulators and drivers
glasgow safe
```

---

## Command-line applet patterns

### UART

```bash
# Basic UART at known baud (pins are always port+number: A0, B3, ...)
glasgow run uart -V 3.3 --baud 115200 --tx A0 --rx A1 tty

# Hardware auto-baud: measures the rate and logs "switched to N baud"
glasgow run uart -V 3.3 --auto-baud --rx A1 tty

# Log all UART output to file
glasgow run uart -V 3.3 --baud 115200 --rx A1 tty --stream > uart-log.bin

# Interactive console (tty is bidirectional when --tx is wired)
glasgow run uart -V 3.3 --baud 115200 --tx A0 --rx A1 tty
```

### SPI Flash

```bash
# --io takes the four data lines in order: COPI(SI), CIPO(SO), WP#, HOLD#

# Identify SPI flash chip
glasgow run memory-25x -V 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 identify

# Read full flash to file
glasgow run memory-25x -V 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 read 0 16777216 -f firmware.bin   # ADDRESS LENGTH; get size from identify

# Program firmware to flash (erase-program erases affected sectors first)
glasgow run memory-25x -V 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 erase-program 0 -S 4096 -P 256 -f patched-firmware.bin

# Erase full chip
glasgow run memory-25x -V 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 erase-chip

# Read at 1.8V (for low-voltage flash)
glasgow run memory-25x -V 1.8 --cs A0 --sck A1 --io A2,A3,A4,A5 read 0 16777216 -f firmware-1v8.bin
```

### I2C

```bash
# Scan I2C bus for devices (hits are logged as "scan found address ...")
glasgow run i2c-controller -V 3.3 --scl A0 --sda A1 scan

# Read I2C EEPROM (device at address 0x50; -W = address width in bytes)
glasgow run memory-24x -V 3.3 --scl A0 --sda A1 --i2c-address 0x50 -W 1 read 0 256 -f eeprom.bin

# Write I2C EEPROM
glasgow run memory-24x -V 3.3 --scl A0 --sda A1 --i2c-address 0x50 -W 1 write 0 -f new-eeprom.bin
```

### JTAG

```bash
# Discover the pin assignment first when it is unknown (4-16 candidates)
glasgow run jtag-pinout -V 3.3 --pins A0,A1,A2,A3,A4,A5

# Scan JTAG chain and identify devices (IDCODEs)
glasgow run jtag-probe -V 3.3 --tck A0 --tms A1 --tdi A2 --tdo A3 scan

# Enumerate IR values per TAP
glasgow run jtag-probe -V 3.3 --tck A0 --tms A1 --tdi A2 --tdo A3 enumerate-ir 0   # per-TAP index; upstream warns this can damage the DUT

# Play SVF file (e.g. to unlock JTAG) — separate jtag-svf applet
glasgow run jtag-svf -V 3.3 --tck A0 --tms A1 --tdi A2 --tdo A3 unlock.svf
```

### Logic analysis

```bash
# Capture 8 channels to VCD (runs until Ctrl-C; samples at system clock)
glasgow run analyzer -V 3.3 --i A0:7 capture.vcd

# View in PulseView
pulseview capture.vcd
```

### GPIO

```bash
# Set pin A0 high, pin A1 low (for power cycling / reset)
glasgow run control-gpio -V 3.3 --pins A0,A1 A0=1 A1=0

# Toggle reset line
glasgow run control-gpio -V 3.3 --pins A0 A0=0  # assert reset
sleep 0.1
glasgow run control-gpio -V 3.3 --pins A0 A0=1  # release reset
```

---

## Python API patterns

For automation and scripted workflows, use Glasgow's Python API directly.

### In-process Python API

The in-process API (``glasgow.hardware.device.GlasgowDevice`` and the
applet classes) is evolving upstream; for automation, shell out to the
``glasgow`` CLI with list-based argv as the samples below do — the CLI
is the stable contract this skill validates against.

### Scripted SPI flash read

```python
import asyncio
import subprocess
import sys

async def read_spi_flash(output_path: str, length: int, voltage: float = 3.3,
                          pins: dict = None) -> bool:
    """
    Read SPI flash using Glasgow memory-25x applet.

    Returns True on success.
    """
    if pins is None:
        # io = COPI, CIPO, WP#, HOLD#
        pins = {"cs": "A0", "sck": "A1", "io": "A2,A3,A4,A5"}

    cmd = [
        "glasgow", "run", "memory-25x",
        "-V", str(voltage),
        "--cs", pins["cs"],
        "--sck", pins["sck"],
        "--io", pins["io"],
        "read", "0", str(length), "-f", output_path
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Glasgow error: {result.stderr}", file=sys.stderr)
        return False

    print(f"[+] Flash read to {output_path}")
    return True


async def identify_spi_flash(voltage: float = 3.3, pins: dict = None) -> dict:
    """
    Identify the SPI flash chip via JEDEC ID.
    Returns dict with manufacturer, device_id, capacity.
    """
    if pins is None:
        # io = COPI, CIPO, WP#, HOLD#
        pins = {"cs": "A0", "sck": "A1", "io": "A2,A3,A4,A5"}

    cmd = [
        "glasgow", "run", "memory-25x",
        "-V", str(voltage),
        "--cs", pins["cs"],
        "--sck", pins["sck"],
        "--io", pins["io"],
        "identify"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    # Parse Glasgow identify output (logger output lands on stderr)
    info = {}
    for line in (result.stdout + result.stderr).splitlines():
        if "manufacturer" in line.lower():
            info["manufacturer"] = line.split(":", 1)[-1].strip()
        elif "device" in line.lower():
            info["device_id"] = line.split(":", 1)[-1].strip()
        elif "size" in line.lower() or "capacity" in line.lower():
            info["capacity"] = line.split(":", 1)[-1].strip()
    return info
```

### Scripted I2C bus scan

```python
import subprocess
import re

def i2c_bus_scan(voltage: float = 3.3, pin_scl: int = 0, pin_sda: int = 1) -> list[int]:
    """
    Scan I2C bus and return list of responding device addresses.
    """
    cmd = [
        "glasgow", "run", "i2c-controller",
        "-V", str(voltage),
        "--scl", f"A{pin_scl}",
        "--sda", f"A{pin_sda}",
        "scan"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    addresses = []
    # Hits are logger output (stderr): "scan found address 0b1010000/0x50"
    for line in (result.stdout + result.stderr).splitlines():
        match = re.search(r'scan found address\s+\S*/0x([0-9a-fA-F]{2})', line)
        if match:
            addresses.append(int(match.group(1), 16))

    return addresses
```

### Scripted UART capture

```python
import asyncio
import subprocess
import threading
from pathlib import Path

def capture_uart_boot(output_path: str, duration_sec: int = 30,
                       baud: int = 115200, pin_tx: int = 0,
                       pin_rx: int = 1, voltage: float = 3.3) -> str:
    """
    Capture UART output during device boot for <duration_sec> seconds.
    Returns path to captured log.
    """
    import signal

    cmd = [
        "glasgow", "run", "uart",
        "-V", str(voltage),
        "--baud", str(baud),
        "--tx", f"A{pin_tx}",
        "--rx", f"A{pin_rx}",
        "tty", "--stream"
    ]

    with open(output_path, "wb") as out:
        proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.PIPE)
        try:
            proc.wait(timeout=duration_sec)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGINT)
            proc.wait()

    return output_path
```

---

## Pin assignment conventions

Use consistent pin numbering across sessions. Document in `recon/target-map.md`:

```
Glasgow Port A (A0-A7): Primary interface
Glasgow Port B (B0-B7): Secondary / logic analysis
Pins are always written port+number (A0, B3); bare numbers are rejected.

Recommended for typical session:
  UART:  TX=A0  RX=A1
  SPI:   CS=A0  SCK=A1  IO=A2,A3,A4,A5 (COPI,CIPO,WP#,HOLD#)
  I2C:   SCL=A0 SDA=A1
  JTAG:  TCK=A0 TMS=A1  TDI=A2  TDO=A3
  SWD:   SWCLK=A0  SWDIO=A1
  GPIO:  RESET=A4  BOOT=A5
```

---

## Voltage selection guide

```
3.3V  - Most common embedded systems, Arduino, Raspberry Pi GPIO
1.8V  - Modern low-power SoCs, many NOR flash chips, eMMC signalling
5.0V  - Older microcontrollers, some industrial equipment
1.2V  - Some DDR/LPDDR signalling (rare for direct Glasgow use)
```

**Always verify target voltage with multimeter before connecting Glasgow.**

---

## Common errors

| Error | Cause | Fix |
|-------|-------|-----|
| `No device found` | Glasgow not connected or USB permissions | Install the udev rules from the Glasgow install guide (running via `sudo` works but is a workaround) |
| `ALERT: voltage too high` | Target voltage doesn't match Glasgow setting | Measure target VCC, adjust `-V` flag |
| `Timeout during identify` | CS/SCK not reaching chip, bad soldering, wrong pins | Check continuity, verify pin mapping |
| `Short circuit detected` | Two signals shorted or voltage mismatch | Power off immediately, check wiring |
| `Permission denied` | Missing udev rule for USB device | See the install guide's udev section: https://glasgow-embedded.org/latest/install.html |

---

## Integration with raptor workflow

When hardware skills produce firmware blobs, hand off to:
- `firmware-extraction` skill for unpacking and analysis kickoff
- `python3 raptor.py scan --firmware-root <extracted_root>` for the firmware scan
- `python3 raptor.py binary investigate <elf>` for per-binary black-box analysis
