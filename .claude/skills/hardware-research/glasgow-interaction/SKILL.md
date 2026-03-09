---
name: glasgow-interaction
description: Glasgow Interface Explorer Python API patterns. How to invoke applets, use the programmatic interface, build custom applets, and integrate Glasgow into automated hardware security workflows.
---

# Glasgow Interaction Skill

Glasgow Interface Explorer is a Python-native FPGA-based multi-protocol interface tool. All hardware interaction skills in this directory build on top of it.

Documentation: https://glasgow-embedded.org/latest/intro.html

---

## Device setup and identification

```bash
# Check Glasgow is attached and recognised
glasgow identify

# List available applets
glasgow run --help

# Check firmware version and device state
glasgow factory-test
```

---

## Command-line applet patterns

### UART

```bash
# Basic UART at known baud
glasgow run uart -V 3.3 --baud 115200 --pins-tx 0 --pins-rx 1 tty

# Auto-detect baud rate on TX pin
glasgow run uart -V 3.3 --baud auto --pins-tx 0 tty

# Log all UART output to file
glasgow run uart -V 3.3 --baud 115200 --pins-tx 0 --pins-rx 1 record uart-log.bin

# Pipe into a terminal emulator
glasgow run uart -V 3.3 --baud 115200 --pins-tx 0 --pins-rx 1 tty | picocom --nolock --logfile uart-session.log /dev/stdin
```

### SPI Flash

```bash
# Identify SPI flash chip
glasgow run memory-25x -V 3.3 --pins-cs 0 --pins-sck 1 --pins-mosi 2 --pins-miso 3 identify

# Read full flash to file
glasgow run memory-25x -V 3.3 --pins-cs 0 --pins-sck 1 --pins-mosi 2 --pins-miso 3 read firmware.bin

# Write firmware to flash
glasgow run memory-25x -V 3.3 --pins-cs 0 --pins-sck 1 --pins-mosi 2 --pins-miso 3 write patched-firmware.bin

# Erase full chip
glasgow run memory-25x -V 3.3 --pins-cs 0 --pins-sck 1 --pins-mosi 2 --pins-miso 3 erase-chip

# Read at 1.8V (for low-voltage flash)
glasgow run memory-25x -V 1.8 --pins-cs 0 --pins-sck 1 --pins-mosi 2 --pins-miso 3 read firmware-1v8.bin
```

### I2C

```bash
# Scan I2C bus for devices
glasgow run i2c-initiator -V 3.3 --pins-scl 0 --pins-sda 1 scan

# Read I2C EEPROM (device at address 0x50)
glasgow run memory-24x -V 3.3 --pins-scl 0 --pins-sda 1 --i2c-address 0x50 read eeprom.bin

# Write I2C EEPROM
glasgow run memory-24x -V 3.3 --pins-scl 0 --pins-sda 1 --i2c-address 0x50 write new-eeprom.bin
```

### JTAG

```bash
# Scan JTAG chain and identify devices
glasgow run jtag-probe -V 3.3 --pins-tck 0 --pins-tdi 1 --pins-tdo 2 --pins-tms 3 scan-dr

# Play SVF file (e.g. to unlock JTAG)
glasgow run jtag-probe -V 3.3 --pins-tck 0 --pins-tdi 1 --pins-tdo 2 --pins-tms 3 run-svf unlock.svf

# Enumerate IR length
glasgow run jtag-probe -V 3.3 --pins-tck 0 --pins-tdi 1 --pins-tdo 2 --pins-tms 3 scan-ir
```

### Logic analysis

```bash
# Capture 8 channels, 10M samples
glasgow run logic-analyzer --pins 0,1,2,3,4,5,6,7 --sample-rate 100e6 record capture.vcd

# View in PulseView
pulseview capture.vcd
```

### GPIO

```bash
# Set pin 0 high, pin 1 low (for power cycling / reset)
glasgow run gpio --pins 0,1 set 0=1 1=0

# Toggle reset line
glasgow run gpio --pins 0 set 0=0  # assert reset
sleep 0.1
glasgow run gpio --pins 0 set 0=1  # release reset
```

---

## Python API patterns

For automation and scripted workflows, use Glasgow's Python API directly.

### Basic async applet invocation

```python
import asyncio
from glasgow.target.hardware import GlasgowHardwareTarget
from glasgow.device.hardware import GlasgowHardwareDevice

async def main():
    device = GlasgowHardwareDevice()
    await device.reset_alert()
    await device.set_voltage("AB", 3.3)

    # Use applets programmatically via the CLI API
    # Most automation is done by shelling out or using the applet classes directly

asyncio.run(main())
```

### Scripted SPI flash read

```python
import asyncio
import subprocess
import sys

async def read_spi_flash(output_path: str, voltage: float = 3.3,
                          pins: dict = None) -> bool:
    """
    Read SPI flash using Glasgow memory-25x applet.

    Returns True on success.
    """
    if pins is None:
        pins = {"cs": 0, "sck": 1, "mosi": 2, "miso": 3}

    cmd = [
        "glasgow", "run", "memory-25x",
        "-V", str(voltage),
        "--pins-cs", str(pins["cs"]),
        "--pins-sck", str(pins["sck"]),
        "--pins-mosi", str(pins["mosi"]),
        "--pins-miso", str(pins["miso"]),
        "read", output_path
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
        pins = {"cs": 0, "sck": 1, "mosi": 2, "miso": 3}

    cmd = [
        "glasgow", "run", "memory-25x",
        "-V", str(voltage),
        "--pins-cs", str(pins["cs"]),
        "--pins-sck", str(pins["sck"]),
        "--pins-mosi", str(pins["mosi"]),
        "--pins-miso", str(pins["miso"]),
        "identify"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    # Parse Glasgow identify output
    info = {}
    for line in result.stdout.splitlines():
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
        "glasgow", "run", "i2c-initiator",
        "-V", str(voltage),
        "--pins-scl", str(pin_scl),
        "--pins-sda", str(pin_sda),
        "scan"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    addresses = []
    for line in result.stdout.splitlines():
        match = re.search(r'0x([0-9a-fA-F]{2})', line)
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
        "--pins-tx", str(pin_tx),
        "--pins-rx", str(pin_rx),
        "record", output_path
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
Glasgow Port A (pins 0-7):  Primary interface
Glasgow Port B (pins 8-15): Secondary / logic analysis

Recommended for typical session:
  UART:  TX=0  RX=1
  SPI:   CS=0  SCK=1  MOSI=2  MISO=3
  I2C:   SCL=0 SDA=1
  JTAG:  TCK=0 TDI=1  TDO=2   TMS=3
  SWD:   SWDCLK=0  SWDIO=1
  GPIO:  RESET=4   BOOT=5
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
| `No device found` | Glasgow not connected or needs udev rule | `sudo glasgow run ...` or fix udev |
| `ALERT: voltage too high` | Target voltage doesn't match Glasgow setting | Measure target VCC, adjust `-V` flag |
| `Timeout during identify` | CS/SCK not reaching chip, bad soldering, wrong pins | Check continuity, verify pin mapping |
| `Short circuit detected` | Two signals shorted or voltage mismatch | Power off immediately, check wiring |
| `Permission denied` | Missing udev rule for USB device | See Glasgow installation docs |

```bash
# Fix udev on Linux
sudo glasgow -h  # shows udev rule to add
```

---

## Integration with raptor workflow

When hardware skills produce firmware blobs, hand off to:
- `firmware-extraction` skill for unpacking and analysis kickoff
- `raptor.py analyze` for LLM-assisted firmware analysis
- `raptor.py scan` against extracted filesystem/source
