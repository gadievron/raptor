---
name: i2c-enumeration
description: I2C bus reconnaissance, device enumeration, EEPROM read/write, and attacks targeting I2C-connected security devices, configuration EEPROMs, and sensors.
---

# I2C Enumeration Skill

I2C is a two-wire bus (SDA + SCL) commonly used for EEPROMs, sensors, PMICs, and crypto chips. Configuration and key material often live in I2C EEPROMs.

Load `glasgow-interaction` skill for Glasgow command patterns.

---

## I2C fundamentals

```
Protocol: 7-bit or 10-bit addressing
  Address 0x50-0x57: EEPROM (AT24C series)
  Address 0x68-0x6F: RTC, IMU (MPU-6050 etc.)
  Address 0x20-0x27: I/O expanders (MCP23017)
  Address 0x48-0x4F: ADC, temperature (LM75)
  Address 0x76-0x77: Barometric pressure (BMP280)
  Address 0x18-0x1F: Crypto/secure elements (ATECC508A)

Special addresses:
  0x00: General call
  0x10: SMBus alert
```

---

## Phase 1: Bus enumeration

```bash
# Scan all I2C addresses
glasgow run i2c-controller --voltage 3.3 --scl A0 --sda A1 scan

# Expected output:
# device 0x50: present
# device 0x68: present

# At 1.8V
glasgow run i2c-controller --voltage 1.8 --scl A0 --sda A1 scan
```

### Python enumeration script

```python
import subprocess
import re

def i2c_enumerate(voltage: float = 3.3, pin_scl: int = 0, pin_sda: int = 1) -> list[dict]:
    """
    Enumerate I2C bus and annotate known devices.
    """
    KNOWN_DEVICES = {
        range(0x50, 0x58): "EEPROM (24C series)",
        range(0x68, 0x70): "RTC or IMU",
        range(0x20, 0x28): "I/O Expander",
        range(0x48, 0x50): "ADC or temperature sensor",
        range(0x18, 0x20): "Crypto/Secure Element",
        range(0x76, 0x78): "Pressure/environmental sensor",
    }

    cmd = [
        "glasgow", "run", "i2c-controller",
        "--voltage", str(voltage),
        "--scl", f"A{pin_scl}",
        "--sda", f"A{pin_sda}",
        "scan"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    devices = []
    for line in result.stdout.splitlines():
        m = re.search(r'0x([0-9a-fA-F]{2})', line)
        if m:
            addr = int(m.group(1), 16)
            device_type = "Unknown"
            for addr_range, desc in KNOWN_DEVICES.items():
                if addr in addr_range:
                    device_type = desc
                    break
            devices.append({"address": hex(addr), "type": device_type})

    return devices

devices = i2c_enumerate()
for d in devices:
    print(f"  {d['address']}: {d['type']}")
```

---

## Phase 2: EEPROM read/write

### AT24C series (most common)

```bash
# Read full EEPROM (e.g. AT24C02 = 256 bytes at 0x50)
glasgow run memory-24x --voltage 3.3 --scl A0 --sda A1 --i2c-address 0x50 read eeprom.bin

# AT24C16 (multiple address pages: 0x50-0x57)
for addr in 50 51 52 53 54 55 56 57; do
  glasgow run memory-24x --voltage 3.3 --scl A0 --sda A1 \
    --i2c-address 0x$addr read eeprom-page-$addr.bin
done
cat eeprom-page-*.bin > eeprom-full.bin

# Write EEPROM
glasgow run memory-24x --voltage 3.3 --scl A0 --sda A1 --i2c-address 0x50 write new-eeprom.bin
```

### Parse EEPROM contents

```python
from pathlib import Path

def parse_eeprom(path: str) -> dict:
    """Attempt to identify EEPROM content structure."""
    data = Path(path).read_bytes()

    findings = {
        "size_bytes": len(data),
        "strings": [],
        "possible_mac": [],
        "possible_keys": [],
        "all_ff": data.count(0xFF) == len(data),
    }

    # Extract printable strings
    current = []
    for b in data:
        if 0x20 <= b < 0x7F:
            current.append(chr(b))
        else:
            if len(current) >= 4:
                findings["strings"].append("".join(current))
            current = []

    # Find possible MAC addresses (6-byte sequences not all 0 or FF)
    for i in range(len(data) - 5):
        chunk = data[i:i+6]
        if chunk != b'\xff\xff\xff\xff\xff\xff' and chunk != b'\x00\x00\x00\x00\x00\x00':
            # Check if it looks like a MAC (first byte multicast bit = 0)
            if chunk[0] & 1 == 0:
                mac = ":".join(f"{b:02x}" for b in chunk)
                findings["possible_mac"].append({"offset": hex(i), "mac": mac})

    return findings

result = parse_eeprom("eeprom.bin")
print(f"Strings: {result['strings']}")
print(f"Possible MACs: {result['possible_mac']}")
```

---

## Phase 3: Crypto/secure element attacks

### Microchip ATECC508A / ATECC608A

Secure elements store keys in tamper-resistant hardware. Common in:
- IoT devices with PKI
- Authentication tokens
- Embedded TLS clients

```bash
# Enumerate via I2C (default address 0x60) — use Python API for raw read
# i2c-controller CLI only has 'scan' subcommand; use Python API for arbitrary reads
# See Phase 4 for Python-based device interaction

# The ATECC responds with 4-byte info:
# First byte = chip revision
```

```python
# Read ATECC configuration zone
# Configuration zone is readable without auth on most devices
def read_atecc_config(pin_scl: int = 0, pin_sda: int = 1) -> bytes:
    """
    Read ATECC508A/608A configuration zone (88 bytes).
    This reveals slot configurations, key types, and access policies.
    """
    import subprocess

    # CRC-16 calculation (ATECC uses custom CRC)
    def crc16_atecc(data: bytes) -> int:
        crc = 0
        for b in data:
            for _ in range(8):
                if (crc ^ b) & 1:
                    crc = (crc >> 1) ^ 0x8005
                else:
                    crc >>= 1
                b >>= 1
        return crc

    # Build Read command for config zone
    # This requires raw I2C interaction — use glasgow i2c-controller
    # ATECC command format: count, opcode, param1, param2_lsb, param2_msb, CRC16
    read_config_cmd = bytes([
        0x07,     # count
        0x02,     # opcode: Read
        0x80,     # param1: 32-byte read, config zone
        0x00, 0x00,  # param2: address 0
    ])

    # CRC over command bytes
    crc = crc16_atecc(read_config_cmd)
    read_config_cmd += bytes([crc & 0xFF, (crc >> 8) & 0xFF])

    print("[*] ATECC config zone read requires raw I2C sequence")
    print("[*] Use cryptoauthlib Python library for full ATECC interaction:")
    print("    pip install cryptoauthlib")
    print("    python3 -c \"from cryptoauthlib import *; cfg = cfg_ateccx08a_i2c_default(0xC0); atcab_init(cfg); print('Connected')\"")

    return read_config_cmd
```

---

## Phase 4: I2C fuzzing

Test I2C devices for unexpected behaviour:

```python
import subprocess
import time

def fuzz_i2c_device(address: int, voltage: float = 3.3,
                     pin_scl: int = 0, pin_sda: int = 1):
    """
    Send random commands to an I2C device and observe behaviour.
    Documents unexpected ACKs, hangs, or power changes.
    """
    import random

    print(f"[*] Fuzzing I2C device at {hex(address)}")

    for i in range(256):
        payload = bytes([i])  # Single-byte register addresses
        # i2c-controller CLI only has 'scan'. For write/read use the Python API:
        # from glasgow.applet.interface.i2c_controller import I2CControllerInterface
        # Use I2CControllerInterface.write() then .read() in a transaction() context
        # For subprocess-based fuzzing, use smbus2 or i2ctransfer (Linux i2c-tools):
        cmd = [
            "i2ctransfer", "-y", "1",
            f"w1@{hex(address)}", hex(i),
            f"r1@{hex(address)}"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            print(f"  Reg {hex(i)}: ACK, response: {result.stdout.strip()}")
        time.sleep(0.01)
```

---

## I2C EEPROM write-attack vectors

### MAC address spoofing

Many devices store their MAC address in I2C EEPROM:

```bash
# Read EEPROM to find MAC
strings eeprom.bin | grep -E '([0-9a-f]{2}:){5}[0-9a-f]{2}'

# If found, create modified EEPROM with different MAC
python3 -c "
data = bytearray(open('eeprom.bin','rb').read())
# Assuming MAC at offset 0x10:
data[0x10:0x16] = bytes.fromhex('deadbeefcafe')
open('eeprom-patched.bin','wb').write(data)
"
glasgow run memory-24x --voltage 3.3 --scl A0 --sda A1 --i2c-address 0x50 write eeprom-patched.bin
```

### License/serial spoofing

Configuration EEPROMs often store device serial numbers, license keys, or feature flags:

```bash
# Dump, analyse, look for flags
binwalk eeprom.bin
strings -n 4 eeprom.bin

# If license check logic found in firmware, cross-reference offset in EEPROM
```

---

## Output artefacts

```
i2c/
├── bus-scan.txt         # Device addresses found
├── eeprom-0x50.bin      # EEPROM dump per address
├── eeprom-analysis.json # Parsed EEPROM contents
└── fuzz-results.txt     # Fuzzing responses (if run)
```
