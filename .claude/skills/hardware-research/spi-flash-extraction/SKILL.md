---
name: spi-flash-extraction
description: SPI and QSPI NOR flash identification, in-circuit and out-of-circuit extraction, verification, differential analysis between firmware versions, and write-back for patching.
---

# SPI Flash Extraction Skill

SPI NOR flash is used to store firmware on most embedded devices. Extracting it gives you the full firmware image for offline analysis.

Load `glasgow-interaction` skill for Glasgow command patterns.

---

## Common SPI flash chips

| Manufacturer | Series | Common parts | Capacity |
|-------------|--------|-------------|----------|
| Winbond | W25Q | W25Q64, W25Q128, W25Q256 | 8MB-32MB |
| Macronix | MX25L | MX25L64, MX25L128 | 8MB-16MB |
| GigaDevice | GD25Q | GD25Q64, GD25Q128 | 8MB-16MB |
| Micron | MT25Q | MT25QL128 | 16MB |
| Microchip/SST | SST25VF | SST25VF016B | 2MB |

All use the SPI protocol with JEDEC standard ID and command set.

---

## Phase 1: Chip identification

### Visual identification

SOIC-8 package: 8 pins, standard SOP footprint.

WSON-8: Flat no-lead package (harder to clip, needs rework station).

```
SOIC-8 standard pinout:
  1: CS#   (chip select, active low)
  2: SO/IO1 (MISO / data out)
  3: WP#   (write protect, pull high to disable)
  4: GND
  5: SI/IO0 (MOSI / data in)
  6: SCK   (serial clock)
  7: HOLD# (hold, pull high to disable)
  8: VCC   (3.3V or 1.8V)
```

```bash
# Identify chip via JEDEC ID
# --io takes 4 comma-separated pins in order: copi (MOSI), cipo (MISO), wp, hold
# Default Glasgow pinout (clockwise from pin 1 on SOIC-8):
#   --cs A5  --sck A1  --io A2,A4,A3,A0   (copi=A2, cipo=A4, wp=A3, hold=A0)
# Custom pinout example:
glasgow run memory-25x --voltage 3.3 --cs A5 --sck A1 --io A2,A4,A3,A0 identify

# Expected output:
# W25Q128JV: 128 Mbit (16 MiB), 3.3V
```

---

## Phase 2: Extraction approaches

### In-circuit reading (preferred — non-destructive)

The chip remains soldered. Glasgow connects directly to its pins.

**Challenge:** The SoC may still be driving the SPI bus. Strategies:

```bash
# Option A: Hold CPU in reset while reading
# Connect a GPIO pin to the RESET# pin of the SoC
glasgow run control-gpio --voltage 3.3 A4=0    # Assert reset (active low)
glasgow run memory-25x --voltage 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 read firmware.bin
glasgow run control-gpio --voltage 3.3 A4=1    # Release reset

# Option B: Power device down, connect chip power directly
# Use Glasgow to power just the flash (without the SoC)
# This isolates the SPI bus
```

**Wiring for in-circuit:**

```
Glasgow  →  SPI Flash
pin 0    →  CS#    (pin 1)
pin 1    →  SCK    (pin 6)
pin 2    →  MOSI   (pin 5)
pin 3    →  MISO   (pin 2)
VCC (via Glasgow -V 3.3) → VCC (pin 8)
GND      →  GND    (pin 4)
          → WP#    (pin 3) via 10k to VCC (disable write protect)
          → HOLD#  (pin 7) via 10k to VCC (disable hold)
```

### Out-of-circuit reading

If in-circuit fails, remove the chip and read it standalone.

```bash
# Use hot air rework station to remove SOIC-8
# Or SOIC-8 clip if you're lucky and there's clearance
# Connect via test socket or direct wiring

# Same Glasgow command, but cleaner bus:
glasgow run memory-25x -V 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 read firmware-oot.bin
```

### SOIC-8 clip (Pomona 5250 or equivalent)

```bash
# Clip directly onto chip without removing from board
# Requires good physical access and chip must be raised enough
# Check clip polarity (pin 1 marker)
```

---

## Phase 3: Verification and integrity

```bash
# Always read twice and compare
glasgow run memory-25x -V 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 read firmware-1.bin
glasgow run memory-25x -V 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 read firmware-2.bin

# Compare reads
md5sum firmware-1.bin firmware-2.bin
# They should be identical

# If not, check:
# - Loose connections
# - Device running (SoC interfering)
# - Speed too high (try lower SPI clock)
```

---

## Phase 4: Flash analysis

```python
import hashlib
from pathlib import Path

def analyse_flash(path: str) -> dict:
    """Basic analysis of a flash dump."""
    data = Path(path).read_bytes()
    size = len(data)

    # Check for all-0xFF (erased) or all-0x00
    ff_ratio = data.count(0xFF) / size
    zero_ratio = data.count(0x00) / size

    # Find partition table markers
    markers = {
        "squashfs": data.find(b'sqsh'),
        "jffs2": data.find(b'\x85\x19'),
        "ext2": data.find(b'\x53\xEF', 0x400),  # ext2 magic at offset 0x438
        "gzip": data.find(b'\x1f\x8b'),
        "lzma": data.find(b'\x5d\x00\x00'),
        "uimage": data.find(b'\x27\x05\x19\x56'),  # uImage magic
        "dtb": data.find(b'\xd0\x0d\xfe\xed'),    # Device tree blob
    }

    return {
        "path": path,
        "size_bytes": size,
        "size_mb": size / (1024*1024),
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "all_ff_ratio": f"{ff_ratio:.1%}",
        "all_zero_ratio": f"{zero_ratio:.1%}",
        "filesystem_markers": {k: hex(v) if v != -1 else "not found" for k, v in markers.items()},
        "likely_erased": ff_ratio > 0.9,
        "likely_encrypted": ff_ratio < 0.05 and zero_ratio < 0.05,
    }

# Example usage
result = analyse_flash("firmware.bin")
for k, v in result.items():
    print(f"  {k}: {v}")
```

```bash
# Automated firmware analysis with binwalk
binwalk firmware.bin

# Extract all components
binwalk -e firmware.bin

# Entropy analysis (high entropy = encrypted/compressed)
binwalk -E firmware.bin

# Find strings
strings -n 8 firmware.bin | grep -i "password\|user\|root\|admin\|key\|secret"
```

---

## Phase 5: Differential analysis (two firmware versions)

```python
import difflib
from pathlib import Path

def diff_firmware(fw_a: str, fw_b: str, chunk_size: int = 512) -> list[dict]:
    """
    Find differing blocks between two firmware images.
    Useful for: patch analysis, identifying changed code regions.
    """
    data_a = Path(fw_a).read_bytes()
    data_b = Path(fw_b).read_bytes()

    diffs = []
    min_len = min(len(data_a), len(data_b))

    i = 0
    while i < min_len:
        block_a = data_a[i:i+chunk_size]
        block_b = data_b[i:i+chunk_size]
        if block_a != block_b:
            diffs.append({
                "offset": hex(i),
                "a_bytes": block_a[:16].hex(),
                "b_bytes": block_b[:16].hex(),
            })
        i += chunk_size

    return diffs

# Example:
diffs = diff_firmware("firmware-v1.0.bin", "firmware-v1.1.bin")
print(f"[+] {len(diffs)} differing blocks found")
for d in diffs[:10]:
    print(f"  @ {d['offset']}: {d['a_bytes']} → {d['b_bytes']}")
```

---

## Phase 6: Patching and write-back

```bash
# Patch firmware image (example: null out a check)
python3 -c "
import sys
with open('firmware.bin', 'rb') as f:
    data = bytearray(f.read())

# Example: zero out bytes at offset 0x1234
offset = 0x1234
data[offset:offset+4] = b'\\x00\\x00\\x00\\x00'

with open('firmware-patched.bin', 'wb') as f:
    f.write(data)
print('Patched firmware written')
"

# Erase then program in one step (preferred)
glasgow run memory-25x --voltage 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 erase-program firmware-patched.bin

# Or erase chip first, then program separately
glasgow run memory-25x --voltage 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 erase-chip
glasgow run memory-25x --voltage 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 program firmware-patched.bin

# Verify write
glasgow run memory-25x --voltage 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 verify firmware-patched.bin
md5sum firmware-patched.bin firmware-verify.bin
```

---

## QSPI / Quad SPI

Some devices use Quad SPI for higher throughput (4 data lines vs 1):

```bash
# Glasgow memory-25x handles QSPI via the same --io flag with 4 pins
# copi=A2, cipo=A3, wp/io2=A4, hold/io3=A5
glasgow run memory-25x --voltage 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 read firmware-qspi.bin
# For true QSPI quad-mode reads, use fast-read subcommand:
glasgow run memory-25x --voltage 3.3 --cs A0 --sck A1 --io A2,A3,A4,A5 fast-read firmware-qspi.bin
```

---

## Output artefacts

```
spi-flash/
├── firmware-1.bin         # First read
├── firmware-2.bin         # Second read (verification)
├── analysis.json          # Flash analysis output
├── binwalk-output.txt     # Binwalk scan
├── _firmware.extracted/   # Binwalk extracted components
├── firmware-patched.bin   # Patched version (if applicable)
└── strings.txt            # Extracted strings
```

---

## Common issues

| Issue | Cause | Fix |
|-------|-------|-----|
| Reads all 0xFF | WP# or HOLD# floating | Pull both to VCC |
| Inconsistent reads | SoC on bus | Hold SoC in reset |
| JEDEC ID 0xFF 0xFF | CS not reaching chip | Check CS connection |
| Wrong flash size | Wrong chip series | Check -25x vs -26x applet |
| Write verify fails | WP# still asserted | Ground WP# to VCC during write |
