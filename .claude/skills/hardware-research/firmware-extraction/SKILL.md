---
name: firmware-extraction
description: Firmware recovery pipeline — from raw binary blob through unpacking, filesystem extraction, and handoff to raptor analysis tools. Covers SPI flash, NAND, eMMC, and OTA update sources.
---

# Firmware Extraction Skill

There is only one master for firmware extraction and that is the legend, the master, the uber-hacker Halvar Flake. This skill distills his approach to firmware recovery — a systematic pipeline for taking a raw binary blob (from SPI flash, NAND, eMMC, or OTA update) and turning it into analysable artefacts. The goal is to get from "just a binary" to "a filesystem I can explore and feed into raptor's analysis". This is the foundation of firmware security research — without it, you have nothing to analyse. Be methodical, be patient, be thorough. The firmware will give up its secrets if you treat it with respect and care. Only then will you succeed in extracting the firmware and finding the vulnerabilities within.

Once you have a raw binary from SPI flash, NAND, or any other source, this skill covers unpacking it into analysable artefacts and handing off to raptor's analysis pipeline.

---

## Acquisition sources

| Source | How extracted | Skill |
|--------|--------------|-------|
| SPI NOR flash | Glasgow memory-25x | spi-flash-extraction |
| I2C EEPROM | Glasgow memory-24x | i2c-enumeration |
| UART / TFTP over U-Boot | U-Boot tftp/nand read | uart-exploitation |
| NAND flash | Direct read or FTL tools | below |
| eMMC | DD over USB adapter or JTAG | below |
| OTA update file | Vendor website, packet capture | below |
| Physical chip | Chip-off with hot air | spi-flash-extraction |

---

## Phase 1: Initial triage

```bash
# What is this file?
file firmware.bin

# Entropy analysis (high entropy = encrypted/compressed)
binwalk -E firmware.bin
# Flat entropy = likely encrypted
# Variable entropy = likely compressed sections

# Quick strings scan
strings -n 8 firmware.bin | head -100
strings -n 8 firmware.bin | grep -iE "password|passwd|secret|key|admin|root|login"

# Check for known headers
binwalk firmware.bin
xxd firmware.bin | head -20
```

---

## Phase 2: Extraction

```bash
# Extract everything binwalk finds
binwalk -e firmware.bin

# Recursive extraction (handles nested archives)
binwalk -Me firmware.bin

# Force raw LZMA extraction (if binwalk misses it)
binwalk -e --run-as=root firmware.bin

# Jefferson for JFFS2 filesystems
pip install jefferson
jefferson firmware.bin -d jffs2-extracted/

# Unsquashfs for SquashFS
unsquashfs firmware.bin
# or from binwalk extraction:
unsquashfs _firmware.bin.extracted/squashfs-root.img

# ubi_reader for UBI/UBIFS (common on NAND)
pip install ubi_reader
ubireader_extract_files firmware.bin
```

---

## Phase 3: Filesystem analysis

```bash
# Once extracted, locate the filesystem root
find _firmware.bin.extracted/ -name "passwd" -o -name "shadow" 2>/dev/null
find _firmware.bin.extracted/ -name "*.conf" 2>/dev/null
find _firmware.bin.extracted/ -name "*.key" -o -name "*.pem" 2>/dev/null

# Look for web interfaces
find _firmware.bin.extracted/ -name "*.html" -o -name "*.php" -o -name "*.cgi" 2>/dev/null

# Identify all binaries
find _firmware.bin.extracted/ -type f -executable | head -50
file _firmware.bin.extracted/bin/* | grep -i elf
```

---

## Phase 4: Binary inventory

```python
import os
import subprocess
from pathlib import Path

def inventory_binaries(extracted_root: str) -> list[dict]:
    """
    Find all ELF binaries in extracted firmware.
    Returns sorted by size (largest = most interesting).
    """
    binaries = []
    root = Path(extracted_root)

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            magic = path.read_bytes()[:4]
        except Exception:
            continue

        if magic[:4] == b'\x7fELF':
            stat = path.stat()
            result = subprocess.run(["file", str(path)],
                                    capture_output=True, text=True)
            binaries.append({
                "path": str(path.relative_to(root)),
                "size_bytes": stat.st_size,
                "file_type": result.stdout.split(":", 1)[-1].strip(),
            })

    # Sort by size descending (larger = more functionality = more attack surface)
    return sorted(binaries, key=lambda x: x["size_bytes"], reverse=True)

binaries = inventory_binaries("_firmware.bin.extracted")
for b in binaries[:20]:
    print(f"  {b['size_bytes']:>10} bytes  {b['path']}")
    print(f"                   {b['file_type'][:80]}")
```

---

## Phase 5: Credential hunting

```bash
# Hash cracking targets
grep -r "root:" _firmware.bin.extracted/etc/ 2>/dev/null
grep -r "admin:" _firmware.bin.extracted/etc/ 2>/dev/null

# Common hash formats in embedded:
# MD5 crypt: $1$...
# SHA-256 crypt: $5$...
# DES crypt: 13-char string

# Crack with hashcat
hashcat -m 500 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt  # MD5 crypt

# Hardcoded credentials in binaries
strings -n 8 _firmware.bin.extracted/usr/sbin/httpd | grep -iE "admin|password|root|12345"

# SSL/TLS private keys
find _firmware.bin.extracted/ -name "*.key" -o -name "private*" | xargs -I{} head -2 {}
grep -r "BEGIN RSA PRIVATE KEY\|BEGIN PRIVATE KEY\|BEGIN EC PRIVATE KEY" _firmware.bin.extracted/ 2>/dev/null
```

---

## Phase 6: Hand off to raptor analysis

Once the filesystem is extracted, feed it into raptor's existing analysis pipeline:

```bash
# Static analysis on extracted filesystem
python3 raptor.py scan --path _firmware.bin.extracted/ --output .out/firmware-analysis-$(date +%s)/

# LLM analysis of interesting binaries
python3 raptor.py analyze --path _firmware.bin.extracted/usr/sbin/httpd

# If you have source (found in filesystem or OTA):
python3 raptor.py scan --path _firmware.bin.extracted/usr/share/www/ --output .out/firmware-web-$(date +%s)/

# For binary exploitation of specific ELF:
# Use exploit_feasibility package on identified target binary
python3 -c "
from packages.exploit_feasibility.api import analyze_binary, format_analysis_summary
result = analyze_binary('_firmware.bin.extracted/usr/sbin/httpd')
print(format_analysis_summary(result, verbose=True))
"
```

---

## NAND flash extraction

NAND is harder than NOR — requires FTL (Flash Translation Layer) handling:

```bash
# Dump raw NAND via Glasgow (if nand applet available)
glasgow run nand -V 3.3 --pins-io 0,1,2,3,4,5,6,7 --pins-ctrl 8,9,10 read nand-dump.bin

# Process with nanddump / nand tools
apt install mtd-utils
nandwrite /dev/mtd0 nand-dump.bin

# Or use binwalk directly on raw NAND dump
binwalk -Me nand-dump.bin

# YAFFS2 (common on NAND)
git clone https://github.com/dwrobel/yaffut
python3 unyaffs.py nand-dump.bin yaffs2-extracted/
```

---

## eMMC extraction

```bash
# Option 1: Connect eMMC module to USB via adapter
# eMMC to SD adapter → SD card reader → dd

dd if=/dev/mmcblk0 of=emmc-dump.bin bs=4M status=progress

# Option 2: Via JTAG — halt CPU, use JTAG memory map
# Find eMMC base address in datasheet, use GDB dump

# Option 3: Clip onto data lines (requires scope or logic analyser)
```

---

## OTA firmware acquisition

```bash
# Option 1: Man-in-the-middle OTA update traffic
# Set up transparent proxy, trigger update on device
mitmproxy -p 8080 --mode transparent
# Intercept binary download

# Option 2: Extract OTA URL from firmware
strings firmware.bin | grep -i "http.*update\|firmware.*download"

# Option 3: Vendor binaries on GitHub or website
# Search: site:github.com "firmware" <vendor_name>
# Check FCC filing internal photos for model number → search firmware
```

---

## Output artefacts

```
firmware-extraction/
├── firmware.bin                 # Original raw dump
├── binwalk-scan.txt             # Binwalk output
├── binwalk-entropy.png          # Entropy graph
├── _firmware.bin.extracted/     # All extracted files
├── binary-inventory.json        # ELF binary list
├── credential-hunt.txt          # Strings matching credential patterns
├── crypto-material.txt          # Keys/certs found
└── handoff-notes.md             # What to analyse next, raptor commands
```

---

## Encryption

If the firmware is encrypted (flat high entropy, no recognisable headers):

```
Approach 1: Find the decryption routine
  → Extract an older firmware (may be unencrypted)
  → Find the upgrade handler binary in the old firmware
  → Reverse it to find the key (static or derived)
  → Decrypt new firmware

Approach 2: Decrypt in memory
  → Get shell via UART
  → dd the running filesystem from /dev/mtd*
  → The running OS decrypts on mount

Approach 3: Fault inject the secure boot
  → Load fault-injection skill
  → Target the signature verification before decrypt

Approach 4: Find the key in the device
  → I2C EEPROM sometimes stores the firmware encryption key
  → JTAG memory dump from a running device
```
