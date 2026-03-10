---
name: hardware-security
description: Hardware security research and exploitation using Glasgow Interface Explorer and complementary tools. Covers physical recon, protocol analysis, firmware extraction, fault injection, and side-channel attacks.
---

# Hardware Security Skill

Methodology for hardware security research — PCB reconnaissance through firmware extraction to exploitation. Built around the Glasgow Interface Explorer Python API with supplementary tooling.

## Philosophy

Hardware is the last line of defense. When software controls fail, you go lower. 
As Joe Fitz once said "the idea of hardware is to get the hell out of there and into software as quickly as possible"

The best approach for this is the bottom-up way:
```
Physical layer  → identify interfaces, chips, test points
Protocol layer  → sniff, replay, inject on JTAG/SPI/I2C/UART
Firmware layer  → extract, unpack, analyse
Logic layer     → fault inject to bypass checks
```

This mirrors the methodology used by Joe Grand (hardware reverse engineering) and Joe FitzPatrick (embedded systems security) — understand the board before touching it, then enumerate, then extract, then break.

## Skills in this directory

| Skill | Purpose | Key practitioners |
|-------|---------|-------------------|
| `hardware-recon` | PCB photography, chip ID, test point mapping | Joe Grand |
| `glasgow-interaction` | Glasgow Python API patterns and applet usage | Glasgow project |
| `jtag-exploitation` | JTAG enumeration, boundary scan, chain identification | Joe Grand, Joe FitzPatrick |
| `swd-exploitation` | ARM SWD — DAP/AP traversal, CoreSight, memory extraction, vendor protections (STM32 RDP, nRF52 APPROTECT, LPC CRP), bypass techniques | Joe Grand, Joe FitzPatrick |
| `uart-exploitation` | UART discovery, baud detection, console exploitation | Joe FitzPatrick |
| `spi-flash-extraction` | SPI/QSPI flash dump, verify, and diff workflows | Joe FitzPatrick |
| `i2c-enumeration` | I2C bus scan, EEPROM read/write, device attacks | Joe FitzPatrick |
| `fault-injection` | Voltage/clock glitching, EMFI — methodology | Thomas Roth (Stacksmashing), Colin O'Flynn |
| `chipwhisperer` | CW-Lite/Pro/Husky API — voltage glitch, clock glitch, CPA | Colin O'Flynn (NewAE Technology) |
| `firmware-extraction` | Firmware recovery pipeline and analysis kickoff | Halvar Flake |

## When to load which skill

```
Target in hand, unknown board       → load hardware-recon
Have JTAG pinout (4-wire)            → load jtag-exploitation
Have SWD pinout (2-wire, ARM)        → load swd-exploitation
UART shell or bootloader visible    → load uart-exploitation
SPI flash identified on board       → load spi-flash-extraction
I2C devices visible on bus          → load i2c-enumeration
Need to bypass secure boot / checks → load fault-injection, then chipwhisperer
Have ChipWhisperer hardware         → load chipwhisperer directly
Have firmware blob                  → load firmware-extraction
Any Glasgow interaction             → load glasgow-interaction first
```

## Prerequisites

```bash
# Glasgow Interface Explorer
pip install glasgow

# Supporting tools (Linux - which really is the best approach when messing with hardware).
pip install binwalk pyserial pwntools
apt install openocd flashrom stlink-tools
# macOS (YMMV using this platform) 
brew install open-ocd flashrom stlink

# Verify Glasgow device attached
glasgow identify
```

## Output convention

All hardware session output goes to `.out/hardware-<timestamp>/`:
- `recon/` - photos, component list, board annotations
- `dumps/` - raw binary dumps from flash/EEPROM
- `protocols/` - captured bus traffic (VCD, logic analyser exports)
- `firmware/` - extracted and unpacked firmware
- `glitch-logs/` - fault injection attempt logs

## Notice

This skill is for authorised hardware security research and education.
