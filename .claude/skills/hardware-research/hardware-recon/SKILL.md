---
name: hardware-recon
description: Physical reconnaissance of hardware targets. Identify chips, debug interfaces, test points, and communication buses from PCB inspection before any active probing.
---

# Hardware Recon Skill

**Do not touch the board with active tools until you understand what you are looking at.**

Physical reconnaissance first. Read the board, then probe it. You are a detective, not a brute-force hacker. Take your time to understand the layout, components, and potential attack surface before connecting any tools. This is the foundation of all hardware hacking — without it, you are flying blind. Think of yourself as Joe Grand, the master of hardware reverse engineering. Be methodical, be patient, be observant. The board will tell you its secrets if you listen and look carefully. Only then should you start probing with your Glasgow, logic analyser, and multimeter. If you don't understand, ask the human for help. Don't guess. Don't risk damaging the board. Be the master of hardware recon.

---

## Phase 1: Visual Inspection

### What to photograph

Take high-resolution photographs before any probing:
- Top and bottom of PCB (full board)
- Every IC in detail (read all markings)
- All headers, connectors, test pads
- Power input and USB/serial ports
- Any labelled debug pads (JTAG, SWD, UART, GND, VCC)

### What to note

```
Board markings:     PCB revision, manufacturer, date code
Power rails:        3.3V, 5V, 1.8V regulators visible?
Main processor:     Part number, package type
Flash storage:      SPI flash (8-pin SOIC common), eMMC, NAND
Debug headers:      Through-hole unpopulated headers (prime targets)
Test pads:          Labelled TP01, TP02 etc. on silkscreen
Crystal/oscillator: Frequency (useful for fault injection timing)
```

---

## Phase 2: IC Identification

### Primary target chips

For every IC on the board, search the part number. Priority order:

1. **Main SoC / CPU** - Defines architecture, JTAG variant, debug capabilities
2. **Flash storage** - SPI NOR (firmware), eMMC (OS), SPI NAND (filesystem)
3. **EEPROM** - Config data, keys, certificates (I2C typically)
4. **Secure element / TPM** - Certificate storage, crypto operations
5. **Power management IC (PMIC)** - Voltage rails — needed for glitching

### How to read obscured markings

```bash
# If markings are laser-removed, try:
# 1. Angled lighting / oblique illumination
# 2. UV light (some markings fluoresce)
# 3. Identify package, pin count, adjacent chip context
# 4. Cross-reference board photos with FCC filings (if product has FCC ID)

# Look up FCC IDs:
# https://fccid.io/<FCC-ID-HERE>
# These often contain internal photos with component lists
```

---

## Phase 3: Debug Interface Discovery

### UART hunting

Most common — look for:
- 4-pin headers (VCC, GND, TX, RX) near the SoC
- Test pads in corners or near serial-number labels
- Unpopulated headers with 2.54mm pitch
- Pads labelled TX, RX, CON, DEBUG, UART, J1, J2

```bash
# Confirm TX pin with multimeter / logic analyser:
# - TX idles HIGH (~3.3V or 1.8V)
# - When booting: shows pulses (data being sent)
# Use logic analyser to find baud rate, or try:
glasgow uart auto-baud --pins TX=<pin>
```

### JTAG / SWD hunting

Look for:
- 10-pin or 20-pin unpopulated headers (ARM JTAG standard pinouts)
- 4-pin SWD header (SWDIO, SWDCLK, GND, VCC)
- Pads labelled TCK, TDI, TDO, TMS (JTAG) or SWDIO, SWDCLK (SWD)
- Some boards label these as J_TCK, JCLK, or similar

```bash
# Use JTAGulator approach with Glasgow:
# Load jtag-exploitation skill for active enumeration
```

### SPI flash identification

8-pin SOIC or WSON packages, usually near the SoC:
- Common parts: W25Q series (Winbond), MX25L series (Macronix), GD25Q (GigaDevice)
- Check datasheet for pinout (CS, CLK, SI, SO, WP, HOLD, VCC, GND)
- Note voltage: 1.8V or 3.3V — critical for Glasgow voltage selection

### I2C EEPROM identification

Small 8-pin packages:
- Common: AT24C series (Atmel/Microchip), 24LC series (Microchip)
- SDA and SCL lines, device address set by A0/A1/A2 pins
- Often stores MAC address, config, crypto material

---

## Phase 4: Build a target map

Create `recon/target-map.md` with this structure:

```markdown
# Target Map: <device name>

## Board
- PCB rev: X.X
- Voltages: 3.3V main, 1.8V flash

## ICs
| Ref | Part | Package | Interface | Notes |
|-----|------|---------|-----------|-------|
| U1  | BCM2837 | BGA | JTAG/SWD, UART | Main SoC |
| U2  | W25Q128JV | SOIC-8 | SPI | 128Mbit NOR Flash |
| U3  | AT24C02 | SOIC-8 | I2C (0x50) | Config EEPROM |

## Debug Interfaces
| Interface | Location | Pinout | Voltage | Status |
|-----------|----------|--------|---------|--------|
| UART | J1 (4-pin header) | 1=VCC 2=TX 3=RX 4=GND | 3.3V | Active |
| JTAG | TP3-TP7 (test pads) | TCK=TP3 TDI=TP4 TDO=TP5 TMS=TP6 GND=TP7 | 3.3V | Unverified |
| SPI Flash | U2 direct | SOIC-8 standard | 3.3V | In-circuit |

## Attack surface
- UART console visible on boot (confirmed)
- SPI flash accessible in-circuit
- JTAG interface present, lock status unknown
```

---

## Tools and setup

```bash
# Glasgow for active probing
glasgow identify

# Logic analyser (to sniff before active probing)
# PulseView / sigrok with Glasgow logic applet:
glasgow logic --pins 0,1,2,3 --capture-size 10M --out logic-capture.vcd

# Multimeter for:
# - Continuity (find GND)
# - DC voltage (confirm rail voltages)
# - Diode mode (identify test pad connections without power)
```

---

## Safety notes

- Always check voltage before connecting Glasgow — 1.8V devices will be damaged by 3.3V
- Short GND between Glasgow and target before any other connection
- In-circuit probing of SPI flash: the SoC may hold CS or CLK lines — may need to hold CPU in reset
- Never probe a device under power that you cannot risk damaging
