# /hardware - RAPTOR Hardware Security Workflow

Hardware security research mode. Physical access to firmware — enumerate
interfaces, extract firmware, analyse with the full raptor pipeline.

## On invocation

Follow these steps in order:

### Step 1 — Load context
- Load `tiers/personas/hardware_security_researcher.md`
- Load `.claude/skills/hardware-research/SKILL.md`

### Step 2 — Check Glasgow
Run:
```bash
glasgow identify
```

**If glasgow is not found or returns an error:**
- Tell the user: `glasgow` binary not found or device not detected.
- Note: `pip install glasgow` installs a **placeholder** (version 0.0.0) — it does nothing.
- Direct them to the real installation: https://glasgow-embedded.org/latest/install.html
- Stop here until Glasgow is working.

**If glasgow responds:**
- Show the version and serial number.
- Continue to Step 3.

### Step 3 — Gather target info
Ask the user two questions (can be answered together):
1. **Voltage**: 3.3V or 1.8V? (default: 3.3V)
2. **Pins**: Which Glasgow pins are connected to the target? (default: 0-7)

Also ask: do you have a target description? (optional, for context)

### Step 4 — Run enumeration
Set `TIMESTAMP=$(date +%s)` and run:
```bash
python3 raptor.py hardware --voltage <V> --pins <PINS> --out .out/hardware-$TIMESTAMP/
```

Before running, tell the user:
> "Starting passive capture in Stage 1 — **please power-cycle your target now** when prompted."

Add `--jtag` if the user wants JTAG scanning (warn it takes 5-10 minutes).
Add `--skip-passive` if the target cannot be power-cycled.

### Step 5 — Read and present the report
Read `.out/hardware-<TIMESTAMP>/hardware-report.json`.

Present findings in a clean table:

| Protocol | Confidence | Pins | Notes |
|----------|------------|------|-------|
| uart     | High       | rx=1 | U-Boot @ 115200 |
| spi_flash | Confirmed | cs=0 sck=1 mosi=2 miso=3 | W25Q128JV (16MB) |

Show `active_pins` and `duration_seconds`.

### Step 6 — Offer next steps per finding

**SPI flash found:**
- Offer to extract immediately:
  ```bash
  glasgow run memory-25x -V3.3 --pins-cs <C> --pins-sck <K> --pins-mosi <O> --pins-miso <I> read flash.bin
  ```
- After extraction, run: `python3 raptor.py scan --path <extracted_root>`
- Load `spi-flash-extraction` skill for full workflow

**UART found:**
- Load `uart-exploitation` skill
- Guide interactive session: boot log analysis, U-Boot interrupt, shell escape
- If U-Boot detected, offer to attempt console:
  ```bash
  glasgow run uart -V3.3 --baud <BAUD> --pins-rx <PIN> --pins-tx <TX_PIN> console
  ```

**I2C found:**
- Load `i2c-enumeration` skill
- Offer to read EEPROM at detected addresses

**JTAG found:**
- Load `jtag-exploitation` skill
- Guide through debug access, CPU halt, memory extraction

**JTAG not scanned:**
- Ask: "JTAG was not scanned. Run JTAG brute-force? (adds ~5-10 minutes)"
- If yes, re-run with `--jtag` flag

### Step 7 — Firmware analysis (if extracted)
After any firmware extraction, unpack and hand off to raptor:
```bash
binwalk -Me flash.bin
python3 raptor.py scan \
  --firmware-root _flash.bin.extracted/ \
  --arch mips \
  --output .out/firmware-$TIMESTAMP/
```
This runs firmware-aware Semgrep rules (dangerous C functions, CGI injection, hardcoded creds)
and writes `firmware-inventory.json` listing all ELF binaries sorted by interest.

Then load `firmware-extraction` skill for manual triage and deeper binary analysis.

---

## Usage

```
/hardware                          # Interactive guided session
/hardware --target <description>   # With target context
/hardware --firmware <path>        # Skip extraction, analyse existing dump
/hardware --interface uart         # Focus on specific interface
/hardware --interface spi
/hardware --interface jtag
/hardware --interface i2c
```

## Prerequisites

- Glasgow Interface Explorer connected and detected (`glasgow identify`)
- Install from source — NOT via pip: https://glasgow-embedded.org/latest/install.html
- Physical access to target hardware
- Pin mapping from hardware-recon phase (or probe 0-7 to discover)

## Output

All output goes to `.out/hardware-<timestamp>/`
- `passive.vcd` — logic capture from power-cycle
- `uart-<pin>-<baud>.bin` — UART captures per pin/baud
- `hardware-report.json` — structured findings report

## Skills

Load as needed based on findings:
- `.claude/skills/hardware-research/hardware-recon/SKILL.md` — PCB inspection, chip ID
- `.claude/skills/hardware-research/uart-exploitation/SKILL.md` — UART/U-Boot/shell
- `.claude/skills/hardware-research/spi-flash-extraction/SKILL.md` — SPI read/write
- `.claude/skills/hardware-research/i2c-enumeration/SKILL.md` — I2C bus / EEPROM
- `.claude/skills/hardware-research/jtag-exploitation/SKILL.md` — JTAG debug access
- `.claude/skills/hardware-research/fault-injection/SKILL.md` — voltage/clock glitching
- `.claude/skills/hardware-research/firmware-extraction/SKILL.md` — unpack + raptor handoff

For defensive security research, education, and authorised hardware security assessments.
