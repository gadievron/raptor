# Hardware Security Gap Analysis

What raptor currently does well, what is missing, and what needs to be built to make it a first-class hardware exploitation platform.

---

## What exists today

Raptor is a strong software security platform:

| Capability | Status |
|-----------|--------|
| Static code analysis (Semgrep) | Solid |
| CodeQL dataflow analysis | Solid |
| Binary exploitation feasibility | Solid |
| Fuzzing (AFL++) | Solid |
| Web application scanning | Solid |
| LLM-assisted analysis | Solid |
| Crash root-cause analysis | Solid |
| Exploit PoC generation | Beta |
| Secure patch generation | Beta |

**Hardware coverage: None.** Everything above assumes you already have code or a binary running in a normal environment. Hardware targets require getting to that point first.

---

## What the hardware skills provide (this branch)

The skills added in `hardware-phun` provide **methodology and Glasgow API patterns**. They tell you *what to do* and give you copy-paste commands.

The following have since been built and integrated:
- `packages/hardware/` — automated enumeration pipeline (UART, SPI, I2C, JTAG, passive VCD)
- `raptor.py hardware` mode — registered CLI entry point
- `.claude/commands/hardware.md` — guided `/hardware` session workflow

The following are not yet provided:
- Hardware-aware firmware scan mode (`--firmware-root`)
- Autonomous hardware agent (end-to-end, no prompts)
- ARM/MIPS support in `exploit_feasibility`

---

## Gap 1: No hardware enumeration pipeline

**Status: Resolved.**

`packages/hardware/enumerator.py` implements `HardwareEnumerator` and is registered in `raptor.py` as `mode_hardware`. The 5-stage pipeline:

1. Glasgow device check (`glasgow list`)
2. Passive logic capture (VCD — user power-cycles target during window)
3. I2C scan (adjacent pin pairs, safe ACK probing)
4. SPI flash detection (4-pin groups, JEDEC identify across 6 role orderings)
5. UART detection (active pins × common baud rates, printable byte scoring)
6. JTAG brute-force (opt-in via `--jtag`, 5-10 min)

Output: `hardware-report.json` with findings, active pins, confidence levels, and copy-paste next-step commands.

```bash
# Usage
python3 raptor.py hardware --voltage 3.3 --pins 0-7
python3 raptor.py hardware --voltage 1.8 --pins 0-3 --jtag
python3 raptor.py hardware --skip-passive --out /tmp/target/
```

---

## Gap 2: No firmware analysis integration path

**Status: Resolved.**

`packages/static-analysis/scanner.py` now accepts `--firmware-root` as a mutually-exclusive alternative to `--repo`. When used, it activates firmware scan mode:

1. **ELF inventory** — walks the extracted root, detects architecture from ELF `e_machine` header, scores binaries by name (`httpd`, `cgi`, daemons score 10), writes `firmware-inventory.json`
2. **Auto-arch detection** — if `--arch auto` (default), the most common `e_machine` across all ELFs is used; overridable with `--arch arm|mips|x86_64|aarch64|...`
3. **Firmware-aware Semgrep rules** — new `firmware` policy group in `engine/semgrep/rules/firmware/`:
   - `dangerous-functions.yaml` — `gets()`, unbounded `scanf`/`sprintf`, `strcpy`/`strcat`, `system()`/`popen()`
   - `cgi-injection.yaml` — taint from `getenv("QUERY_STRING")` / `HTTP_*` → `system()`/`popen()`/`sprintf()`/`strcpy()`
   - `hardcoded-creds.yaml` — `strcmp(pass, "literal")`, hardcoded password assignments, default credentials
4. **Default policy groups** — `firmware,injection,secrets` (instead of `crypto`) when `--firmware-root` is used
5. **Manifest fields** — `firmware_mode: true`, `arch`, `kernel_version` recorded in `scan-manifest.json`
6. **`--output PATH`** — explicit output directory flag (previously always auto-generated)

```bash
# Basic firmware scan after binwalk extraction
python3 raptor.py scan --firmware-root _firmware.bin.extracted/ \
  --arch arm --kernel-version 4.14 \
  --output .out/firmware-$(date +%s)/

# Auto-detect architecture
python3 raptor.py scan --firmware-root _firmware.bin.extracted/

# Add general injection rules on top
python3 raptor.py scan --firmware-root _firmware.bin.extracted/ \
  --policy_groups firmware,injection,secrets,auth
```

**What is still missing:**
- CVE cross-reference against identified SoC/kernel version (needs external CVE DB — high effort)

---

## Gap 3: Native Glasgow glitch applet (partially addressed)

**Status:** ChipWhisperer integration is now covered by `.claude/skills/hardware-research/chipwhisperer/SKILL.md`. This skill provides full CW-Lite/Pro/Husky Python API for voltage glitching, clock glitching, power trace capture, and CPA.

**What is still missing:**
- A native Glasgow Amaranth applet for glitching (would allow single-device workflows)
- Glasgow's GPIO is not fast enough for sub-microsecond glitches — CW is required for ns precision

**Current tool choice:**
- Sub-microsecond precision → ChipWhisperer-Lite (load `chipwhisperer` skill)
- Budget/experimentation → Glasgow GPIO + MOSFET (described in `fault-injection` skill)
- EMFI → ChipSHOUTER (also documented in `fault-injection` skill)

**Remaining effort:** A custom Glasgow Amaranth glitch applet would be high effort. The CW integration covers the practical need.

---

## Gap 4: No side-channel analysis capability

**What is missing:** Power Analysis (PA) and Electromagnetic Analysis (EMA) require:
- Hardware: oscilloscope with differential probe, or dedicated tool (ChipWhisperer, Riscure)
- Software: signal processing (numpy/scipy), leakage models, correlation
- Expertise: understanding of Hamming weight models, correlation power analysis (CPA)

Raptor has no hooks for this at all.

**Effort:** High. Specialised domain requiring dedicated Python package.

**Proposed:**
- Add `packages/side-channel/` with CPA implementation
- Add a `side-channel` skill for methodology
- Integrate with ChipWhisperer Jupyter workflows

---

## Gap 5: No binary analysis for embedded architectures

**What is missing:** The existing `exploit_feasibility` package is x86/x86_64-focused. Embedded targets are typically:
- ARM Cortex-M (bare-metal, no ASLR, no NX in older parts)
- ARM Cortex-A (Linux, ASLR may be disabled)
- MIPS (big endian, different ROP gadget landscape)
- RISC-V (emerging)

**Issues:**
- `checksec` checks don't apply the same way to bare-metal firmware
- ROP gadget density and usability differs significantly by architecture
- Heap exploitation on uClib/musl/newlib is different from glibc

**Effort:** Medium-High. Needs architecture-aware analysis in `exploit_feasibility`.

**Proposed:**
```python
# Extended exploit_feasibility for embedded targets
result = analyze_binary(
    path='firmware-httpd',
    arch='arm',
    embedded=True,
    libc='uclibc'
)
```

---

## Gap 6: No hardware-aware Ghidra integration

**What exists:** The `ghidra-headless` skill does Ghidra analysis, but:
- Does not auto-detect embedded architectures from firmware
- Does not cross-reference MMIO addresses with SoC register maps
- Does not identify ROM functions using known ROM hashes (common in Cortex-M)

**Effort:** Medium. Ghidra supports all the above via scripting — needs raptor integration.

**Proposed:**
- Glasgow device IDCODE → SoC identification → load correct Ghidra SVD file (memory map)
- Auto-run ROM hash matching against known Cortex-M ROM databases

---

## Gap 7: No `/hardware` command or agent

**Status: Partially resolved.**

`.claude/commands/hardware.md` exists and provides a full guided session workflow:
- Loads `hardware_security_researcher` persona and hardware skills
- Checks Glasgow device on invocation
- Gathers voltage and pin info from user
- Runs `python3 raptor.py hardware` enumeration pipeline
- Reads `hardware-report.json` and presents findings as a table
- Offers per-protocol next steps (SPI extract, UART console, I2C read, JTAG debug)
- Hands off to raptor scan after firmware extraction

**What is still missing:** A `hardware-agent.md` — an autonomous agent variant that runs the full workflow end-to-end without interactive prompts, analogous to `/agentic` for software. This would allow hands-off: enumerate → extract → analyse → report.

**Remaining effort:** Low — primarily orchestration markdown.

---

## Gap 8: No test data for hardware skills

**What exists:** `test/data/` has software-focused test cases (XSS, SQL injection).

**What is missing:** Hardware test fixtures:
- Sample SPI flash dumps (from public firmware releases)
- Sample UART boot logs (from known devices)
- Sample JTAG scan output (for parser testing)
- Known-bad firmware images (for analysis pipeline testing)

**Effort:** Low — collect from public sources (OpenWRT builds, vendor sites).

---

## Recommended build order

Priority based on value vs. effort:

| Priority | Item | Effort | Value | Status |
|---------|------|--------|-------|--------|
| 1 | `/hardware` command | Low | High | **Done** (`.claude/commands/hardware.md`) |
| 2 | Hardware enumeration Python package | Medium | High | **Done** (`packages/hardware/`) |
| 3 | ChipWhisperer integration skill | Low | Medium | **Done** (`chipwhisperer` skill) |
| 4 | `/hardware` autonomous agent | Low | High | Pending (`hardware-agent.md`) |
| 5 | Firmware-aware scan mode | Medium | High | **Done** (`--firmware-root`, `rules/firmware/`) |
| 6 | ARM/MIPS exploit_feasibility support | High | Medium | Pending |
| 7 | Custom Glasgow glitch applet | High | High | Partially addressed by CW skill |
| 8 | Side-channel analysis package | High | Medium | Pending |
| 9 | Ghidra hardware-aware integration | Medium | Medium | Pending |
| 10 | Hardware test fixtures | Low | Medium | Pending |

---

## What the skills cover vs. what they assume

The skills added in this branch assume you have:
- A Glasgow device (or can use equivalent tools)
- Physical access to the target
- Basic multimeter and logic analyser

The skills do not require:
- ChipWhisperer (fault injection skill notes this is a gap)
- Oscilloscope (side-channel is noted as a gap)
- Rework station (chip-off noted as last resort)

This is an intentional choice — the Glasgow covers 80% of hardware attack surface. The remaining 20% (glitching, side-channel, decap) is captured in the gap analysis for future development.
