# /firmware - RAPTOR Firmware Security Scan

Firmware analysis mode. Takes an extracted firmware filesystem root and runs
hardware-aware static analysis: ELF inventory, architecture detection, and
firmware-specific Semgrep rules.

## On invocation

### Step 1 — Identify the firmware root

Ask the user: what is the path to the extracted firmware root?

If they have a raw binary (`.bin`), extract it first:
```bash
binwalk -Me firmware.bin
# Extracted root will be at _firmware.bin.extracted/
```

If `binwalk` fails to extract the SquashFS (sasquatch missing), carve and use `unsquashfs`:
```bash
binwalk firmware.bin                          # find SquashFS offset
dd if=firmware.bin bs=1 skip=<OFFSET> of=squashfs.sqsh
unsquashfs -d extracted/ squashfs.sqsh
```

### Step 2 — Run the firmware scan

```bash
TIMESTAMP=$(date +%s)
python3 raptor.py scan \
  --firmware-root <extracted_root>/ \
  --output .out/firmware-$TIMESTAMP/
```

Add `--arch` if known (skips ELF header detection):
```bash
python3 raptor.py scan \
  --firmware-root <extracted_root>/ \
  --arch mips \
  --kernel-version 6.6 \
  --output .out/firmware-$TIMESTAMP/
```

### Step 3 — Read and present the inventory

Read `.out/firmware-$TIMESTAMP/firmware-inventory.json`.

Present as a table:

| Binary | Arch | Size | Interest |
|--------|------|------|----------|
| usr/sbin/uhttpd | mips | 66 KB | High |
| www/cgi-bin/cgi-exec | mips | 65 KB | High |
| usr/sbin/dropbear | mips | 258 KB | High |

Show detected architecture and total ELF count.

### Step 4 — Summarise findings by category

From the SARIF results, group findings:

**Firmware-specific rules** (`raptor.firmware.*`):
- Dangerous C functions: `gets`, `sprintf`, `strcpy`, `system`, `popen`
- CGI injection: `getenv(QUERY_STRING)` → shell execution
- Hardcoded credentials: `strcmp(pass, "literal")`, default creds

**Shell/script findings** — IFS tampering, unquoted variables in init scripts

**Web UI findings** — LuCI/JavaScript: `innerHTML`, `eval`, prototype pollution

**Secrets** — shadow/passwd files present in firmware image

### Step 5 — Offer next steps

For each high-value finding:
- Load `firmware-extraction` skill for manual binary triage
- For identified CGI binaries: suggest Ghidra analysis (load `ghidra-headless` skill)
- For credential findings: suggest `strings`-based deeper search
- For shadow/passwd: extract and attempt to crack hashes

```bash
# Deeper binary analysis of a specific target
python3 -c "
from packages.exploit_feasibility.api import analyze_binary, format_analysis_summary
result = analyze_binary('<extracted_root>/usr/sbin/uhttpd')
print(format_analysis_summary(result, verbose=True))
"
```

---

## Usage

```
/firmware                              # Interactive guided session
/firmware --root <extracted_path>      # With known extraction path
/firmware --binary <binary_path>       # Focus on a specific ELF
```

## What the firmware rules cover

Rules in `engine/semgrep/rules/firmware/` (C/C++ source only — not compiled binaries):

| File | Rules |
|------|-------|
| `dangerous-functions.yaml` | `gets`, unbounded `scanf`/`sprintf`, `strcpy`/`strcat`, `system`/`popen` |
| `cgi-injection.yaml` | `getenv("QUERY_STRING")`/`HTTP_*` taint → `system`/`popen`/`sprintf`/`strcpy` |
| `hardcoded-creds.yaml` | `strcmp(pass, literal)`, hardcoded assignments, default credentials |

**Note:** These rules fire on C source code. For compiled MIPS/ARM firmware without source,
the scan will still find issues in shell scripts, Lua, and JavaScript (e.g. LuCI web UI).
For binary-level analysis of compiled ELFs, use the `ghidra-headless` skill.

## Output

All output goes to `.out/firmware-<timestamp>/`
- `firmware-inventory.json` — all ELF binaries, arch, size, interest score
- `scan-manifest.json` — scan parameters including arch and kernel version
- `combined.sarif` — merged findings from all Semgrep rules
- `semgrep_category_firmware.sarif` — firmware-specific rule results

For defensive security research, education, and authorised firmware analysis.
