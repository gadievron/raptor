---
description: Firmware security scan — ELF inventory, arch detection, firmware Semgrep rules over an extracted root
dispatch: skill
---

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
python3 raptor.py scan --firmware-root <extracted_root>/
```

The run lifecycle resolves the output directory (project dir or
`out/scan_<root>_<run>/`) and prints it.

Add `--arch` if known (skips ELF header detection):
```bash
python3 raptor.py scan --firmware-root <extracted_root>/ --arch mips --kernel-version 6.6
```

### Step 3 — Read and present the inventory

Read `firmware-inventory.json` from the run output directory.

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

**Injection group** — command-injection patterns in the languages it
covers (C/C++, Go, Java, JavaScript/TypeScript, PHP, Python — e.g.
LuCI web UI JavaScript)

**Secrets group** — hardcoded API keys/credentials in source and config
text

There are no shell-script or Lua rules in the default set, and nothing
flags shadow/passwd files mechanically — check `etc/` by hand (it's
listed in the inventory step).

### Step 5 — Offer next steps

For a full autonomous pass (scan → dedup → LLM analysis with
high-value targets prioritized):
```bash
python3 raptor.py agentic --firmware-root <extracted_root>/
```

For known-CVE exposure of the shipped components (busybox, dropbear,
openssl, ... — versions extracted from the ELF binaries themselves and
checked against OSV's Debian advisory shard):
```bash
python3 raptor.py sca <extracted_root>/ --firmware-elf
```

For each high-value finding:
- Load `firmware-extraction` skill for manual binary triage
- For identified CGI binaries and daemons: `/binary investigate <path>`
  (black-box investigation), or `/ghidra` for decompilation
- For credential findings: suggest `strings`-based deeper search
- For shadow/passwd: extract and attempt to crack hashes

```bash
# Black-box investigation of a specific target
python3 raptor.py binary investigate <extracted_root>/usr/sbin/uhttpd
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
the scan still covers interpreted content the rule languages reach (e.g. LuCI JavaScript);
shell scripts and Lua have no rules today. For binary-level analysis of compiled ELFs,
use `/binary` (investigation) or `/ghidra` (decompilation).

## Output

All output goes to the run output directory (project dir or `out/scan_<root>_<run>/`)
- `firmware-inventory.json` — all ELF binaries, arch, size, interest score
- `scan-manifest.json` — scan parameters including arch and kernel version
- `combined.sarif` — merged findings from all Semgrep rules (per-pack
  SARIFs are cleaned up after the merge; filter combined results by
  `raptor.firmware.*` rule IDs for the firmware-specific subset)

For defensive security research, education, and authorised firmware analysis.
