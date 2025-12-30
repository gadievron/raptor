# Exploit Development Instructions

## CRITICAL: Use Existing ExploitContext

Before attempting ANY exploit development, you MUST load the existing ExploitContext
from the mitigation analysis phase. DO NOT re-run reconnaissance commands.

### Load Context

```python
from packages.exploit_feasibility import FeasibilityReport, ExploitContext

# Option 1: Load full report
report = FeasibilityReport.load("out/context.json")
ctx = report.to_context()

# Option 2: Load just the context
ctx = FeasibilityReport.load_context("out/context.json")
```

### Query Data

```python
# Dot-path access
system_offset = ctx.get('libc.system_offset')
has_canary = ctx.get('binary.protections.canary')
full_relro = ctx.get('binary.protections.full_relro')
bad_bytes = ctx.get('payload.bad_bytes', [])

# Attribute access
if ctx.libc.hooks_available:
    hook_addr = ctx.libc.malloc_hook_offset

# Get all libc data
libc_data = ctx.get_section('libc')

# Check source of data
source = ctx.get_source('libc.system_offset')  # Returns 'nm -D libc'
```

## FORBIDDEN: Redundant Commands

The following commands have ALREADY been run during mitigation analysis.
DO NOT run them again:

| Command | Use Instead |
|---------|-------------|
| `checksec --file=binary` | `ctx.get('binary.protections.*')` |
| `readelf -d binary` | `ctx.get('binary.protections.full_relro')` |
| `readelf -S binary` | `ctx.get('binary.sections.*')` |
| `nm -D libc.so.6` | `ctx.get('libc.*_offset')` |
| `strings -t x libc.so.6` | `ctx.get('libc.bin_sh_offset')` |
| `ROPgadget --binary=...` | `ctx.get('rop.*')` |
| `ldd binary` | `ctx.get('libc.path')` |
| `libc.so.6 --version` | `ctx.get('libc.version')` |
| `one_gadget libc.so.6` | `ctx.get('libc.one_gadgets')` |

## Standard Context Keys

```
libc.path               - Path to libc.so
libc.version            - Full version string
libc.version_float      - Numeric version (e.g., 2.42)
libc.hooks_available    - True if glibc < 2.34
libc.system_offset      - system() offset from base
libc.execve_offset      - execve() offset
libc.bin_sh_offset      - "/bin/sh" string offset
libc.malloc_hook_offset - __malloc_hook offset
libc.free_hook_offset   - __free_hook offset
libc.one_gadgets        - List of one_gadget offsets

binary.protections.relro        - RELRO enabled
binary.protections.full_relro   - Full RELRO (GOT read-only)
binary.protections.pie          - Position Independent Executable
binary.protections.nx           - Non-executable stack
binary.protections.canary       - Stack canary present

binary.sections.got_plt_addr    - .got.plt address
binary.sections.fini_array_addr - .fini_array address
binary.sections.bss_addr        - .bss address
binary.got_entries              - Dict of function -> GOT address
binary.input_handlers           - List of input functions

rop.total_gadgets       - Total gadgets found
rop.usable_gadgets      - Gadgets without bad bytes
rop.filtered_count      - Gadgets filtered by bad bytes
rop.pop_rdi_ret         - pop rdi; ret gadget offset
rop.pop_rsi_ret         - pop rsi; ret gadget offset
rop.pop_rdx_ret         - pop rdx; ret gadget offset
rop.ret                 - ret gadget offset (stack alignment)

kernel.aslr             - ASLR level (0, 1, or 2)
kernel.version          - Kernel version string

payload.bad_bytes       - List of bytes that can't appear in payload
payload.input_handler   - Primary input function

address_space.binary_base   - Sampled binary base address
address_space.libc_base     - Sampled libc base address

write_targets           - List of ranked write targets
verdict                 - Exploitability verdict
blockers                - List of exploitation blockers
warnings                - List of exploitation warnings
```

## Workflow

1. **Check if context exists**
   ```python
   from pathlib import Path
   context_path = f"out/{binary_name}_context.json"
   if not Path(context_path).exists():
       print("ERROR: Run mitigation analysis first")
       print("  python3 raptor.py analyze <binary>")
       sys.exit(1)
   ```

2. **Load and validate context**
   ```python
   ctx = FeasibilityReport.load_context(context_path)

   # Check for blockers
   if ctx.get('verdict') == 'blocked':
       print("Exploitation blocked by:")
       for b in ctx.get('blockers', []):
           print(f"  - {b}")
       sys.exit(1)
   ```

3. **Use context data for exploit**
   ```python
   # Calculate addresses
   libc_base = leaked_addr - ctx.get('libc.system_offset')
   system = libc_base + ctx.get('libc.system_offset')
   bin_sh = libc_base + ctx.get('libc.bin_sh_offset')

   # Check constraints
   if ctx.get('binary.protections.full_relro'):
       print("Cannot use GOT overwrite - Full RELRO")

   # Get write targets
   for target in ctx.get('write_targets', []):
       if not target['has_bad_bytes']:
           print(f"Try: {target['name']} @ 0x{target['address']:x}")
   ```

## Why This Matters

- **Efficiency**: Don't waste time re-collecting data that already exists
- **Consistency**: Same data used across analysis and exploitation phases
- **Debugging**: Source tracking shows where each value came from
- **Reproducibility**: Context can be saved/loaded for later use
