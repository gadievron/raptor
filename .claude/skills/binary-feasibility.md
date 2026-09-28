---
name: binary-feasibility
description: Exploit-feasibility analysis for binaries — why checksec/readelf are not substitutes, exploitation_paths semantics, SMT integration points
user-invocable: false
---

# Exploit-Feasibility Analysis (reference)

The always-loaded contract (vulnerabilities FIRST, then the MANDATORY
`analyze_binary` feasibility pass; `exploitation_paths` is the verdict) lives
in CLAUDE.md § BINARY ANALYSIS. This file is the full reference.

## Invocation

```python
from packages.exploit_feasibility.api import analyze_binary, format_analysis_summary

# MANDATORY: Run this after finding vulnerabilities
result = analyze_binary('/path/to/binary')
print(format_analysis_summary(result, verbose=True))
```

## Why checksec / readelf are not substitutes

They miss critical constraints like:

- Empirical %n verification (glibc may block it)
- Null byte constraints from strcpy (can't write 64-bit addresses)
- ROP gadget quality (0 usable gadgets = no ROP chain)
- Input handler bad bytes
- Full RELRO blocks .fini_array too (not just GOT)

**The `exploitation_paths` section tells you if code execution is actually
possible** given the system's mitigations (glibc version, RELRO, etc.).

## SMT integration (optional, requires `pip install z3-solver`)

Two places Z3 is used — both degrade gracefully when absent:

1. **Binary / one-gadget** (`packages/exploit_feasibility/smt_onegadget.py`):
   checks whether a one-gadget's register/memory constraints are satisfiable
   given a crash state. Result in
   `exploitation_paths[vuln].one_gadget_info.smt_feasibility`.

2. **CodeQL dataflow** (`core/smt_solver/path_feasibility.py`, invoked from
   `packages/codeql/dataflow_validator.py`): checks whether the branch
   conditions along a dataflow path are jointly satisfiable. `unsat` → false
   positive, skip LLM. `sat` → concrete input values fed into the LLM prompt
   and `DataflowValidation.prerequisites`. Best coverage: CWE-190,
   CWE-120/122, CWE-193, CWE-476.

## Follow-on

Exploit development doctrine (verdict tiers, `chain_breaks`,
`what_would_help`, next-steps guidance): `tiers/exploit-guidance.md`.
