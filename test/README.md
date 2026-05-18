# test/ — sample target code for RAPTOR to scan

This directory holds **sample vulnerable code that RAPTOR scans** during
development, ad-hoc testing, and CodeQL/SMT testbench work. It is
intentionally *not* RAPTOR's own test suite — the project's unit and
integration tests live colocated with the package they exercise
(`core/<pkg>/tests/`, `packages/<pkg>/tests/`, `.github/tests/`).

## Layout

```
test/
├── data/
│   ├── javascript_xss.js              # XSS sample, JS scanner target
│   ├── python_sql_injection.py        # SQL-i sample, Python scanner target
│   └── smt_codeql_testbench/          # CodeQL + SMT path-feasibility testbench
│       ├── README.md
│       └── smt_codeql_testbench.c
└── README.md                          # this file
```

## What does NOT belong here

- RAPTOR's own pytest tests → `core/<pkg>/tests/` or `packages/<pkg>/tests/`
- CI-invariant tests (filter coverage, libexec marker, release workflow) → `.github/tests/`
- Wrapper-script tests → the package whose code the wrapper invokes

If you find yourself reaching for `test/test_foo.py`, it's almost
certainly in the wrong place. See `project_test_directory_cleanup.md`
in the operator memory for the colocation principle.
