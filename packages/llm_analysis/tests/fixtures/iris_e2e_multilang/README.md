# IRIS multi-language LocalFlowSource fixtures

Minimal CLI-driven command-injection samples for JS, Java, Go, and C —
one file per language showing `argv[N] → exec(...)` with no
sanitisation. Used to validate that IRIS Tier 1 discovers and runs the
right `.ql` query for each language and that the discovered query
catches the local (non-network) input flow.

## Files

- `js/cmd_inj.js`   — `process.argv[2]` flows to `child_process.exec`
- `java/CmdInj.java` — `args[0]`         flows to `Runtime.getRuntime().exec`
- `go/cmd_inj.go`   — `os.Args[1]`       flows to `os/exec.Command`
- `c/cmd_inj.c`     — `argv[1]`          flows to `system()`

## Why these flows would otherwise be missed

CodeQL's stdlib CWE-78 queries for JS, Java, and Go default to
`ActiveThreatModelSource` / `RemoteFlowSource` — network inputs only.
CLI arguments fall outside that source model unless the operator has
explicitly enabled the `commandargs` threat model (which the standard
code-scanning configuration does not).

The RAPTOR-shipped LocalFlowSource packs at
`packages/llm_analysis/codeql_packs/<lang>-queries/` widen the source
selection to include `commandargs` / `environment` / `stdin` / `file`
threat-model categories alongside `remote`, so a single Tier 1 query
covers both kinds of input.

C is intentionally different: the stdlib `ExecTainted.ql` already uses
the parent `FlowSource` class (the union of remote + local), so no
RAPTOR pack is required — the gap was operator install layout, not
source-model coverage. Discovery's `codeql resolve qlpacks` pointer
fallback closes that gap.

## Reproduction (manual)

```bash
# Build a CodeQL DB per language
codeql database create /tmp/iris-js   --language=javascript --source-root=js   --overwrite
codeql database create /tmp/iris-java --language=java       --source-root=java --command="javac CmdInj.java" --overwrite
codeql database create /tmp/iris-go   --language=go         --source-root=go   --overwrite
codeql database create /tmp/iris-c    --language=cpp        --source-root=c    --command="gcc -c cmd_inj.c -o /tmp/cmd_inj.o" --overwrite

# Run RAPTOR's Tier 1 discovery + invocation
python3 - <<'PY'
from pathlib import Path
from packages.llm_analysis.dataflow_query_builder import discover_prebuilt_query
from packages.hypothesis_validation.adapters.codeql import CodeQLAdapter

for lang, db in [
    ("javascript", "/tmp/iris-js"),
    ("java",       "/tmp/iris-java"),
    ("go",         "/tmp/iris-go"),
    ("cpp",        "/tmp/iris-c"),
]:
    ql = discover_prebuilt_query(lang, "CWE-78")
    adapter = CodeQLAdapter(database_path=Path(db), sandbox=False)
    ev = adapter.run_prebuilt_query(ql, Path("."), timeout=240)
    print(lang, "→", len(ev.matches), "match(es)")
PY
```

Expected: 1 match per language, all confirmed.

## Reproducible CI use

CI does NOT run real CodeQL against these fixtures (DB build + analysis
is minutes of wallclock per language). The unit tests in
`tests/test_dataflow_query_builder.py` mock discovery and verify the
walk logic. This README documents the manual real-CodeQL smoke that
proved the wiring works end-to-end on real installations.
