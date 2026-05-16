# IRIS dataflow validation — synthetic E2E target

Two Flask apps with surface-similar `subprocess.call(cmd, shell=True)`
patterns. Real Semgrep flags both; the LLM analysis stage typically
distinguishes them; IRIS dataflow validation provides a third
mechanical signal.

## Files

- **`src/real_command_injection.py`** — `request.args.get("cmd")` flows
  unsanitised to `subprocess.call(cmd, shell=True)`. CodeQL's prebuilt
  `CommandInjectionFlow` should find this path.

- **`src/false_positive_command.py`** — Same surface pattern, but
  guarded by a strict allowlist sanitiser that returns `None` on bad
  input. The LLM should recognise the sanitiser; CodeQL's conservative
  taint propagation may or may not see through it (empirically, it
  often still emits a match).

## Manual real-LLM E2E

```bash
python3 raptor.py agentic \
    --repo packages/llm_analysis/tests/fixtures/iris_e2e \
    --codeql --languages python \
    --policy-groups injection \
    --validate-dataflow \
    --model gemini-2.5-flash \
    --no-sandbox
```

Expected outcome:
- Semgrep flags both files.
- LLM analysis marks the real one Exploitable, the FP file False
  Positive.
- IRIS Tier 1 (prebuilt CommandInjectionFlow) confirms the real one.
- The FP is filtered at eligibility (already not-exploitable), so IRIS
  doesn't run on it.
- Final report: 1 Exploitable + 1 False Positive (matches LLM verdict).

## Why these specific files

The first iteration of this fixture used `sys.argv[1]` as the source.
That **does not** trigger CodeQL's `RemoteFlowSource` (which models
network input), so the prebuilt query produced no matches and IRIS
incorrectly downgraded a real CLI-driven vulnerability. The Flask
fixture switches to `request.args.get(...)`, which CodeQL definitively
recognises as a remote source.

This is documented in `dataflow_validation._verdict_from_prebuilt`'s
docstring as the reason Tier 1 only confirms (no matches → inconclusive,
not refuted). When extending IRIS to handle CLI-driven flows, a custom
`LocalFlowSource` library would be the right next step (see follow-ups).

## Reproducible CI use

`tests/test_e2e_iris.py` runs against this fixture's source content
inline (no real LLM/CodeQL invocation — the LLM and CodeQL adapter are
both mocked). This README is for the manual real-LLM smoke test that
proved the wiring works end-to-end.
