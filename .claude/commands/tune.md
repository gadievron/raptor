---
description: Show or update RAPTOR resource tuning (max / balanced / default profiles)
dispatch: libexec/raptor-tune $ARGUMENTS
---

# /tune — Resource Tuning

Show or update RAPTOR resource tuning.

## Usage

- `/tune` — show current resolved values and hardware info
- `/tune max` — rewrite tuning.json to use all available resources (also sets `llm_account_posture=solo` — the LLM account is declared this host's alone)
- `/tune balanced` — rewrite tuning.json with conservative values for shared machines (`llm_account_posture=shared`)
- `/tune default` — reset tuning.json to shipped defaults (`llm_account_posture=shared`)

## Implementation

Run the libexec script and show the output:

```bash
libexec/raptor-tune [profile]
```

Where `[profile]` is the optional argument from the user (`max`, `balanced`, or `default`).

If the user says `/tune` with no argument, run it with no argument to show current values.

Show the output verbatim — it's already formatted for terminal display.
