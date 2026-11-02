# WSL refusal-boundary recovery

When an untrusted-exec run refuses on a WSL host because the floor
requires the Landlock layer, the refusal message itself names the
remedies, including the grant command — that is the complete
non-interactive behaviour. An interactive session may additionally
put the decision in front of the operator as a structured choice,
per the INTERACTIVE PROMPTS doctrine in the root `CLAUDE.md`: run
`libexec/raptor-may-ask` first and ask only when it prints
`interactive` AND AskUserQuestion is available; ask at the run
boundary, after the refusal — never mid-pipeline. Quote the refusal
text with non-printables escaped. Options:

1. **Keep the refusal (Recommended)** — no consent; fix the kernel
   instead for the full contract (custom-kernel setup in `docs/wsl.md`).
2. **Grant the standing host consent** — tell the operator to run
   `bin/raptor wsl-consent grant` **at their own terminal**. The CLI
   hard-refuses a non-TTY stdin, so the session cannot run it for
   them — never offer to. Once granted, re-run the refused command.
3. **Consent for this run / project only** — re-run with
   `--sandbox-floor ns-only`, or set the standing project consent
   with `/project set sandbox-floor ns-only` (per-run/project consent
   setup in `docs/wsl.md`).

Non-interactive fallback (may-ask says `non-interactive`, errors, or
the tool is absent): do not ask — the refusal text plus the named
grant command already printed is the complete behaviour; report it
and stop. Never select a floor on the operator's behalf.
