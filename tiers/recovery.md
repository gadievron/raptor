# Failure Recovery Guidance
# Auto-loads: When Python encounters errors (keywords: "error", "failed", "timeout")
# Token cost: ~200 tokens
# Purpose: Help user recover when Python execution fails

## Common Failures and Solutions

### Semgrep Issues

**Timeout:**
- Reduce policy groups: `--policy-groups secrets`
- Scan subdirectories separately
- Exclude large files if needed

**No findings (but expected):**
- Check: Git tracking (Semgrep scans git-tracked files only)
- Check: Policy groups selected (try `--policy-groups all`)
- Check: Target language supported

**Parse errors:**
- Check: SARIF files in `out/` directory
- Validate: SARIF format with `python3 -m json.tool <file>`

---

### CodeQL Issues

**Database creation fails:**
- Check: Language support (`codeql resolve languages`)
- Provide: Build command `--build-command "make build"`
- Alternative: Use Semgrep-only (`--no-codeql`)

**Timeout:**
- Use: `--extended` flag for security-extended suite (faster)
- Alternative: Skip CodeQL, use Semgrep only

**Not installed:**
- Note: CodeQL is optional
- Alternative: Semgrep-only mode works fine

---

### LLM Issues

**Rate limit:**
- Python handles: Automatic fallback (Claude → GPT-4 → Ollama)
- If all fail: Analyze SARIF files manually

**Placeholder exploits (TODO comments):**
- Preferred: `/exploit <finding-id>` — wraps the
  exploit-developer workflow with sandbox + budget tracking
  and produces a working PoC in `out/exploit_<id>/`.
- Manual fallback: load `tiers/personas/exploit_developer.md`
  explicitly only if `/exploit` is unavailable / disabled.
  Command: "Load tiers/personas/exploit_developer.md and fix
  finding #X".

**Template patches (recommendations not code):**
- Preferred: `/patch <finding-id>` — wraps the patch-engineer
  workflow and produces an applyable diff in
  `out/patch_<id>/`. For exploit PoC patches, run `/exploit`
  first to confirm the finding is exploitable.
- Manual fallback: load `tiers/personas/patch_engineer.md`
  (or `tiers/personas/exploit_developer.md` for exploit PoC
  patches) only if `/patch` is unavailable.
  Command: "Load tiers/personas/patch_engineer.md and create
  working patch".

**Model not found (Ollama):**
- Check: `ollama list` for available models
- Install: `ollama pull <model>`
- Alternative: Use cloud models (Claude/GPT-4)

---

### AFL++ Issues

**Not found:**
- Install: `brew install afl++` (macOS) or `apt install afl++` (Linux)
- Alternative: Skip fuzzing, use static analysis

**macOS restrictions (shared memory, crash reporter):**
- **RAPTOR auto-detects and works around this**
- Generates manual crash test corpus instead of AFL++ fuzzing
- Creates targeted crash inputs without AFL++ fork server
- User sees: "[*] AFL++ encountered macOS restrictions. Generating manual crash corpus..."
- Alternative: Use Linux VM or Docker for full AFL++ support

**No crashes after 1+ hour:**
- Improve: Corpus quality (format-specific seeds)
- Increase: Duration `--duration 7200` (2 hours)
- Alternative: Static analysis on input parsers

**Crash not reproducible:**
- Check: ASLR disabled (`sysctl -a | grep randomize`)
- Run: Multiple times (10+ attempts)
- Try: Exact environment (same OS, libraries)

**GDB analysis fails:**
- Use: ASan build (`clang -fsanitize=address`)
- Alternative: Manual crash analysis with crash analyst persona

---

### Sandbox containment-floor refusal (`SandboxFloorError`)

A run that stops with "sandbox containment floor violated" or "the
fresh-procfs contract cannot be met" refused to execute
attacker-derived/untrusted code below the required containment tier.
The refusal text names the required floor, the achievable tier, and
the exact remedies. This is a run-boundary decision point (nothing
executed).

In an interactive session, offer the remedies as a structured choice
(see CLAUDE.md § INTERACTIVE PROMPTS; gate with
`libexec/raptor-may-ask` first — only if it prints `interactive` AND
the AskUserQuestion tool is available). Quote the actual refusal text
for the host condition and the exact tier labels from the error;
never invent values:

1. **Fix the environment (Recommended)** — apply the named host
   remedy from the refusal (e.g. install the uidmap package, relax
   the AppArmor userns sysctl, upgrade to a Landlock kernel) and
   re-run at full containment.
2. **Lower the floor for this run** — re-run with the exact flag the
   refusal names (e.g. `--sandbox-floor landlock`). State exactly
   what is being accepted (the refusal says: e.g. host process table
   visible to attacker-derived code; /proc read grant withdrawn).
3. **Persist for this project** — `/project set sandbox-floor
   <tier>`; the same grant, standing for every subsequent run on the
   project (per-run `--sandbox-floor` still overrides).

**Non-interactive fallback: refuse** — report the refusal text
(which already names all the remedies) and stop. Never select a
floor on the operator's behalf, and never re-run with a lowered
floor without the operator choosing it. Note: `--sandbox-floor none`
is not a consentable untrusted floor — if the operator truly wants
no sandbox, that is the authoritative `--sandbox none` /
`--no-sandbox` surface.

---

## Always Offer Alternatives

When Python fails, always present user with:
1. Suggested fix (adjust parameters, install tool)
2. Alternative approach (different tool, different mode)
3. Manual fallback (use persona for manual analysis)
4. Skip option (continue without this component)

**Never leave user stuck - always provide 3-4 options.**
