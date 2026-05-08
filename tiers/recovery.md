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
- Load: `tiers/personas/exploit_developer.md` explicitly
- Command: "Load tiers/personas/exploit_developer.md and fix finding #X"

**Template patches (recommendations not code):**
- Load: `tiers/personas/patch_engineer.md` (or
  `tiers/personas/exploit_developer.md` for exploit
  PoC patches)
- Command: "Load tiers/personas/patch_engineer.md and create working patch"

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

## Always Offer Alternatives

When Python fails, always present user with:
1. Suggested fix (adjust parameters, install tool)
2. Alternative approach (different tool, different mode)
3. Manual fallback (use persona for manual analysis)
4. Skip option (continue without this component)

**Never leave user stuck - always provide 3-4 options.**
