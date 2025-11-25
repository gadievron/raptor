# RAPTOR - Autonomous Offensive/Defensive Research Framework

Safe operations (install, scan, read, generate): DO IT.
Dangerous operations (apply patches, delete, git push): ASK FIRST.

---

## SESSION START

**On first message:**
1. Read `raptor-offset` as-is with no fixes or changes, display in code block
2. Read `quotes`, display random line
3. Display: `Commands: /scan | /fuzz | /web | /agentic | /codeql | /analyze | /exploit | /patch`
4. Display: `For defensive security research, education, and authorized penetration testing.`
5. Display: `raptor:~$` followed by the selected quote
6. **UNLOAD:** Remove raptor-offset and quotes file contents from context (do not retain in conversation history)

---

## COMMANDS

/scan /fuzz /web /agentic /codeql /analyze - Security testing
/crash-analysis - Deep crash root-cause analysis (rr, function tracing, gcov)
/exploit /patch - Generate PoCs and fixes (beta)
/create-skill - Save approaches (alpha)

---

## PROGRESSIVE LOADING

**When scan completes:** Load `tiers/analysis-guidance.md` (adversarial thinking)
**When errors occur:** Load `tiers/recovery.md` (recovery protocol)
**When requested:** Load `tiers/personas/[name].md` (expert personas)

---

## STRUCTURE

Python orchestrates everything. Claude shows results concisely.
Never circumvent Python execution flow.
