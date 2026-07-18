# RAPTOR Visual Design Elements

## ASCII Banner (for Python CLI)

```
╔═══════════════════════════════════════════════════════════════════════════╗ 
+                                                                            ║
║             ██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗             ║ 
║             ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗            ║ 
║             ██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝            ║ 
║             ██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗            ║ 
║             ██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║            ║ 
║             ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝            ║ 
║                                                                           ║ 
║             Autonomous Offensive/Defensive Research Framework             ║
║             Based on Claude Code - v1.0-alpha                             ║
║                                                                           ║ 
║             By Gadi Evron, Daniel Cuthbert                                ║
║                and Thomas Dullien (Halvar Flake)                          ║ 
║                                                                           - 
╚═══════════════════════════════════════════════════════════════════════════╝ 
                              __                                              
                             / _)                                             
                      .-^^^-/ /                                               
                   __/       /                                                
                  <__.|_|-|_|   
```

## Claude Code Session Greeting

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚡ RAPTOR ACTIVE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Commands: /scan | /fuzz | /web | /agentic | /codeql | /analyze
Natural language: "Scan this code" or "Find vulnerabilities"

▓▓▓ Autonomous Offensive/Defensive Security Research Framework ▓▓▓

For defensive security research, education, and authorized penetration testing.
Meant for use in lab environments.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Scan Results Format

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ SCAN RESULTS                                               ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                            ┃
┃  [!] CRITICAL: 2 findings - immediate action required     ┃
┃  [*] HIGH:     5 findings - review recommended            ┃
┃  [~] MEDIUM:   3 findings - assess when convenient        ┃
┃                                                            ┃
┃  TOP THREAT: Hardcoded AWS credentials                     ┃
┃              Location: config/settings.py:23               ┃
┃              Status: Target is pwnable                     ┃
┃                                                            ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

## Progress Indicators

```
[*] Initializing scan...
[████████████████████░░░░░░░░░░░░] 60% | Semgrep scanning...
[▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓] 100% | Scan complete

[*] Analyzing findings...
[>] LLM analysis in progress...
[+] Exploit generated: target is pwnable
[✓] Analysis complete
```

## Status Indicators

```
[*] Information / In progress
[+] Success / Found
[!] Critical / Warning
[>] Processing / Working
[✓] Complete / Verified
[✗] Failed / Error
[~] Medium priority
[#] Generating / Creating
```

## Original Taglines (Hacker Culture Inspired)

**Approved by user:**
1. "Autonomous security testing, evolved."
2. "Evolved security testing."
3. "Where AI meets offensive security."
4. "Autonomous. Aggressive. Accurate."
5. "See through the code."

**Additional original taglines:**
- "Break it before they do."
- "Autonomous offense. Intelligent defense."
- "Code has no secrets from us."
- "Find vulnerabilities. Prove exploitability. Ship patches."
- "We don't guess. We prove."
- "The system's weakness is our strength."
- "Security through aggressive testing."
- "Question everything. Trust no input."
- "Your code. Our analysis. Real exploits."
- "Offensive minds. Defensive goals."

**Rotate taglines** on each session start for variety.

---

## Implementation Notes

- ASCII art: Use in Python CLI banner
- Session greeting: Use in Claude Code (CLAUDE.md)
- Scan results: Use in analysis-guidance.md presentation
- Progress: Use during long operations
- Taglines: Rotate in greetings (select randomly)
