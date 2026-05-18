# RAPTOR + Claude Code Quick Start

## TL;DR
Use RAPTOR with plain English in Claude Code via slash commands!

## Commands

| Command | Use Case | Example |
|---------|----------|---------|
| `/raptor` | General help | `/raptor - I want to test my app` |
| `/raptor-scan` | Scan source code | `/raptor-scan - check this repo for bugs` |
| `/raptor-fuzz` | Fuzz binaries | `/raptor-fuzz - test ./myapp for crashes` |
| `/raptor-web` | Test web apps | `/raptor-web - scan https://myapp.com` |

## Natural Language Examples

Just talk naturally to Claude:

### Code Scanning
```
/raptor-scan - scan this directory
/raptor-scan - find secrets in my code
/raptor-scan - check for SQL injection vulnerabilities
```

### Binary Fuzzing
```
/raptor-fuzz - fuzz this binary
/raptor-fuzz - test ./myapp for 5 minutes
/raptor-fuzz - find crashes in /usr/local/bin/myapp
```

### Web Testing
```
/raptor-web - test my website
/raptor-web - scan https://localhost:3000 for XSS
/raptor-web - check this app for OWASP Top 10
```

### General
```
/raptor - scan my code for vulnerabilities
/raptor - I need to fuzz a binary
/raptor - help me test my application
```

## What Claude Does

1. ✅ Understands your request in plain English
2. ✅ Runs the appropriate RAPTOR command
3. ✅ Analyzes the results
4. ✅ Explains vulnerabilities found
5. ✅ Shows generated exploits and patches
6. ✅ Offers to help fix issues

## Interactive Workflow

```
You: /raptor-scan - scan this code

Claude: I'll scan the current directory with RAPTOR...
        [Runs scan...]
        Found 5 vulnerabilities!

        1. SQL Injection (CRITICAL) - api/db.py:23
           Generated exploit: out/exploits/sqli_001.py
           Generated patch: out/patches/sqli_001.patch

        Would you like me to:
        1. Apply the patches?
        2. Explain the SQL injection?
        3. Show the exploit code?

You: Show me the exploit

Claude: [Reads and displays the exploit code]
        This exploit works by...

You: Apply the patch for that one

Claude: [Applies the patch using Edit tool]
        ✓ Patch applied! The SQL injection is now fixed.

        Want me to scan again to verify the fix?
```

## Benefits

🎯 **No command-line syntax to remember**
🤖 **AI understands your intent**
📊 **Results explained in plain English**
🔧 **Interactive fix workflow**
⚡ **Fast and autonomous**

## Setup (Through Claude Code)

```bash
# 1. Clone and open in Claude Code
git clone https://github.com/gadievron/raptor.git
cd raptor
claude

# 2. Let Claude handle setup
"Install Python packages from requirements.txt"
"Install semgrep"  # External tool

# 3. Set up LLM (choose one)
"Set my ANTHROPIC_API_KEY to [your-key]"          # Cloud (best quality)
# OR
"Install Ollama and pull deepseek-r1 model"       # Local/free

# 4. Start using RAPTOR
/scan - Scan code for vulnerabilities
/fuzz - Fuzz binaries (asks to install AFL++ if needed)
/web  - Test web applications
```

**Optional tools** (Claude Code helps install when you use them):
- AFL++ (for fuzzing)
- CodeQL (for deep static analysis)
- LLDB/GDB (for crash analysis - LLDB pre-installed on macOS)

Let Claude Code handle it!

## Examples by Scenario

### "I just cloned a new repo and want to check it"
```
/raptor-scan - scan this repository for all security issues
```

### "I have a binary and want to find bugs"
```
/raptor-fuzz - fuzz ./myapp for 30 minutes
```

### "I want to test my web app before deploying"
```
/raptor-web - test http://localhost:8000
```

### "I'm not sure what I need"
```
/raptor - help me secure my application
```

---

**That's it!** Just use `/raptor` commands and chat naturally with Claude.

Claude Code will handle:
- Running RAPTOR commands
- Interpreting results
- Explaining vulnerabilities
- Applying fixes
- Answering questions

No more memorizing command-line flags! 🎉
