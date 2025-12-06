# Raptor - General RAPTOR Assistant

General help command that assists users in choosing appropriate RAPTOR modes and understanding the framework.

## Usage

`/raptor [request or question]`

## Examples

- `/raptor scan my code for vulnerabilities`
- `/raptor I need to fuzz a binary`
- `/raptor help me test my web application`
- `/raptor what command should I use?`

## Execution Steps

1. **Understand user intent**:
   - Parse the user's request or question
   - Identify what they want to test (code, binary, web app)
   - Determine their security testing goals

2. **Recommend appropriate command**:
   - Code scanning → `/agentic` or `/scan`
   - Binary testing → `/fuzz`
   - Web application → `/web`
   - Existing SARIF analysis → `/analyze`
   - Exploit generation → `/exploit`
   - Patch generation → `/patch`

3. **Help execute command**:
   - Ask for missing required arguments (repo path, binary path, URL)
   - Infer paths from workspace context when possible
   - Execute the recommended command

4. **Explain results**:
   - Summarize findings
   - Show exploits and patches
   - Offer to apply patches or fix issues

## Understanding User Intent

When the user says:
- "scan this code" → Recommend `/agentic` or `/scan`
- "fuzz this binary" → Recommend `/fuzz`
- "test this website" → Recommend `/web`
- "find vulnerabilities" → Ask what they want to test, then recommend appropriate mode
- "check for secrets" → Recommend `/scan` with `--policy-groups secrets`

## What is RAPTOR?

RAPTOR (Recursive Autonomous Penetration Testing and Observation Robot) is an AI-powered security testing framework that:
- Scans code with Semgrep and CodeQL
- Fuzzes binaries with AFL++
- Tests web applications
- Automatically generates working exploits
- Creates secure patches
- Uses LLMs for deep vulnerability analysis

## Available Commands

**Core Security Testing**:
- `/agentic` - Full autonomous workflow (Semgrep + CodeQL + LLM + exploits + patches)
- `/scan` / `/raptor-scan` - Quick Semgrep scan
- `/fuzz` / `/raptor-fuzz` - Binary fuzzing with AFL++
- `/web` / `/raptor-web` - Web application scanning
- `/codeql` - CodeQL-only analysis
- `/analyze` - LLM analysis of existing SARIF files

**Exploit/Patch Generation**:
- `/exploit` - Generate exploit PoCs
- `/patch` - Generate secure patches

**Specialized Workflows**:
- `/crash-analysis` - Crash root-cause analysis
- `/oss-forensics` - OSS GitHub forensics

**Utilities**:
- `/create-skill` - Save custom approaches as reusable skills
- `/test-workflows` - Test suite runner

## Important Guidelines

- Always use absolute paths when possible
- Explain security concepts in simple terms
- Be helpful but responsible (only test owned/authorized systems)
- If unsure what they want, ask clarifying questions
- Show command output and interpret results

## Reference

See `.cursor/rules/command-usage.mdc` for complete command documentation.
