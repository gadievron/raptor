---
name: code-understanding-teach
description: Explains unfamiliar code, frameworks, or patterns in depth, focusing on security properties and failure conditions, and returns a clear security verdict to resume interrupted analysis.
user-invocable: false
---

# [TEACH] Code Explanation Mode

Explain unfamiliar code, frameworks, or patterns in enough depth to reason about their security properties. Used when the analyst hits something they don't understand well enough to attack correctly.

## Input

One of:
- A code snippet or file path (`--teach src/parsers/query.py`)
- A framework or library name (`--teach ANTLR`, `--teach SQLAlchemy`)
- A pattern pulled from an active trace (`--teach` inline during `--trace`)

## Purpose

Answer: *"How does this actually work, and what are the security-relevant properties I need to know before I continue?"*

The goal is not general documentation — it is targeted understanding of the mechanism from an attacker's perspective. How does this thing work? What does it protect against? What does it not protect against? What assumptions does it make?

## Task

**[TEACH-1] Mechanism**

Explain what the code or framework does at the implementation level:
- Show the actual code path (read the relevant files; don't just describe the API)
- Explain what the mechanism protects against when used correctly
- Explain what assumptions it makes about its inputs

**[TEACH-2] Security Properties**

Answer these questions for the subject:
- Does this prevent a specific class of attack? How? (e.g., "parameterized queries prevent SQL injection by sending query structure and data separately")
- Under what conditions does the protection fail? (e.g., "SQLAlchemy's `text()` construct bypasses parameterization if the argument contains string interpolation")
- What does correct use look like vs. incorrect use?

Show both with code examples from the actual codebase when possible.

**[TEACH-3] Return to Analysis**

After explaining the mechanism, return immediately to the interrupted analysis with a clear security conclusion:

```
[TEACH complete]
Conclusion: SQLAlchemy's text() construct used at src/db/query.py:89 is NOT parameterized
because the query string is built before being passed to text(). Attacker input at step 4
reaches this as a raw string. Continuing trace...
```

Do not leave the analyst in a state of uncertainty — the teach explanation must resolve into a security verdict.

## Output Format

Teach mode produces inline output (no JSON file). Structure:

```
[TEACH: <subject>]

Mechanism:
<explanation of how it works, with code references>

Security properties:
- Protects against: <what>
- Fails when: <conditions>
- Correct use: <example from codebase>
- Incorrect use: <example from codebase if present>

Relevant to current analysis:
<specific conclusion for the interrupted trace or analysis>

[TEACH complete — returning to <mode> at step N]
```

## When to Trigger Teach Mode

Teach mode should be triggered explicitly whenever:
- A framework or library is encountered that you haven't read in this session
- A pattern appears whose security properties are ambiguous (e.g., a custom sanitizer)
- A parsing or serialization mechanism is in the flow path
- An authentication or session mechanism is being evaluated

**Do not trace through code you don't understand.** Tracing through an opaque function and guessing it's safe is worse than pausing to understand it — it produces false confidence.

## Gates

GATES APPLY: U1 [READ-FIRST], U5 [EVIDENCE-ONLY]

Teach explanations must be grounded in code — either the actual library source, framework documentation read via WebFetch, or the project's own implementation. Do not explain how a library "usually" works without verifying it matches the version in use.
