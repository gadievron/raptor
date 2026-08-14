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

**[TEACH-0] SAGE Prior Knowledge** *(automatic, before analysis)*

Before reading code, recall prior study concepts from SAGE and check if they are still fresh. Run:

```bash
python3 -c "
import sys, os, json; sys.path.insert(0, os.environ['RAPTOR_DIR'])
from core.sage.hooks import recall_concepts_for_teach
from core.concepts.study import _verify_evidence_hashes, _extract_evidence_hashes
from pathlib import Path

rows = recall_concepts_for_teach(
    repo_path='<resolved_target>',
    subject='<teach_subject>',
)
source_root = Path('<resolved_target>')
verified = []
unverified = []
for r in rows:
    content = r.get('content', '')
    if _extract_evidence_hashes(content) and _verify_evidence_hashes(content, source_root):
        verified.append(content)
    elif content:
        unverified.append(content)

print(json.dumps({'verified': len(verified), 'unverified': len(unverified)}))
for v in verified:
    print('--- VERIFIED ---')
    print(v)
for u in unverified:
    print('--- UNVERIFIED ---')
    print(u[:500])
if not verified and not unverified:
    print('No prior concepts found.')
"
```

**If SAGE returns verified concepts** (evidence hashes match current source): check whether the concept names and descriptions are actually relevant to `<teach_subject>` (semantic search can return unrelated concepts from the same domain). If relevant, present them directly as the teach output. Format as the standard TEACH output (Mechanism, Security properties, Relevant to analysis) drawn from the concept's description, invariants, contracts, and evidence. **Skip TEACH-1/2/3** — no LLM call needed, no code reading needed. The concept was already studied and the source hasn't changed. If not relevant, treat as "no prior concepts found".

**If SAGE returns only unverified concepts** (no hashes, or source has changed): use them as context for TEACH-1/2/3 but still read the code and verify. Do not repeat analysis they already cover; build on top of it.

**If SAGE returns nothing:** continue without prior knowledge.

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

**[TEACH-4] Store to SAGE** *(automatic, after TEACH-1/2/3)*

After completing a fresh analysis (TEACH-1/2/3), store the findings as structured concepts to SAGE so they can be recalled next time — by teach (caching) or by study (cross-pollination).

```bash
python3 -c "
import sys, os, json; sys.path.insert(0, os.environ['RAPTOR_DIR'])
from core.sage.hooks import store_teach_concepts

stored = store_teach_concepts(
    repo_path='<resolved_target>',
    teach_json=<TEACH_JSON>,
)
print(f'Stored {stored} concepts to SAGE')
"
```

Where `<TEACH_JSON>` is a Python dict literal you construct from the analysis:

```python
{
    "subject": "<teach_subject>",
    "source_root": "<resolved_target>",
    "concepts": [
        {
            "id": "<subject>_<aspect>",  # e.g. "scatterlist_lifetime"
            "description": "<one-line: what this concept is>",
            "confidence": "traced",      # traced | corroborated | documented
            "evidence": [
                {
                    "type": "code_path",  # code_path | type_definition | api_pattern
                    "file": "relative/path/to/file.c",
                    "line": 42,
                    "observation": "<what you observed at this location>"
                }
            ]
        }
    ],
    "invariants": [
        {
            "id": "<concept_id>_inv_<n>",
            "concept": "<concept_id>",
            "statement": "<what must always be true>",
            "negation": "<what happens when violated — the bug class>",
            "relevant_cwes": ["CWE-416"],  # optional
            "mechanism_tags": ["lifetime", "refcount"]  # optional
        }
    ],
    "contracts": [
        {
            "function": "function_name",
            "file": "relative/path/to/file.c",
            "when": "<precondition>",
            "input_semantics": "<what inputs mean>",
            "output_semantics": "<what outputs mean>",
            "ownership_transfer": "<who owns what after the call>"
        }
    ]
}
```

Guidelines for structured output:
- One concept per distinct mechanism or abstraction you explained (typically 1-3 for a teach session)
- Evidence must point to real lines you read — file paths relative to `<resolved_target>`, line numbers exact
- Invariants capture the security-relevant "must always be true" properties from TEACH-2
- Contracts capture per-function caller/callee obligations from TEACH-1
- Skip TEACH-4 if the subject is a general framework explanation with no codebase-specific evidence (e.g. `--teach ANTLR` without a target)
- Skip TEACH-4 if SAGE is unavailable (TEACH-0 returned no rows and the query itself failed)

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
