# Collision Log — raptor-integration / OpenAnt Integration

Records all past and future agent/session file-write collisions or near-collisions.
**Rule**: When a collision is detected or prevented, append a dated entry here.

---

## Format

```
[DATE] [SEVERITY] COLLISION/NEAR-COLLISION
  Agents involved: <agent-A>, <agent-B>
  Files affected: <files>
  What happened: <description>
  Outcome: RESOLVED | PREVENTED | DATA LOSS | NONE
  Prevention: <what prevented it or what should>
```

---

## Collision Log

### 2026-05-05 — Session 5 Audit

**[2026-05-05] [PREVENTED] Audit agent vs. main session — potential clobber of raptor_agentic.py**
  Agents involved: `audit-agent-ac450798` (dispatched by main session), `main-session`
  Files affected: `raptor_agentic.py`, `packages/openant/scanner.py`
  What happened: The audit agent was launched while main session had already edited
    `raptor_agentic.py` (Bug-A fix, Bug-R-016 merge fix) in the same session. The audit
    agent was given READ-ONLY instructions and only created a new file
    (`audit-bug-A-R016-new.md`). No shared file was touched.
  Outcome: PREVENTED
  Prevention: Audit agent prompt explicitly said "READ-ONLY: raptor_agentic.py" and
    "write report to audit-bug-A-R016-new.md only". AGENT-LOG.md ledger now enforces this
    pattern.

**[2026-05-05] [NEAR-COLLISION] test_phase1b_integration.py double-update**
  Agents involved: `main-session` (two successive Edit calls to same file)
  Files affected: `packages/openant/tests/test_phase1b_integration.py`
  What happened: Main session updated the file twice in rapid succession:
    (1) Added TestBugR016DictFormatMerge class (correct)
    (2) Then updated again to fix _replay_merge() for BUG-R-016-VARIANT and fix
        test_merge_when_no_findings_file_exists() to expect dict not plain list.
    This was sequential (not parallel), so no data was lost. But if two agents had
    done this concurrently, edit #2 might have been based on the pre-edit-#1 state
    and clobbered edit #1.
  Outcome: NONE (sequential edits within same session, no data loss)
  Prevention: AGENT-LOG.md reservation system. Before any agent edits a file, it
    must reserve it in AGENT-LOG.md. Other agents seeing the reservation must wait.

---

## Coordination Rules (see also AGENT-LOG.md)

1. All agents READ-ONLY for git. Only main Claude thread commits/pushes.
2. Before writing any file: append reservation to AGENT-LOG.md.
3. After writing any file: append completion to AGENT-LOG.md and release reservation.
4. If two agents need the same file: serialize via AGENT-LOG.md reservation.
5. New collisions: append here immediately with severity and outcome.
6. AGENT-LOG.md is the write-lock mechanism. This file is the post-mortem record.
