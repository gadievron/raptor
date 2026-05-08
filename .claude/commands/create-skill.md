---
description: Save a custom approach as a reusable skill
---

# /create-skill - Save Custom Approach as Reusable Skill

Save a successful custom approach as a reusable specialist skill.

## When to Use

After you've helped the user with a custom security testing approach:
- Custom analysis focus (e.g., "focus on API security only")
- Custom priority order (e.g., "check auth before secrets")
- Custom techniques (e.g., "specific testing methodology")
- Successful findings (approach actually worked)

---

## What This Does

Guides skill creation process:

### Step 1: Capture Successful Approach

```
What was successful about this approach?

Examples:
- Custom priorities: Auth → API security → Business logic
- Specific focus: API endpoint authentication testing
- Custom technique: Token generation + endpoint fuzzing
- Domain expertise: Mobile app security patterns
```

### Step 2: Define Skill Parameters

```
Skill name: [descriptive_name]
Trigger keywords: [when should this auto-load?]
Domain: [what type of targets?]

Examples:
- Name: api_security_auth_focus
- Keywords: API, REST, authentication, admin panel
- Domain: Web APIs with authentication
```

### Step 3: Extract Reusable Patterns

Review approach for:
- ✓ Generalizable patterns (not hardcoded to one target)
- ✓ Reusable priorities (applicable to similar targets)
- ✓ Tool combinations (what worked together)
- ✗ Target-specific details (remove these)

### Step 4: Validate Token Budget

```
Skill size: ___ tokens (must be <500 tokens)
Current total skills: ___ (warn if >10 skills)
Session impact: +___ tokens when auto-loaded
```

### Step 5: Create Skill File

Save to: `.claude/skills/[skill_name]/SKILL.md` (the
canonical Claude Code skills directory). For
single-file skills, `.claude/skills/[skill_name].md`
also works — Claude Code's skill discovery walks
`.claude/skills/` and picks up both layouts.

(Pre-fix this said `tiers/specialists/custom/[name].md`.
That path is from an earlier RAPTOR layout that
predates Claude Code's skills mechanism — files there
aren't auto-loaded by Claude Code today, so saving
new skills there would have made them invisible to
the LLM. Existing files under `tiers/personas/` and
`tiers/specialists/` are still loaded VIA EXPLICIT
prompts, but new skills should go under
`.claude/skills/` for auto-load.)

**Skill structure:**
```markdown
# [Skill Name]
# Created: [date]
# Source: Successful approach from [session]
# Token cost: [X] tokens
# Auto-loads: [trigger keywords]

## Core Philosophy
[What makes this approach unique/successful]

## When to Use
[What types of targets/situations]

## Approach
[Successful priorities, techniques, tools]

## Integration with Python
[How this guides Python execution parameters]
```

### Step 6: Test Auto-Loading

Verify skill will auto-load correctly:
- Keywords defined clearly
- File in correct location
- Token budget acceptable

---

## Token Budget Guidelines

**Skill size limits:**
- Minimum: 200 tokens (enough for useful content)
- Recommended: 300-400 tokens (sweet spot)
- Maximum: 500 tokens (hard limit, enforced)

**Total skills warning:**
- Yellow (5 skills): 1,500-2,000 tokens in skills
- Red (10 skills): 3,000-4,000 tokens (approaching budget)
- Critical (15+ skills): Consider consolidating or removing unused

---

## Example Skill Creation

```
User: /create-skill

Claude: What successful approach should we save?

User: "We focused on API authentication, checking auth bypass before anything else, and it found critical issues faster"

Claude:
  ✓ Extracting approach patterns...

  Skill preview:
  - Name: api_auth_priority
  - Keywords: API, REST, authentication, auth bypass
  - Focus: Authentication issues in web APIs
  - Priority: Auth bypass → API security → Input validation
  - Size: 380 tokens ✓

  Create this skill? [Y/n/Customize]

User: Y

Claude: ✓ Created: tiers/specialists/custom/api_auth_priority.md
        Will auto-load when keywords match: API, authentication

        Test it now? Run /scan on API codebase
```

---

## Quality Checks

Before saving skill:
- [ ] Not overfitted to one target (generalized patterns)
- [ ] Token limit respected (<500 tokens)
- [ ] Keywords defined (will auto-load correctly)
- [ ] Approach documented (clear priorities/techniques)
- [ ] Integration clear (how it guides Python parameters)

---

## Maintenance

Skills are stored in: `tiers/specialists/custom/`

**Manage skills:**
- List: `ls tiers/specialists/custom/`
- Disable: Add `.disabled` suffix to filename
- Remove: Delete file
- Edit: Modify file directly

**Quarterly review prompt** (if 5+ skills exist):
```
Review custom skills? Usage stats available.
```
