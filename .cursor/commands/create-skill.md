# Create-Skill - Save Custom Approach as Reusable Skill

Save a successful custom security testing approach as a reusable specialist skill.

## Usage

`/create-skill`

## When to Use

After you've helped the user with a custom security testing approach that was successful:
- Custom analysis focus (e.g., "focus on API security only")
- Custom priority order (e.g., "check auth before secrets")
- Custom techniques (e.g., "specific testing methodology")
- Successful findings (approach actually worked)

## Execution Steps

1. **Capture successful approach**:
   - Ask user what was successful about their approach
   - Identify generalizable patterns (not target-specific)

2. **Define skill parameters**:
   - Skill name: descriptive name
   - Trigger keywords: when should this auto-load?
   - Domain: what type of targets?

3. **Extract reusable patterns**:
   - Review approach for generalizable patterns
   - Remove target-specific details
   - Keep reusable priorities and tool combinations

4. **Validate token budget**:
   - Skill must be <500 tokens (hard limit)
   - Warn if total skills >10 (approaching budget)
   - Show token cost when auto-loaded

5. **Create skill file**:
   - Save to: `tiers/specialists/custom/<skill_name>.md`
   - Follow skill structure template
   - Include: Core Philosophy, When to Use, Approach, Integration with Python

6. **Test auto-loading**:
   - Verify keywords defined clearly
   - Confirm file in correct location
   - Validate token budget acceptable

## Skill Structure

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

## Token Budget Guidelines

- **Minimum**: 200 tokens (enough for useful content)
- **Recommended**: 300-400 tokens (sweet spot)
- **Maximum**: 500 tokens (hard limit, enforced)

**Total skills warning**:
- Yellow (5 skills): 1,500-2,000 tokens in skills
- Red (10 skills): 3,000-4,000 tokens (approaching budget)
- Critical (15+ skills): Consider consolidating or removing unused

## Quality Checks

Before saving skill:
- [ ] Not overfitted to one target (generalized patterns)
- [ ] Token limit respected (<500 tokens)
- [ ] Keywords defined (will auto-load correctly)
- [ ] Approach documented (clear priorities/techniques)
- [ ] Integration clear (how it guides Python parameters)

## Maintenance

Skills are stored in: `tiers/specialists/custom/`

**Manage skills**:
- List: `ls tiers/specialists/custom/`
- Disable: Add `.disabled` suffix to filename
- Remove: Delete file
- Edit: Modify file directly

## Reference

See `.claude/commands/create-skill.md` for detailed examples and workflow.
