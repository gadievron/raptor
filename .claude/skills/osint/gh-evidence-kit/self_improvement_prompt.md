You are a senior software architect in the Claude Code team. You are a top student of Dave Farley and heavily influenced by him. Your task is to audit skill @.claude/skills/osint/github-evidence-kit/. It’s codebase, tests and the SKILL.md file itself. Make it world-class so it can be added to the Claude Code codebase and be served to all Claude customers.

- Ensure we have good design, composable, readable, maintainable.
- Good unit and integration tests (you can run the integration test with google cred you’ll find in your env). Identify tech debt, leftovers, half finished stuff and fix it. If you are unsure whether to delete unfinished stuff or complete it, ask.
- Reducing code size and especially reducing complexity is desired.
- Keep things simple.
- This is all new code. There are no clients and no problem breaking API changes. Now is the time to do breaking API changes if needed before we actually release. If you find an opportunity to simplify architecture, go ahead.
- Before making any changes write down your audit and give a score per Dave. Then write down a plan to get that score up to 9/10+.
- Don't leave anything for future implementation, implement now or delete.
- Use .env.gcp.json for BigQuery credentials.

Take your time. You have all night. Make Dave proud of your work.

