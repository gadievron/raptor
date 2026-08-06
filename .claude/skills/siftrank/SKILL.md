---
name: siftrank
description: Prioritize many security-relevant candidate items with SiftRank when review attention is scarce, relative comparison is easier than absolute scoring, and RAPTOR needs an ordered queue before expensive validation or deeper analysis.
user-invocable: false
---

# SiftRank Skill

Use SiftRank for attention-constrained prioritization. It is useful when RAPTOR or Claude has many candidate security-relevant items and the next problem is deciding what deserves scarce review time first.

SiftRank is a ranking aid, not a validator. It does not prove reachability, exploitability, severity, or correctness. Use it to choose review order, then continue normal RAPTOR validation or direct code review.

## Why This Helps

Use SiftRank when relative comparison is likely easier than absolute scoring. LLMs are often noisy when asked to judge one item in isolation or assign calibrated numeric scores, but they can still provide useful signal when asked to compare several items and rank them by relevance to a query.

SiftRank is especially useful as a broad triage pass before expensive analysis. A lower-cost model can rank many candidates, allowing Claude, a human analyst, or a higher-tier model to spend deeper reasoning on the most promising prefix of the list.

## When to Use

Use this when there are many candidate items and manual or agentic review would be expensive, such as:

- scanner findings
- CodeQL or Semgrep results
- suspicious files or functions
- decompiled functions
- call chains or traces
- crash reports
- dependency findings
- exploit hypotheses
- fuzz targets
- injection points
- validation notes or intermediate tool outputs

Good SiftRank problems look like needle-in-a-haystack triage: the relevance criteria may be fuzzy, but a useful item should be recognizable when compared against nearby alternatives.

Do not use it for:

- only a few items
- final exploitability verdicts
- deterministic severity sorting
- cases where the next action is already obvious
- inputs with too little context to compare meaningfully

## Workflow

1. Prepare a JSON array of candidates. Include useful common fields when available: `id`, `kind`, `source`, `title`, `severity`, `path`, `line`, `summary`, and `context`.

2. Choose the prompt based on the ranking task. The `--prompt` flag accepts either a named built-in prompt such as `security-triage` or literal prompt text describing the ranking goal. Use `security-triage` for normal security candidate prioritization. Use literal prompt text for task-specific ranking, such as ordering integers, ranking functions for a particular CWE, or ranking files by audit interest. Prefer language that describes the review goal, not a rigid scoring rubric, like:

   "Rank these items by expected value for follow-up vulnerability analysis. Prefer likely true positives, practical exploitability, attacker-controlled input, reachable dangerous sinks, clear dataflow or control-flow evidence, production reachability, and meaningful security impact."

3. Run the helper exactly as:

```bash
libexec/raptor-siftrank --input "$CANDIDATES_JSON" --output "$RANKED_JSON" --prompt security-triage --top 25
```

   With literal task-specific prompt text:

```bash
libexec/raptor-siftrank --input "$CANDIDATES_JSON" --output "$RANKED_JSON" --prompt "Rank these functions by how likely they contain a CWE-787 out-of-bounds write." --top 25
```

4. Read the ranked output as a review queue. Lower rank numbers are higher priority. Use the `item` field as the original candidate. Preserve original IDs when discussing results.

5. Review the top-ranked prefix first. If it does not yield a confirmed issue, continue down the ranking.

The helper ensures SiftRank is available. If SiftRank is not installed, it may install it using Go. The skill should still call only `libexec/raptor-siftrank` and should not run installation commands directly.

Run libexec scripts exactly as shown. Do not prepend bash, use absolute paths, export environment variables, or wrap the command in additional shell logic.
