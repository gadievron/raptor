---
name: github-archive
description: Investigate GitHub security incidents using tamper-proof GitHub Archive data via BigQuery. Use when verifying repository activity claims, recovering deleted PRs/branches/tags/repos, attributing actions to actors, or reconstructing attack timelines. Provides immutable forensic evidence of all public GitHub events since 2011.
version: 1.0
author: mbrg
tags:
  - github
  - gharchive
  - security
  - osint
  - forensics
  - git
---

# GitHub Archive

**Purpose**: Query immutable GitHub event history via BigQuery to obtain tamper-proof forensic evidence for security investigations.

## When to Use This Skill

- Investigating security incidents involving GitHub repositories
- Building threat actor attribution profiles
- Verifying claims about repository activity (media reports, incident reports)
- Reconstructing attack timelines with definitive timestamps
- Analyzing automation system compromises
- Detecting supply chain reconnaissance
- Cross-repository behavioral analysis
- Workflow execution verification (legitimate vs API abuse)
- Pattern-based anomaly detection
- **Recovering deleted content**: PRs, issues, branches, tags, entire repositories

GitHub Archive analysis should be your **FIRST step** in any GitHub-related security investigation. Start with the immutable record, then enrich with additional sources.

## Core Principles

**ALWAYS PREFER GitHub Archive as forensic evidence over**:
- Local git command outputs (`git log`, `git show`) - commits can be backdated/forged
- Unverified claims from articles or reports - require independent confirmation
- GitHub web interface screenshots - can be manipulated
- Single-source evidence - always cross-verify

**GitHub Archive IS your ground truth for**:
- Actor attribution (who performed actions)
- Timeline reconstruction (when events occurred)
- Event verification (what actually happened)
- Pattern analysis (behavioral fingerprinting)
- Cross-repository activity tracking
- **Deleted content recovery** (issues, PRs, tags, commit references remain in archive)
- **Repository deletion forensics** (commit SHAs persist even after repo deletion and history rewrites)

### What Persists After Deletion

**Deleted Issues & PRs**:
- Issue creation events (`IssuesEvent`) remain in archive
- Issue comments (`IssueCommentEvent`) remain accessible
- PR open/close/merge events (`PullRequestEvent`) persist
- **Forensic Value**: Recover deleted evidence of social engineering, reconnaissance, or coordination

**Deleted Tags & Branches**:
- `CreateEvent` records for tag/branch creation persist
- `DeleteEvent` records document when deletion occurred
- **Forensic Value**: Reconstruct attack staging infrastructure (e.g., malicious payload delivery tags)

**Deleted Repositories**:
- All `PushEvent` records to the repository remain queryable
- Commit SHAs are permanently recorded in archive
- Fork relationships (`ForkEvent`) survive deletion
- **Forensic Value**: Access commit metadata even after threat actor deletes evidence

**Deleted User Accounts**:
- All activity events remain attributed to deleted username
- Timeline reconstruction remains possible
- **Limitation**: Direct code access lost, but commit SHAs can be searched elsewhere

## Quick Start

**Investigate if user opened PRs in June 2025:**

```python
from google.cloud import bigquery
from google.oauth2 import service_account

# Initialize client (see Setup section for credentials)
credentials = service_account.Credentials.from_service_account_file(
    'path/to/credentials.json',
    scopes=['https://www.googleapis.com/auth/bigquery']
)
client = bigquery.Client(credentials=credentials, project=credentials.project_id)

# Query for PR events
query = """
SELECT
    created_at,
    repo.name,
    JSON_EXTRACT_SCALAR(payload, '$.pull_request.number') as pr_number,
    JSON_EXTRACT_SCALAR(payload, '$.pull_request.title') as pr_title,
    JSON_EXTRACT_SCALAR(payload, '$.action') as action
FROM `githubarchive.day.202506*`
WHERE
    actor.login = 'suspected-actor'
    AND repo.name = 'target/repository'
    AND type = 'PullRequestEvent'
ORDER BY created_at
"""

results = client.query(query)
for row in results:
    print(f"{row.created_at}: PR #{row.pr_number} - {row.action}")
    print(f"  Title: {row.pr_title}")
```

**Expected Output (if PR exists)**:
```
2025-06-15 14:23:11 UTC: PR #123 - opened
  Title: Add new feature
2025-06-20 09:45:22 UTC: PR #123 - closed
  Title: Add new feature
```

**Interpretation**:
- **No results** → Claim disproven (no PR activity found)
- **Results found** → Claim verified, proceed with detailed analysis

## Setup

### Prerequisites

1. **Google Cloud Project**:
   - Login to [Google Developer Console](https://console.cloud.google.com/)
   - Create a project and activate BigQuery API
   - Create a service account with `BigQuery User` role
   - Download JSON credentials file

2. **Install BigQuery Client**:
```bash
pip install google-cloud-bigquery google-auth
```

### Initialize Client

```python
from google.cloud import bigquery
from google.oauth2 import service_account

credentials = service_account.Credentials.from_service_account_file(
    'path/to/credentials.json',
    scopes=['https://www.googleapis.com/auth/bigquery']
)

client = bigquery.Client(
    credentials=credentials,
    project=credentials.project_id
)
```

**Free Tier**: Google provides 1 TB of data processed per month free.

## Cost Management & Query Optimization

### Understanding GitHub Archive Costs

BigQuery charges **$6.25 per TiB** of data scanned (after the 1 TiB free tier). GitHub Archive tables are **large** - a single month table can be 50-100 GB, and yearly wildcards can scan multiple TiBs. **Unoptimized queries can cost $10-100+**, while optimized versions of the same query cost $0.10-1.00.

**Key Cost Principle**: BigQuery uses columnar storage - you pay for ALL data in the columns you SELECT, not just matching rows. A query with `SELECT *` on one day of data scans ~3 GB even with LIMIT 10.

### ALWAYS Estimate Costs Before Querying

**CRITICAL RULE**: Run a dry run to estimate costs before executing any query against GitHub Archive production tables.

```python
from google.cloud import bigquery

def estimate_gharchive_cost(query: str) -> dict:
    """Estimate cost before running GitHub Archive query."""
    client = bigquery.Client()

    # Dry run - validates query and returns bytes to scan
    dry_run_config = bigquery.QueryJobConfig(dry_run=True, use_query_cache=False)
    job = client.query(query, job_config=dry_run_config)

    bytes_processed = job.total_bytes_processed
    gb_processed = bytes_processed / (1024**3)
    tib_processed = bytes_processed / (1024**4)
    estimated_cost = tib_processed * 6.25

    return {
        'bytes': bytes_processed,
        'gigabytes': round(gb_processed, 2),
        'tib': round(tib_processed, 4),
        'estimated_cost_usd': round(estimated_cost, 4)
    }

# Example: Always check cost before running
estimate = estimate_gharchive_cost(your_query)
print(f"Cost estimate: {estimate['gigabytes']} GB → ${estimate['estimated_cost_usd']}")

if estimate['estimated_cost_usd'] > 1.0:
    print("⚠️ HIGH COST QUERY - Review optimization before proceeding")
```

**Command-line dry run**:
```bash
bq query --dry_run --use_legacy_sql=false 'YOUR_QUERY_HERE' 2>&1 | grep "bytes"
```

### When to Ask the User About Costs

**ASK USER BEFORE RUNNING** if any of these conditions apply:

1. **Estimated cost > $1.00** - Always confirm with user for queries over $1
2. **Wildcard spans > 3 months** - Queries like `githubarchive.day.2025*` scan entire year (~400 GB)
3. **No partition filter** - Queries without date/time filters scan entire table range
4. **SELECT * used** - Selecting all columns dramatically increases cost
5. **Cross-repository searches** - Queries without `repo.name` filter scan all GitHub activity

**Example user confirmation**:
```
Query estimate: 120 GB ($0.75)
Scanning: githubarchive.day.202506* (June 2025, 30 days)
Reason: Cross-repository search for actor 'suspected-user'

This exceeds typical query cost ($0.10-0.30). Proceed? [y/n]
```

**DON'T ASK if**:
- Estimated cost < $0.50 AND query is well-scoped (specific repo + date range)
- User explicitly requested broad analysis (e.g., "scan all of 2025")

### Cost Optimization Techniques for GitHub Archive

#### 1. Select Only Required Columns (50-90% cost reduction)

```sql
-- ❌ EXPENSIVE: Scans ALL columns (~3 GB per day)
SELECT * FROM `githubarchive.day.20250615`
WHERE actor.login = 'target-user'

-- ✅ OPTIMIZED: Scans only needed columns (~0.3 GB per day)
SELECT
    type,
    created_at,
    repo.name,
    actor.login,
    JSON_EXTRACT_SCALAR(payload, '$.action') as action
FROM `githubarchive.day.20250615`
WHERE actor.login = 'target-user'
```

**Never use `SELECT *` in production queries.** Always specify exact columns needed.

#### 2. Use Specific Date Ranges (10-100x cost reduction)

```sql
-- ❌ EXPENSIVE: Scans entire year (~400 GB)
SELECT ... FROM `githubarchive.day.2025*`
WHERE actor.login = 'target-user'

-- ✅ OPTIMIZED: Scans specific month (~40 GB)
SELECT ... FROM `githubarchive.day.202506*`
WHERE actor.login = 'target-user'

-- ✅ BEST: Scans single day (~3 GB)
SELECT ... FROM `githubarchive.day.20250615`
WHERE actor.login = 'target-user'
```

**Strategy**: Start with narrow date ranges (1-7 days), then expand if needed. Use monthly tables (`githubarchive.month.202506`) for multi-month queries instead of daily wildcards.

#### 3. Filter by Repository Name (5-50x cost reduction)

```sql
-- ❌ EXPENSIVE: Scans all GitHub activity
SELECT ... FROM `githubarchive.day.202506*`
WHERE actor.login = 'target-user'

-- ✅ OPTIMIZED: Filter by repo (BigQuery can prune data blocks)
SELECT ... FROM `githubarchive.day.202506*`
WHERE
    repo.name = 'target-org/target-repo'
    AND actor.login = 'target-user'
```

**Rule**: Always include `repo.name` filter when investigating a specific repository.

#### 4. Avoid SELECT * with Wildcards (Critical)

```sql
-- ❌ CATASTROPHIC: Can scan 1+ TiB ($6.25+)
SELECT * FROM `githubarchive.day.2025*`
WHERE type = 'PushEvent'

-- ✅ OPTIMIZED: Scans ~50 GB ($0.31)
SELECT
    created_at,
    actor.login,
    repo.name,
    JSON_EXTRACT_SCALAR(payload, '$.ref') as branch
FROM `githubarchive.day.2025*`
WHERE type = 'PushEvent'
```

#### 5. Use LIMIT Correctly (Does NOT reduce cost on GHArchive)

**IMPORTANT**: LIMIT does **not** reduce BigQuery costs on non-clustered tables like GitHub Archive. BigQuery must scan all matching data before applying LIMIT.

```sql
-- ❌ MISCONCEPTION: Still scans full dataset
SELECT * FROM `githubarchive.day.20250615`
LIMIT 100  -- Cost: ~3 GB scanned

-- ✅ CORRECT: Use WHERE filters and column selection
SELECT type, created_at, actor.login
FROM `githubarchive.day.20250615`
WHERE repo.name = 'target/repo'  -- Cost: ~0.2 GB scanned
LIMIT 100
```

### Safe Query Execution Template

Use this template for all GitHub Archive queries in production:

```python
def safe_gharchive_query(query: str, max_cost_usd: float = 1.0):
    """Execute GitHub Archive query with cost controls."""
    client = bigquery.Client()

    # Step 1: Dry run estimate
    dry_run_config = bigquery.QueryJobConfig(dry_run=True, use_query_cache=False)
    dry_job = client.query(query, job_config=dry_run_config)

    bytes_processed = dry_job.total_bytes_processed
    gb = bytes_processed / (1024**3)
    estimated_cost = (bytes_processed / (1024**4)) * 6.25

    print(f"📊 Estimate: {gb:.2f} GB → ${estimated_cost:.4f}")

    # Step 2: Check budget
    if estimated_cost > max_cost_usd:
        raise ValueError(
            f"Query exceeds ${max_cost_usd} budget (estimated ${estimated_cost:.2f}). "
            f"Optimize query or increase max_cost_usd parameter."
        )

    # Step 3: Execute with safety limit
    job_config = bigquery.QueryJobConfig(
        maximum_bytes_billed=int(bytes_processed * 1.2)  # 20% buffer
    )

    print(f"✅ Executing query (max ${estimated_cost:.2f})...")
    return client.query(query, job_config=job_config).result()

# Usage
results = safe_gharchive_query("""
    SELECT created_at, repo.name, actor.login
    FROM `githubarchive.day.20250615`
    WHERE repo.name = 'aws/aws-toolkit-vscode'
        AND type = 'PushEvent'
""", max_cost_usd=0.50)
```

### Common Investigation Patterns: Cost Comparison

| Investigation Type | Expensive Approach | Cost | Optimized Approach | Cost |
|-------------------|-------------------|------|-------------------|------|
| **Verify user opened PR in June** | `SELECT * FROM githubarchive.day.202506*` | ~$5.00 | `SELECT created_at, repo.name, payload FROM githubarchive.day.202506* WHERE actor.login='user' AND type='PullRequestEvent'` | ~$0.30 |
| **Find all actor activity in 2025** | `SELECT * FROM githubarchive.day.2025*` | ~$60.00 | `SELECT type, created_at, repo.name FROM githubarchive.month.2025*` | ~$5.00 |
| **Recover deleted PR content** | `SELECT * FROM githubarchive.day.20250615` | ~$0.20 | `SELECT created_at, payload FROM githubarchive.day.20250615 WHERE repo.name='target/repo' AND type='PullRequestEvent'` | ~$0.02 |
| **Cross-repo behavioral analysis** | `SELECT * FROM githubarchive.day.202506*` | ~$5.00 | Start with `githubarchive.month.202506`, identify specific repos, then query daily tables | ~$0.50 |

### Development vs Production Queries

**During investigation/development**:
1. Start with single-day queries to test pattern: `githubarchive.day.20250615`
2. Verify query returns expected results
3. Expand to date range only after validation: `githubarchive.day.202506*`

**Production checklist**:
- [ ] Used specific column names (no `SELECT *`)
- [ ] Included narrowest possible date range
- [ ] Added `repo.name` filter if investigating specific repository
- [ ] Ran dry run and verified cost < $1.00 (or got user approval)
- [ ] Set `maximum_bytes_billed` in query config

### Cost Monitoring

Track your BigQuery spending with this query:

```sql
-- View GitHub Archive query costs (last 7 days)
SELECT
    DATE(creation_time) as query_date,
    COUNT(*) as queries,
    ROUND(SUM(total_bytes_billed) / (1024*1024*1024), 2) as total_gb,
    ROUND(SUM(total_bytes_billed) / (1024*1024*1024*1024) * 6.25, 2) as cost_usd
FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
WHERE
    creation_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
    AND job_type = 'QUERY'
    AND REGEXP_CONTAINS(query, r'githubarchive\.')
GROUP BY query_date
ORDER BY query_date DESC
```

## Schema Reference

### Table Organization

**Dataset**: `githubarchive`

**Table Patterns**:
- **Daily tables**: `githubarchive.day.YYYYMMDD` (e.g., `githubarchive.day.20250713`)
- **Monthly tables**: `githubarchive.month.YYYYMM` (e.g., `githubarchive.month.202507`)
- **Yearly tables**: `githubarchive.year.YYYY` (e.g., `githubarchive.year.2025`)

**Wildcard Patterns**:
- All days in June 2025: `githubarchive.day.202506*`
- All months in 2025: `githubarchive.month.2025*`
- All data in 2025: `githubarchive.year.2025*`

**Data Availability**: February 12, 2011 to present (updated hourly)

### Schema Structure

**Top-Level Fields**:
```sql
type              -- Event type (PushEvent, IssuesEvent, etc.)
created_at        -- Timestamp when event occurred (UTC)
actor.login       -- GitHub username who performed the action
actor.id          -- GitHub user ID
repo.name         -- Repository name (org/repo format)
repo.id           -- Repository ID
org.login         -- Organization login (if applicable)
org.id            -- Organization ID
payload           -- JSON string with event-specific data
```

**Payload Field**: JSON-encoded string containing event-specific details. Must be parsed with `JSON_EXTRACT_SCALAR()` in SQL or `json.loads()` in Python.

### Event Types Reference

#### Repository Events

**PushEvent** - Commits pushed to a repository
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.ref')        -- Branch (refs/heads/master)
JSON_EXTRACT_SCALAR(payload, '$.before')     -- SHA before push
JSON_EXTRACT_SCALAR(payload, '$.after')      -- SHA after push
JSON_EXTRACT_SCALAR(payload, '$.size')       -- Number of commits
-- payload.commits[] contains array of commit objects with sha, message, author
```

**PullRequestEvent** - Pull request opened, closed, merged
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.action')              -- opened, closed, merged
JSON_EXTRACT_SCALAR(payload, '$.pull_request.number')
JSON_EXTRACT_SCALAR(payload, '$.pull_request.title')
JSON_EXTRACT_SCALAR(payload, '$.pull_request.merged') -- true/false
```

**CreateEvent** - Branch or tag created
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.ref_type')   -- branch, tag, repository
JSON_EXTRACT_SCALAR(payload, '$.ref')        -- Name of branch/tag
```

**DeleteEvent** - Branch or tag deleted
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.ref_type')   -- branch or tag
JSON_EXTRACT_SCALAR(payload, '$.ref')        -- Name of deleted ref
```

**ForkEvent** - Repository forked
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.forkee.full_name')  -- New fork name
```

#### Automation & CI/CD Events

**WorkflowRunEvent** - GitHub Actions workflow run status changes
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.action')               -- requested, completed
JSON_EXTRACT_SCALAR(payload, '$.workflow_run.name')
JSON_EXTRACT_SCALAR(payload, '$.workflow_run.path')    -- .github/workflows/file.yml
JSON_EXTRACT_SCALAR(payload, '$.workflow_run.status')  -- queued, in_progress, completed
JSON_EXTRACT_SCALAR(payload, '$.workflow_run.conclusion') -- success, failure, cancelled
JSON_EXTRACT_SCALAR(payload, '$.workflow_run.head_sha')
JSON_EXTRACT_SCALAR(payload, '$.workflow_run.head_branch')
```

**WorkflowJobEvent** - Individual job within workflow
**CheckRunEvent** - Check run status (CI systems)
**CheckSuiteEvent** - Check suite for commits

#### Issue & Discussion Events

**IssuesEvent** - Issue opened, closed, edited
```sql
-- Payload fields:
JSON_EXTRACT_SCALAR(payload, '$.action')        -- opened, closed, reopened
JSON_EXTRACT_SCALAR(payload, '$.issue.number')
JSON_EXTRACT_SCALAR(payload, '$.issue.title')
JSON_EXTRACT_SCALAR(payload, '$.issue.body')
```

**IssueCommentEvent** - Comment on issue or pull request
**PullRequestReviewEvent** - PR review submitted
**PullRequestReviewCommentEvent** - Comment on PR diff

#### Other Events

**WatchEvent** - Repository starred
**ReleaseEvent** - Release published
**MemberEvent** - Collaborator added/removed
**PublicEvent** - Repository made public

## Investigation Patterns

### Deleted Issue & PR Text Recovery

**Scenario**: Issue or PR was deleted from GitHub (by author, maintainer, or moderation) but you need to recover the original title and body text for investigation, compliance, or historical reference.

**Step 1: Recover Deleted Issue Content**
```sql
SELECT
    created_at,
    actor.login,
    JSON_EXTRACT_SCALAR(payload, '$.action') as action,
    JSON_EXTRACT_SCALAR(payload, '$.issue.number') as issue_number,
    JSON_EXTRACT_SCALAR(payload, '$.issue.title') as title,
    JSON_EXTRACT_SCALAR(payload, '$.issue.body') as body
FROM `githubarchive.day.20250713`
WHERE
    repo.name = 'aws/aws-toolkit-vscode'
    AND actor.login = 'lkmanka58'
    AND type = 'IssuesEvent'
ORDER BY created_at
```

**Step 2: Recover Deleted PR Description**
```sql
SELECT
    created_at,
    actor.login,
    JSON_EXTRACT_SCALAR(payload, '$.action') as action,
    JSON_EXTRACT_SCALAR(payload, '$.pull_request.number') as pr_number,
    JSON_EXTRACT_SCALAR(payload, '$.pull_request.title') as title,
    JSON_EXTRACT_SCALAR(payload, '$.pull_request.body') as body,
    JSON_EXTRACT_SCALAR(payload, '$.pull_request.merged') as merged
FROM `githubarchive.day.202506*`
WHERE
    repo.name = 'target/repository'
    AND actor.login = 'target-user'
    AND type = 'PullRequestEvent'
ORDER BY created_at
```

**Evidence Recovery**:
- **Issue/PR Title**: Full title text preserved in `$.issue.title` or `$.pull_request.title`
- **Issue/PR Body**: Complete body text preserved in `$.issue.body` or `$.pull_request.body`
- **Comments**: `IssueCommentEvent` preserves comment text in `$.comment.body`
- **Actor Attribution**: `actor.login` identifies who created the content
- **Timestamps**: Exact creation time in `created_at`

**Real Example**: Amazon Q investigation recovered deleted issue content from `lkmanka58`. The issue titled "aws amazon donkey aaaaaaiii aaaaaaaiii" contained a rant calling Amazon Q "deceptive" and "scripted fakery". The full issue body was preserved in GitHub Archive despite deletion from github.com, providing context for the timeline reconstruction.

### Deleted PRs

**Scenario**: Media claims attacker submitted a PR in "late June" containing malicious code, but PR is now deleted and cannot be found on github.com.

**Step 1: Query Archive**
```python
query = """
SELECT
    type,
    created_at,
    repo.name,
    JSON_EXTRACT_SCALAR(payload, '$.action') as action,
    JSON_EXTRACT_SCALAR(payload, '$.pull_request.number') as pr_number,
    JSON_EXTRACT_SCALAR(payload, '$.pull_request.title') as pr_title
FROM `githubarchive.day.202506*`
WHERE
    actor.login = 'suspected-actor'
    AND repo.name = 'target/repository'
    AND type = 'PullRequestEvent'
ORDER BY created_at
"""

results = client.query(query)
pr_events = list(results)
```

**Step 2: Analyze Results**
```python
if not pr_events:
    print("❌ CLAIM DISPROVEN: No PR activity found in June 2025")
else:
    for event in pr_events:
        print(f"✓ VERIFIED: PR #{event.pr_number} {event.action} on {event.created_at}")
        print(f"  Title: {event.pr_title}")
        print(f"  Repo: {event.repo_name}")
```

**Evidence Validation**:
- **Claim TRUE**: Archive shows `PullRequestEvent` with `action='opened'`
- **Claim FALSE**: No events found → claim disproven
- **Investigation Outcome**: Definitively verify or refute timeline claims

**Real Example**: Amazon Q investigation verified no PR from attacker's account in late June 2025, disproving media's claim of malicious code committed via deleted PR.

### Deleted Repository Forensics

**Scenario**: Threat actor creates staging repository, pushes malicious code, then deletes repo to cover tracks.

**Step 1: Find Repository Activity**
```python
query = """
SELECT
    type,
    created_at,
    JSON_EXTRACT_SCALAR(payload, '$.ref') as ref,
    JSON_EXTRACT_SCALAR(payload, '$.repository.name') as repo_name,
    payload
FROM `githubarchive.day.2025*`
WHERE
    actor.login = 'threat-actor'
    AND type IN ('CreateEvent', 'PushEvent')
    AND (
        JSON_EXTRACT_SCALAR(payload, '$.repository.name') = 'staging-repo'
        OR repo.name LIKE 'threat-actor/staging-repo'
    )
ORDER BY created_at
"""

results = client.query(query)
```

**Step 2: Extract Commit SHAs**
```python
import json

commits = []
for row in results:
    if row.type == 'PushEvent':
        payload_data = json.loads(row.payload)
        for commit in payload_data.get('commits', []):
            commits.append({
                'sha': commit['sha'],
                'message': commit['message'],
                'timestamp': row.created_at
            })

for c in commits:
    print(f"{c['timestamp']}: {c['sha'][:8]} - {c['message']}")
```

**Evidence Recovery**:
- `CreateEvent` reveals repository creation timestamp
- `PushEvent` records contain commit SHAs and metadata
- Commit SHAs can be used to recover code content via other archives or forks
- **Investigation Outcome**: Complete reconstruction of attacker's staging infrastructure

**Real Example**: `lkmanka58/code_whisperer` repository deleted after attack, but GitHub Archive revealed June 13 creation with 3 commits containing AWS IAM role assumption attempts.

### Deleted Tag Analysis

**Scenario**: Malicious tag used for payload delivery, then deleted to hide evidence.

**Step 1: Search for Tag Events**
```sql
SELECT
    type,
    created_at,
    actor.login,
    JSON_EXTRACT_SCALAR(payload, '$.ref') as tag_name,
    JSON_EXTRACT_SCALAR(payload, '$.ref_type') as ref_type
FROM `githubarchive.day.20250713`
WHERE
    repo.name = 'target/repository'
    AND type IN ('CreateEvent', 'DeleteEvent')
    AND JSON_EXTRACT_SCALAR(payload, '$.ref_type') = 'tag'
ORDER BY created_at
```

**Timeline Reconstruction**:
```
2025-07-13 19:41:44 UTC | CreateEvent | aws-toolkit-automation | tag 'stability'
2025-07-13 20:30:24 UTC | PushEvent   | aws-toolkit-automation | commit references tag
2025-07-14 08:15:33 UTC | DeleteEvent | aws-toolkit-automation | tag 'stability' deleted
```

**Analysis**: 48-hour window between tag creation and deletion reveals staging period for attack infrastructure.

**Real Example**: Amazon Q attack used 'stability' tag for malicious payload delivery. Tag was deleted, but `CreateEvent` in GitHub Archive preserved creation timestamp and actor, proving 48-hour staging window.

### Deleted Branch Reconstruction

**Scenario**: Attacker creates development branch with malicious code, pushes commits, then deletes branch after merging or to cover tracks.

**Step 1: Find Branch Lifecycle**
```sql
SELECT
    type,
    created_at,
    actor.login,
    JSON_EXTRACT_SCALAR(payload, '$.ref') as branch_name,
    JSON_EXTRACT_SCALAR(payload, '$.ref_type') as ref_type
FROM `githubarchive.day.2025*`
WHERE
    repo.name = 'target/repository'
    AND type IN ('CreateEvent', 'DeleteEvent')
    AND JSON_EXTRACT_SCALAR(payload, '$.ref_type') = 'branch'
ORDER BY created_at
```

**Step 2: Extract All Commit SHAs from Deleted Branch**
```sql
SELECT
    created_at,
    actor.login as pusher,
    JSON_EXTRACT_SCALAR(payload, '$.ref') as branch_ref,
    JSON_EXTRACT_SCALAR(commit, '$.sha') as commit_sha,
    JSON_EXTRACT_SCALAR(commit, '$.message') as commit_message,
    JSON_EXTRACT_SCALAR(commit, '$.author.name') as author_name,
    JSON_EXTRACT_SCALAR(commit, '$.author.email') as author_email
FROM `githubarchive.day.2025*`,
UNNEST(JSON_EXTRACT_ARRAY(payload, '$.commits')) as commit
WHERE
    repo.name = 'target/repository'
    AND type = 'PushEvent'
    AND JSON_EXTRACT_SCALAR(payload, '$.ref') = 'refs/heads/deleted-branch-name'
ORDER BY created_at
```

**Evidence Recovery**:
- **Commit SHAs**: All commit identifiers permanently recorded in `PushEvent` payload
- **Commit Messages**: Full commit messages preserved in commits array
- **Author Metadata**: Name and email from commit author field
- **Pusher Identity**: Actor who executed the push operation
- **Temporal Sequence**: Exact timestamps for each push operation
- **Branch Lifecycle**: Complete creation-to-deletion timeline

**Forensic Value**: Even after branch deletion, commit SHAs can be used to:
- Search for commits in forked repositories
- Check if commits were merged into other branches
- Search external code archives (Software Heritage, etc.)
- Reconstruct complete attack development timeline

### Automation vs Direct API Attribution

**Scenario**: Suspicious commits appear under automation account name. Determine if they came from legitimate GitHub Actions workflow execution or direct API abuse with compromised token.

**Step 1: Search for Workflow Events During Suspicious Window**
```python
query = """
SELECT
    type,
    created_at,
    actor.login,
    JSON_EXTRACT_SCALAR(payload, '$.workflow_run.name') as workflow_name,
    JSON_EXTRACT_SCALAR(payload, '$.workflow_run.head_sha') as commit_sha,
    JSON_EXTRACT_SCALAR(payload, '$.workflow_run.conclusion') as conclusion
FROM `githubarchive.day.20250713`
WHERE
    repo.name = 'org/repository'
    AND type IN ('WorkflowRunEvent', 'WorkflowJobEvent')
    AND created_at >= '2025-07-13T20:25:00Z'
    AND created_at <= '2025-07-13T20:35:00Z'
ORDER BY created_at
"""

workflow_events = list(client.query(query))
```

**Step 2: Establish Baseline Pattern**
```python
baseline_query = """
SELECT
    type,
    created_at,
    actor.login,
    JSON_EXTRACT_SCALAR(payload, '$.workflow_run.name') as workflow_name
FROM `githubarchive.day.20250713`
WHERE
    repo.name = 'org/repository'
    AND actor.login = 'automation-account'
    AND type = 'WorkflowRunEvent'
ORDER BY created_at
"""

baseline = list(client.query(baseline_query))
print(f"Total workflows for day: {len(baseline)}")
```

**Step 3: Analyze Results**
```python
if not workflow_events:
    print("🚨 DIRECT API ATTACK DETECTED")
    print("No WorkflowRunEvent during suspicious commit window")
    print("Commit was NOT from legitimate workflow execution")
else:
    print("✓ Legitimate workflow execution detected")
    for event in workflow_events:
        print(f"{event.created_at}: {event.workflow_name} - {event.conclusion}")
```

**Expected Results if Legitimate Workflow**:
```
2025-07-13 20:30:15 UTC | WorkflowRunEvent | deploy-automation | requested
2025-07-13 20:30:24 UTC | PushEvent        | aws-toolkit-automation | refs/heads/main
2025-07-13 20:31:08 UTC | WorkflowRunEvent | deploy-automation | completed
```

**Expected Results if Direct API Abuse**:
```
2025-07-13 20:30:24 UTC | PushEvent | aws-toolkit-automation | refs/heads/main
[NO WORKFLOW EVENTS IN ±10 MINUTE WINDOW]
```

**Investigation Outcome**: Absence of `WorkflowRunEvent` = Direct API attack with stolen token

**Real Example**: Amazon Q investigation needed to determine if malicious commit `678851bbe9776228f55e0460e66a6167ac2a1685` (pushed July 13, 2025 20:30:24 UTC by `aws-toolkit-automation`) came from compromised workflow or direct API abuse. GitHub Archive query showed ZERO `WorkflowRunEvent` or `WorkflowJobEvent` records during the 20:25-20:35 UTC window. Baseline analysis revealed the same automation account had 18 workflows that day, all clustered in 20:48-21:02 UTC. The temporal gap and complete workflow absence during the malicious commit proved direct API attack, not workflow compromise.

## Troubleshooting

**Permission denied errors**:
- Verify service account has `BigQuery User` role
- Check credentials file path is correct
- Ensure BigQuery API is enabled in Google Cloud project

**Query exceeds free tier (>1TB)**:
- Use daily tables instead of wildcard: `githubarchive.day.20250615`
- Add date filters: `WHERE created_at >= '2025-06-01' AND created_at < '2025-07-01'`
- Limit columns: Select only needed fields, not `SELECT *`
- Use monthly tables for broader searches: `githubarchive.month.202506`

**No results for known event**:
- Verify date range (archive starts Feb 12, 2011)
- Check timezone (GitHub Archive uses UTC)
- Confirm `actor.login` spelling (case-sensitive)
- Some events may take up to 1 hour to appear (hourly updates)

**Payload extraction returns NULL**:
- Verify JSON path exists with `JSON_EXTRACT()` before using `JSON_EXTRACT_SCALAR()`
- Check event type has that payload field (not all events have all fields)
- Inspect raw payload: `SELECT payload FROM ... LIMIT 1`

**Query timeout or slow performance**:
- Add `repo.name` filter when possible (significantly reduces data scanned)
- Use specific date ranges instead of wildcards
- Consider using monthly aggregated tables for long-term analysis
- Partition queries by date and run in parallel

### Force Push Recovery (Zero-Commit PushEvents)

**Scenario**: Developer accidentally commits secrets, then force pushes to "delete" the commit. The commit remains accessible on GitHub, but finding it requires knowing the SHA.

**Background**: When a developer runs `git reset --hard HEAD~1 && git push --force`, Git removes the reference to that commit from the branch. However:
- GitHub stores these "dangling" commits indefinitely
- GitHub Archive records the `before` SHA in PushEvent payloads
- Force pushes appear as PushEvents with zero commits (empty commits array)

**Step 1: Find All Zero-Commit PushEvents (Organization-Wide)**
```sql
SELECT
    created_at,
    actor.login,
    repo.name,
    JSON_EXTRACT_SCALAR(payload, '$.before') as deleted_commit_sha,
    JSON_EXTRACT_SCALAR(payload, '$.head') as current_head,
    JSON_EXTRACT_SCALAR(payload, '$.ref') as branch
FROM `githubarchive.day.2025*`
WHERE
    repo.name LIKE 'target-org/%'
    AND type = 'PushEvent'
    AND JSON_EXTRACT_SCALAR(payload, '$.size') = '0'
ORDER BY created_at DESC
```

**Step 2: Search for Specific Repository**
```sql
SELECT
    created_at,
    actor.login,
    JSON_EXTRACT_SCALAR(payload, '$.before') as deleted_commit_sha,
    JSON_EXTRACT_SCALAR(payload, '$.head') as after_sha,
    JSON_EXTRACT_SCALAR(payload, '$.ref') as branch
FROM `githubarchive.day.202506*`
WHERE
    repo.name = 'org/repository'
    AND type = 'PushEvent'
    AND JSON_EXTRACT_SCALAR(payload, '$.size') = '0'
ORDER BY created_at
```

**Step 3: Bulk Recovery Query**
```python
query = """
SELECT
    created_at,
    actor.login,
    repo.name,
    JSON_EXTRACT_SCALAR(payload, '$.before') as deleted_sha,
    JSON_EXTRACT_SCALAR(payload, '$.ref') as branch
FROM `githubarchive.year.2024`
WHERE
    type = 'PushEvent'
    AND JSON_EXTRACT_SCALAR(payload, '$.size') = '0'
    AND repo.name LIKE 'target-org/%'
"""

results = client.query(query)
deleted_commits = []
for row in results:
    deleted_commits.append({
        'timestamp': row.created_at,
        'actor': row.actor_login,
        'repo': row.repo_name,
        'deleted_sha': row.deleted_sha,
        'branch': row.branch
    })

print(f"Found {len(deleted_commits)} force-pushed commits to investigate")
```

**Evidence Recovery**:
- **`before` SHA**: The commit that was "deleted" by the force push
- **`head` SHA**: The commit the branch was reset to
- **`ref`**: Which branch was force pushed
- **`actor.login`**: Who performed the force push
- **Commit Access**: Use recovered SHA to access commit via GitHub API or web UI

**Forensic Applications**:
- **Secret Scanning**: Scan recovered commits for leaked credentials, API keys, tokens
- **Incident Timeline**: Identify when secrets were committed and when they were "hidden"
- **Attribution**: Determine who committed secrets and who attempted to cover them up
- **Compliance**: Prove data exposure window for breach notifications

**Real Example**: Security researcher Sharon Brizinov scanned all zero-commit PushEvents since 2020 across GitHub, recovering "deleted" commits and scanning them for secrets. This technique uncovered credentials worth $25k in bug bounties, including an admin-level GitHub PAT with access to all Istio repositories (36k stars, used by Google, IBM, Red Hat). The token could have enabled a massive supply-chain attack.

**Important Notes**:
- Force pushing does NOT delete commits from GitHub - they remain accessible via SHA
- GitHub Archive preserves the `before` SHA indefinitely
- Zero-commit PushEvents are the forensic fingerprint of history rewrites
- This technique provides 100% coverage of "deleted" commits (vs brute-forcing 4-char SHA prefixes)

## Learn More

- **GH Archive Documentation**: https://www.gharchive.org/
- **GitHub Event Types Schema**: https://docs.github.com/en/rest/using-the-rest-api/github-event-types
- **BigQuery Documentation**: https://cloud.google.com/bigquery/docs
- **BigQuery SQL Reference**: https://cloud.google.com/bigquery/docs/reference/standard-sql/query-syntax
- **Force Push Scanner Tool**: https://github.com/trufflesecurity/force-push-scanner
