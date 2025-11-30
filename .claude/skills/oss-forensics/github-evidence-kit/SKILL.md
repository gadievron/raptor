---
name: github-evidence-kit
description: Generate, export, load, and verify forensic evidence from GitHub sources. Use when creating verifiable evidence objects from GitHub API, GH Archive, Wayback Machine, local git repositories, or security vendor reports. Handles evidence storage, querying, and re-verification against original sources.
version: 2.0
author: mbrg
tags:
  - github
  - forensics
  - osint
  - evidence
  - verification
  - git
---

# GH Evidence Kit

**Purpose**: Create, store, and verify forensic evidence from GitHub-related public sources and local git repositories.

## When to Use This Skill

- Creating verifiable evidence objects from GitHub activity
- **Local git forensics** - analyzing cloned repositories, dangling commits, reflog
- Exporting evidence collections to JSON for sharing/archival
- Loading and re-verifying previously collected evidence
- Recovering deleted GitHub content (issues, PRs, commits) from GH Archive
- Tracking IOCs (Indicators of Compromise) with source verification

## Quick Start

```python
from src.collectors import GitHubAPICollector, LocalGitCollector, GHArchiveCollector
from src import EvidenceStore

# Create collectors for different sources
github = GitHubAPICollector()
local = LocalGitCollector("/path/to/repo")
archive = GHArchiveCollector()

# Collect evidence from GitHub API
commit = github.collect_commit("aws", "aws-toolkit-vscode", "678851b...")
pr = github.collect_pull_request("aws", "aws-toolkit-vscode", 7710)

# Collect evidence from local git (first-class forensic source)
local_commit = local.collect_commit("HEAD")
dangling = local.collect_dangling_commits()  # Forensic gold!

# Store and export
store = EvidenceStore()
store.add(commit)
store.add(pr)
store.add(local_commit)
store.add_all(dangling)
store.save("evidence.json")

# Verify all evidence against original sources
is_valid, errors = store.verify_all()
```

## Collectors

### GitHubAPICollector

Collects evidence from the live GitHub API.

```python
from src.collectors import GitHubAPICollector

collector = GitHubAPICollector()
```

| Method | Returns |
|--------|---------|
| `collect_commit(owner, repo, sha)` | CommitObservation |
| `collect_issue(owner, repo, number)` | IssueObservation |
| `collect_pull_request(owner, repo, number)` | IssueObservation |
| `collect_file(owner, repo, path, ref)` | FileObservation |
| `collect_branch(owner, repo, branch_name)` | BranchObservation |
| `collect_tag(owner, repo, tag_name)` | TagObservation |
| `collect_release(owner, repo, tag_name)` | ReleaseObservation |
| `collect_forks(owner, repo)` | list[ForkObservation] |

### LocalGitCollector (First-Class Forensics)

Collects evidence from local git repositories. Essential for forensic analysis of cloned repos.

```python
from src.collectors import LocalGitCollector

collector = LocalGitCollector("/path/to/cloned/repo")

# Collect a specific commit
commit = collector.collect_commit("HEAD")
commit = collector.collect_commit("abc123")

# Find dangling commits (not reachable from any ref)
# This is forensic gold - reveals force-pushed or deleted commits!
dangling = collector.collect_dangling_commits()
for commit in dangling:
    print(f"Found dangling: {commit.sha[:8]} - {commit.message}")
```

| Method | Returns |
|--------|---------|
| `collect_commit(sha)` | CommitObservation |
| `collect_dangling_commits()` | list[CommitObservation] |

### GHArchiveCollector

Collects and recovers evidence from GH Archive (BigQuery). Requires credentials.

```python
from src.collectors import GHArchiveCollector

collector = GHArchiveCollector()

# Query events by timestamp (YYYYMMDDHHMM format)
events = collector.collect_events(
    timestamp="202507132037",
    repo="aws/aws-toolkit-vscode"
)

# Recover deleted content
deleted_issue = collector.recover_issue("aws/aws-toolkit-vscode", 123, "2025-07-13T20:30:24Z")
deleted_pr = collector.recover_pr("aws/aws-toolkit-vscode", 7710, "2025-07-13T20:30:24Z")
deleted_commit = collector.recover_commit("aws/aws-toolkit-vscode", "678851b", "2025-07-13T20:30:24Z")
force_pushed = collector.recover_force_push("aws/aws-toolkit-vscode", "2025-07-13T20:30:24Z")
```

| Method | Returns |
|--------|---------|
| `collect_events(timestamp, repo, actor, event_type)` | list[Event] |
| `recover_issue(repo, number, timestamp)` | IssueObservation |
| `recover_pr(repo, number, timestamp)` | IssueObservation |
| `recover_commit(repo, sha, timestamp)` | CommitObservation |
| `recover_force_push(repo, timestamp)` | CommitObservation |

### WaybackCollector

Collects archived snapshots from the Wayback Machine.

```python
from src.collectors import WaybackCollector

collector = WaybackCollector()

# Get all snapshots for a URL
snapshots = collector.collect_snapshots("https://github.com/owner/repo")

# With date filtering
snapshots = collector.collect_snapshots(
    "https://github.com/owner/repo",
    from_date="20250101",
    to_date="20250731"
)

# Fetch actual content of a snapshot
content = collector.collect_snapshot_content(
    "https://github.com/owner/repo",
    "20250713203024"  # YYYYMMDDHHMMSS format
)
```

## Verification

Verification is separated from data collection. Use `ConsistencyVerifier` to validate evidence against original sources.

```python
from src.verifiers import ConsistencyVerifier

verifier = ConsistencyVerifier()

# Verify single evidence
result = verifier.verify(commit)
if not result.is_valid:
    print(f"Errors: {result.errors}")

# Verify multiple
result = verifier.verify_all([commit, pr, issue])
```

Or use the convenience method on `EvidenceStore`:

```python
store = EvidenceStore()
store.add_all([commit, pr, issue])
is_valid, errors = store.verify_all()
```

## EvidenceStore

Store, query, and export evidence collections.

```python
from src import EvidenceStore
from datetime import datetime

store = EvidenceStore()

# Add evidence
store.add(commit)
store.add_all([pr, issue, ioc])

# Query
commits = store.filter(observation_type="commit")
recent = store.filter(after=datetime(2025, 7, 1))
from_github = store.filter(source="github")
from_git = store.filter(source="git")
repo_events = store.filter(repo="aws/aws-toolkit-vscode")

# Export/Import
store.save("evidence.json")
store = EvidenceStore.load("evidence.json")

# Summary
print(store.summary())
# {'total': 5, 'events': {...}, 'observations': {...}, 'by_source': {...}}

# Verify all against sources
is_valid, errors = store.verify_all()
```

## Loading Evidence from JSON

```python
from src import load_evidence_from_json
import json

with open("evidence.json") as f:
    data = json.load(f)

for item in data:
    evidence = load_evidence_from_json(item)
    # Evidence is now a typed Pydantic model
```

## Evidence Types

### Events (from GH Archive)

All 12 GitHub event types are supported:

| Type | Description |
|------|-------------|
| PushEvent | Commits pushed |
| PullRequestEvent | PR opened/closed/merged |
| IssueEvent | Issue opened/closed |
| IssueCommentEvent | Comment on issue/PR |
| CreateEvent | Branch/tag created |
| DeleteEvent | Branch/tag deleted |
| ForkEvent | Repository forked |
| WatchEvent | Repository starred |
| MemberEvent | Collaborator added/removed |
| PublicEvent | Repository made public |
| ReleaseEvent | Release published/created/deleted |
| WorkflowRunEvent | GitHub Actions run |

### Observations (from GitHub API, Local Git, Wayback, Vendors)

| Type | Description | Sources |
|------|-------------|---------|
| CommitObservation | Commit metadata and files | GitHub, Git, GH Archive |
| IssueObservation | Issue or PR | GitHub, GH Archive |
| FileObservation | File content at ref | GitHub |
| BranchObservation | Branch HEAD | GitHub |
| TagObservation | Tag target | GitHub |
| ReleaseObservation | Release metadata | GitHub |
| ForkObservation | Fork relationship | GitHub |
| SnapshotObservation | Wayback snapshots | Wayback |
| IOC | Indicator of Compromise | Vendor |
| ArticleObservation | Security report/blog | Vendor |

## IOC Types

```python
from src import EvidenceSource, IOCType
from src.schema import IOC, VerificationInfo
from pydantic import HttpUrl
from datetime import datetime, timezone

# IOCs are created directly as schema objects
ioc = IOC(
    evidence_id="ioc-commit-sha-abc123",
    observed_when=datetime.now(timezone.utc),
    observed_by=EvidenceSource.SECURITY_VENDOR,
    observed_what="Malicious commit SHA found in vendor report",
    verification=VerificationInfo(
        source=EvidenceSource.SECURITY_VENDOR,
        url=HttpUrl("https://vendor.com/report")
    ),
    ioc_type=IOCType.COMMIT_SHA,
    value="678851bbe9776228f55e0460e66a6167ac2a1685",
)
```

Available IOC types: `COMMIT_SHA`, `FILE_PATH`, `FILE_HASH`, `CODE_SNIPPET`, `EMAIL`, `USERNAME`, `REPOSITORY`, `TAG_NAME`, `BRANCH_NAME`, `WORKFLOW_NAME`, `IP_ADDRESS`, `DOMAIN`, `URL`, `API_KEY`, `SECRET`

## Testing

### Run Unit Tests

```bash
cd .claude/skills/github-forensics/github-evidence-kit
pip install -r requirements.txt
pytest tests/ -v --ignore=tests/test_integration.py
```

### Run Integration Tests (Optional)

Integration tests hit real external services (GitHub API, BigQuery, vendor URLs):

```bash
# All integration tests
pytest tests/test_integration.py -v -m integration

# Skip integration tests in CI
pytest tests/ -v -m "not integration"
```

**Note**: GitHub API integration tests use 60 req/hr unauthenticated rate limit. BigQuery tests require credentials (see below).

## GCP BigQuery Credentials (for GH Archive)

GH Archive queries require Google Cloud BigQuery credentials. Two options:

### Option 1: JSON File Path

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
```

### Option 2: JSON Content in Environment Variable

Useful for `.env` files or CI secrets:

```bash
export GOOGLE_APPLICATION_CREDENTIALS='{"type":"service_account","project_id":"...","private_key":"..."}'
```

The client auto-detects JSON content vs file path.

### Setup Steps

1. Create a [Google Cloud Project](https://console.cloud.google.com/)
2. Enable BigQuery API
3. Create a Service Account with `BigQuery User` role
4. Download JSON credentials
5. Set `GOOGLE_APPLICATION_CREDENTIALS` env var

**Free Tier**: 1 TB/month of BigQuery queries included.

## Requirements

```bash
pip install -r requirements.txt
```

- `pydantic` - Schema validation
- `requests` - HTTP client
- `google-cloud-bigquery` - GH Archive queries (optional)
- `google-auth` - GCP authentication (optional)
