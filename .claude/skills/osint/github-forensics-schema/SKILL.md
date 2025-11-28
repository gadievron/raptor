---
name: github-forensics-schema
description: Pydantic schema for GitHub forensic evidence. Event (when/who/what) and Observation (original + observer perspectives).
version: 3.0
author: mbrg
tags: [github, forensics, schema, pydantic, osint]
---

# GitHub Forensics Evidence Schema

## Two Evidence Types

```
EVENT - Something that happened
├── when: when it happened
├── who: who did it
├── what: what they did
└── Sources: GH Archive, git

OBSERVATION - Something we observed
├── original_when: when it actually happened (if known)
├── original_who: who actually did it (if known)
├── original_what: what actually happened (if known)
├── observed_when: when we/they found it
├── observed_by: who observed (wayback, vendor, github)
├── observed_what: what was found
└── Sources: GitHub, Wayback, security vendors
```

## Sources

| Source | For |
|--------|-----|
| `GHARCHIVE` | Events (BigQuery) |
| `GIT` | Events (local git) |
| `GITHUB` | Observations (API/web) |
| `WAYBACK` | Observations (archive.org) |
| `SECURITY_VENDOR` | Observations/IOCs (blogs) |

## Events

| Type | What |
|------|------|
| `PushEvent` | Pushed commits |
| `PullRequestEvent` | PR action |
| `IssueEvent` | Issue action |
| `IssueCommentEvent` | Comment |
| `CreateEvent` | Branch/tag created |
| `DeleteEvent` | Branch/tag deleted |
| `ForkEvent` | Repo forked |
| `WorkflowRunEvent` | GitHub Actions |
| `ReleaseEvent` | Release |
| `WatchEvent` | Starred |
| `MemberEvent` | Collaborator |
| `PublicEvent` | Made public |

## Observations

| Type | What |
|------|------|
| `CommitObservation` | Full commit |
| `ForcePushedCommitRef` | Overwritten commit |
| `WaybackObservation` | Wayback snapshots |
| `RecoveredIssue` | Issue/PR content |
| `RecoveredFile` | File content |
| `RecoveredWiki` | Wiki content |
| `RecoveredForks` | Fork list |
| `IOC` | Indicator of Compromise |

## IOC Types

`commit_sha`, `file_path`, `file_hash`, `code_snippet`, `email`, `username`, `repository`, `tag_name`, `branch_name`, `workflow_name`, `ip_address`, `domain`, `url`, `api_key`, `secret`

## Examples

### Event

```python
PushEvent(
    evidence_id="push-001",
    when=datetime(2025, 7, 13, 20, 30),
    who=GitHubActor(login="attacker"),
    what="Force pushed to main",
    repository=GitHubRepository(...),
    verification=VerificationInfo(source=EvidenceSource.GHARCHIVE),
    ref="refs/heads/main",
    before_sha="abc...",
    after_sha="def...",
    size=0,
    is_force_push=True
)
```

### Observation

```python
IOC(
    evidence_id="ioc-001",
    # Original event (if known)
    original_when=datetime(2025, 7, 13, 20, 30),
    original_who=GitHubActor(login="attacker"),
    original_what="Malicious commit to main",
    # Observer
    observed_when=datetime(2025, 7, 14, 10, 0),
    observed_by=EvidenceSource.SECURITY_VENDOR,
    observed_what="Malicious commit SHA reported",
    # IOC fields
    ioc_type=IOCType.COMMIT_SHA,
    value="678851bbe9776228...",
    confidence="confirmed",
    verification=VerificationInfo(source=EvidenceSource.SECURITY_VENDOR)
)
```
