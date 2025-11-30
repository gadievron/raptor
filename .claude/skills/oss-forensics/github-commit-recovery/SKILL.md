---
name: github-commit-recovery
description: Recover deleted commits from GitHub using REST API, web interface, and git fetch. Use when you have commit SHAs and need to retrieve actual commit content, diffs, or patches. Includes techniques for accessing "deleted" commits that remain on GitHub servers.
version: 1.0
author: mbrg
tags:
  - github
  - git
  - forensics
  - recovery
  - osint
---

# GitHub Commit Recovery

**Purpose**: Access commit content, diffs, and metadata directly from GitHub when you have commit SHAs. Includes methods for retrieving "deleted" commits that remain accessible on GitHub servers.

## When to Use This Skill

- You have commit SHAs and need actual code content
- Investigating commits that were force-pushed over ("deleted")
- Need commit diffs, patches, or full file contents
- Verifying commit authorship or metadata
- Retrieving content from dangling commits

**SHA Sources**: GitHub Archive, git reflog, CI/CD logs, PR comments, issue references, external archives, security reports.

## Core Principles

**Deleted Commits Are Never Really Deleted**:
- When developers force push to "delete" commits, GitHub keeps them indefinitely
- Any commit SHA remains accessible if you know the hash
- GitHub displays a warning ("This commit does not belong to any branch") but serves the content
- Even 4 hex digits can access commits (with collision risk)

**Rate Limits Matter**:
- Authenticated API: 5,000 requests/hour
- Unauthenticated API: 60 requests/hour
- Web interface: Undocumented limits, WAF may block heavy usage
- Git operations: No explicit limit, but excessive cloning may trigger throttling

## Quick Start

**Access a "deleted" commit via web browser**:
```
https://github.com/org/repo/commit/FULL_COMMIT_SHA
```

**Get commit as patch file**:
```bash
curl -L https://github.com/org/repo/commit/FULL_COMMIT_SHA.patch
```

**Query via REST API**:
```bash
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/org/repo/commits/FULL_COMMIT_SHA
```

## Accessing Deleted Commits

### Method 1: Direct Web Access

GitHub serves "deleted" commits at predictable URLs. These commits show a warning banner but content remains fully accessible.

**Commit View**:
```
https://github.com/<ORG>/<REPO>/commit/<SHA>
```

**Patch Format** (raw diff with headers):
```
https://github.com/<ORG>/<REPO>/commit/<SHA>.patch
```

**Diff Format** (unified diff only):
```
https://github.com/<ORG>/<REPO>/commit/<SHA>.diff
```

**Example**:
```bash
# View commit that was force-pushed over
curl -L https://github.com/grapefruit623/gcloud-python/commit/e9c3d31212847723aec86ef96aba0a77f9387493

# Download as patch
curl -L -o leaked_commit.patch \
  https://github.com/grapefruit623/gcloud-python/commit/e9c3d31212847723aec86ef96aba0a77f9387493.patch
```

**Short SHA Access**: GitHub allows accessing commits with just 4+ hex characters (if unique):
```
https://github.com/org/repo/commit/e9c3
```

### Method 2: REST API

The GitHub REST API provides structured commit data including file changes, author info, and commit message.

**Endpoint**:
```
GET https://api.github.com/repos/{owner}/{repo}/commits/{ref}
```

**Example Request**:
```bash
curl -H "Accept: application/vnd.github+json" \
     -H "Authorization: Bearer $GITHUB_TOKEN" \
     https://api.github.com/repos/org/repo/commits/abc123def456
```

**Response Structure**:
```json
{
  "sha": "abc123def456...",
  "commit": {
    "author": {
      "name": "Developer Name",
      "email": "dev@example.com",
      "date": "2025-06-15T14:23:11Z"
    },
    "message": "Commit message here"
  },
  "files": [
    {
      "filename": "src/config.js",
      "status": "added",
      "patch": "@@ -0,0 +1,3 @@\n+// config"
    }
  ]
}
```

**Rate Limit Headers**:
```
x-ratelimit-limit: 5000
x-ratelimit-remaining: 4999
x-ratelimit-reset: 1623456789
```

### Method 3: Git Fetch

For bulk analysis or when you need full repository context, fetch specific commits via Git.

**Minimal Clone + Fetch Specific Commit**:
```bash
# Clone without file contents (just history/trees/commits)
git clone --filter=blob:none --no-checkout https://github.com/org/repo.git
cd repo

# Fetch the specific "deleted" commit
git fetch origin <COMMIT_SHA>

# View the commit
git show FETCH_HEAD

# View specific file from that commit
git show FETCH_HEAD:path/to/file.txt
```

**Why This Works**:
- `--filter=blob:none`: Omits file contents initially (fast clone)
- `--no-checkout`: Doesn't populate working directory
- `git fetch origin <SHA>`: Retrieves specific commit even if "deleted"
- Blobs are fetched on-demand when you access them

## Investigation Patterns

### Batch Download Patches

**Scenario**: You have a list of commit SHAs to investigate and need their content.

```python
import requests
import time

def download_commit_patch(repo, sha, token=None):
    url = f"https://github.com/{repo}/commit/{sha}.patch"
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    response = requests.get(url, headers=headers, allow_redirects=True)
    if response.status_code == 200:
        return response.text
    return None

# Download patches for a list of commits
commits = [
    {"repo": "org/repo1", "sha": "abc123..."},
    {"repo": "org/repo2", "sha": "def456..."},
]

for commit in commits:
    patch = download_commit_patch(commit["repo"], commit["sha"])
    if patch:
        with open(f"{commit['sha'][:8]}.patch", "w") as f:
            f.write(patch)
    time.sleep(0.5)  # Rate limit courtesy
```

### Verifying Commit Authorship

**Scenario**: Need to verify who actually authored a suspicious commit (committer vs author can differ).

**API Query**:
```bash
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/repos/org/repo/commits/SHA" | \
  jq '{
    author: .commit.author,
    committer: .commit.committer,
    verified: .commit.verification.verified
  }'
```

**Response Analysis**:
```json
{
  "author": {
    "name": "Real Developer",
    "email": "dev@company.com",
    "date": "2025-06-15T10:00:00Z"
  },
  "committer": {
    "name": "CI Bot",
    "email": "bot@company.com",
    "date": "2025-06-15T10:05:00Z"
  },
  "verified": false
}
```

**Forensic Notes**:
- Author: Who wrote the code (can be forged via `git commit --author`)
- Committer: Who created the commit object
- Verified: Whether commit has valid GPG signature
- Discrepancies between author/committer warrant investigation

## Real-World Examples

### Istio Supply Chain Attack Prevention

**Discovery**: Security researcher Sharon Brizinov used GitHub Archive to find zero-commit PushEvents, recovering commit SHAs of "deleted" commits. Using GitHub API to fetch commit content, discovered a leaked GitHub PAT token.

**Impact**: The token had admin access to ALL Istio repositories (36k stars, used by Google, IBM, Red Hat). Could have enabled:
- Reading environment variables and secrets
- Modifying CI/CD pipelines
- Pushing malicious code releases
- Deleting entire repositories

**Resolution**: Reported via Istio's security disclosure process; token was immediately revoked.

**Technique Chain**:
1. GitHub Archive → Found zero-commit PushEvent with `before` SHA
2. GitHub API → `GET /repos/istio/istio/commits/{SHA}.patch`
3. TruffleHog → Identified valid GitHub PAT in commit diff
4. GitHub API → Verified token permissions via `/user` endpoint

### High-Value Secret Categories

From scanning recovered force-pushed commits, the most impactful secrets found in order:
1. **GitHub PATs** - Often have org-wide or admin permissions
2. **AWS Credentials** - IAM keys with production access
3. **MongoDB Connection Strings** - Direct database access
4. **API Keys** - Stripe, Twilio, SendGrid with billing access

**Files Most Likely to Contain Secrets**:
- `.env`, `.env.local`, `.env.production`
- `config.js`, `config.py`, `config.json`
- `docker-compose.yml`, `docker-compose.yaml`
- `application.properties`, `application.yml`
- `hardhat.config.js` (crypto/web3 projects)

## Troubleshooting

**403 Forbidden on API requests**:
- Check authentication token is valid
- Verify token has required scopes (`repo` for private repos)
- May have hit rate limit - check `x-ratelimit-remaining` header

**404 Not Found for commit**:
- Verify SHA is complete (at least 7 characters recommended)
- Repository may have been deleted (try searching forks)
- Commit may be in private repo (requires authenticated access)

**Rate limit exceeded**:
- Wait for reset (check `x-ratelimit-reset` header for Unix timestamp)
- Use authenticated requests for 5000/hour vs 60/hour
- Implement exponential backoff in automation

**Web access blocked by WAF**:
- Reduce request frequency
- Use API instead of web scraping
- Consider using Git fetch method for bulk operations

**Git fetch fails for commit**:
- Some very old dangling commits may be garbage collected (rare)
- Try accessing via web interface first to confirm availability
- Check if repo has been transferred to different org

## Learn More

- **GitHub REST API**: https://docs.github.com/en/rest
- **GitHub Commit API**: https://docs.github.com/en/rest/commits/commits
