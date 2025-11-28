---
name: github-wayback-recovery
description: Recover deleted GitHub content using the Wayback Machine and Archive.org APIs. Use when repositories, files, issues, PRs, or wiki pages have been deleted from GitHub but may persist in web archives. Covers CDX API queries, URL patterns, and systematic recovery workflows.
version: 1.0
author: mbrg
tags:
  - github
  - wayback
  - archive
  - osint
  - forensics
  - recovery
---

# GitHub Wayback Recovery

**Purpose**: Recover deleted GitHub content (README files, issues, PRs, wiki pages, repository metadata) from the Internet Archive's Wayback Machine when content is no longer available on GitHub.

## When to Use This Skill

- Repository has been deleted and you need README, wiki, or metadata
- Issues or PRs were deleted by author, maintainer, or moderation
- Need to recover file contents that may have been archived
- Investigating historical state of a repository
- Finding forks of deleted repositories via archived network pages
- Recovering release notes or documentation from deleted projects

**Complementary Skills**:
- **github-archive**: For structured event data (who did what, when) - always check first
- **github-commit-recovery**: For accessing commits when you have SHAs
- **github-wayback-recovery** (this skill): For web page snapshots when content is fully deleted

## Core Principles

**Wayback Machine Archives Web Pages, Not Git Repositories**:
- Cannot `git clone` from archived content
- Cannot reconstruct full commit history
- Recovery success depends on whether specific URLs were crawled

**What CAN Be Recovered**:
- README files and repository descriptions
- Issue titles, bodies, and comments (Archive Team prioritizes these)
- PR conversations and descriptions (Files Changed tab often fails)
- Wiki pages (especially wiki home)
- Release notes and descriptions
- Repository metadata (stars, language, license visible on homepage)
- Commit SHAs from archived commit list pages (use with **github-commit-recovery** skill to access actual content)

**What CANNOT Be Recovered**:
- Private repository content (never crawled)
- Complete git history or repository clone
- Content behind authentication

## Quick Start

**Check if a repository page was archived**:
```bash
curl -s "https://archive.org/wayback/available?url=github.com/owner/repo" | jq
```

**Search for all archived URLs under a repository**:
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=github.com/owner/repo/*&output=json&collapse=urlkey" | head -50
```

**Access an archived snapshot**:
```
https://web.archive.org/web/{TIMESTAMP}/https://github.com/owner/repo
```

## GitHub URL Patterns for Archive Searches

Understanding GitHub's URL structure is essential for constructing archive queries.

### Repository-Level URLs

| Content Type | URL Pattern |
|--------------|-------------|
| Homepage | `github.com/{owner}/{repo}` |
| Commits list | `github.com/{owner}/{repo}/commits/{branch}` |
| Individual commit | `github.com/{owner}/{repo}/commit/{full-sha}` |
| Fork network | `github.com/{owner}/{repo}/network/members` |

### File and Directory URLs

| Content Type | URL Pattern |
|--------------|-------------|
| File view | `github.com/{owner}/{repo}/blob/{branch}/{path/to/file}` |
| Directory view | `github.com/{owner}/{repo}/tree/{branch}/{directory}` |
| File history | `github.com/{owner}/{repo}/commits/{branch}/{path/to/file}` |
| Raw file | `raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}` |

**Note**: `blob` = files, `tree` = directories. Raw URLs are rarely archived compared to rendered views.

### Collaboration Artifacts

| Content Type | URL Pattern |
|--------------|-------------|
| Pull request | `github.com/{owner}/{repo}/pull/{number}` |
| PR files | `github.com/{owner}/{repo}/pull/{number}/files` |
| PR commits | `github.com/{owner}/{repo}/pull/{number}/commits` |
| Issue | `github.com/{owner}/{repo}/issues/{number}` |
| Wiki page | `github.com/{owner}/{repo}/wiki/{page-name}` |
| Release | `github.com/{owner}/{repo}/releases/tag/{tag-name}` |
| All PRs | `github.com/{owner}/{repo}/pulls?state=all` |
| All issues | `github.com/{owner}/{repo}/issues?state=all` |

## CDX API Reference

The Capture Index (CDX) API provides structured search across all archived URLs.

### Basic Query Structure

```
https://web.archive.org/cdx/search/cdx?url={URL}&output=json
```

### Essential Parameters

| Parameter | Effect | Example |
|-----------|--------|---------|
| `matchType=exact` | Exact URL only (default) | Single page |
| `matchType=prefix` | All URLs starting with path | All repo content |
| `url=.../*` | Wildcard (same as prefix) | `github.com/owner/repo/*` |
| `from=YYYY` | Start date filter | `from=2023` |
| `to=YYYY` | End date filter | `to=2024` |
| `filter=statuscode:200` | Only successful captures | Skip redirects/errors |
| `collapse=timestamp:8` | One capture per day | Reduce duplicates |
| `collapse=urlkey` | Unique URLs only | List all archived pages |
| `limit=N` | Limit results | `limit=100` |
| `output=json` | JSON format | Machine-readable |

### Query Examples

**Find all archived pages under a repository**:
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=github.com/facebook/react/*&matchType=prefix&output=json&collapse=urlkey"
```

**Find archived issues for a specific repository**:
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=github.com/owner/repo/issues/*&output=json&collapse=urlkey&filter=statuscode:200"
```

**Find archived snapshots of a specific file**:
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=github.com/owner/repo/blob/*/path/to/file&output=json"
```

**Check for archived snapshots near a specific date**:
```bash
curl -s "https://archive.org/wayback/available?url=github.com/owner/repo&timestamp=20230615"
```

### CDX Response Format

```json
[
  ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
  ["com,github)/owner/repo", "20230615142311", "https://github.com/owner/repo", "text/html", "200", "ABC123...", "12345"]
]
```

## Investigation Patterns

### Recovering Deleted File Contents

**Scenario**: Repository or file has been deleted, need to recover file contents.

**Step 1: Search for blob URLs**
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=github.com/owner/repo/blob/*/README.md&output=json"
```

**Step 2: Construct archive URL from timestamp**
```
https://web.archive.org/web/20230615142311/https://github.com/owner/repo/blob/main/README.md
```

**Step 3: Extract content manually or use waybackpack**
```bash
pip install waybackpack
waybackpack "https://github.com/owner/repo/blob/main/README.md" -d output_dir
```

**Forensic Value**: Recover documentation, configuration files, or evidence that existed at specific points in time.

### Recovering Deleted Issue/PR Content

**Scenario**: Issue or PR was deleted and you need the original content.

**Step 1: Query for issue page snapshots**
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=github.com/owner/repo/issues/123*&output=json"
```

**Step 2: Access archived page**
```
https://web.archive.org/web/{TIMESTAMP}/https://github.com/owner/repo/issues/123
```

**Step 3: If issue number unknown, search PR/issue listing**
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=github.com/owner/repo/issues?state=all&output=json"
```

**Note**: Archive Team actively crawls GitHub issues and PRs since 2020. Issue content has higher recovery success than file contents.

### Finding Forks of Deleted Repositories

**Scenario**: Repository is deleted, but forks may contain the full git history.

**Step 1: Search for archived fork network page**
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=github.com/owner/repo/network/members&output=json"
```

**Step 2: Access archived network page**
```
https://web.archive.org/web/{TIMESTAMP}/https://github.com/owner/repo/network/members
```

**Step 3: Extract fork usernames from archived page, check if forks still exist**
```bash
# Check if fork exists
curl -s -o /dev/null -w "%{http_code}" https://github.com/forker/repo
```

**Forensic Value**: Active forks contain complete git history including all commits. This often yields better results than trying to recover individual files.

### Recovering Wiki Content

**Scenario**: Repository wiki has been deleted or made private.

**Step 1: Search for wiki pages**
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=github.com/owner/repo/wiki*&output=json&collapse=urlkey"
```

**Step 2: Access wiki home or specific pages**
```
https://web.archive.org/web/{TIMESTAMP}/https://github.com/owner/repo/wiki
https://web.archive.org/web/{TIMESTAMP}/https://github.com/owner/repo/wiki/Page-Name
```

## Python Implementation

```python
import requests
import json
from typing import Optional, List, Dict
from time import sleep

class WaybackGitHubRecovery:
    CDX_API = "https://web.archive.org/cdx/search/cdx"
    AVAILABILITY_API = "https://archive.org/wayback/available"
    ARCHIVE_URL = "https://web.archive.org/web"

    def check_availability(self, url: str, timestamp: Optional[str] = None) -> Optional[Dict]:
        """Check if URL has any archived snapshots."""
        params = {"url": url}
        if timestamp:
            params["timestamp"] = timestamp

        resp = requests.get(self.AVAILABILITY_API, params=params)
        data = resp.json()

        if data.get("archived_snapshots", {}).get("closest"):
            return data["archived_snapshots"]["closest"]
        return None

    def search_cdx(self, url: str, match_type: str = "prefix",
                   collapse: str = "urlkey", limit: int = 1000) -> List[Dict]:
        """Search CDX API for archived URLs."""
        params = {
            "url": url,
            "output": "json",
            "matchType": match_type,
            "collapse": collapse,
            "filter": "statuscode:200",
            "limit": limit
        }

        resp = requests.get(self.CDX_API, params=params)
        data = resp.json()

        if len(data) <= 1:  # Only header row
            return []

        headers = data[0]
        results = []
        for row in data[1:]:
            results.append(dict(zip(headers, row)))

        return results

    def find_repository_content(self, owner: str, repo: str) -> Dict[str, List]:
        """Find all archived content for a repository."""
        base_url = f"github.com/{owner}/{repo}"

        results = {
            "homepage": self.search_cdx(base_url, match_type="exact"),
            "issues": self.search_cdx(f"{base_url}/issues/*"),
            "pulls": self.search_cdx(f"{base_url}/pull/*"),
            "wiki": self.search_cdx(f"{base_url}/wiki*"),
            "files": self.search_cdx(f"{base_url}/blob/*"),
            "network": self.search_cdx(f"{base_url}/network/members", match_type="exact"),
        }

        return results

    def get_archived_page(self, url: str, timestamp: str) -> Optional[str]:
        """Retrieve archived page content."""
        archive_url = f"{self.ARCHIVE_URL}/{timestamp}/{url}"
        resp = requests.get(archive_url)

        if resp.status_code == 200:
            return resp.text
        return None

    def find_forks(self, owner: str, repo: str) -> List[str]:
        """Find potential forks from archived network page."""
        network_results = self.search_cdx(
            f"github.com/{owner}/{repo}/network/members",
            match_type="exact"
        )

        forks = []
        if network_results:
            # Get most recent snapshot
            latest = network_results[-1]
            content = self.get_archived_page(
                f"https://github.com/{owner}/{repo}/network/members",
                latest["timestamp"]
            )
            if content:
                # Extract fork usernames (simplified - would need HTML parsing)
                # Look for patterns like href="/username/repo"
                import re
                pattern = rf'href="/([^/]+)/{repo}"'
                matches = re.findall(pattern, content)
                forks = list(set(matches) - {owner})

        return forks


# Usage Example
recovery = WaybackGitHubRecovery()

# Check if repository homepage was archived
snapshot = recovery.check_availability("https://github.com/deleted-user/deleted-repo")
if snapshot:
    print(f"Archived at: {snapshot['url']}")
    print(f"Timestamp: {snapshot['timestamp']}")

# Find all archived content
content = recovery.find_repository_content("deleted-user", "deleted-repo")
print(f"Found {len(content['issues'])} archived issue pages")
print(f"Found {len(content['files'])} archived file pages")

# Find potential forks
forks = recovery.find_forks("deleted-user", "deleted-repo")
for fork in forks:
    print(f"Potential fork: github.com/{fork}/deleted-repo")
```

## Limitations and Considerations

### Technical Limitations

- **JavaScript-rendered content**: GitHub's modern interface uses AJAX; archived pages may have broken file trees, blame views, and navigation
- **Raw file downloads**: `raw.githubusercontent.com` URLs are rarely archived
- **Binary assets**: Release binaries and attachments typically fail to archive

### Rate Limiting

Archive.org has undocumented rate limits:
- Sustainable rate: ~100 requests/minute
- Implement exponential backoff if you receive 429 responses
- Use `collapse` parameters to reduce result count
- Cache results locally for repeated analysis

## Troubleshooting

**No archived snapshots found**:
- Repository may be too new or obscure for crawling
- Try searching with wildcards: `github.com/owner/repo/*`
- Check if repo was ever public (private repos not crawled)

**Archived page shows broken layout**:
- Normal for JavaScript-heavy pages
- Try "View Source" to extract text content
- Use older timestamps (pre-2020 GitHub had simpler rendering)

**CDX API returns empty results**:
- Verify URL format (no trailing slashes, correct case)
- Try `matchType=prefix` instead of exact
- Remove `filter=statuscode:200` to see all captures

**Rate limited by Archive.org**:
- Implement delays between requests (1-2 seconds)
- Use `collapse=timestamp:8` to reduce duplicates
- Download during off-peak hours

## Learn More

- **Wayback Machine CDX API**: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
- **Archive Team GitHub Project**: https://wiki.archiveteam.org/index.php/GitHub
- **Internet Archive Python Library**: https://archive.org/services/docs/api/internetarchive/
- **waybackpy Documentation**: https://pypi.org/project/waybackpy/
