"""
GitHub Forensics Evidence Creation Functions (OSINT)

Factory for creating verified evidence objects from public sources.
Consumer provides identifiers + source, we look up and verify independently.

All sources are public - no authentication required:
- GHArchive: BigQuery for Events (immutable, free 1TB/month)
- GitHub: REST API for Observations (60 req/hr unauthenticated)
- Wayback: CDX API for archived Observations (public)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from pydantic import HttpUrl

from ._helpers import (
    generate_evidence_id,
    make_actor,
    make_repo,
    parse_datetime_strict,
)
from ._schema import (
    AnyEvent,
    ArticleObservation,
    BranchObservation,
    CommitAuthor,
    CommitObservation,
    EvidenceSource,
    FileChange,
    FileObservation,
    ForkObservation,
    GitHubActor,
    IOC,
    IOCType,
    IssueObservation,
    ReleaseObservation,
    SnapshotObservation,
    TagObservation,
    VerificationInfo,
    WaybackSnapshot,
)
from ._clients import GHArchiveClient, GitHubClient, WaybackClient
from ._parsers import parse_gharchive_event


class EvidenceFactory:
    """Factory for creating verified OSINT evidence objects.

    All data sources are public and require no authentication:
    - GitHub API: Public repos, commits, issues, PRs (60 req/hr)
    - Wayback Machine: Archived web pages
    - GH Archive: BigQuery (requires GCP project, free tier: 1TB/month)

    Usage:
        factory = EvidenceFactory()

        # From GitHub API
        commit = factory.commit("aws", "aws-toolkit-vscode", "678851b...")
        pr = factory.pull_request("aws", "aws-toolkit-vscode", 7710)

        # From GH Archive
        events = factory.events_from_gharchive("202507132037", repo="aws/aws-toolkit-vscode")

        # IOC with verification
        ioc = factory.ioc(IOCType.COMMIT_SHA, "678851b...", "https://vendor.com/report")
    """

    def __init__(
        self,
        gharchive_credentials: str | None = None,
        gharchive_project: str | None = None,
    ):
        self._github_client: GitHubClient | None = None
        self._wayback_client: WaybackClient | None = None
        self._gharchive_client: GHArchiveClient | None = None
        self._gharchive_credentials = gharchive_credentials
        self._gharchive_project = gharchive_project

    @property
    def github(self) -> GitHubClient:
        if self._github_client is None:
            self._github_client = GitHubClient()
        return self._github_client

    @property
    def wayback(self) -> WaybackClient:
        if self._wayback_client is None:
            self._wayback_client = WaybackClient()
        return self._wayback_client

    @property
    def gharchive(self) -> GHArchiveClient:
        if self._gharchive_client is None:
            self._gharchive_client = GHArchiveClient(
                credentials_path=self._gharchive_credentials,
                project_id=self._gharchive_project,
            )
        return self._gharchive_client

    # =========================================================================
    # GITHUB API METHODS
    # =========================================================================

    def commit(self, owner: str, repo: str, sha: str) -> CommitObservation:
        """Create CommitObservation from GitHub API."""
        data = self.github.get_commit(owner, repo, sha)
        commit = data["commit"]
        now = datetime.now(timezone.utc)

        files = [
            FileChange(
                filename=f["filename"],
                status=f.get("status", "modified"),
                additions=f.get("additions", 0),
                deletions=f.get("deletions", 0),
                patch=f.get("patch"),
            )
            for f in data.get("files", [])
        ]

        author = commit["author"]
        committer = commit["committer"]
        gh_author = data.get("author") or {}

        return CommitObservation(
            evidence_id=generate_evidence_id("commit", f"{owner}/{repo}", data["sha"]),
            original_when=parse_datetime_strict(committer.get("date")),
            original_who=make_actor(gh_author.get("login", author.get("name", "unknown"))),
            original_what=commit.get("message", "").split("\n")[0],
            observed_when=now,
            observed_by=EvidenceSource.GITHUB,
            observed_what=f"Commit {data['sha'][:8]} observed via GitHub API",
            repository=make_repo(owner, repo),
            verification=VerificationInfo(
                source=EvidenceSource.GITHUB,
                url=HttpUrl(f"https://github.com/{owner}/{repo}/commit/{data['sha']}"),
            ),
            sha=data["sha"],
            message=commit.get("message", ""),
            author=CommitAuthor(
                name=author.get("name", ""),
                email=author.get("email", ""),
                date=parse_datetime_strict(author.get("date")),
            ),
            committer=CommitAuthor(
                name=committer.get("name", ""),
                email=committer.get("email", ""),
                date=parse_datetime_strict(committer.get("date")),
            ),
            parents=[p["sha"] for p in data.get("parents", [])],
            files=files,
            is_dangling=False,
        )

    def issue(self, owner: str, repo: str, number: int) -> IssueObservation:
        """Create IssueObservation from GitHub API."""
        return self._create_issue_observation(owner, repo, number, is_pr=False)

    def pull_request(self, owner: str, repo: str, number: int) -> IssueObservation:
        """Create IssueObservation for PR from GitHub API."""
        return self._create_issue_observation(owner, repo, number, is_pr=True)

    def _create_issue_observation(
        self, owner: str, repo: str, number: int, is_pr: bool
    ) -> IssueObservation:
        """Internal: Create issue/PR observation."""
        if is_pr:
            data = self.github.get_pull_request(owner, repo, number)
        else:
            data = self.github.get_issue(owner, repo, number)

        now = datetime.now(timezone.utc)
        state = data.get("state", "open")
        if data.get("merged"):
            state = "merged"

        return IssueObservation(
            evidence_id=generate_evidence_id("issue", f"{owner}/{repo}", str(number)),
            original_when=parse_datetime_strict(data.get("created_at")),
            original_who=make_actor(data.get("user", {}).get("login", "unknown")),
            original_what=f"{'PR' if is_pr else 'Issue'} #{number} created",
            observed_when=now,
            observed_by=EvidenceSource.GITHUB,
            observed_what=f"{'PR' if is_pr else 'Issue'} #{number} observed via GitHub API",
            repository=make_repo(owner, repo),
            verification=VerificationInfo(
                source=EvidenceSource.GITHUB,
                url=HttpUrl(f"https://github.com/{owner}/{repo}/{'pull' if is_pr else 'issues'}/{number}"),
            ),
            issue_number=number,
            is_pull_request=is_pr,
            title=data.get("title"),
            body=data.get("body"),
            state=state,
            is_deleted=False,
        )

    def file(self, owner: str, repo: str, path: str, ref: str = "HEAD") -> FileObservation:
        """Create FileObservation from GitHub API."""
        import base64
        import hashlib

        data = self.github.get_file(owner, repo, path, ref)
        now = datetime.now(timezone.utc)

        content = ""
        if data.get("content"):
            content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        return FileObservation(
            evidence_id=generate_evidence_id("file", f"{owner}/{repo}", path, ref),
            observed_when=now,
            observed_by=EvidenceSource.GITHUB,
            observed_what=f"File {path} at {ref} observed via GitHub API",
            repository=make_repo(owner, repo),
            verification=VerificationInfo(
                source=EvidenceSource.GITHUB,
                url=HttpUrl(f"https://github.com/{owner}/{repo}/blob/{ref}/{path}"),
            ),
            file_path=path,
            branch=ref if ref != "HEAD" else None,
            content_hash=content_hash,
            size_bytes=data.get("size", 0),
        )

    def branch(self, owner: str, repo: str, branch_name: str) -> BranchObservation:
        """Create BranchObservation from GitHub API."""
        data = self.github.get_branch(owner, repo, branch_name)
        now = datetime.now(timezone.utc)

        return BranchObservation(
            evidence_id=generate_evidence_id("branch", f"{owner}/{repo}", branch_name),
            observed_when=now,
            observed_by=EvidenceSource.GITHUB,
            observed_what=f"Branch {branch_name} observed via GitHub API",
            repository=make_repo(owner, repo),
            verification=VerificationInfo(
                source=EvidenceSource.GITHUB,
                url=HttpUrl(f"https://github.com/{owner}/{repo}/tree/{branch_name}"),
            ),
            branch_name=branch_name,
            head_sha=data.get("commit", {}).get("sha"),
            protected=data.get("protected", False),
        )

    def tag(self, owner: str, repo: str, tag_name: str) -> TagObservation:
        """Create TagObservation from GitHub API."""
        data = self.github.get_tag(owner, repo, tag_name)
        now = datetime.now(timezone.utc)

        return TagObservation(
            evidence_id=generate_evidence_id("tag", f"{owner}/{repo}", tag_name),
            observed_when=now,
            observed_by=EvidenceSource.GITHUB,
            observed_what=f"Tag {tag_name} observed via GitHub API",
            repository=make_repo(owner, repo),
            verification=VerificationInfo(
                source=EvidenceSource.GITHUB,
                url=HttpUrl(f"https://github.com/{owner}/{repo}/releases/tag/{tag_name}"),
            ),
            tag_name=tag_name,
            target_sha=data.get("object", {}).get("sha"),
        )

    def release(self, owner: str, repo: str, tag_name: str) -> ReleaseObservation:
        """Create ReleaseObservation from GitHub API."""
        data = self.github.get_release(owner, repo, tag_name)
        now = datetime.now(timezone.utc)

        return ReleaseObservation(
            evidence_id=generate_evidence_id("release", f"{owner}/{repo}", tag_name),
            observed_when=now,
            observed_by=EvidenceSource.GITHUB,
            observed_what=f"Release {tag_name} observed via GitHub API",
            repository=make_repo(owner, repo),
            verification=VerificationInfo(
                source=EvidenceSource.GITHUB,
                url=HttpUrl(f"https://github.com/{owner}/{repo}/releases/tag/{tag_name}"),
            ),
            tag_name=tag_name,
            release_name=data.get("name"),
            release_body=data.get("body"),
            created_at=parse_datetime_strict(data.get("created_at")),
            published_at=parse_datetime_strict(data.get("published_at")),
            is_prerelease=data.get("prerelease", False),
            is_draft=data.get("draft", False),
        )

    def forks(self, owner: str, repo: str) -> list[ForkObservation]:
        """Create ForkObservations from GitHub API."""
        data = self.github.get_forks(owner, repo)
        now = datetime.now(timezone.utc)
        full_name = f"{owner}/{repo}"

        return [
            ForkObservation(
                evidence_id=generate_evidence_id("fork", full_name, fork["full_name"]),
                observed_when=now,
                observed_by=EvidenceSource.GITHUB,
                observed_what=f"Fork {fork['full_name']} observed via GitHub API",
                repository=make_repo(owner, repo),
                verification=VerificationInfo(
                    source=EvidenceSource.GITHUB,
                    url=HttpUrl(f"https://github.com/{fork['full_name']}"),
                ),
                fork_full_name=fork["full_name"],
                parent_full_name=full_name,
                fork_owner=fork["owner"]["login"],
                fork_repo=fork["name"],
                forked_at=parse_datetime_strict(fork.get("created_at")),
            )
            for fork in data
        ]

    # =========================================================================
    # WAYBACK MACHINE METHOD
    # =========================================================================

    def wayback_snapshots(
        self,
        url: str,
        from_date: str | None = None,
        to_date: str | None = None,
    ) -> SnapshotObservation:
        """Create SnapshotObservation from Wayback Machine."""
        snapshots_data = self.wayback.search_cdx(
            url=url,
            from_date=from_date,
            to_date=to_date,
        )
        now = datetime.now(timezone.utc)

        snapshots = [
            WaybackSnapshot(
                timestamp=s.get("timestamp", ""),
                original=s.get("original", ""),
                digest=s.get("digest", ""),
                mimetype=s.get("mimetype", ""),
            )
            for s in snapshots_data
        ]

        return SnapshotObservation(
            evidence_id=generate_evidence_id("snapshot", url),
            observed_when=now,
            observed_by=EvidenceSource.WAYBACK,
            observed_what=f"Found {len(snapshots)} Wayback snapshots for {url}",
            verification=VerificationInfo(
                source=EvidenceSource.WAYBACK,
                url=HttpUrl(f"https://web.archive.org/cdx/search/cdx?url={url}"),
            ),
            original_url=HttpUrl(url),
            snapshots=snapshots,
            total_snapshots=len(snapshots),
        )

    # =========================================================================
    # GH ARCHIVE METHODS
    # =========================================================================

    def events_from_gharchive(
        self,
        timestamp: str,
        repo: str | None = None,
        actor: str | None = None,
        event_type: str | None = None,
    ) -> list[AnyEvent]:
        """Query GH Archive and create Events.

        Args:
            timestamp: Specific time in YYYYMMDDHHMM format (12 digits)
            repo: Repository in "owner/name" format (required if no actor)
            actor: GitHub username (required if no repo)
            event_type: Filter by event type (e.g., "PushEvent")

        Raises:
            ValueError: If timestamp format invalid or neither repo nor actor specified
        """
        if len(timestamp) != 12 or not timestamp.isdigit():
            raise ValueError(f"timestamp must be YYYYMMDDHHMM format (12 digits), got: {timestamp}")

        if not repo and not actor:
            raise ValueError("Must specify at least 'repo' or 'actor' to avoid expensive full-table scans")

        rows = self.gharchive.query_events(
            repo=repo,
            actor=actor,
            event_type=event_type,
            from_date=timestamp,
            to_date=timestamp,
        )

        events = []
        for row in rows:
            try:
                events.append(parse_gharchive_event(row))
            except (KeyError, ValueError):
                continue

        return events

    def recover_issue(self, repo: str, issue_number: int, timestamp: str) -> IssueObservation:
        """Recover deleted issue content from GH Archive.

        Args:
            repo: Full repo name (owner/repo)
            issue_number: Issue number
            timestamp: ISO timestamp when event occurred (e.g. "2025-07-13T20:30:24Z")
        """
        return self._recover_from_gharchive("issue", repo, issue_number, timestamp)

    def recover_pr(self, repo: str, pr_number: int, timestamp: str) -> IssueObservation:
        """Recover deleted PR content from GH Archive."""
        return self._recover_from_gharchive("pr", repo, pr_number, timestamp)

    def recover_commit(self, repo: str, sha: str, timestamp: str) -> CommitObservation:
        """Recover commit metadata from GH Archive."""
        owner, name = repo.split("/", 1)
        date = timestamp[:10].replace("-", "")

        rows = self.gharchive.query_events(repo=repo, event_type="PushEvent", from_date=date)

        for row in rows:
            row_ts = str(row.get("created_at", ""))
            if timestamp not in row_ts:
                continue

            payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
            for commit in payload.get("commits", []):
                if commit["sha"].startswith(sha) or sha.startswith(commit["sha"]):
                    return CommitObservation(
                        evidence_id=generate_evidence_id("commit-gharchive", repo, commit["sha"]),
                        original_when=parse_datetime_strict(row["created_at"]),
                        original_who=GitHubActor(login=commit.get("author", {}).get("name", "")),
                        original_what=commit.get("message", "").split("\n")[0],
                        observed_when=parse_datetime_strict(row["created_at"]),
                        observed_by=EvidenceSource.GHARCHIVE,
                        observed_what=f"Commit {commit['sha'][:8]} recovered from GH Archive",
                        repository=make_repo(owner, name),
                        verification=VerificationInfo(
                            source=EvidenceSource.GHARCHIVE,
                            bigquery_table=f"githubarchive.day.{date}",
                            query=f"repo.name='{repo}' AND type='PushEvent' AND created_at='{timestamp}'",
                        ),
                        sha=commit["sha"],
                        message=commit.get("message", ""),
                        author=CommitAuthor(
                            name=commit.get("author", {}).get("name", ""),
                            email=commit.get("author", {}).get("email", ""),
                            date=parse_datetime_strict(row["created_at"]),
                        ),
                        committer=CommitAuthor(
                            name=commit.get("author", {}).get("name", ""),
                            email=commit.get("author", {}).get("email", ""),
                            date=parse_datetime_strict(row["created_at"]),
                        ),
                        parents=[],
                        files=[],
                        is_dangling=True,
                    )

        raise ValueError(f"Commit {sha} not found in GH Archive for {repo} at {timestamp}")

    def recover_force_push(self, repo: str, timestamp: str) -> CommitObservation:
        """Recover force-pushed commit from GH Archive."""
        owner, name = repo.split("/", 1)
        date = timestamp[:10].replace("-", "")

        rows = self.gharchive.query_events(repo=repo, event_type="PushEvent", from_date=date)

        for row in rows:
            row_ts = str(row.get("created_at", ""))
            if timestamp not in row_ts:
                continue

            payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
            size = int(payload.get("size", 0))
            before_sha = payload.get("before", "0" * 40)

            if size == 0 and before_sha != "0" * 40:
                return CommitObservation(
                    evidence_id=generate_evidence_id("forcepush-gharchive", repo, before_sha, timestamp),
                    original_when=parse_datetime_strict(row["created_at"]),
                    original_who=make_actor(row["actor_login"]),
                    original_what="Commit overwritten by force push",
                    observed_when=parse_datetime_strict(row["created_at"]),
                    observed_by=EvidenceSource.GHARCHIVE,
                    observed_what=f"Force push detected, before SHA: {before_sha[:8]}",
                    repository=make_repo(owner, name),
                    verification=VerificationInfo(
                        source=EvidenceSource.GHARCHIVE,
                        bigquery_table=f"githubarchive.day.{date}",
                        query=f"repo.name='{repo}' AND type='PushEvent' AND created_at='{timestamp}' AND size=0",
                    ),
                    sha=before_sha,
                    message="[Force pushed - fetch content via GitHub API]",
                    author=CommitAuthor(
                        name="unknown",
                        email="unknown",
                        date=parse_datetime_strict(row["created_at"]),
                    ),
                    committer=CommitAuthor(
                        name="unknown",
                        email="unknown",
                        date=parse_datetime_strict(row["created_at"]),
                    ),
                    parents=[],
                    files=[],
                    is_dangling=True,
                )

        raise ValueError(f"Force push not found in GH Archive for {repo} at {timestamp}")

    def _recover_from_gharchive(
        self, item_type: str, repo: str, number: int, timestamp: str
    ) -> IssueObservation:
        """Internal: Recover issue or PR from GH Archive."""
        owner, name = repo.split("/", 1)
        date = timestamp[:10].replace("-", "")
        event_type = "PullRequestEvent" if item_type == "pr" else "IssuesEvent"
        payload_key = "pull_request" if item_type == "pr" else "issue"

        rows = self.gharchive.query_events(repo=repo, event_type=event_type, from_date=date)

        for row in rows:
            payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
            item = payload.get(payload_key, {})
            row_ts = str(row.get("created_at", ""))

            if item.get("number") == number and timestamp in row_ts:
                state = item.get("state", "open")
                if item.get("merged"):
                    state = "merged"

                is_pr = item_type == "pr"
                prefix = "pr-gharchive" if is_pr else "issue-gharchive"

                return IssueObservation(
                    evidence_id=generate_evidence_id(prefix, repo, str(number), timestamp),
                    original_when=parse_datetime_strict(item.get("created_at")),
                    original_who=make_actor(item.get("user", {}).get("login", row["actor_login"])),
                    original_what=f"{'PR' if is_pr else 'Issue'} #{number} created",
                    observed_when=parse_datetime_strict(row["created_at"]),
                    observed_by=EvidenceSource.GHARCHIVE,
                    observed_what=f"{'PR' if is_pr else 'Issue'} #{number} recovered from GH Archive",
                    repository=make_repo(owner, name),
                    verification=VerificationInfo(
                        source=EvidenceSource.GHARCHIVE,
                        bigquery_table=f"githubarchive.day.{date}",
                        query=f"repo.name='{repo}' AND type='{event_type}' AND created_at='{timestamp}'",
                    ),
                    issue_number=number,
                    is_pull_request=is_pr,
                    title=item.get("title"),
                    body=item.get("body"),
                    state=state,
                    is_deleted=True,
                )

        label = "PR" if item_type == "pr" else "Issue"
        raise ValueError(f"{label} #{number} not found in GH Archive for {repo} at {timestamp}")

    # =========================================================================
    # IOC AND ARTICLE METHODS
    # =========================================================================

    def ioc(
        self,
        ioc_type: IOCType | str,
        value: str,
        source_url: str,
        extracted_from: str | None = None,
    ) -> IOC:
        """Create IOC by verifying it exists in vendor report.

        Fetches source_url and confirms IOC value appears in content.
        Raises ValueError if IOC cannot be verified at source.
        """
        import requests

        if isinstance(ioc_type, str):
            ioc_type = IOCType(ioc_type)

        try:
            resp = requests.get(source_url, timeout=30)
            resp.raise_for_status()
            content = resp.text
        except Exception as e:
            raise ValueError(f"Failed to fetch source URL {source_url}: {e}")

        if value.lower() not in content.lower():
            raise ValueError(f"IOC value '{value[:50]}' not found in source {source_url}")

        now = datetime.now(timezone.utc)

        return IOC(
            evidence_id=generate_evidence_id("ioc", ioc_type.value, value),
            observed_when=now,
            observed_by=EvidenceSource.SECURITY_VENDOR,
            observed_what=f"IOC {ioc_type.value}: {value[:50]}{'...' if len(value) > 50 else ''}",
            verification=VerificationInfo(
                source=EvidenceSource.SECURITY_VENDOR,
                url=HttpUrl(source_url),
            ),
            ioc_type=ioc_type,
            value=value,
            first_seen=now,
            last_seen=now,
            extracted_from=extracted_from,
        )

    def article(
        self,
        url: str,
        title: str,
        author: str | None = None,
        published_date: datetime | None = None,
        source_name: str | None = None,
        summary: str | None = None,
    ) -> ArticleObservation:
        """Create ArticleObservation for a blog post or security report."""
        now = datetime.now(timezone.utc)

        return ArticleObservation(
            evidence_id=generate_evidence_id("article", url),
            observed_when=now,
            observed_by=EvidenceSource.SECURITY_VENDOR,
            observed_what=f"Article: {title[:50]}{'...' if len(title) > 50 else ''}",
            verification=VerificationInfo(
                source=EvidenceSource.SECURITY_VENDOR,
                url=HttpUrl(url),
            ),
            url=HttpUrl(url),
            title=title,
            author=author,
            published_date=published_date,
            source_name=source_name,
            summary=summary,
        )
