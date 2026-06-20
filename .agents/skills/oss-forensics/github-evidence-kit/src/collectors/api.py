"""
GitHub API Collector.
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

from pydantic import HttpUrl

from ..clients.github import GitHubClient
from ..schema.common import EvidenceSource, VerificationInfo
from ..schema.observations import (
    BranchObservation,
    CommitAuthor,
    CommitObservation,
    FileChange,
    FileObservation,
    ForkObservation,
    IssueObservation,
    ReleaseObservation,
    TagObservation,
)
from ..helpers import (
    generate_evidence_id,
    make_actor,
    make_repo,
    parse_datetime_strict,
)


class GitHubAPICollector:
    """Collects evidence from GitHub API."""

    def __init__(self, client: GitHubClient | None = None):
        self.client = client or GitHubClient()

    def collect_commit(self, owner: str, repo: str, sha: str) -> CommitObservation:
        """Collect commit evidence."""
        data = self.client.get_commit(owner, repo, sha)
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

    def collect_issue(self, owner: str, repo: str, number: int) -> IssueObservation:
        """Collect issue evidence."""
        return self._collect_issue_or_pr(owner, repo, number, is_pr=False)

    def collect_pull_request(self, owner: str, repo: str, number: int) -> IssueObservation:
        """Collect PR evidence."""
        return self._collect_issue_or_pr(owner, repo, number, is_pr=True)

    def _collect_issue_or_pr(
        self, owner: str, repo: str, number: int, is_pr: bool
    ) -> IssueObservation:
        if is_pr:
            data = self.client.get_pull_request(owner, repo, number)
        else:
            data = self.client.get_issue(owner, repo, number)

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

    def collect_file(self, owner: str, repo: str, path: str, ref: str = "HEAD") -> FileObservation:
        """Collect file evidence."""
        data = self.client.get_file(owner, repo, path, ref)
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
            content=content,
            content_hash=content_hash,
            size_bytes=data.get("size", 0),
        )

    def collect_branch(self, owner: str, repo: str, branch_name: str) -> BranchObservation:
        """Collect branch evidence."""
        data = self.client.get_branch(owner, repo, branch_name)
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

    def collect_tag(self, owner: str, repo: str, tag_name: str) -> TagObservation:
        """Collect tag evidence."""
        data = self.client.get_tag(owner, repo, tag_name)
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

    def collect_release(self, owner: str, repo: str, tag_name: str) -> ReleaseObservation:
        """Collect release evidence."""
        data = self.client.get_release(owner, repo, tag_name)
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

    def collect_forks(self, owner: str, repo: str) -> list[ForkObservation]:
        """Collect forks evidence."""
        data = self.client.get_forks(owner, repo)
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
