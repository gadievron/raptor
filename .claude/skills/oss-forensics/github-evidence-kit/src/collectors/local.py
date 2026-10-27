"""
Local Git Collector.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..clients.git import GitClient
from ..schema.common import EvidenceSource, GitHubActor, VerificationInfo
from ..schema.observations import CommitAuthor, CommitObservation, FileChange
from ..helpers import generate_evidence_id, parse_datetime_strict


class LocalGitCollector:
    """Collects evidence from local git repository."""

    def __init__(self, repo_path: str = ".", client: GitClient | None = None) -> None:
        self.client = client or GitClient(repo_path)

    def collect_commit(self, sha: str) -> CommitObservation:
        """Collect commit evidence from local git."""
        data = self.client.get_commit(sha)
        files_data = self.client.get_commit_files(data["sha"])
        now = datetime.now(timezone.utc)

        files = [
            FileChange(
                filename=f["filename"],
                status=f.get("status", "modified"),
                additions=0,
                deletions=0,
            )
            for f in files_data
        ]

        return CommitObservation(
            evidence_id=generate_evidence_id("commit-git", data["sha"]),
            original_when=parse_datetime_strict(data.get("author_date")),
            original_who=GitHubActor(login=data.get("author_name", "unknown")),
            original_what=data.get("message", "").split("\n")[0],
            observed_when=now,
            observed_by=EvidenceSource.GIT,
            observed_what=f"Commit {data['sha'][:8]} observed from local git",
            verification=VerificationInfo(
                source=EvidenceSource.GIT,
            ),
            sha=data["sha"],
            message=data.get("message", ""),
            author=CommitAuthor(
                name=data.get("author_name", ""),
                email=data.get("author_email", ""),
                date=parse_datetime_strict(data.get("author_date")) or now,
            ),
            committer=CommitAuthor(
                name=data.get("committer_name", ""),
                email=data.get("committer_email", ""),
                date=parse_datetime_strict(data.get("committer_date")) or now,
            ),
            parents=data.get("parents", []),
            files=files,
            is_dangling=False,
        )

    def collect_log_commits(
        self,
        ref: str = "HEAD",
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
        all_refs: bool = False,
    ) -> list[CommitObservation]:
        """Collect commits from git log for cross-source corroboration.

        Enumerates commits reachable from *ref* (or all refs when
        *all_refs* is set) and returns full ``CommitObservation``
        records.  Individual commits that fail to parse are skipped
        silently so one corrupt object does not abort the batch.
        """
        log_entries = self.client.get_log(
            ref=ref, since=since, until=until, limit=limit,
            all_refs=all_refs,
        )
        commits: list[CommitObservation] = []
        for entry in log_entries:
            try:
                commits.append(self.collect_commit(entry["sha"]))
            except Exception:
                continue
        return commits

    def collect_dangling_commits(self) -> list[CommitObservation]:
        """Collect dangling commits (commits not reachable from any ref)."""
        # This is a placeholder for future implementation using git fsck
        # For now, we just return an empty list or implement basic logic if needed.
        # The user plan mentioned: "New capability: find commits not reachable by any ref (forensic gold)"
        
        # We can use fsck to find dangling commits
        fsck_output = self.client.fsck()
        dangling_commits = []
        for line in fsck_output.split("\n"):
            if "dangling commit" in line:
                parts = line.split()
                if len(parts) >= 3:
                    sha = parts[2]
                    try:
                        commit = self.collect_commit(sha)
                        commit.is_dangling = True
                        dangling_commits.append(commit)
                    except Exception:
                        # Ignore if we can't parse it
                        continue
        return dangling_commits
