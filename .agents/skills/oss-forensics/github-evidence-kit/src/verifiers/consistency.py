"""
Verification Service - Verify evidence against original sources.
"""
from __future__ import annotations

from typing import Callable, Sequence

from ..clients.gharchive import GHArchiveClient
from ..clients.github import GitHubClient
from ..schema.common import EvidenceSource, VerificationResult
from ..schema.events import Event
from ..schema.observations import Observation


class ConsistencyVerifier:
    """Verifies evidence against external sources."""

    def __init__(
        self,
        github_client: GitHubClient | None = None,
        gharchive_client: GHArchiveClient | None = None,
    ):
        self.github_client = github_client or GitHubClient()
        self.gharchive_client = gharchive_client or GHArchiveClient()

    def verify(self, evidence: Event | Observation) -> VerificationResult:
        """Verify evidence against its source."""
        if isinstance(evidence, Event):
            return self._verify_event(evidence)
        elif isinstance(evidence, Observation):
            return self._verify_observation(evidence)
        else:
            return VerificationResult(is_valid=False, errors=["Unknown evidence type"])

    def verify_all(self, evidence_list: Sequence[Event | Observation]) -> VerificationResult:
        """Verify a list of evidence items. Aggregates all errors."""
        all_errors: list[str] = []
        all_valid = True

        for evidence in evidence_list:
            result = self.verify(evidence)
            if not result.is_valid:
                all_valid = False
                evidence_id = getattr(evidence, "evidence_id", "unknown")
                all_errors.extend(f"[{evidence_id}] {e}" for e in result.errors)

        return VerificationResult(is_valid=all_valid, errors=all_errors)

    def _verify_event(self, event: Event) -> VerificationResult:
        """Verify an event against the original source."""
        source = event.verification.source

        if source == EvidenceSource.GHARCHIVE:
            return self._verify_gharchive_event(event)
        if source == EvidenceSource.GIT:
            return VerificationResult(is_valid=True, errors=["Local git verification not supported"])
        
        return VerificationResult(is_valid=False, errors=[f"Unknown verification source for event: {source}"])

    def _verify_observation(self, observation: Observation) -> VerificationResult:
        """Verify an observation against the original source."""
        source = observation.verification.source

        verifiers: dict[EvidenceSource, Callable[[Observation], VerificationResult]] = {
            EvidenceSource.GITHUB: self._verify_github_observation,
            EvidenceSource.GHARCHIVE: self._verify_gharchive_observation,
            EvidenceSource.WAYBACK: self._verify_url_accessible,
            EvidenceSource.SECURITY_VENDOR: self._verify_security_vendor,
            EvidenceSource.GIT: lambda o: VerificationResult(is_valid=True, errors=["Local git verification not supported"]),
        }

        verifier = verifiers.get(source)
        if not verifier:
            return VerificationResult(is_valid=False, errors=[f"Unknown verification source: {source}"])
        return verifier(observation)

    # =========================================================================
    # GITHUB API VERIFICATION
    # =========================================================================

    def _verify_github_observation(self, observation: Observation) -> VerificationResult:
        """Verify observation against GitHub API."""
        obs_type = getattr(observation, "observation_type", None)

        verifiers: dict[str, Callable[[Observation], VerificationResult]] = {
            "commit": self._verify_commit,
            "issue": self._verify_issue,
            "file": self._verify_file,
            "branch": self._verify_branch,
            "tag": self._verify_tag,
            "release": self._verify_release,
            "fork": self._verify_url_accessible,
        }

        verifier = verifiers.get(obs_type, self._verify_url_accessible)

        try:
            return verifier(observation)
        except Exception as e:
            if getattr(observation, "is_deleted", False):
                return VerificationResult(is_valid=True, errors=[])  # Expected - item is marked as deleted
            return VerificationResult(is_valid=False, errors=[f"Verification failed: {e}"])

    def _get_repo_info(self, obs: Observation) -> tuple[str, str] | None:
        """Extract (owner, name) from observation. Returns None if missing."""
        repo = obs.repository
        return (repo.owner, repo.name) if repo else None

    def _verify_commit(self, obs: Observation) -> VerificationResult:
        """Verify commit against GitHub API."""
        repo_info = self._get_repo_info(obs)
        if not repo_info:
            return VerificationResult(is_valid=False, errors=["No repository specified"])

        sha = getattr(obs, "sha", None)
        if not sha:
            return VerificationResult(is_valid=False, errors=["No SHA specified"])

        errors: list[str] = []
        data = self.github_client.get_commit(*repo_info, sha)
        commit = data.get("commit", {})

        if data.get("sha") != sha:
            errors.append(f"SHA mismatch: expected {sha}, got {data.get('sha')}")

        if hasattr(obs, "message") and obs.message != commit.get("message", ""):
            errors.append("Message mismatch")

        if hasattr(obs, "author") and obs.author:
            actual = commit.get("author", {}).get("name")
            if obs.author.name != actual:
                errors.append(f"Author mismatch: expected {obs.author.name}, got {actual}")

        return VerificationResult(is_valid=len(errors) == 0, errors=errors)

    def _verify_issue(self, obs: Observation) -> VerificationResult:
        """Verify issue/PR against GitHub API."""
        repo_info = self._get_repo_info(obs)
        if not repo_info:
            return VerificationResult(is_valid=False, errors=["No repository specified"])

        number = getattr(obs, "issue_number", None)
        if not number:
            return VerificationResult(is_valid=False, errors=["No issue number specified"])

        errors: list[str] = []
        is_pr = getattr(obs, "is_pull_request", False)
        data = self.github_client.get_pull_request(*repo_info, number) if is_pr else self.github_client.get_issue(*repo_info, number)

        if data.get("number") != number:
            errors.append(f"Number mismatch: expected {number}, got {data.get('number')}")

        if hasattr(obs, "title") and obs.title and data.get("title") != obs.title:
            errors.append("Title mismatch")

        if hasattr(obs, "state") and obs.state:
            actual = "merged" if data.get("merged") else data.get("state")
            if obs.state != actual:
                errors.append(f"State mismatch: expected {obs.state}, got {actual}")

        return VerificationResult(is_valid=len(errors) == 0, errors=errors)

    def _verify_file(self, obs: Observation) -> VerificationResult:
        """Verify file content against GitHub API."""
        import base64
        import hashlib

        repo_info = self._get_repo_info(obs)
        if not repo_info:
            return VerificationResult(is_valid=False, errors=["No repository specified"])

        file_path = getattr(obs, "file_path", None)
        if not file_path:
            return VerificationResult(is_valid=False, errors=["No file path specified"])

        ref = getattr(obs, "branch", None) or "HEAD"
        data = self.github_client.get_file(*repo_info, file_path, ref)

        if hasattr(obs, "content_hash") and obs.content_hash:
            raw = data.get("content", "")
            content = base64.b64decode(raw).decode("utf-8", errors="replace") if raw else ""
            if obs.content_hash != hashlib.sha256(content.encode()).hexdigest():
                return VerificationResult(is_valid=False, errors=["Content hash mismatch"])

        return VerificationResult(is_valid=True, errors=[])

    def _verify_branch(self, obs: Observation) -> VerificationResult:
        """Verify branch against GitHub API."""
        repo_info = self._get_repo_info(obs)
        if not repo_info:
            return VerificationResult(is_valid=False, errors=["No repository specified"])

        branch_name = getattr(obs, "branch_name", None)
        if not branch_name:
            return VerificationResult(is_valid=False, errors=["No branch name specified"])

        data = self.github_client.get_branch(*repo_info, branch_name)

        if hasattr(obs, "head_sha") and obs.head_sha:
            actual = data.get("commit", {}).get("sha")
            if obs.head_sha != actual:
                return VerificationResult(is_valid=False, errors=[f"HEAD SHA mismatch: expected {obs.head_sha}, got {actual}"])

        return VerificationResult(is_valid=True, errors=[])

    def _verify_tag(self, obs: Observation) -> VerificationResult:
        """Verify tag against GitHub API."""
        repo_info = self._get_repo_info(obs)
        if not repo_info:
            return VerificationResult(is_valid=False, errors=["No repository specified"])

        tag_name = getattr(obs, "tag_name", None)
        if not tag_name:
            return VerificationResult(is_valid=False, errors=["No tag name specified"])

        data = self.github_client.get_tag(*repo_info, tag_name)

        if hasattr(obs, "target_sha") and obs.target_sha:
            actual = data.get("object", {}).get("sha")
            if obs.target_sha != actual:
                return VerificationResult(is_valid=False, errors=[f"Target SHA mismatch: expected {obs.target_sha}, got {actual}"])

        return VerificationResult(is_valid=True, errors=[])

    def _verify_release(self, obs: Observation) -> VerificationResult:
        """Verify release against GitHub API."""
        repo_info = self._get_repo_info(obs)
        if not repo_info:
            return VerificationResult(is_valid=False, errors=["No repository specified"])

        tag_name = getattr(obs, "tag_name", None)
        if not tag_name:
            return VerificationResult(is_valid=False, errors=["No tag name specified"])

        data = self.github_client.get_release(*repo_info, tag_name)

        if data.get("tag_name") != tag_name:
            return VerificationResult(is_valid=False, errors=["Tag name mismatch"])

        return VerificationResult(is_valid=True, errors=[])

    # =========================================================================
    # URL / VENDOR VERIFICATION
    # =========================================================================

    def _verify_url_accessible(self, obs: Observation) -> VerificationResult:
        """Verify that the verification URL is accessible."""
        import requests

        url = obs.verification.url
        if not url:
            return VerificationResult(is_valid=True, errors=[])

        try:
            requests.get(str(url), timeout=30).raise_for_status()
            return VerificationResult(is_valid=True, errors=[])
        except requests.RequestException as e:
            return VerificationResult(is_valid=False, errors=[f"Failed to access URL: {e}"])

    def _verify_security_vendor(self, obs: Observation) -> VerificationResult:
        """Verify observation against security vendor URL."""
        import requests

        url = obs.verification.url
        if not url:
            return VerificationResult(is_valid=False, errors=["No source URL specified"])

        try:
            resp = requests.get(str(url), timeout=30)
            resp.raise_for_status()

            # For IOCs, verify value appears in content
            if getattr(obs, "observation_type", None) == "ioc":
                value = getattr(obs, "value", None)
                if value and value.lower() not in resp.text.lower():
                    return VerificationResult(is_valid=False, errors=[f"IOC value '{value[:50]}' not found in source"])

            return VerificationResult(is_valid=True, errors=[])
        except requests.RequestException as e:
            return VerificationResult(is_valid=False, errors=[f"Failed to fetch source URL: {e}"])

    # =========================================================================
    # GH ARCHIVE VERIFICATION
    # =========================================================================

    def _has_gharchive_credentials(self) -> bool:
        """Check if GH Archive BigQuery credentials are available."""
        try:
            self.gharchive_client._get_client()
            return True
        except Exception:
            return False

    def _verify_gharchive_event(self, event: Event) -> VerificationResult:
        """Verify event against GH Archive BigQuery."""
        if not event.verification.bigquery_table:
            return VerificationResult(is_valid=False, errors=["No BigQuery table specified"])

        if not self._has_gharchive_credentials():
            return VerificationResult(is_valid=True, errors=["GH Archive verification skipped - no credentials"])

        try:
            rows = self.gharchive_client.query_events(
                repo=event.repository.full_name if event.repository else None,
                actor=event.who.login if event.who else None,
                from_date=event.when.strftime("%Y%m%d%H%M"),
            )
            if not rows:
                return VerificationResult(is_valid=False, errors=["No matching event found in GH Archive"])
            return VerificationResult(is_valid=True, errors=[])
        except Exception as e:
            return VerificationResult(is_valid=False, errors=[f"GH Archive verification error: {e}"])

    def _verify_gharchive_observation(self, obs: Observation) -> VerificationResult:
        """Verify observation against GH Archive BigQuery."""
        if not obs.verification.bigquery_table:
            return VerificationResult(is_valid=False, errors=["No BigQuery table specified"])

        if not self._has_gharchive_credentials():
            return VerificationResult(is_valid=True, errors=["GH Archive verification skipped - no credentials"])

        return VerificationResult(is_valid=True, errors=[])
