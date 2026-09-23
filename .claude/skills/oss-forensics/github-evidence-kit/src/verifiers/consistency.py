"""
Verification Service - Verify evidence against original sources.
"""
from __future__ import annotations

import json

from ..clients.gharchive import GHArchiveClient
from ..clients.github import GitHubClient
from ..schema.common import EvidenceSource, VerificationResult
from ..schema.events import Event
from ..schema.observations import Observation
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


# Kit event_type -> GH Archive `type` column value (the reverse of
# parsers._PARSERS). Verification must filter on it: repo + actor +
# minute alone is not evidence — any unrelated event in the same busy
# minute (a WatchEvent) would "verify" a fabricated event of any type.
_GHARCHIVE_TYPE_BY_EVENT_TYPE: dict[str, str] = {
    "push": "PushEvent",
    "issue": "IssuesEvent",
    "create": "CreateEvent",
    "delete": "DeleteEvent",
    "pull_request": "PullRequestEvent",
    "issue_comment": "IssueCommentEvent",
    "watch": "WatchEvent",
    "fork": "ForkEvent",
    "member": "MemberEvent",
    "public": "PublicEvent",
    "release": "ReleaseEvent",
    "workflow_run": "WorkflowRunEvent",
}


def _row_payload(row: dict[str, Any]) -> dict[str, Any]:
    """Decode a GH Archive row's payload column (JSON string, dict, or
    absent) to a dict; malformed payloads read as empty (they then
    fail any discriminator comparison — never verify on garbage)."""
    raw = row.get("payload")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return decoded if isinstance(decoded, dict) else {}
    return {}


def _sub(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


def _num(value: Any) -> int | None:
    """GH Archive numerics are JSON numbers on modern rows, strings on
    some pre-2015 rows (same coercion the parsers apply)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _discriminator_pair(event: Event, payload: dict[str, Any]) -> tuple[Any, Any] | None:
    """(row value, expected value) for the event type's discriminating
    payload field, or None when the type has no per-event payload to
    compare (watch/public — type + repo/actor + minute is all GH
    Archive carries for those)."""
    event_type = getattr(event, "event_type", None)
    if event_type == "push":
        return (payload.get("head", payload.get("after")),
                getattr(event, "after_sha", None))
    if event_type == "pull_request":
        return (_num(_sub(payload, "pull_request").get("number")),
                getattr(event, "pr_number", None))
    if event_type == "issue":
        return (_num(_sub(payload, "issue").get("number")),
                getattr(event, "issue_number", None))
    if event_type == "issue_comment":
        return (_num(_sub(payload, "comment").get("id")),
                getattr(event, "comment_id", None))
    if event_type in ("create", "delete"):
        return payload.get("ref"), getattr(event, "ref_name", None)
    if event_type == "fork":
        return (_sub(payload, "forkee").get("full_name"),
                getattr(event, "fork_full_name", None))
    if event_type == "release":
        return (_sub(payload, "release").get("tag_name"),
                getattr(event, "tag_name", None))
    if event_type == "workflow_run":
        return (_sub(payload, "workflow_run").get("head_sha"),
                getattr(event, "head_sha", None))
    if event_type == "member":
        member = getattr(event, "member", None)
        return (_sub(payload, "member").get("login"),
                getattr(member, "login", None))
    return None


class ConsistencyVerifier:
    """Verifies evidence against external sources."""

    def __init__(
        self,
        github_client: GitHubClient | None = None,
        gharchive_client: GHArchiveClient | None = None,
    ) -> None:
        self.github_client = github_client or GitHubClient()
        self.gharchive_client = gharchive_client or GHArchiveClient()

    def verify(self, evidence: Event | Observation) -> VerificationResult:
        """Verify evidence against its source."""
        if isinstance(evidence, Event):
            return self._verify_event(evidence)
        if isinstance(evidence, Observation):
            return self._verify_observation(evidence)
        return VerificationResult(is_valid=False, errors=["Unknown evidence type"])

    def verify_all(self, evidence_list: Sequence[Event | Observation]) -> VerificationResult:
        """Verify a list of evidence items. Aggregates all errors.

        Skipped checks (no credentials, unsupported source) surface as
        warnings on the aggregate result: this verifier is the
        pipeline's anti-fabrication chokepoint, so "not checked" must
        be distinguishable from "verified" even when nothing failed.
        """
        all_errors: list[str] = []
        all_warnings: list[str] = []
        all_valid = True

        for evidence in evidence_list:
            result = self.verify(evidence)
            evidence_id = getattr(evidence, "evidence_id", "unknown")
            if not result.is_valid:
                all_valid = False
                all_errors.extend(f"[{evidence_id}] {e}" for e in result.errors)
            all_warnings.extend(f"[{evidence_id}] {w}" for w in result.warnings)

        return VerificationResult(is_valid=all_valid, errors=all_errors, warnings=all_warnings)

    def _verify_event(self, event: Event) -> VerificationResult:
        """Verify an event against the original source."""
        source = event.verification.source

        if source == EvidenceSource.GHARCHIVE:
            return self._verify_gharchive_event(event)
        if source == EvidenceSource.GIT:
            return VerificationResult(
                is_valid=True,
                warnings=["Local git verification not supported - not checked"],
            )
        
        return VerificationResult(is_valid=False, errors=[f"Unknown verification source for event: {source}"])

    def _verify_observation(self, observation: Observation) -> VerificationResult:
        """Verify an observation against the original source."""
        source = observation.verification.source

        verifiers: dict[EvidenceSource, Callable[[Observation], VerificationResult]] = {
            EvidenceSource.GITHUB: self._verify_github_observation,
            EvidenceSource.GHARCHIVE: self._verify_gharchive_observation,
            EvidenceSource.WAYBACK: self._verify_url_accessible,
            EvidenceSource.SECURITY_VENDOR: self._verify_security_vendor,
            EvidenceSource.GIT: lambda _o: VerificationResult(
                is_valid=True,
                warnings=["Local git verification not supported - not checked"],
            ),
        }

        verifier = verifiers.get(source)
        if not verifier:
            return VerificationResult(is_valid=False, errors=[f"Unknown verification source: {source}"])
        return verifier(observation)

    # =========================================================================
    # GITHUB API VERIFICATION
    # =========================================================================

    def _verify_github_observation(self, observation: Observation) -> VerificationResult:
        """Verify observation against GitHub API.

        Fail closed on unmapped observation types: this dispatcher is
        an anti-fabrication chokepoint (mirroring the GH Archive
        lane), and the previous URL-accessibility default let ANY
        fabricated observation "verify" by carrying a reachable — or
        absent — URL. Every type the GitHub-lane collectors produce
        must have an explicit entry here (pinned by
        tests/test_github_lane_fail_closed.py).
        """
        obs_type = getattr(observation, "observation_type", None)

        verifiers: dict[str, Callable[[Observation], VerificationResult]] = {
            "commit": self._verify_commit,
            "issue": self._verify_issue,
            "file": self._verify_file,
            "branch": self._verify_branch,
            "tag": self._verify_tag,
            "release": self._verify_release,
            # Explicit decision, not a fallback: a fork's strongest
            # API-side witness is its repo URL resolving.
            "fork": self._verify_url_accessible,
        }

        verifier = verifiers.get(obs_type)
        if verifier is None:
            return VerificationResult(
                is_valid=False,
                errors=[
                    "GitHub verification unsupported for observation "
                    f"type {obs_type!r} — unmapped types fail closed"
                ],
            )

        try:
            return verifier(observation)
        except Exception as e:
            if getattr(observation, "is_deleted", False):
                # Fail CLOSED. ``is_deleted`` is a freely settable schema
                # field, so "the fetch failed and the record says it's
                # deleted" must never self-verify — a fabricated deleted
                # issue attributed to a repo that 404s would otherwise
                # pass verification with attacker-chosen title/body.
                # Genuinely recovered deleted content comes from the
                # GH Archive collector with source=GHARCHIVE and a
                # bigquery_table, and is verified independently by
                # _verify_gharchive_observation.
                return VerificationResult(
                    is_valid=False,
                    errors=[
                        "unverifiable: source fetch failed for deleted-marked "
                        f"observation ({e}); deletion claims must be verified "
                        "via GH Archive recovery (source=gharchive with a "
                        "bigquery_table), not by fetch failure"
                    ],
                )
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
        errors: list[str] = []
        data = self.github_client.get_file(*repo_info, file_path, ref)

        # Echo check: the response must describe the path the
        # observation claims (mirrors the commit/release legs). A
        # response that resolves to some other object — whatever URL
        # trickery produced it — must not verify the record.
        actual_path = data.get("path")
        if actual_path != file_path:
            errors.append(
                f"Path mismatch: expected {file_path}, got {actual_path}")

        if hasattr(obs, "content_hash") and obs.content_hash:
            raw = data.get("content", "")
            content = base64.b64decode(raw).decode("utf-8", errors="replace") if raw else ""
            if obs.content_hash != hashlib.sha256(content.encode()).hexdigest():
                errors.append("Content hash mismatch")

        return VerificationResult(is_valid=len(errors) == 0, errors=errors)

    def _verify_branch(self, obs: Observation) -> VerificationResult:
        """Verify branch against GitHub API."""
        repo_info = self._get_repo_info(obs)
        if not repo_info:
            return VerificationResult(is_valid=False, errors=["No repository specified"])

        branch_name = getattr(obs, "branch_name", None)
        if not branch_name:
            return VerificationResult(is_valid=False, errors=["No branch name specified"])

        errors: list[str] = []
        data = self.github_client.get_branch(*repo_info, branch_name)

        # Echo check: the response must name the branch the
        # observation claims (mirrors the commit/release legs).
        actual_name = data.get("name")
        if actual_name != branch_name:
            errors.append(
                f"Branch name mismatch: expected {branch_name}, got {actual_name}")

        if hasattr(obs, "head_sha") and obs.head_sha:
            actual = data.get("commit", {}).get("sha")
            if obs.head_sha != actual:
                errors.append(
                    f"HEAD SHA mismatch: expected {obs.head_sha}, got {actual}")

        return VerificationResult(is_valid=len(errors) == 0, errors=errors)

    def _verify_tag(self, obs: Observation) -> VerificationResult:
        """Verify tag against GitHub API."""
        repo_info = self._get_repo_info(obs)
        if not repo_info:
            return VerificationResult(is_valid=False, errors=["No repository specified"])

        tag_name = getattr(obs, "tag_name", None)
        if not tag_name:
            return VerificationResult(is_valid=False, errors=["No tag name specified"])

        errors: list[str] = []
        data = self.github_client.get_tag(*repo_info, tag_name)

        # Echo check: the response ref must name the tag the
        # observation claims (mirrors the commit/release legs).
        actual_ref = data.get("ref")
        expected_ref = f"refs/tags/{tag_name}"
        if actual_ref != expected_ref:
            errors.append(
                f"Tag ref mismatch: expected {expected_ref}, got {actual_ref}")

        if hasattr(obs, "target_sha") and obs.target_sha:
            actual = data.get("object", {}).get("sha")
            if obs.target_sha != actual:
                errors.append(
                    f"Target SHA mismatch: expected {obs.target_sha}, got {actual}")

        return VerificationResult(is_valid=len(errors) == 0, errors=errors)

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
        """Verify that the verification URL is accessible.

        No URL, no verification: a record with nothing to check must
        never read as verified (the previous is_valid=True was
        indistinguishable from a real pass in verify_all, so a
        fabricated observation could simply omit the URL).
        """
        import requests

        url = obs.verification.url
        if not url:
            return VerificationResult(
                is_valid=False,
                errors=["no verification URL — nothing was checked"],
            )

        try:
            # nosemgrep: sinks.raptor.web.ssrf.dynamic-url
            # ``url`` is an operator-supplied evidence URL for
            # forensic verification (this whole module's purpose
            # is verifying URLs from collected forensic evidence).
            # Not SSRF — the analyst chose the URL.
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
            # nosemgrep: sinks.raptor.web.ssrf.dynamic-url
            # ``url`` is an operator-supplied evidence URL for
            # forensic verification. Same trust shape as the
            # ``_verify_url`` method above. Not SSRF.
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
        """Verify event against GH Archive BigQuery.

        Type-aware: the query filters on the event's GH Archive type,
        and where the type carries a discriminating payload field
        (SHA, issue/PR number, ref, tag, member login) at least one
        returned row must match it. A same-minute repo/actor
        existence check alone would let ANY event in a busy minute
        "verify" a fabricated event of any type.
        """
        if not event.verification.bigquery_table:
            return VerificationResult(is_valid=False, errors=["No BigQuery table specified"])

        if not self._has_gharchive_credentials():
            return VerificationResult(
                is_valid=True,
                warnings=["GH Archive verification skipped - no credentials - not checked"],
            )

        event_type = getattr(event, "event_type", None)
        gharchive_type = _GHARCHIVE_TYPE_BY_EVENT_TYPE.get(event_type or "")
        if gharchive_type is None:
            # Fail closed — this verifier is the anti-fabrication
            # chokepoint; an event type it cannot discriminate must
            # not read as verified.
            return VerificationResult(
                is_valid=False,
                errors=[f"GH Archive verification unsupported for event type {event_type!r}"],
            )

        try:
            rows = self.gharchive_client.query_events(
                repo=event.repository.full_name if event.repository else None,
                actor=event.who.login if event.who else None,
                event_type=gharchive_type,
                from_date=event.when.strftime("%Y%m%d%H%M"),
            )
            if not rows:
                return VerificationResult(is_valid=False, errors=["No matching event found in GH Archive"])
            expected = None
            for row in rows:
                pair = _discriminator_pair(event, _row_payload(row))
                if pair is None:
                    # watch/public — type + repo/actor + minute is the
                    # strongest check GH Archive supports.
                    return VerificationResult(is_valid=True, errors=[])
                found, expected = pair
                if found is not None and found == expected:
                    return VerificationResult(is_valid=True, errors=[])
            return VerificationResult(
                is_valid=False,
                errors=[
                    f"GH Archive rows of type {gharchive_type} exist for the "
                    f"repo/actor/minute, but none carries the event's "
                    f"discriminating payload value ({expected!r})"
                ],
            )
        except Exception as e:
            return VerificationResult(is_valid=False, errors=[f"GH Archive verification error: {e}"])

    def _verify_gharchive_observation(self, obs: Observation) -> VerificationResult:
        """Verify observation against GH Archive BigQuery.

        Type- and payload-aware, mirroring ``_verify_gharchive_event``.
        This lane is the deletion-claim oracle — the GitHub-side
        verifier fail-closes deletion claims onto it — and its records
        ("recovered deleted issue/PR/commit") are the highest-stakes
        evidence type in a supply-chain timeline. A repo/actor/minute
        existence check alone let ANY same-minute row "verify" a
        fabricated recovery carrying attacker-chosen title/body. The
        observation's type derives the GH Archive type filter; at
        least one returned row must carry its discriminating payload
        value (issue/PR number, commit sha) AND match the
        observation's verbatim-copied free text where both sides carry
        it — title/body for issue/PR recoveries, message and author
        name/email for commit recoveries (all are copied verbatim from
        the archive row at recovery, and the free text is exactly what
        a fabricated record forges). Force-push rows carry no
        ``commits[]`` and hence no free text — sha-only is all the
        archive can corroborate there. Observation types this verifier
        cannot discriminate fail closed.
        """
        if not obs.verification.bigquery_table:
            return VerificationResult(is_valid=False, errors=["No BigQuery table specified"])

        if not self._has_gharchive_credentials():
            return VerificationResult(
                is_valid=True,
                warnings=["GH Archive verification skipped - no credentials - not checked"],
            )

        obs_type = getattr(obs, "observation_type", None)
        if obs_type == "issue":
            is_pr = bool(getattr(obs, "is_pull_request", False))
            gharchive_type = "PullRequestEvent" if is_pr else "IssuesEvent"
            payload_key = "pull_request" if is_pr else "issue"
            number = getattr(obs, "issue_number", None)
            title = getattr(obs, "title", None)
            body = getattr(obs, "body", None)

            def _row_matches(payload: dict[str, Any]) -> bool:
                item = _sub(payload, payload_key)
                if number is None or _num(item.get("number")) != number:
                    return False
                if title is not None and item.get("title") != title:
                    return False
                return not (body is not None and item.get("body") != body)

        elif obs_type == "commit":
            gharchive_type = "PushEvent"
            sha = getattr(obs, "sha", None)
            message = getattr(obs, "message", None)
            obs_author = getattr(obs, "author", None)
            author_name = getattr(obs_author, "name", None)
            author_email = getattr(obs_author, "email", None)

            def _free_text_matches(commit: dict[str, Any]) -> bool:
                # message and author name/email are copied VERBATIM
                # from the archive row at recovery — the identical
                # rationale as the issue leg's title/body rule: the
                # free text is what a fabricated record forges. Where
                # the sha-matched row entry carries the field and the
                # observation's copy is non-empty (recovery stamps ""
                # when the payload lacked it), they must agree.
                if (message and "message" in commit
                        and commit.get("message") != message):
                    return False
                row_author = commit.get("author")
                if isinstance(row_author, dict):
                    if (author_name and "name" in row_author
                            and row_author.get("name") != author_name):
                        return False
                    if (author_email and "email" in row_author
                            and row_author.get("email") != author_email):
                        return False
                return True

            def _row_matches(payload: dict[str, Any]) -> bool:
                if not isinstance(sha, str) or not sha:
                    return False
                commits = payload.get("commits", [])
                for commit in commits:
                    row_sha = commit.get("sha") if isinstance(commit, dict) else None
                    # Prefix-tolerant in both directions, matching the
                    # recovery collector (pre-2015 rows carry short shas).
                    if (isinstance(row_sha, str) and row_sha
                            and (row_sha.startswith(sha)
                                 or sha.startswith(row_sha))
                            and _free_text_matches(commit)):
                        return True
                # Force-push recovery rows carry no commits[]; head /
                # after / before are their only sha-bearing fields, so
                # sha-only is all the archive can corroborate there.
                # Rows that DO carry commits[] never fall through to
                # this arm: a head/after match on such a row would let
                # forged free text ride a sha the row's own commits[]
                # entry (with its verbatim text) refused above.
                if commits:
                    return False
                return sha in (payload.get("head"), payload.get("after"),
                               payload.get("before"))

        else:
            # Fail closed — this verifier is the anti-fabrication
            # chokepoint; an observation type it cannot discriminate
            # must not read as verified.
            return VerificationResult(
                is_valid=False,
                errors=[
                    "GH Archive observation verification unsupported "
                    f"for observation type {obs_type!r}"
                ],
            )

        try:
            # No actor filter: recovered commits stamp original_who
            # with the commit AUTHOR NAME (not a GitHub login), and a
            # recovered issue row's actor can be a later actor (close/
            # edit) rather than the creator — filtering on it fails
            # legitimate recoveries. Type + repo + minute + the
            # discriminating payload match is the evidence.
            rows = self.gharchive_client.query_events(
                repo=obs.repository.full_name if obs.repository else None,
                event_type=gharchive_type,
                from_date=obs.observed_when.strftime("%Y%m%d%H%M") if obs.observed_when else None,
            )
            if not rows:
                return VerificationResult(is_valid=False, errors=["No matching observation found in GH Archive"])
            for row in rows:
                if _row_matches(_row_payload(row)):
                    return VerificationResult(is_valid=True, errors=[])
            return VerificationResult(
                is_valid=False,
                errors=[
                    f"GH Archive rows of type {gharchive_type} exist for "
                    "the repo/minute, but none carries the observation's "
                    "discriminating payload values"
                ],
            )
        except Exception as e:
            return VerificationResult(is_valid=False, errors=[f"GH Archive observation verification error: {e}"])
