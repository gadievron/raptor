"""
Common schema definitions for GitHub Evidence Kit.
"""
from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, HttpUrl, model_validator

# ---------------------------------------------------------------------------
# Identity-field shape validators.
#
# owner / name / branch_name / tag_name / file_path values come from
# attacker-influenced sources (archived pages, vendor reports, a
# prompt-injected collector) and are later assembled into the GitHub
# API verification URLs. The client percent-encodes every path segment
# (clients/github.py), and these validators reject hostile shapes at
# record-construction time so a forged record never even reaches the
# verifier. Mirrors the sibling local-git client's ref/sha validation
# (clients/git.py).
# ---------------------------------------------------------------------------

# GitHub logins/org names: alphanumeric plus interior hyphens, max 39.
_GITHUB_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?$")

# GitHub repository names: alphanumeric plus ``._-``, max 100.
_GITHUB_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")

# Characters git check-ref-format forbids anywhere in a refname, plus
# URL metacharacters (``?`` ``#``) that would smuggle query/fragment
# structure into a verification URL.
_REF_FORBIDDEN_CHARS = set(' ~^:?*[\\#')

_SHA1_HEX_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def validate_sha1_hex(value: str, what: str = "sha") -> str:
    """A full 40-char hex SHA-1 object name, nothing else."""
    if not _SHA1_HEX_RE.fullmatch(value):
        msg = f"invalid {what} (expected 40 hex chars): {value!r}"
        raise ValueError(msg)
    return value


def validate_git_ref_name(value: str, what: str = "ref") -> str:
    """Refuse branch/tag names that violate git check-ref-format rules
    or carry URL metacharacters. Hierarchical names (``release/v1.0``)
    pass; traversal (``..``), option shapes (leading ``-``), control
    bytes, and query/fragment injectors fail closed."""
    ok = (
        bool(value)
        and not value.startswith(("-", "/"))
        and not value.endswith(("/", "."))
        and value != "@"
        and "@{" not in value
        and ".." not in value
        and "//" not in value
    )
    if ok:
        for ch in value:
            if ord(ch) < 0x20 or ord(ch) == 0x7F or ch in _REF_FORBIDDEN_CHARS:
                ok = False
                break
    if ok:
        for component in value.split("/"):
            if component.startswith(".") or component.endswith(".lock"):
                ok = False
                break
    if not ok:
        msg = f"invalid {what}: {value!r}"
        raise ValueError(msg)
    return value


def validate_repo_relative_path(value: str, what: str = "file path") -> str:
    """A repository-relative file path: no absolute paths, no ``.``/
    ``..``/empty components, no control bytes, no URL metacharacters,
    no backslashes."""
    ok = bool(value) and not value.startswith("/")
    if ok:
        for ch in value:
            if ord(ch) < 0x20 or ord(ch) == 0x7F or ch in ("?", "#", "\\"):
                ok = False
                break
    if ok:
        for component in value.split("/"):
            if component in ("", ".", ".."):
                ok = False
                break
    if not ok:
        msg = f"invalid {what}: {value!r}"
        raise ValueError(msg)
    return value


# =============================================================================
# ENUMS
# =============================================================================


class EvidenceSource(str, Enum):
    """Where evidence was obtained."""

    GHARCHIVE = "gharchive"
    GIT = "git"
    GITHUB = "github"
    WAYBACK = "wayback"
    SECURITY_VENDOR = "security_vendor"


class EventType(str, Enum):
    """GitHub event types from GH Archive."""

    PUSH = "PushEvent"
    PULL_REQUEST = "PullRequestEvent"
    ISSUES = "IssuesEvent"
    ISSUE_COMMENT = "IssueCommentEvent"
    CREATE = "CreateEvent"
    DELETE = "DeleteEvent"
    FORK = "ForkEvent"
    WATCH = "WatchEvent"
    RELEASE = "ReleaseEvent"
    MEMBER = "MemberEvent"
    PUBLIC = "PublicEvent"
    WORKFLOW_RUN = "WorkflowRunEvent"


class RefType(str, Enum):
    BRANCH = "branch"
    TAG = "tag"
    REPOSITORY = "repository"


class PRAction(str, Enum):
    OPENED = "opened"
    CLOSED = "closed"
    REOPENED = "reopened"
    MERGED = "merged"


class IssueAction(str, Enum):
    OPENED = "opened"
    CLOSED = "closed"
    REOPENED = "reopened"
    DELETED = "deleted"


class WorkflowConclusion(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    CANCELLED = "cancelled"


class IOCType(str, Enum):
    """Indicator types."""

    COMMIT_SHA = "commit_sha"
    FILE_PATH = "file_path"
    FILE_HASH = "file_hash"
    CODE_SNIPPET = "code_snippet"
    EMAIL = "email"
    USERNAME = "username"
    REPOSITORY = "repository"
    TAG_NAME = "tag_name"
    BRANCH_NAME = "branch_name"
    WORKFLOW_NAME = "workflow_name"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    API_KEY = "api_key"
    SECRET = "secret"


# =============================================================================
# COMMON MODELS
# =============================================================================


class GitHubActor(BaseModel):
    """GitHub user/actor."""

    login: str
    id: int | None = None


class GitHubRepository(BaseModel):
    """GitHub repository."""

    owner: str
    name: str
    full_name: str

    @model_validator(mode='after')
    def validate_identity(self):
        """Reject repository identities a verification URL cannot be
        canonically built from, and require ``full_name`` to agree
        with ``owner``/``name`` — the verifier fetches by owner/name
        while reports cite full_name, so a mismatch lets a record
        claim one repository and verify against another."""
        if not _GITHUB_OWNER_RE.fullmatch(self.owner):
            msg = f"invalid GitHub owner: {self.owner!r}"
            raise ValueError(msg)
        if (not _GITHUB_REPO_NAME_RE.fullmatch(self.name)
                or self.name in (".", "..")):
            msg = f"invalid GitHub repository name: {self.name!r}"
            raise ValueError(msg)
        if self.full_name != f"{self.owner}/{self.name}":
            msg = (
                f"full_name {self.full_name!r} does not match "
                f"owner/name {self.owner!r}/{self.name!r}"
            )
            raise ValueError(msg)
        return self


class VerificationInfo(BaseModel):
    """How to verify this evidence."""

    source: EvidenceSource
    url: HttpUrl | None = None
    bigquery_table: str | None = None
    query: str | None = None

    @model_validator(mode='after')
    def validate_gharchive_table(self):
        """Ensure GHARCHIVE sources have a specific BigQuery table, not a wildcard."""
        if self.source == EvidenceSource.GHARCHIVE:
            if not self.bigquery_table:
                msg = (
                    "GHARCHIVE evidence must specify bigquery_table. "
                    "Use format 'githubarchive.year.YYYY' or 'githubarchive.month.YYYYMM'"
                )
                raise ValueError(msg)
            if self.bigquery_table.endswith('.*'):
                msg = (
                    f"GHARCHIVE evidence must specify exact table, not wildcard: {self.bigquery_table}. "
                    "Use format 'githubarchive.year.YYYY' or 'githubarchive.month.YYYYMM'"
                )
                raise ValueError(msg)
        return self


class VerificationResult(BaseModel):
    """Result of verification.

    ``warnings`` carries checks that were SKIPPED (no credentials,
    unsupported source) rather than performed. A skipped check must
    never read as "verified" — reports distinguish "verified" from
    "not checked" via this field.
    """
    is_valid: bool
    errors: list[str] = []
    warnings: list[str] = []


