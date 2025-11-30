"""
Common schema definitions for GitHub Evidence Kit.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, HttpUrl


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


class VerificationInfo(BaseModel):
    """How to verify this evidence."""

    source: EvidenceSource
    url: HttpUrl | None = None
    bigquery_table: str | None = None
    query: str | None = None


class VerificationResult(BaseModel):
    """Result of verification."""
    is_valid: bool
    errors: list[str] = []


