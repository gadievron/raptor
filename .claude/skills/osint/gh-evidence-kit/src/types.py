"""
Type hints for GitHub Forensics Evidence Schema.

These types are for static type checking and IDE autocomplete ONLY.
Do NOT instantiate these classes directly - use EvidenceFactory.

Usage (type hints only):
    from src.types import CommitObservation, IssueObservation

    def process_commit(commit: CommitObservation) -> None:
        print(commit.sha)

To create instances, use:
    from src import EvidenceFactory
    factory = EvidenceFactory()
    commit = factory.commit("owner", "repo", "sha")

WARNING: Importing from this module does NOT grant instantiation privileges.
The classes here are re-exported for type annotations only.
"""

# Re-export all schema types for type hints
from ._schema import (
    # Common Models
    GitHubActor,
    GitHubRepository,
    VerificationInfo,
    # Events
    Event,
    CommitInPush,
    PushEvent,
    PullRequestEvent,
    IssueEvent,
    IssueCommentEvent,
    CreateEvent,
    DeleteEvent,
    ForkEvent,
    WorkflowRunEvent,
    ReleaseEvent,
    WatchEvent,
    MemberEvent,
    PublicEvent,
    AnyEvent,
    # Observations
    Observation,
    CommitAuthor,
    FileChange,
    CommitObservation,
    IssueObservation,
    FileObservation,
    ForkObservation,
    BranchObservation,
    TagObservation,
    ReleaseObservation,
    WaybackSnapshot,
    SnapshotObservation,
    IOC,
    ArticleObservation,
    AnyObservation,
    # Type aliases
    AnyEvidence,
)

__all__ = [
    # Common
    "GitHubActor",
    "GitHubRepository",
    "VerificationInfo",
    # Events
    "Event",
    "CommitInPush",
    "PushEvent",
    "PullRequestEvent",
    "IssueEvent",
    "IssueCommentEvent",
    "CreateEvent",
    "DeleteEvent",
    "ForkEvent",
    "WorkflowRunEvent",
    "ReleaseEvent",
    "WatchEvent",
    "MemberEvent",
    "PublicEvent",
    "AnyEvent",
    # Observations
    "Observation",
    "CommitAuthor",
    "FileChange",
    "CommitObservation",
    "IssueObservation",
    "FileObservation",
    "ForkObservation",
    "BranchObservation",
    "TagObservation",
    "ReleaseObservation",
    "WaybackSnapshot",
    "SnapshotObservation",
    "IOC",
    "ArticleObservation",
    "AnyObservation",
    "AnyEvidence",
]
