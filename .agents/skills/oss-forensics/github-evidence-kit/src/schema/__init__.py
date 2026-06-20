"""
Schema definitions for evidence types.
"""
from .common import (
    EvidenceSource,
    EventType,
    RefType,
    PRAction,
    IssueAction,
    WorkflowConclusion,
    IOCType,
    GitHubActor,
    GitHubRepository,
    VerificationInfo,
    VerificationResult,
)
from .events import (
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
)
from .observations import (
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
)

# Combined type alias for any evidence type
AnyEvidence = AnyEvent | AnyObservation

__all__ = [
    # Enums
    "EvidenceSource",
    "EventType",
    "RefType",
    "PRAction",
    "IssueAction",
    "WorkflowConclusion",
    "IOCType",
    # Common models
    "GitHubActor",
    "GitHubRepository",
    "VerificationInfo",
    "VerificationResult",
    # Type aliases
    "AnyEvent",
    "AnyObservation",
    "AnyEvidence",
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
]
