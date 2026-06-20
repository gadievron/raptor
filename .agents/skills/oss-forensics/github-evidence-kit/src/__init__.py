"""
GitHub Evidence Kit - Evidence collection and verification for GitHub forensics.

Evidence collection uses Collectors that fetch data from trusted sources:

    from src.collectors.api import GitHubAPICollector
    from src.collectors.archive import GHArchiveCollector
    from src.collectors.local import LocalGitCollector

    # Collect evidence from various sources
    github_collector = GitHubAPICollector()
    archive_collector = GHArchiveCollector()
    git_collector = LocalGitCollector()

    commit = github_collector.collect_commit("aws", "aws-toolkit-vscode", "678851b...")
    events = archive_collector.collect_events(timestamp="202507132037", repo="aws/aws-toolkit-vscode")

For loading previously serialized evidence from JSON:

    from src import load_evidence_from_json
    evidence = load_evidence_from_json(json_data)

For schema types (type hints, manual construction):

    from src.schema import CommitObservation, IOC, EvidenceSource
"""

from typing import Annotated, Union

from pydantic import Field, TypeAdapter

from .store import EvidenceStore

# Import all types needed for discriminated union deserialization
from .schema.events import (
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
from .schema.observations import (
    CommitObservation,
    IssueObservation,
    FileObservation,
    ForkObservation,
    BranchObservation,
    TagObservation,
    ReleaseObservation,
    SnapshotObservation,
    IOC,
    ArticleObservation,
    AnyObservation,
)

# Re-export commonly used enums for convenience
from .schema.common import EvidenceSource, IOCType

# Combined type alias
AnyEvidence = AnyEvent | AnyObservation

# Pydantic discriminated unions for efficient JSON deserialization
_EventUnion = Annotated[
    Union[
        PushEvent, PullRequestEvent, IssueEvent, IssueCommentEvent,
        CreateEvent, DeleteEvent, ForkEvent, WorkflowRunEvent,
        ReleaseEvent, WatchEvent, MemberEvent, PublicEvent,
    ],
    Field(discriminator="event_type"),
]

_ObservationUnion = Annotated[
    Union[
        CommitObservation, IssueObservation, FileObservation, ForkObservation,
        BranchObservation, TagObservation, ReleaseObservation, SnapshotObservation,
        IOC, ArticleObservation,
    ],
    Field(discriminator="observation_type"),
]

_event_adapter = TypeAdapter(_EventUnion)
_observation_adapter = TypeAdapter(_ObservationUnion)


def load_evidence_from_json(data: dict) -> AnyEvidence:
    """
    Load a previously serialized evidence object from JSON.

    Args:
        data: Dictionary from JSON deserialization (e.g., json.load())

    Returns:
        The appropriate Event or Observation instance

    Raises:
        ValueError: If the data cannot be parsed into a known evidence type
    """
    if "event_type" in data:
        try:
            return _event_adapter.validate_python(data)
        except Exception as e:
            raise ValueError(f"Unknown event_type: {data.get('event_type')}") from e

    if "observation_type" in data:
        try:
            return _observation_adapter.validate_python(data)
        except Exception as e:
            raise ValueError(f"Unknown observation_type: {data.get('observation_type')}") from e

    raise ValueError("Data must contain 'event_type' or 'observation_type' field")


# Public API - minimal surface area
__all__ = [
    # Main entry points
    "EvidenceStore",
    "load_evidence_from_json",
    # Type aliases (for type hints)
    "AnyEvidence",
    "AnyEvent",
    "AnyObservation",
    # Commonly used enums
    "EvidenceSource",
    "IOCType",
]
