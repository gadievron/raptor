"""The GITHUB-lane verifier dispatcher must fail CLOSED.

verify_all is the anti-fabrication chokepoint. The GITHUB dispatcher
previously fell back to URL accessibility for any observation type it
did not map, and a missing URL verified with zero checks — so a
fabricated observation of an unmapped type (or one that simply
omitted its URL) read as verified. Mirrors the GH Archive lane's
fail-closed closure (test_gharchive_type_verification.py).
"""

from __future__ import annotations

import ast
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from src.schema.common import (
    EvidenceSource,
    GitHubRepository,
    VerificationInfo,
)
from src.schema.observations import Observation
from src.verifiers.consistency import ConsistencyVerifier

_KIT_ROOT = Path(__file__).parents[1]


def _observation(obs_type: str | None = None, url: str | None = None):
    obs = Observation(
        evidence_id="EVD-100",
        observed_when=datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
        observed_by=EvidenceSource.GITHUB,
        observed_what="fabricated thing",
        repository=GitHubRepository(owner="o", name="r", full_name="o/r"),
        verification=VerificationInfo(source=EvidenceSource.GITHUB, url=url),
    )
    if obs_type is not None:
        object.__setattr__(obs, "observation_type", obs_type)
    return obs


def test_unmapped_observation_type_fails_closed():
    verifier = ConsistencyVerifier()
    result = verifier._verify_github_observation(
        _observation("totally_new_type"),
    )
    assert not result.is_valid
    assert any("fail" in e for e in result.errors)


def test_missing_observation_type_fails_closed():
    verifier = ConsistencyVerifier()
    result = verifier._verify_github_observation(_observation(None))
    assert not result.is_valid


def test_url_none_never_verifies():
    verifier = ConsistencyVerifier()
    result = verifier._verify_url_accessible(_observation("fork", url=None))
    assert not result.is_valid
    assert result.errors


def _github_dispatcher_keys() -> set[str]:
    """Mechanically read the dispatcher mapping's keys from source."""
    src = (_KIT_ROOT / "src" / "verifiers" / "consistency.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if (isinstance(node, ast.FunctionDef)
                and node.name == "_verify_github_observation"):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Dict):
                    keys = {
                        k.value for k in sub.keys
                        if isinstance(k, ast.Constant)
                    }
                    if keys:
                        return keys
    raise AssertionError("dispatcher mapping not found")


def _collector_produced_types() -> set[str]:
    """Observation types the API (GitHub-lane) collector produces —
    real producers, enumerated mechanically, never a hand-list."""
    schema_src = (_KIT_ROOT / "src" / "schema" / "observations.py").read_text()
    schema_tree = ast.parse(schema_src)
    class_to_type: dict[str, str] = {}
    for node in ast.walk(schema_tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for stmt in node.body:
            if (isinstance(stmt, ast.AnnAssign)
                    and isinstance(stmt.target, ast.Name)
                    and stmt.target.id == "observation_type"
                    and isinstance(stmt.value, ast.Constant)):
                class_to_type[node.name] = stmt.value.value

    api_src = (_KIT_ROOT / "src" / "collectors" / "api.py").read_text()
    api_tree = ast.parse(api_src)
    produced: set[str] = set()
    for node in ast.walk(api_tree):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if name in class_to_type:
                produced.add(class_to_type[name])
    return produced


def test_every_collector_produced_type_is_mapped():
    # Registry closure: the GitHub API collector's real producer set
    # must be covered by the dispatcher — a new observation type
    # without a verifier entry would otherwise fail closed at run
    # time, and this test names the entry to add.
    produced = _collector_produced_types()
    assert produced, "producer enumeration came back empty"
    missing = produced - _github_dispatcher_keys()
    assert not missing, (
        f"GitHub-lane collector produces {sorted(missing)} with no "
        "dispatcher entry in _verify_github_observation"
    )
