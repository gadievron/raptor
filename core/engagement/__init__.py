"""Engagement-lane substrate — per-artifact state for install-directory
targets.

``core.engagement`` is the home the binary-engagement capabilities
share: the artifact ledger (this series), and — in LATER series that
consume its API — the depth-policy governor and the per-class chain
composition. It deliberately mirrors the graph-store precedent
(``core/understand_graph``): its own core package, stores under the
project output directory, operator verbs on ``/project``.

Naming note: "ledger" inside ``core/project`` already means the
SESSION RUN ledger (``core.project.sessions``) — the artifact ledger
lives here so the two never share a module namespace.
"""

from core.engagement.ledger import (
    LEDGER_FILENAME,
    LedgerCaps,
    append_policy_amendment,
    append_residual,
    build_ledger,
    checklist_slot_path,
    is_artifact_id,
    ledger_path,
    list_artifact_checklists,
    load_engagement_policy,
    load_ledger,
    load_policy_amendments,
    read_artifact_checklist,
    set_artifact_policies,
    set_artifact_policy,
    set_artifact_status,
    update_engagement_policy,
    write_artifact_checklist,
)

__all__ = [
    "LEDGER_FILENAME",
    "LedgerCaps",
    "append_policy_amendment",
    "append_residual",
    "build_ledger",
    "checklist_slot_path",
    "is_artifact_id",
    "ledger_path",
    "list_artifact_checklists",
    "load_engagement_policy",
    "load_ledger",
    "load_policy_amendments",
    "read_artifact_checklist",
    "set_artifact_policies",
    "set_artifact_policy",
    "set_artifact_status",
    "update_engagement_policy",
    "write_artifact_checklist",
]
