"""Re-export from canonical location in core.concepts.contract_pairs."""

from core.concepts.contract_pairs import (
    ContractKind,
    ContractPairGroup,
    ContractPartner,
    build_contract_index,
    detect_contract_pairs,
    discover_project_verbs,
    format_contract_pairs_for_prompt,
    load_project_verbs,
    load_project_verbs_with_siblings,
    save_project_verbs,
)

__all__ = [
    "ContractKind",
    "ContractPairGroup",
    "ContractPartner",
    "build_contract_index",
    "detect_contract_pairs",
    "discover_project_verbs",
    "format_contract_pairs_for_prompt",
    "load_project_verbs",
    "load_project_verbs_with_siblings",
    "save_project_verbs",
]
