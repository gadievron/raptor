"""Shared offline domain-boundary utilities."""

from core.domains.public_suffix import SuffixRules, load_suffix_rules, registrable_domain

__all__ = ["SuffixRules", "load_suffix_rules", "registrable_domain"]
