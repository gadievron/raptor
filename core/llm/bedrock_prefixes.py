"""Bedrock model-id prefix constants — single source of truth.

AWS Bedrock surfaces models under ``<region>.<provider>.<model>``
inference-profile IDs (eg ``us.anthropic.claude-opus-4-7``).  Two
separate concerns consume these:

  * ``core.security.llm_family`` — peels prefixes for family /
    routing-provider resolution
  * ``core.llm.model_data`` — peels prefixes + applies the regional
    cost multiplier

Previously each module duplicated its own copy of the constants;
adding a new AWS region or Bedrock provider segment required updating
two places.  This module is the single source of truth — both
consumers import from here.
"""

from __future__ import annotations


# AWS regional inference-profile prefixes that route a model id to
# a specific region.  ``global.`` is the cross-region SKU that AWS
# offers for some Claude models at the same price as direct
# Anthropic API; ``us./eu./au./apac.`` are geographic in-region or
# geo-region SKUs that carry an approximately 10% surcharge over
# global (when a global counterpart exists for that model).
#
# Add new prefixes here as AWS rolls them out (verify on the
# Bedrock inference-profile docs).
BEDROCK_REGIONAL_PREFIXES: tuple[str, ...] = (
    "us.", "eu.", "au.", "apac.", "global.",
)

# Subset that carries the regional cost surcharge — ``global.`` is
# explicitly the cheaper baseline.
BEDROCK_REGIONAL_SURCHARGE_PREFIXES: tuple[str, ...] = (
    "us.", "eu.", "au.", "apac.",
)
BEDROCK_GLOBAL_PREFIX: str = "global."

# Bedrock provider segment (the second dot-separated component).
# Only providers we map to a RAPTOR Family are listed; ``amazon.``
# (Titan / Nova) and ``ai21.`` (Jamba / Jurassic) have no Family
# mapping yet and would need extending core.security.llm_family.Family
# before they can participate in cross-family validation.
BEDROCK_PROVIDER_SEGMENTS: tuple[str, ...] = (
    "anthropic.",
    "meta.",
    "mistral.",
    "cohere.",
)


__all__ = [
    "BEDROCK_REGIONAL_PREFIXES",
    "BEDROCK_REGIONAL_SURCHARGE_PREFIXES",
    "BEDROCK_GLOBAL_PREFIX",
    "BEDROCK_PROVIDER_SEGMENTS",
]
