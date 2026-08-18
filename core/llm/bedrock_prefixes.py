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


def regional_prefix_of(model_id: str) -> str | None:
    """The regional inference-profile prefix on ``model_id``, or
    ``None`` when the id is bare (``anthropic.claude-…``), an ARN, or
    otherwise unprefixed."""
    for prefix in BEDROCK_REGIONAL_PREFIXES:
        if model_id.startswith(prefix):
            return prefix
    return None


def mantle_model_id(model_id: str) -> str:
    """Normalize a model id for the Mantle surface, which accepts
    ONLY bare ``<provider>.<model>`` ids — regional routing happens
    via the hostname, and a prefixed id is rejected upstream.

    Two lossless fixes: peel a regional prefix, and prepend the
    provider segment when the id is a bare catalog name whose family
    implies one (``claude-x`` → ``anthropic.claude-x``).  Ids already
    in Mantle shape (and anything unrecognisable, e.g. ARNs) pass
    through verbatim.
    """
    prefix = regional_prefix_of(model_id)
    if prefix:
        model_id = model_id[len(prefix):]
    if not model_id.startswith(BEDROCK_PROVIDER_SEGMENTS):
        # Catalog-bare name: derive the provider segment from the
        # model family rather than hardcoding a vocabulary here.
        from core.security.llm_family import provider_of
        derived = provider_of(model_id)
        if derived and f"{derived}." in BEDROCK_PROVIDER_SEGMENTS:
            model_id = f"{derived}.{model_id}"
    return model_id


def bedrock_shaped_model_id(model_id: str) -> bool:
    """True when ``model_id`` is unmistakably a Bedrock id shape:
    a Bedrock ARN, a bare ``<provider>.<model>`` id, or a regional
    inference-profile id (``us./eu./au./apac./global.`` + vendor
    segment).

    The misroute predicate for transport guards: a direct-API or
    claudecode-on-direct-API path can never serve such an id -- the
    upstream rejects it with a bare 400.  Deliberately conservative
    the other way: bare catalog names (``claude-opus-4-8``), the
    ``session-default`` sentinel, operator aliases, and Vertex ids
    (``claude-...@date``) are never shaped.
    """
    if not model_id:
        return False
    if model_id.startswith("arn:aws:bedrock:"):
        return True
    prefix = regional_prefix_of(model_id)
    if prefix:
        # ``us.<vendor>.<model>`` -- Bedrock-shaped even for vendor
        # segments without a Family mapping (``amazon.``, ``ai21.``):
        # the regional prefix + a dotted vendor segment is the
        # inference-profile grammar, nothing else uses it.
        body = model_id[len(prefix):]
        head, dot, rest = body.partition(".")
        return bool(dot and head and rest)
    return model_id.startswith(BEDROCK_PROVIDER_SEGMENTS)


def prefix_region_mismatch(model_id: str, region: str) -> str | None:
    """Operator-actionable message when ``model_id``'s geographic
    inference-profile prefix cannot be served from ``region``, else
    ``None``.

    Deliberately conservative — only clear contradictions are flagged
    (a ``us.`` profile invoked from a non-``us-*`` region, and the
    symmetric cases), because AWS's geography→region mapping grows
    over time and a stale strict table would false-positive.
    ``global.`` never mismatches.
    """
    prefix = regional_prefix_of(model_id)
    if not prefix or prefix == BEDROCK_GLOBAL_PREFIX or not region:
        return None
    geo_region_starts = {
        "us.": ("us-",),
        "eu.": ("eu-",),
        # apac./au. profiles are served from Asia-Pacific regions;
        # flag only the unambiguous wrong-continent cases.
        "apac.": ("ap-",),
        "au.": ("ap-",),
    }
    allowed = geo_region_starts.get(prefix)
    if allowed and not region.startswith(allowed):
        return (
            f"model id {model_id!r} carries the {prefix!r} "
            f"inference-profile prefix but the configured region is "
            f"{region!r} — Bedrock will reject the invocation. Use a "
            f"region matching the profile's geography, the 'global.' "
            f"profile, or a bare id on the mantle surface."
        )
    return None


__all__ = [
    "BEDROCK_REGIONAL_PREFIXES",
    "BEDROCK_REGIONAL_SURCHARGE_PREFIXES",
    "BEDROCK_GLOBAL_PREFIX",
    "BEDROCK_PROVIDER_SEGMENTS",
    "bedrock_shaped_model_id",
    "mantle_model_id",
    "prefix_region_mismatch",
    "regional_prefix_of",
]
