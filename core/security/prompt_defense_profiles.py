"""Per-model defence profiles for prompt-envelope construction.

Each profile encodes which envelope layers (tag style, datamarking, base64,
markdown stripping, role placement) apply for a given model. Profiles are
populated empirically: a canary test suite probes each model against known
injection patterns at onboarding, and the results are committed here as a
PR. There is no automatic profile mutation — see prompt-injection-base64
memory entry for the rationale (CI/CD cannot run LLM tasks reliably,
adversarial telemetry, auditability).

The lookup function get_profile_for() maps a model identifier (as written
in models.json) to a profile. Unknown models fall back to CONSERVATIVE,
which assumes the model honours none of the model-dependent defences.
Even on CONSERVATIVE the model-independent floor still holds — slot
discipline, control-char sanitisation, role placement, markdown
stripping, output schema validation, capability isolation.
"""

from __future__ import annotations

from core.security.prompt_envelope import ModelDefenseProfile


CONSERVATIVE = ModelDefenseProfile(
    name="conservative",
    tag_style="nonce-only",
    envelope_xml=True,
    datamarking=False,
    base64_code=False,
    slot_discipline=True,
    markdown_strip=True,
    role_placement="user-only",
)


ANTHROPIC_CLAUDE = ModelDefenseProfile(
    name="anthropic-claude",
    tag_style="nonce-only",
    envelope_xml=True,
    datamarking=True,
    base64_code=True,
    slot_discipline=True,
    markdown_strip=True,
    role_placement="user-only",
)


OPENAI_GPT = ModelDefenseProfile(
    name="openai-gpt",
    tag_style="openai-untrusted-text",
    envelope_xml=True,
    datamarking=True,
    base64_code=True,
    slot_discipline=True,
    markdown_strip=True,
    role_placement="user-only",
)


GOOGLE_GEMINI = ModelDefenseProfile(
    name="google-gemini",
    tag_style="nonce-only",
    envelope_xml=True,
    datamarking=True,
    base64_code=True,
    slot_discipline=True,
    markdown_strip=True,
    role_placement="user-only",
)


META_LLAMA = ModelDefenseProfile(
    name="meta-llama",
    tag_style="nonce-only",
    envelope_xml=True,
    datamarking=True,
    base64_code=False,
    slot_discipline=True,
    markdown_strip=True,
    role_placement="user-only",
)


OLLAMA_SMALL = ModelDefenseProfile(
    name="ollama-small",
    tag_style="nonce-only",
    envelope_xml=True,
    datamarking=False,
    base64_code=False,
    slot_discipline=True,
    markdown_strip=True,
    role_placement="user-only",
)


PASSTHROUGH = ModelDefenseProfile(
    name="passthrough",
    tag_style="passthrough",
    envelope_xml=False,
    datamarking=False,
    base64_code=False,
    slot_discipline=False,
    markdown_strip=True,
    role_placement="user-only",
)


_BY_PREFIX: tuple[tuple[str, ModelDefenseProfile], ...] = (
    ("claude-", ANTHROPIC_CLAUDE),
    ("anthropic/", ANTHROPIC_CLAUDE),
    ("gpt-", OPENAI_GPT),
    ("openai/", OPENAI_GPT),
    ("o1-", OPENAI_GPT),
    ("o3-", OPENAI_GPT),
    ("gemini-", GOOGLE_GEMINI),
    ("gemini/", GOOGLE_GEMINI),
    ("google/", GOOGLE_GEMINI),
    ("llama-", META_LLAMA),
    ("meta-llama/", META_LLAMA),
    ("ollama/", OLLAMA_SMALL),
)


def get_profile_for(model_id: str) -> ModelDefenseProfile:
    """Return the defence profile for a model identifier.

    Matching is by prefix on the lowered identifier — `claude-opus-4-7`
    and `anthropic/claude-sonnet-4-6` both resolve to ANTHROPIC_CLAUDE.
    Unknown identifiers return CONSERVATIVE. Identifiers may include a
    provider prefix (`openai/gpt-5`) or be bare (`gpt-5`); both forms
    are handled.
    """
    needle = model_id.lower()
    for prefix, profile in _BY_PREFIX:
        if needle.startswith(prefix):
            return profile
    return CONSERVATIVE
