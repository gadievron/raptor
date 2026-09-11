"""`temperature` is deprecated for Anthropic's reasoning tier (Opus 4.7+).

Cutoff verified empirically against the live API: opus-4-7/4-8 reject it with a
400; opus<=4-6 and all sonnet/haiku accept it. The gate omits temperature for
version >= 4.7 across tiers (over-omitting a future tier that still accepts it is
harmless; sending it to a deprecated model is a hard 400).
"""

from core.llm.providers import supports_temperature


def test_opus_cutoff_at_4_7():
    assert supports_temperature("claude-opus-4-6") is True      # verified: accepts
    assert supports_temperature("claude-opus-4-7") is False     # verified: 400
    assert supports_temperature("claude-opus-4-8") is False     # verified: 400
    assert supports_temperature("claude-opus-4-1") is True


def test_other_tiers_below_cutoff_keep_temperature():
    assert supports_temperature("claude-sonnet-4-6") is True     # verified: accepts
    assert supports_temperature("claude-sonnet-4-5") is True
    assert supports_temperature("claude-haiku-4-5") is True


def test_future_versions_at_or_above_cutoff_omit():
    assert supports_temperature("claude-opus-4-9") is False
    assert supports_temperature("claude-sonnet-4-7") is False    # over-omit, but safe
    assert supports_temperature("claude-opus-5-0") is False


def test_bedrock_prefixes_and_snapshots():
    assert supports_temperature("us.anthropic.claude-opus-4-7") is False
    assert supports_temperature("global.anthropic.claude-opus-4-8") is False
    assert supports_temperature("claude-opus-4-7-20260301") is False
    assert supports_temperature("us.anthropic.claude-sonnet-4-6") is True


def test_non_claude_and_unparseable_keep_temperature():
    assert supports_temperature("gemini-2.5-pro") is True
    assert supports_temperature("gpt-5.2") is True
    assert supports_temperature("") is True
    assert supports_temperature("llama3:70b") is True


def test_single_number_5_family_omits_temperature():
    """The 5 family carries single-number versions (no minor); absent
    minor gates as 0, so (5, 0) >= (4, 7) omits.  Verified live: a
    5-family model on Bedrock Mantle rejects ``temperature`` with the
    same 400 as opus-4-7."""
    assert supports_temperature("claude-sonnet-5") is False
    assert supports_temperature("claude-opus-5") is False
    assert supports_temperature("anthropic.claude-sonnet-5") is False
    assert supports_temperature("global.anthropic.claude-opus-5") is False


def test_single_number_below_cutoff_keeps_temperature():
    """Optional-minor parsing must not over-omit old single-number
    versions: (4, 0) and lower still accept temperature."""
    assert supports_temperature("claude-opus-4") is True
    assert supports_temperature("claude-instant-1") is True


def test_dated_snapshot_of_major_only_id_keeps_temperature():
    """An 8-digit date suffix on a major-only id is a snapshot date,
    not a minor version: parsing ``claude-opus-4-20250514`` as
    (4, 20250514) gated it >= (4, 7) and silently dropped
    ``temperature`` for a 4.0 model that accepts it."""
    assert supports_temperature("claude-opus-4-20250514") is True
    assert supports_temperature("claude-sonnet-4-20250514") is True
    assert supports_temperature("us.anthropic.claude-opus-4-20250514") is True


def test_dated_snapshot_of_two_part_id_still_gates():
    """Two-part dated ids keep their real minor version — the
    date-suffix exclusion must not swallow a genuine minor."""
    assert supports_temperature("claude-sonnet-4-7-20260115") is False
    assert supports_temperature("claude-opus-4-7-20260301") is False
    assert supports_temperature("claude-sonnet-4-5-20250929") is True
