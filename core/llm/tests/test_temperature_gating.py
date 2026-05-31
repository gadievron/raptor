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
