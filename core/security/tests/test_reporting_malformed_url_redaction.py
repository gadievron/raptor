"""Foreign report diagnostics must not bypass URL credential redaction."""
import pytest

from core.security.redaction import redact_secrets, redact_url_secrets_only


@pytest.mark.parametrize("redact", [redact_secrets, redact_url_secrets_only])
@pytest.mark.parametrize("url", [
    "https://user:owned-password@example.invalid\x1b[31m",
    "https://user:owned-password@[invalid",
    "https://user:owned-password@example.invalid\uff1aport",
])
def test_malformed_url_redaction_fails_closed(redact, url):
    assert "owned-password" not in redact("upstream failure: " + url)
    assert "[REDACTED malformed URL]" in redact("upstream failure: " + url)


@pytest.mark.parametrize("redact", [redact_secrets, redact_url_secrets_only])
def test_explicit_secret_reveal_retains_malformed_diagnostic(redact):
    value = "https://user:owned-password@[invalid"
    assert redact(value, reveal_secrets=True) == value
