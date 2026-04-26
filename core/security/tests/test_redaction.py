import pytest

from core.security.redaction import redact_secrets


def test_redacts_query_string_secrets_by_default():
    api_value = "api-" + "a" * 24
    access_value = "access-" + "b" * 24
    value = f"https://example.test/login?api_key={api_value}&next=/home&access_token={access_value}"

    redacted = redact_secrets(value)

    assert api_value not in redacted
    assert access_value not in redacted
    assert "api_key=[REDACTED]" in redacted
    assert "access_token=[REDACTED]" in redacted
    assert "next=/home" in redacted


@pytest.mark.parametrize(
    "param_name",
    [
        "api_key",
        "apikey",
        "access_token",
        "auth_token",
        "bearer_token",
        "client_secret",
        "consumer_secret",
        "id_token",
        "refresh_token",
        "secret",
        "session_token",
        "service_token",
        "token",
    ],
)
def test_redacts_supported_secret_query_parameter_names(param_name):
    value = "value-" + "c" * 24
    redacted = redact_secrets(f"https://example.test/callback?{param_name}={value}")

    assert value not in redacted
    assert f"{param_name}=[REDACTED]" in redacted


def test_preserves_non_secret_query_parameters_and_fragments():
    value = "https://example.test/search?q=report&next=/home&page_token=cursor123#section"

    assert redact_secrets(value) == value


def test_redacts_url_userinfo_and_authorization_headers():
    password = "pw-" + "d" * 24
    bearer = "Bearer " + "e" * 24
    basic = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    value = f"https://alice:{password}@example.test/path Authorization: {bearer} Authorization: {basic}"

    redacted = redact_secrets(value)

    assert password not in redacted
    assert bearer not in redacted
    assert basic not in redacted
    assert "alice:[REDACTED]@example.test" in redacted
    assert "Bearer [REDACTED]" in redacted
    assert "Basic [REDACTED]" in redacted


def test_redacts_lowercase_auth_schemes():
    bearer = "bearer " + "f" * 24
    basic = "basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="

    redacted = redact_secrets(f"headers: {bearer} {basic}")

    assert bearer not in redacted
    assert basic not in redacted
    assert "Bearer [REDACTED]" in redacted
    assert "Basic [REDACTED]" in redacted


def test_preserves_short_non_authorization_values():
    value = "Bearer short basic setup tokenization page_token=cursor123"

    assert redact_secrets(value) == value


def test_can_keep_secrets_for_operator_debugging():
    api_value = "api-" + "g" * 24
    bearer = "Bearer " + "h" * 24
    value = f"https://example.test/?api_key={api_value} Authorization: {bearer}"

    assert redact_secrets(value, reveal_secrets=True) == value
