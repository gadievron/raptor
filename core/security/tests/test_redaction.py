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
    value = "https://example.test/search?q=report&next=/home&page=cursor123#section"

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
    # `page_token=cursor123` is NOT here: `_token`-suffixed assignments
    # now redact in free text exactly as they always did in URL query
    # strings (see test_secret_assignment_shapes_redact).
    value = "Bearer short basic setup tokenization"

    assert redact_secrets(value) == value


def test_can_keep_secrets_for_operator_debugging():
    api_value = "api-" + "g" * 24
    bearer = "Bearer " + "h" * 24
    value = f"https://example.test/?api_key={api_value} Authorization: {bearer}"

    assert redact_secrets(value, reveal_secrets=True) == value


# ----- redact_url_secrets_only (path-specific redactor) -----

from core.security.redaction import redact_url_secrets_only  # noqa: E402


class TestRedactUrlSecretsOnly:
    """Path-specific variant: URL credentials redacted, Bearer/Basic
    NOT redacted (avoids false positives on filesystem paths
    containing those substrings as filename components)."""

    def test_url_with_userinfo_still_redacted(self):
        # URL credentials must still be scrubbed even via the
        # path-specific entry point.
        value = "/cache/key/https://user:hunter2@example.com/x.html"
        out = redact_url_secrets_only(value)
        assert "hunter2" not in out
        assert "[REDACTED]" in out

    def test_bearer_substring_preserved(self):
        # `redact_secrets` would have replaced this; the path-specific
        # variant leaves it untouched (it's a filename, not a header).
        value = "./Bearer abcdefghij1234567890abcdef.dat"
        out = redact_url_secrets_only(value)
        assert "abcdefghij1234567890abcdef" in out, (
            f"Bearer-shaped substring wrongly redacted in path: {out!r}"
        )

    def test_basic_substring_preserved(self):
        value = "/var/log/Basic deadbeef1234567890.log"
        out = redact_url_secrets_only(value)
        assert "deadbeef1234567890" in out

    def test_clean_path_passes_through(self):
        path = "/usr/lib/python3/site-packages/__init__.py"
        assert redact_url_secrets_only(path) == path

    def test_reveal_flag_honoured(self):
        value = "https://user:secret@example.com/x"
        assert redact_url_secrets_only(value, reveal_secrets=True) == value

    def test_url_query_param_redaction_still_works(self):
        # URL query-string secret keys (api_key, token, etc.) get
        # redacted because URL parsing is still applied.
        value = "/cache/https://example.com/?api_key=abcdefghijklmnop"
        out = redact_url_secrets_only(value)
        assert "abcdefghijklmnop" not in out
        assert "api_key=[REDACTED]" in out


class TestVendorShapeCoverage:
    """Credential shapes from the injection-evasion battery that
    survived redaction verbatim — each pinned here with its exact
    repro form plus the shape family around it."""

    @pytest.mark.parametrize("text,fragment", [
        # AWS secret access key (assignment-context anchored).
        ("aws_secret_access_key = "
         "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEYxx", "wJalrXUtnFEMIK7"),
        ("AWS_SECRET_KEY: wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEYxx",
         "wJalrXUtnFEMIK7"),
        ('"aws_secret_access_key": "abcdEFGHijklMNOPqrstUVWXyz0123456789ABCD"',
         "abcdEFGHijklMNOP"),
        # PEM private-key blocks, with and without the END line.
        ("dump:\n-----BEGIN PRIVATE KEY-----\n"
         "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
         "-----END PRIVATE KEY-----", "MIIEvQIBADAN"),
        ("truncated:\n-----BEGIN RSA PRIVATE KEY-----\n"
         "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEA", "MIIEvQIBADAN"),
        # Azure storage AccountKey and AD client secret.
        ("AccountKey=QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
         "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==;EndpointSuffix=core.windows.net",
         "QUFBQUFBQUFB"),
        ("client_secret: 8Q~dummYsecretVALUEabcdefghijklmnopqrs",
         "dummYsecretVALUE"),
        # Slack browser-session token (xoxc — outside the old class).
        ("session xoxc-1234567890123-abcdefghijklmnop", "abcdefghijklmnop"),
        # Google OAuth refresh token.
        ("refresh: 1//0gABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij-klm",
         "0gABCDEFGHIJ"),
        # JWT whose header JSON has whitespace (eyA..., not eyJ...).
        ("auth eyAiYWxnIjogIkhTMjU2IiB9.eyAic3ViIjogIjEyMzQ1Njc4OTAiIH0."
         "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c", "SflKxwRJSMe"),
    ])
    def test_battery_shape_redacted(self, text, fragment):
        out = redact_secrets(text)
        assert fragment not in out, out

    @pytest.mark.parametrize("text,password", [
        ("postgres://svc:sekrit129@db.internal:5432/app", "sekrit129"),
        ("mongodb+srv://svc:sekrit130@cluster.example/db", "sekrit130"),
        ("redis://:sekrit131@cache.internal:6379/0", "sekrit131"),
        ("amqp://svc:sekrit132@mq.internal:5672/", "sekrit132"),
        ("ftp://svc:sekrit133@files.example/", "sekrit133"),
    ])
    def test_connection_string_password_redacted(self, text, password):
        # Non-http schemes carry credentials in the same userinfo
        # position; the http-only URL pattern let them all through.
        out = redact_secrets(text)
        assert password not in out, out
        # Host survives — the redaction targets the credential only.
        host = text.split("@", 1)[1].split("/", 1)[0].split(":", 1)[0]
        assert host in out

    def test_connection_string_covered_in_url_only_mode(self):
        out = redact_url_secrets_only("postgres://u:sekrit142@h/db")
        assert "sekrit142" not in out

    @pytest.mark.parametrize("benign", [
        "result = 1//divisor",
        "half = n//2",
        "the xox token format is documented at api.example",
        "AccountKey is required for this API",
        "aws_secret_access_key = <redacted-elsewhere>",
    ])
    def test_benign_code_and_prose_untouched(self, benign):
        assert redact_secrets(benign) == benign


class TestFreeTextAssignments:
    """is_secret_field_name + assignment wiring for free text (the
    mechanism URL query redaction always had)."""

    @pytest.mark.parametrize("text,secret", [
        ("GITLAB_TOKEN=glpat_sekrit201x", "glpat_sekrit201x"),
        ("npm_token=npmsekrit202", "npmsekrit202"),
        ("DB_PASSWORD: hunter2hunter2", "hunter2hunter2"),
        ("api_key: sekrit203abc", "sekrit203abc"),
        ('"client_secret": "sekrit204abc"', "sekrit204abc"),
        ("export AWS-SECRET-KEY=sekrit205abc", "sekrit205abc"),
    ])
    def test_secret_assignment_shapes_redact(self, text, secret):
        out = redact_secrets(text)
        assert secret not in out, out
        assert "[REDACTED]" in out

    @pytest.mark.parametrize("benign", [
        # Non-secret names with long values stay put.
        "version = 1.2.3-release+build99",
        "hostname: db-primary.internal.example",
        # Secret-suffixed name but value below the 8-char floor —
        # prose like "password: short" is not a credential.
        "password: short",
        "token: use-it",
        # Name merely CONTAINING "key" (no secret suffix) stays put.
        "monkey = bananasplit123",
    ])
    def test_benign_assignments_untouched(self, benign):
        assert redact_secrets(benign) == benign

    def test_json_member_separator_not_swallowed(self):
        # Unquoted JSON value: pre-fix the value charset included ','
        # so the replacement consumed the separator and dragged the
        # next member into [REDACTED].
        out = redact_secrets('{"access_token": 12345678901, "next": true}')
        assert "12345678901" not in out
        assert out == '{"access_token": [REDACTED], "next": true}'

    def test_quoted_json_value_stays_parseable(self):
        import json as _json
        out = redact_secrets(
            '{"access_token": "sekrit212abcd", "next": true}')
        assert "sekrit212abcd" not in out
        assert _json.loads(out) == {"access_token": "[REDACTED]",
                                    "next": True}

    def test_semicolon_separated_assignment_keeps_tail(self):
        # Cookie/config style `k=v;k2=v2` — the ';' stays outside the
        # replacement. Trade-off (same as parens): a secret CONTAINING
        # ','/';' redacts only up to it — this pass is the net under
        # the URL/vendor passes, not the primary.
        out = redact_secrets("session_token=sekrit213abc;path=/x")
        assert "sekrit213abc" not in out
        assert out.endswith(";path=/x")


class TestUrlParensAndCap:
    def test_paren_wrapped_url_query_secret_redacted(self):
        out = redact_secrets("(see https://e.example/?token=sekrit210ab)")
        assert "sekrit210ab" not in out
        # The prose wrapper survives outside the URL.
        assert out.endswith(")")

    def test_parens_inside_url_path_do_not_truncate_redaction(self):
        # Pre-fix the match stopped at '(' and the query escaped whole.
        out = redact_secrets(
            "https://e.example/wiki/Foo_(bar)?api_key=sekrit211ab&x=1")
        assert "sekrit211ab" not in out
        assert "Foo_(bar)" in out

    def test_paren_url_covered_in_url_only_mode(self):
        out = redact_url_secrets_only(
            "https://e.example/a(b)/c?password=sekrit212ab")
        assert "sekrit212ab" not in out

    def test_secret_beyond_8k_cap_still_redacted(self):
        # A URL longer than the 8 KB match cap splits; the tail pair
        # scan must still catch the credential.
        url = ("https://e.example/?pad=" + "a" * 9000
               + "&access_token=sekrit213ab")
        for fn in (redact_secrets, redact_url_secrets_only):
            out = fn(url)
            assert "sekrit213ab" not in out, fn.__name__
