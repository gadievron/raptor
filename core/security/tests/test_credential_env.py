"""Unit tests for the canonical credential-env vocabulary."""

from core.security.credential_env import (
    ANTHROPIC_FIRST_PARTY_AUTH_VARS,
    CREDENTIAL_BEARING_ENV_VARS,
    CREDENTIAL_ENV_FAMILY,
    CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    CREDENTIAL_FILE_POINTER_ENV_VARS,
    CREDENTIAL_GENERAL_BLOCKLIST_VARS,
    GENERAL_BLOCKLIST_EXEMPT_VARS,
    is_credential_redirect_shaped,
    is_credential_shaped,
    is_model_traffic_redirect_shaped,
)


class TestFamilyStructure:
    def test_family_is_union_of_tiers(self):
        assert CREDENTIAL_ENV_FAMILY == (
            CREDENTIAL_BEARING_ENV_VARS
            | CREDENTIAL_FILE_POINTER_ENV_VARS
            | CREDENTIAL_EXEC_REDIRECT_ENV_VARS
        )

    def test_general_blocklist_is_family_minus_exempt(self):
        assert CREDENTIAL_GENERAL_BLOCKLIST_VARS == (
            CREDENTIAL_ENV_FAMILY - GENERAL_BLOCKLIST_EXEMPT_VARS
        )
        assert not (
            CREDENTIAL_GENERAL_BLOCKLIST_VARS & GENERAL_BLOCKLIST_EXEMPT_VARS
        )

    def test_exempt_vars_are_family_members(self):
        # An exemption for a name outside the family is a stale row.
        assert GENERAL_BLOCKLIST_EXEMPT_VARS <= CREDENTIAL_ENV_FAMILY

    def test_first_party_auth_trio(self):
        assert set(ANTHROPIC_FIRST_PARTY_AUTH_VARS) == {
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN",
        }
        assert set(ANTHROPIC_FIRST_PARTY_AUTH_VARS) <= (
            CREDENTIAL_BEARING_ENV_VARS
        )

    def test_key_members_present(self):
        # The members whose absence from consumer lists motivated the
        # single-homed vocabulary.
        assert "CLAUDE_CODE_OAUTH_TOKEN" in CREDENTIAL_BEARING_ENV_VARS
        assert "AWS_CONFIG_FILE" in CREDENTIAL_FILE_POINTER_ENV_VARS
        assert "AWS_SHARED_CREDENTIALS_FILE" in (
            CREDENTIAL_FILE_POINTER_ENV_VARS
        )
        assert "GOOGLE_APPLICATION_CREDENTIALS" in (
            CREDENTIAL_FILE_POINTER_ENV_VARS
        )
        assert "GIT_ASKPASS" in CREDENTIAL_EXEC_REDIRECT_ENV_VARS
        # Per-ecosystem siblings of long-standing members: wgetrc is
        # the NETRC/CURL_HOME twin, the Azure pair mirrors the gcloud
        # pointers, COMPOSER_AUTH is inline secret material,
        # CLOUDSDK_PYTHON is the CLOUDSDK_CONFIG exec sibling.
        assert "WGETRC" in CREDENTIAL_FILE_POINTER_ENV_VARS
        assert "AZURE_CONFIG_DIR" in CREDENTIAL_FILE_POINTER_ENV_VARS
        assert "AZURE_CLIENT_CERTIFICATE_PATH" in (
            CREDENTIAL_FILE_POINTER_ENV_VARS
        )
        assert "COMPOSER_AUTH" in CREDENTIAL_BEARING_ENV_VARS
        assert "CLOUDSDK_PYTHON" in CREDENTIAL_EXEC_REDIRECT_ENV_VARS

    def test_all_names_are_upper_snake(self):
        for name in CREDENTIAL_ENV_FAMILY:
            assert name == name.upper()
            assert " " not in name


class TestCredentialShape:
    def test_credential_shaped_positives(self):
        for name in (
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "GITHUB_TOKEN",
            "MY_SERVICE_PASSWORD",
            "REPLICATE_API_TOKEN",
            "RAPTOR_SESSION_TOKEN",
            "anthropic_api_key",  # case-folded
        ):
            assert is_credential_shaped(name), name

    def test_credential_shaped_negatives(self):
        for name in (
            "ANTHROPIC_MODEL",
            "ANTHROPIC_SMALL_FAST_MODEL",
            "CLAUDE_CODE_USE_BEDROCK",
            "GPG_PUBKEY",       # KEY embedded in a segment, not a segment
            "SSLKEYLOGFILE",    # single segment
            "MONKEY_PATCH",     # KEY embedded in a segment
            "AWS_REGION",
            "PATH",
            "KEYBOARD_LAYOUT",  # KEY embedded in a segment
            # Documented CC settings knobs: plural TOKENS counts
            # things and is deliberately not a grammar segment.
            "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
            "MAX_THINKING_TOKENS",
            "MAX_MCP_OUTPUT_TOKENS",
            # Exact-name benign-knob carve-out (KEY segment belongs
            # to "apiKeyHelper"; the value is a TTL, not a secret).
            "CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
            "claude_code_api_key_helper_ttl_ms",  # case-folded
        ):
            assert not is_credential_shaped(name), name

    def test_credential_shaped_singular_token_still_matches(self):
        # Two-direction pin for the plural-TOKENS decision: dropping
        # TOKENS must not loosen the singular / explicit coverage.
        for name in (
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_FUTURE_TOKEN",
            "GITHUB_TOKEN",
            "MY_VENDOR_ACCESS_TOKEN",
        ):
            assert is_credential_shaped(name), name
        # And the carve-out is exact-name only: credential-shaped
        # neighbours of the exempted knob still match.
        assert is_credential_shaped("CLAUDE_CODE_API_KEY")
        assert is_credential_shaped("SOME_API_KEY_HELPER")

    def test_redirect_shape_superset(self):
        # Redirect shape must accept everything credential shape does.
        assert is_credential_redirect_shaped("SOME_API_KEY")
        # Plus the config-file / askpass suffixes.
        for name in (
            "AWS_CONFIG_FILE",
            "FOO_CREDENTIALS_FILE",
            "GIT_ASKPASS",
            "aws_config_file",
        ):
            assert is_credential_redirect_shaped(name), name

    def test_redirect_shape_negatives(self):
        for name in ("DEBIAN_FRONTEND", "GIT_CONFIG", "MY_CONFIG_DIR"):
            assert not is_credential_redirect_shaped(name), name

    def test_bearing_members_are_credential_shaped_or_documented(self):
        # The shape rule is the belt for FUTURE members: every current
        # bearing member should be caught by shape too, except the
        # documented header-carrier (a headers blob, not a *_KEY name).
        unshaped = {
            n for n in CREDENTIAL_BEARING_ENV_VARS
            if not is_credential_shaped(n)
        }
        # ANTHROPIC_CUSTOM_HEADERS is a headers blob, COMPOSER_AUTH an
        # inline JSON auth store — neither carries a grammar segment;
        # both have explicit membership (the documented sets/grammar
        # split).
        assert unshaped == {"ANTHROPIC_CUSTOM_HEADERS", "COMPOSER_AUTH"}


class TestModelTrafficRedirectShape:
    def test_endpoint_variants_match(self):
        # The CLI honours a DIFFERENT base-URL name per provider mode
        # and the JS AWS SDK honours AWS_ENDPOINT_URL[_<SERVICE>] —
        # exact-name coverage of the primary alone leaves the variant
        # family open.
        for name in (
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_BEDROCK_BASE_URL",
            "ANTHROPIC_BEDROCK_MANTLE_BASE_URL",
            "ANTHROPIC_VERTEX_BASE_URL",
            "ANTHROPIC_FOUNDRY_BASE_URL",   # future provider variant
            "AWS_ENDPOINT_URL",
            "AWS_ENDPOINT_URL_BEDROCK_RUNTIME",
            "CLAUDE_CODE_SKIP_MANTLE_AUTH",
            "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
            "anthropic_bedrock_mantle_base_url",  # case-folded
        ):
            assert is_model_traffic_redirect_shaped(name), name

    def test_non_endpoint_names_do_not_match(self):
        for name in (
            "ANTHROPIC_MODEL",
            "ANTHROPIC_SMALL_FAST_MODEL",
            "CLAUDE_CODE_USE_BEDROCK",       # backend SELECTION, kept
            "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
            "AWS_REGION",
            "AWS_ENDPOINT",                  # no URL tail
            "MY_SERVICE_BASE_URL",           # not a model-traffic name
        ):
            assert not is_model_traffic_redirect_shaped(name), name
