"""Tests for ``core.startup.aws_imds`` — the AWS IMDS / proxy /
credential-chain interaction matrix.

Hermetic: every scenario builds its own env mapping (``HOME`` pinned
to a tmp dir so no real ``~/.aws`` or ``~/.config/raptor`` leaks in)
and its own fixture config files. No test reads operator state; the
fake account id is ``000000000000``.
"""

from __future__ import annotations

import os

import pytest

from core.startup.aws_imds import _IMDS_DISABLED_ENV, aws_imds_advisories

FAKE_ACCT = "000000000000"


@pytest.fixture
def home(tmp_path):
    return tmp_path


def _env(home, **extra):
    env = {"HOME": str(home)}
    env.update({k: v for k, v in extra.items() if v is not None})
    return env


def _write_config(home, text):
    aws_dir = home / ".aws"
    aws_dir.mkdir(exist_ok=True)
    path = aws_dir / "config"
    path.write_text(text, encoding="utf-8")
    return path


IMDS_PROFILE = (
    "[profile scanner]\n"
    f"role_arn = arn:aws:iam::{FAKE_ACCT}:role/scan\n"
    "credential_source = Ec2InstanceMetadata\n"
)

PROCESS_PROFILE = (
    "[profile scanner]\n"
    "credential_process = /usr/local/bin/fake-creds\n"
)


# ---------------------------------------------------------------------------
# Gate — non-AWS environments stay silent
# ---------------------------------------------------------------------------


class TestGate:
    def test_non_aws_env_is_silent(self, home):
        assert aws_imds_advisories(_env(home)) == []

    def test_non_aws_env_silent_even_when_proxied(self, home):
        env = _env(home, HTTPS_PROXY="http://proxy.example:3128")
        assert aws_imds_advisories(env) == []

    def test_aws_config_file_presence_opens_the_gate(self, home):
        _write_config(home, IMDS_PROFILE)
        env = _env(
            home,
            AWS_PROFILE="scanner",
            **{_IMDS_DISABLED_ENV: "true"},
        )
        assert aws_imds_advisories(env)

    def test_bedrock_models_config_opens_the_gate(self, home):
        cfg = home / "models.json"
        cfg.write_text(
            '// comment\n{"models": [{"provider": "bedrock", '
            '"model": "m"}]}\n',
            encoding="utf-8",
        )
        # No AWS_* vars, no ~/.aws at all: chain is last-resort IMDS,
        # proxied without exclusion → the proxy-routing warning.
        env = _env(
            home,
            RAPTOR_CONFIG=str(cfg),
            HTTPS_PROXY="http://proxy.example:3128",
        )
        out = aws_imds_advisories(env)
        assert len(out) == 1
        assert "169.254.169.254" in out[0]

    def test_non_bedrock_models_config_stays_closed(self, home):
        cfg = home / "models.json"
        cfg.write_text(
            '{"models": [{"provider": "anthropic", "model": "m"}]}',
            encoding="utf-8",
        )
        env = _env(home, RAPTOR_CONFIG=str(cfg))
        assert aws_imds_advisories(env) == []

    def test_default_os_environ_smoke(self, home, monkeypatch):
        """The no-argument form reads os.environ — scrub it hermetic
        and assert silence (never raises, no output)."""
        for k in list(os.environ):
            if k.startswith("AWS_") or k.upper() in (
                "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            ):
                monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.delenv("RAPTOR_CONFIG", raising=False)
        assert aws_imds_advisories() == []


# ---------------------------------------------------------------------------
# Matrix cell 1 — IMDS-dependent chain + AWS_EC2_METADATA_DISABLED
# ---------------------------------------------------------------------------


class TestDisabledVsImdsChain:
    def test_imds_profile_with_metadata_disabled_warns(self, home):
        _write_config(home, IMDS_PROFILE)
        env = _env(
            home,
            AWS_PROFILE="scanner",
            **{_IMDS_DISABLED_ENV: "true"},
        )
        out = aws_imds_advisories(env)
        assert len(out) == 1
        assert "scanner" in out[0]
        assert _IMDS_DISABLED_ENV in out[0]
        assert "fail" in out[0]

    @pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes", "On"])
    def test_truthy_spellings(self, home, value):
        _write_config(home, IMDS_PROFILE)
        env = _env(
            home, AWS_PROFILE="scanner", **{_IMDS_DISABLED_ENV: value},
        )
        out = aws_imds_advisories(env)
        assert len(out) == 1
        assert "fail" in out[0]

    @pytest.mark.parametrize("value", ["false", "0", "off", ""])
    def test_falsy_spellings_do_not_trigger(self, home, value):
        _write_config(home, IMDS_PROFILE)
        env = _env(
            home, AWS_PROFILE="scanner", **{_IMDS_DISABLED_ENV: value},
        )
        assert aws_imds_advisories(env) == []

    def test_last_resort_imds_chain_counts(self, home):
        """No config file, no credentials file, no static env creds:
        SDKs fall through to IMDS — disabling it still warns."""
        env = _env(
            home,
            AWS_DEFAULT_REGION="eu-west-1",
            **{_IMDS_DISABLED_ENV: "true"},
        )
        out = aws_imds_advisories(env)
        assert len(out) == 1
        assert "default" in out[0]
        assert "last resort" in out[0]

    def test_source_profile_chain_to_imds(self, home):
        _write_config(
            home,
            "[profile deploy]\n"
            f"role_arn = arn:aws:iam::{FAKE_ACCT}:role/deploy\n"
            "source_profile = base\n"
            "[profile base]\n"
            f"role_arn = arn:aws:iam::{FAKE_ACCT}:role/base\n"
            "credential_source = Ec2InstanceMetadata\n",
        )
        env = _env(
            home, AWS_PROFILE="deploy", **{_IMDS_DISABLED_ENV: "true"},
        )
        out = aws_imds_advisories(env)
        assert len(out) == 1
        assert "deploy" in out[0]


# ---------------------------------------------------------------------------
# Matrix cell 2 — IMDS-dependent chain + proxy without NO_PROXY exclusion
# ---------------------------------------------------------------------------


class TestProxyVsImdsChain:
    def test_proxied_imds_chain_warns(self, home):
        _write_config(home, IMDS_PROFILE)
        env = _env(
            home,
            AWS_PROFILE="scanner",
            HTTPS_PROXY="http://proxy.example:3128",
        )
        out = aws_imds_advisories(env)
        assert len(out) == 1
        assert "169.254.169.254" in out[0]
        assert "HTTPS_PROXY" in out[0]
        # Points at RAPTOR's own automatic exclusion for its children.
        assert "egress" in out[0]

    def test_no_proxy_exclusion_silences(self, home):
        _write_config(home, IMDS_PROFILE)
        env = _env(
            home,
            AWS_PROFILE="scanner",
            HTTPS_PROXY="http://proxy.example:3128",
            NO_PROXY="localhost,169.254.169.254",
        )
        assert aws_imds_advisories(env) == []

    def test_lowercase_no_proxy_and_wildcard_count(self, home):
        _write_config(home, IMDS_PROFILE)
        base = _env(
            home,
            AWS_PROFILE="scanner",
            https_proxy="http://proxy.example:3128",
        )
        assert aws_imds_advisories({**base, "no_proxy": "*"}) == []
        assert aws_imds_advisories(
            {**base, "no_proxy": " 169.254.169.254 "}
        ) == []

    def test_disabled_supersedes_proxy_warning(self, home):
        """Var truthy + IMDS chain + proxy: the will-fail warning is
        the actionable one; the SDK never reaches the proxy."""
        _write_config(home, IMDS_PROFILE)
        env = _env(
            home,
            AWS_PROFILE="scanner",
            HTTPS_PROXY="http://proxy.example:3128",
            **{_IMDS_DISABLED_ENV: "true"},
        )
        out = aws_imds_advisories(env)
        assert len(out) == 1
        assert "fail" in out[0]


# ---------------------------------------------------------------------------
# Matrix cell 3 — non-IMDS chain, proxied, var unset → optional INFO
# ---------------------------------------------------------------------------


class TestOptionalHygieneSuggestion:
    def test_proxied_non_imds_chain_suggests_optional(self, home):
        _write_config(home, PROCESS_PROFILE)
        env = _env(
            home,
            AWS_PROFILE="scanner",
            HTTPS_PROXY="http://proxy.example:3128",
        )
        out = aws_imds_advisories(env)
        assert len(out) == 1
        assert out[0].startswith("optional:")
        assert _IMDS_DISABLED_ENV in out[0]
        # The breaks-instance-role-setups caveat is inline.
        assert "Ec2InstanceMetadata" in out[0]

    def test_unproxied_non_imds_chain_is_silent(self, home):
        _write_config(home, PROCESS_PROFILE)
        assert aws_imds_advisories(_env(home, AWS_PROFILE="scanner")) == []

    def test_var_already_set_suppresses_suggestion(self, home):
        _write_config(home, PROCESS_PROFILE)
        env = _env(
            home,
            AWS_PROFILE="scanner",
            HTTPS_PROXY="http://proxy.example:3128",
            **{_IMDS_DISABLED_ENV: "false"},
        )
        assert aws_imds_advisories(env) == []

    def test_env_static_creds_count_as_non_imds(self, home):
        env = _env(
            home,
            AWS_ACCESS_KEY_ID="AKIA0000000000000000",
            HTTPS_PROXY="http://proxy.example:3128",
        )
        out = aws_imds_advisories(env)
        assert len(out) == 1
        assert out[0].startswith("optional:")

    def test_env_static_creds_win_over_unparseable_config(self, home):
        _write_config(home, "[profile scanner\nnot ini at all")
        env = _env(
            home,
            AWS_ACCESS_KEY_ID="AKIA0000000000000000",
            HTTPS_PROXY="http://proxy.example:3128",
        )
        out = aws_imds_advisories(env)
        assert len(out) == 1
        assert out[0].startswith("optional:")

    def test_source_profile_chain_to_static(self, home):
        _write_config(
            home,
            "[profile deploy]\n"
            f"role_arn = arn:aws:iam::{FAKE_ACCT}:role/deploy\n"
            "source_profile = base\n"
            "[profile base]\n"
            "credential_process = /usr/local/bin/fake-creds\n",
        )
        env = _env(
            home,
            AWS_PROFILE="deploy",
            HTTPS_PROXY="http://proxy.example:3128",
        )
        out = aws_imds_advisories(env)
        assert len(out) == 1
        assert out[0].startswith("optional:")


# ---------------------------------------------------------------------------
# Matrix cell 4 — var truthy + non-IMDS chain → silence
# ---------------------------------------------------------------------------


class TestDisabledWithNonImdsChain:
    def test_disabled_with_non_imds_chain_is_silent(self, home):
        _write_config(home, PROCESS_PROFILE)
        env = _env(
            home,
            AWS_PROFILE="scanner",
            **{_IMDS_DISABLED_ENV: "true"},
        )
        assert aws_imds_advisories(env) == []

    def test_disabled_non_imds_and_proxied_still_silent(self, home):
        _write_config(home, PROCESS_PROFILE)
        env = _env(
            home,
            AWS_PROFILE="scanner",
            HTTPS_PROXY="http://proxy.example:3128",
            **{_IMDS_DISABLED_ENV: "true"},
        )
        assert aws_imds_advisories(env) == []


# ---------------------------------------------------------------------------
# Degradation — unparseable config, ambiguity, never guessing
# ---------------------------------------------------------------------------


class TestDegradation:
    def test_unparseable_config_with_aws_vars(self, home):
        _write_config(home, "[profile scanner\nnot ini at all")
        env = _env(home, AWS_PROFILE="scanner")
        out = aws_imds_advisories(env)
        assert len(out) == 1
        assert "unable to determine" in out[0]

    def test_unparseable_config_without_aws_vars_is_silent(self, home):
        # Gate opens via the config file's existence, but with no
        # AWS_* variables set the unable-to-determine line stays quiet.
        _write_config(home, "[profile scanner\nnot ini at all")
        assert aws_imds_advisories(_env(home)) == []

    def test_credentials_file_ambiguity_is_silent(self, home):
        """A profile whose keys may live in ~/.aws/credentials is never
        guessed at — even garbage contents don't matter because the
        file is never read, only its existence checked."""
        _write_config(home, "[profile scanner]\nregion = eu-west-1\n")
        (home / ".aws" / "credentials").write_bytes(b"\x00not-ini\xff")
        env = _env(
            home,
            AWS_PROFILE="scanner",
            HTTPS_PROXY="http://proxy.example:3128",
            **{_IMDS_DISABLED_ENV: "true"},
        )
        assert aws_imds_advisories(env) == []

    def test_profile_missing_from_config_is_silent(self, home):
        _write_config(home, PROCESS_PROFILE)
        env = _env(
            home,
            AWS_PROFILE="no-such-profile",
            **{_IMDS_DISABLED_ENV: "true"},
        )
        assert aws_imds_advisories(env) == []

    def test_source_profile_cycle_is_silent(self, home):
        _write_config(
            home,
            "[profile a]\n"
            f"role_arn = arn:aws:iam::{FAKE_ACCT}:role/a\n"
            "source_profile = b\n"
            "[profile b]\n"
            f"role_arn = arn:aws:iam::{FAKE_ACCT}:role/b\n"
            "source_profile = a\n",
        )
        env = _env(
            home, AWS_PROFILE="a", **{_IMDS_DISABLED_ENV: "true"},
        )
        assert aws_imds_advisories(env) == []


# ---------------------------------------------------------------------------
# Redaction — no account ids, no ARNs in output
# ---------------------------------------------------------------------------


class TestRedaction:
    def test_account_id_in_profile_name_redacted(self, home):
        _write_config(
            home,
            f"[profile prod-{FAKE_ACCT}]\n"
            "credential_source = Ec2InstanceMetadata\n",
        )
        env = _env(
            home,
            AWS_PROFILE=f"prod-{FAKE_ACCT}",
            **{_IMDS_DISABLED_ENV: "true"},
        )
        out = aws_imds_advisories(env)
        assert len(out) == 1
        assert FAKE_ACCT not in out[0]
        assert "<acct>" in out[0]

    def test_role_arn_never_printed(self, home):
        _write_config(home, IMDS_PROFILE)
        env = _env(
            home,
            AWS_PROFILE="scanner",
            **{_IMDS_DISABLED_ENV: "true"},
        )
        out = aws_imds_advisories(env)
        assert FAKE_ACCT not in out[0]
        assert "arn:" not in out[0]


# ---------------------------------------------------------------------------
# Doctor integration — advisories land in the env-warnings channel
# ---------------------------------------------------------------------------


class TestDoctorIntegration:
    def test_gather_appends_aws_advisories(self, monkeypatch):
        from core.startup import aws_imds, doctor, init

        monkeypatch.setattr(init, "check_tools", lambda: ([], [], set()))
        monkeypatch.setattr(init, "check_llm", lambda: ([], []))
        monkeypatch.setattr(init, "check_env", lambda _u: ([], []))
        monkeypatch.setattr(init, "check_lang", lambda: (None, []))
        monkeypatch.setattr(init, "check_active_project", lambda: None)
        monkeypatch.setattr(doctor, "_module_dep_warnings", lambda: [])
        monkeypatch.setattr(
            aws_imds, "aws_imds_advisories",
            lambda env=None: ["AWS test advisory"],
        )

        gathered = doctor._gather()
        env_warnings = gathered[5]
        assert "AWS test advisory" in env_warnings

    def test_advisory_renders_as_warning(self):
        from core.startup.doctor import _render

        text, n_fail, n_warn = _render(
            [], [], [], [], [], ["AWS test advisory"], None, None,
            verbose=False,
        )
        assert n_fail == 0
        assert n_warn == 1
        assert "AWS test advisory" in text
