"""RaptorConfig consumption of the canonical credential-env vocabulary.

Covers both directions: the blocklist surfaces gain the family, AND
the documented re-admit lanes (get_llm_env keys/routing, GIT_ENV_VARS
pins) keep working — the vocabulary must never break them.
"""

from core.config import RaptorConfig
from core.security.credential_env import (
    CREDENTIAL_BEARING_ENV_VARS,
    CREDENTIAL_ENV_FAMILY,
    CREDENTIAL_GENERAL_BLOCKLIST_VARS,
    GENERAL_BLOCKLIST_EXEMPT_VARS,
)


class TestDangerousEnvVarsConsumption:
    def test_general_blocklist_subset_present(self):
        assert CREDENTIAL_GENERAL_BLOCKLIST_VARS <= (
            RaptorConfig.DANGEROUS_ENV_VARS
        )

    def test_exempt_members_stay_out(self):
        """Both-direction pin: the documented runtime re-admits must
        NOT be in DANGEROUS_ENV_VARS — the sandbox strict_env sweep
        consumes this list to re-filter caller-supplied envs, and the
        cc_adapter env-mode children legitimately carry these names
        through that sweep (first-party CC auth on API-key /
        setup-token installs; the Bedrock AWS passthrough). Blocking
        them here would strip a child's only working credential."""
        overlap = GENERAL_BLOCKLIST_EXEMPT_VARS & (
            RaptorConfig.DANGEROUS_ENV_VARS
        )
        assert overlap == set()

    def test_key_family_members_present(self):
        for name in (
            "GIT_ASKPASS", "GIT_PROXY_COMMAND", "GIT_SSH_COMMAND",
            "GIT_SSH", "SSH_ASKPASS", "KUBECONFIG", "DOCKER_CONFIG",
            "GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_CONFIG",
            "NETRC", "CURL_HOME", "PIP_CONFIG_FILE",
            "NPM_CONFIG_USERCONFIG", "GRADLE_USER_HOME",
            "RUSTC_WRAPPER", "RUSTC",
            "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES",
            "WGETRC", "COMPOSER_AUTH", "CLOUDSDK_PYTHON",
            "AZURE_CONFIG_DIR", "AZURE_CLIENT_CERTIFICATE_PATH",
        ):
            assert name in RaptorConfig.DANGEROUS_ENV_VARS, name


class TestGetSafeEnvNotWidened:
    def test_allowlist_carries_no_family_member(self):
        assert not (RaptorConfig.SAFE_ENV_ALLOWLIST & CREDENTIAL_ENV_FAMILY)

    def test_family_members_never_flow_through(self, monkeypatch):
        for name in CREDENTIAL_ENV_FAMILY:
            monkeypatch.setenv(name, "attacker-value")
        env = RaptorConfig.get_safe_env()
        leaked = {
            k for k, v in env.items()
            if k in CREDENTIAL_ENV_FAMILY and v == "attacker-value"
        }
        assert leaked == set()

    def test_documented_allowlist_members_still_kept(self, monkeypatch):
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        monkeypatch.setenv("HOME", "/home/op")
        monkeypatch.setenv("LANG", "C.UTF-8")
        env = RaptorConfig.get_safe_env()
        assert env["PATH"] == "/usr/bin:/bin"
        assert env["HOME"] == "/home/op"
        assert env["LANG"] == "C.UTF-8"

    def test_git_askpass_pin_survives(self, monkeypatch):
        """GIT_ASKPASS joined the blocklist via the vocabulary, but
        get_safe_env applies GIT_ENV_VARS after the strip — the inert
        /usr/bin/true pin must survive (git falling back to a real
        askpass under Landlock is the failure the pin prevents)."""
        monkeypatch.setenv("GIT_ASKPASS", "/tmp/evil-askpass")
        env = RaptorConfig.get_safe_env()
        assert env["GIT_ASKPASS"] == "/usr/bin/true"


class TestLlmLaneReadmitsIntact:
    def test_get_llm_env_still_forwards_credential_pointers(
        self, monkeypatch,
    ):
        """The documented LLM-lane re-admits must survive the family
        joining DANGEROUS_ENV_VARS: get_llm_env layers the key and
        routing families AFTER the blocklist strip."""
        monkeypatch.setenv(
            "GOOGLE_APPLICATION_CREDENTIALS", "/home/op/sa.json",
        )
        monkeypatch.setenv("AWS_CONFIG_FILE", "/home/op/.aws/config")
        monkeypatch.setenv("AWS_PROFILE", "prod")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-op")
        env = RaptorConfig.get_llm_env()
        assert env["GOOGLE_APPLICATION_CREDENTIALS"] == "/home/op/sa.json"
        assert env["AWS_CONFIG_FILE"] == "/home/op/.aws/config"
        assert env["AWS_PROFILE"] == "prod"
        assert env["OPENAI_API_KEY"] == "sk-op"


class TestStripLlmEnvVars:
    def test_drops_credential_bearing_family(self):
        env = {name: "v" for name in CREDENTIAL_BEARING_ENV_VARS}
        env["PATH"] = "/usr/bin"
        env["HOME"] = "/home/op"
        RaptorConfig.strip_llm_env_vars(env)
        for name in CREDENTIAL_BEARING_ENV_VARS:
            assert name not in env, name
        assert env["PATH"] == "/usr/bin"
        assert env["HOME"] == "/home/op"

    def test_drops_setup_token_credential(self):
        env = {"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-LIVE"}
        RaptorConfig.strip_llm_env_vars(env)
        assert "CLAUDE_CODE_OAUTH_TOKEN" not in env


class TestDangerousEnvNamePredicate:
    """is_dangerous_env_name is the sweep-facing membership check:
    the exact blocklist plus the credential-env NAME PATTERNS, which
    have no enumerable spelling and therefore cannot live in the
    exact-name set the strict_env sweeps otherwise consume."""

    def test_exact_blocklist_members_match(self):
        assert RaptorConfig.is_dangerous_env_name("LD_PRELOAD")
        assert RaptorConfig.is_dangerous_env_name("GIT_ASKPASS")
        assert RaptorConfig.is_dangerous_env_name("RUSTC_WRAPPER")

    def test_pattern_members_match(self):
        for name in (
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",
            "CARGO_TARGET_WASM32_WASI_RUSTFLAGS",
            "BUNDLE_BUILD__NOKOGIRI",
        ):
            assert RaptorConfig.is_dangerous_env_name(name), name

    def test_benign_names_do_not_match(self):
        for name in (
            "PATH", "HOME", "LANG",
            "CARGO_TARGET_DIR",      # cache/output-dir class, kept
            "CARGO_TARGET__RUNNER",  # empty middle: not a member
        ):
            assert not RaptorConfig.is_dangerous_env_name(name), name

    def test_exempt_members_do_not_match(self):
        # GOFLAGS is a documented general-blocklist exemption (the go
        # autobuild lane carries it through a strict_env sweep) — the
        # predicate must not re-block what the exemption re-admits.
        assert not RaptorConfig.is_dangerous_env_name("GOFLAGS")
