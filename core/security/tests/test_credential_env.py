"""Unit tests for the canonical credential-env vocabulary."""

import os
import re

import pytest

from core.security.credential_env import (
    ANTHROPIC_FIRST_PARTY_AUTH_VARS,
    BUILD_ECOSYSTEM_ENV_SURFACES,
    BUILD_SYSTEM_ECOSYSTEM_MAP,
    CREDENTIAL_BEARING_ENV_VARS,
    CREDENTIAL_ENV_FAMILY,
    CREDENTIAL_ENV_NAME_PATTERNS,
    CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    CREDENTIAL_FILE_POINTER_ENV_VARS,
    CREDENTIAL_GENERAL_BLOCKLIST_VARS,
    GENERAL_BLOCKLIST_EXEMPT_VARS,
    TOOLCHAIN_HOME_ENV_VARS,
    is_credential_env_pattern_member,
    is_credential_redirect_shaped,
    is_credential_shaped,
    is_model_traffic_redirect_shaped,
)

# Documented mixed-case member spellings: the general-blocklist sweep
# matches exact names, so members keep the spelling their tool
# documents; hostile-input consumers match case-folded either way.
_DOCUMENTED_MIXED_CASE = frozenset({"MSBuildSDKsPath"})


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
            if name in _DOCUMENTED_MIXED_CASE:
                continue
            assert name == name.upper()
            assert " " not in name

    def test_mixed_case_members_are_documented(self):
        # Every non-upper spelling must be a pinned, documented one —
        # a stray lowercase member would silently weaken exact-name
        # consumers that assume canonical-upper storage.
        mixed = {n for n in CREDENTIAL_ENV_FAMILY if n != n.upper()}
        assert mixed == _DOCUMENTED_MIXED_CASE


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
        # inline JSON auth store, NPM_CONFIG__AUTH npm's base64
        # basic-auth blob — none carries a grammar segment (the
        # double underscore splits _auth into an empty segment plus
        # AUTH, which is not in the grammar); all have explicit
        # membership (the documented sets/grammar split).
        assert unshaped == {
            "ANTHROPIC_CUSTOM_HEADERS",
            "COMPOSER_AUTH",
            "NPM_CONFIG__AUTH",
        }


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


# --- Per-ecosystem derivation ---------------------------------------

# Every escaping member the derivation change adjudicated IN, pinned
# name-by-name so a planted omission (a member dropped from its
# ecosystem surface, or a surface dropped from the derivation union)
# fails here before any consumer surface is even consulted.
_ECOSYSTEM_MEMBER_TIERS = {
    # npm / yarn / pnpm
    "NPM_CONFIG__AUTH": CREDENTIAL_BEARING_ENV_VARS,
    "NPM_CONFIG_USERCONFIG": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "NPM_CONFIG_GLOBALCONFIG": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "YARN_RC_FILENAME": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "NPM_CONFIG_SCRIPT_SHELL": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "NPM_CONFIG_NODE_GYP": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "YARN_YARN_PATH": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    # python
    "PIP_CONFIG_FILE": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "POETRY_CONFIG_DIR": CREDENTIAL_FILE_POINTER_ENV_VARS,
    # cargo
    "CARGO_HOME": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "RUSTC": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "RUSTC_WRAPPER": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "RUSTC_WORKSPACE_WRAPPER": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "RUSTDOC": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CARGO_BUILD_RUSTC": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CARGO_BUILD_RUSTC_WRAPPER": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER":
        CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CARGO_BUILD_RUSTDOC": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "RUSTFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CARGO_BUILD_RUSTFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CARGO_ENCODED_RUSTFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "RUSTDOCFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CARGO_BUILD_RUSTDOCFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CARGO_ENCODED_RUSTDOCFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    # go
    "GOENV": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "GOFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CGO_CFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CGO_CPPFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CGO_CXXFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CGO_FFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CGO_LDFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    # composer
    "COMPOSER_AUTH": CREDENTIAL_BEARING_ENV_VARS,
    "COMPOSER_HOME": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "COMPOSER": CREDENTIAL_FILE_POINTER_ENV_VARS,
    # maven
    "MAVEN_USER_HOME": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "MVNW_REPOURL": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "MAVEN_OPTS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "MAVEN_ARGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    # gradle
    "GRADLE_USER_HOME": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "GRADLE_OPTS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "JAVA_OPTS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    # ant
    "ANT_OPTS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "ANT_ARGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    # dotnet / nuget / msbuild
    "DOTNET_ADDITIONAL_DEPS": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "DOTNET_SHARED_STORE": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "DOTNET_HOST_PATH": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "DOTNET_STARTUP_HOOKS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "MSBuildSDKsPath": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "NUGET_PLUGIN_PATHS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "NUGET_NETFX_PLUGIN_PATHS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "NUGET_NETCORE_PLUGIN_PATHS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "NUGET_CREDENTIALPROVIDERS_PATH": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "NUGET_EXTENSIONS_PATH": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "NUGET_RESTORE_MSBUILD_ARGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    # rubygems / bundler
    "GEMRC": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "GEM_HOME": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "GEM_PATH": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "BUNDLE_GEMFILE": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "RUBYGEMS_GEMDEPS": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "BUNDLE_USER_HOME": CREDENTIAL_FILE_POINTER_ENV_VARS,
    "BUNDLE_APP_CONFIG": CREDENTIAL_FILE_POINTER_ENV_VARS,
    # native toolchain — the make-manual executed-program catalog
    # plus the cmake resolution overrides and pkg-config/m4.
    "AR": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "AS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CC": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CO": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CPP": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CTANGLE": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CWEAVE": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CXX": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "FC": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "GET": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "LD": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "LEX": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "LINT": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "M2C": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "M4": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "MAKE": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "MAKE_COMMAND": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "MAKEINFO": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "OBJC": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "PC": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "PKG_CONFIG": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "RM": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "TANGLE": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "TEX": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "TEXI2DVI": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "WEAVE": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "YACC": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "MAKEFILES": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CMAKE_TOOLCHAIN_FILE": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CMAKE_PREFIX_PATH": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CMAKE_PROGRAM_PATH": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "MAKEFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    # Env-consumed option carriers (manual 5.7.3): GNUMAKEFLAGS is
    # appended to MAKEFLAGS before parsing (`--eval=$(shell …)` execs
    # at parse time even under -n; `CC=` / `COMPILE.c=` words ride it);
    # MFLAGS is the historical option word (ignored by GNU make 4.x's
    # env read, honoured by older/other implementations).
    "GNUMAKEFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "MFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "ARFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "ASFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "COFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CPPFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "CXXFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "DEFFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "FFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "GFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "LDFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "LDLIBS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "LFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "LINTFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "LOADLIBES": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "M2FLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "MAKEINFO_FLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "MODFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "OBJCFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "OUTPUT_OPTION": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "PFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "RFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "SCCS_OUTPUT_OPTION": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "TARGET_ARCH": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "TARGET_MACH": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "TEXI2DVI_FLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
    "YFLAGS": CREDENTIAL_EXEC_REDIRECT_ENV_VARS,
}


class TestEcosystemDerivation:
    @pytest.mark.parametrize("name", sorted(_ECOSYSTEM_MEMBER_TIERS))
    def test_member_in_expected_tier(self, name):
        assert name in _ECOSYSTEM_MEMBER_TIERS[name]
        assert name in CREDENTIAL_ENV_FAMILY

    def test_category_to_tier_mapping_is_total(self):
        """Derivation lock: every surface row lands in its tier —
        dropping a category from the union (a planted derivation
        omission) fails here for every member of that category."""
        for surface in BUILD_ECOSYSTEM_ENV_SURFACES:
            for name in surface.credential_bearing:
                assert name in CREDENTIAL_BEARING_ENV_VARS, name
            for name in surface.config_redirect:
                assert name in CREDENTIAL_FILE_POINTER_ENV_VARS, name
            for name in surface.tool_override:
                assert name in CREDENTIAL_EXEC_REDIRECT_ENV_VARS, name
            for name in surface.flags_injection:
                assert name in CREDENTIAL_EXEC_REDIRECT_ENV_VARS, name
            for pattern in surface.tool_override_patterns:
                assert is_credential_env_pattern_member(
                    pattern.example,
                ), pattern

    def test_every_surface_names_source_and_completeness(self):
        """Each ecosystem surface must say WHAT documentation it was
        transcribed from, WHEN and against WHICH sections (so a later
        audit can diff mechanically), and what that documentation
        lists that is deliberately not a member — the re-adjudication
        trail. All three are required fields; none may be blank."""
        for surface in BUILD_ECOSYSTEM_ENV_SURFACES:
            assert surface.source.strip(), surface.ecosystem
            assert surface.transcribed.strip(), surface.ecosystem
            assert surface.completeness.strip(), surface.ecosystem

    def test_toolchain_home_class_relations(self):
        """The toolchain-home class is settings-scan-only by design:
        never a family member (the traced-build env_detect passthrough
        would be stripped) and never in the general blocklist
        increment (operators legitimately set these)."""
        assert not (TOOLCHAIN_HOME_ENV_VARS & CREDENTIAL_ENV_FAMILY)
        assert not (
            TOOLCHAIN_HOME_ENV_VARS & CREDENTIAL_GENERAL_BLOCKLIST_VARS
        )
        for name in (
            "JAVA_HOME", "GOROOT", "DOTNET_ROOT", "ANT_HOME",
            "M2_HOME", "POETRY_HOME", "RUSTUP_HOME",
        ):
            assert name in TOOLCHAIN_HOME_ENV_VARS, name

    def test_ecosystem_names_unique(self):
        names = [s.ecosystem for s in BUILD_ECOSYSTEM_ENV_SURFACES]
        assert len(names) == len(set(names))

    def test_census_map_targets_declared_surfaces(self):
        declared = {s.ecosystem for s in BUILD_ECOSYSTEM_ENV_SURFACES}
        for build_system, ecosystem in BUILD_SYSTEM_ECOSYSTEM_MAP.items():
            assert ecosystem in declared, build_system

    def test_no_surface_member_is_model_traffic_shaped(self):
        # Family membership and the model-traffic redirect tier are
        # mutually exclusive by design (see the module comment).
        for name in CREDENTIAL_ENV_FAMILY:
            assert not is_model_traffic_redirect_shaped(name), name


class TestPatternMembers:
    def test_patterns_declared(self):
        keys = {(p.prefix, p.suffix) for p in CREDENTIAL_ENV_NAME_PATTERNS}
        assert keys == {
            ("CARGO_TARGET_", "_RUNNER"),
            ("CARGO_TARGET_", "_LINKER"),
            ("CARGO_TARGET_", "_RUSTFLAGS"),
            ("BUNDLE_BUILD__", ""),
            ("CMAKE_", "_COMPILER_LAUNCHER"),
            ("CMAKE_", "_LINKER_LAUNCHER"),
            ("COMPILE.", ""),
            ("LINK.", ""),
            ("LEX.", ""),
            ("LINT.", ""),
            ("PREPROCESS.", ""),
            ("YACC.", ""),
        }

    @pytest.mark.parametrize("name", [
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
        "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",
        "CARGO_TARGET_WASM32_WASI_RUSTFLAGS",
        "cargo_target_x86_64_unknown_linux_gnu_runner",  # case-folded
        "BUNDLE_BUILD__NOKOGIRI",
        "bundle_build__nokogiri",  # case-folded
        "CMAKE_C_COMPILER_LAUNCHER",
        "CMAKE_CXX_COMPILER_LAUNCHER",
        "CMAKE_CUDA_LINKER_LAUNCHER",
        # make dot-named recipe variables — env-overridable full
        # recipe replacement (COMPILE.c=<cmd> runs <cmd> instead of
        # the compiler); case-folded like every pattern, so the
        # case-significant sibling spellings (COMPILE.C) match too.
        "COMPILE.c",
        "COMPILE.C",
        "compile.cc",  # case-folded
        "LINK.o",
        "LEX.l",
        "LINT.c",
        "PREPROCESS.F",
        "YACC.y",
    ])
    def test_pattern_positives(self, name):
        assert is_credential_env_pattern_member(name), name
        # First-class family citizenship on the hostile-input belt.
        assert is_credential_redirect_shaped(name), name

    @pytest.mark.parametrize("name", [
        "CARGO_TARGET_DIR",        # no pattern tail
        "CARGO_TARGET__RUNNER",    # empty middle segment
        "BUNDLE_BUILD__",          # bare prefix, no member name
        "MY_RUNNER",               # tail without the family prefix
        "CARGO_BUILD_TARGET",      # documented plain knob
        "CMAKE__COMPILER_LAUNCHER",  # empty language segment
        "CMAKE_GENERATOR",         # documented plain knob
        "COMPILE.",                # bare prefix, no suffix segment
        "COMPILE",                 # undotted name is not the family
        "COMPILER_FLAGS",          # dotless lookalike prefix
        "LINKER",                  # ditto for LINK.
        "PATH",
    ])
    def test_pattern_negatives(self, name):
        assert not is_credential_env_pattern_member(name), name

    def test_pattern_examples_are_not_exact_members(self):
        # Patterns are the ONLY home for triple-parameterised names —
        # an exact-name copy appearing in a tier set would be the
        # multi-homing regression the derivation removed.
        for pattern in CREDENTIAL_ENV_NAME_PATTERNS:
            assert pattern.example not in CREDENTIAL_ENV_FAMILY, pattern


class TestMakeOptionCarrierBelt:
    """make's env-consumed option carriers are family members.

    GNUMAKEFLAGS reopened the dot-var class one name over: an
    environment `GNUMAKEFLAGS=--eval=$(shell <cmd>)` executes at
    makefile PARSE time (even under `-n`), and `CC=<prog>` /
    `COMPILE.c=<cmd>` words ride it into every make-driven build.
    Both hostile-env belts derive from CREDENTIAL_ENV_FAMILY, so
    membership here is the refusal pin for both."""

    @pytest.mark.parametrize("name", [
        "MAKEFLAGS", "GNUMAKEFLAGS", "MFLAGS",
    ])
    def test_option_carriers_are_exec_tier_members(self, name):
        assert name in CREDENTIAL_EXEC_REDIRECT_ENV_VARS, name
        assert name in CREDENTIAL_ENV_FAMILY, name

    @pytest.mark.parametrize("name", [
        # make-SET information carriers with no env-side option or
        # exec power — the refusal must not widen into these.
        "MAKELEVEL",
        "MAKE_TERMOUT",
        "MAKE_TERMERR",
        "MAKE_RESTARTS",
    ])
    def test_inert_make_names_stay_out(self, name):
        assert name not in CREDENTIAL_ENV_FAMILY, name


class TestMakeDefaultDatabaseCrossCheck:
    """Executable transcription cross-check for the native surface.

    The native surface's `transcribed` stamp cites the GNU make
    default-rule database. Prose stamps can drift; this oracle runs
    the citation: it extracts every ``$(VAR)`` reference from
    ``make -p -f /dev/null`` (the variables the built-in rules
    interpolate into executed command lines — programs, flags, and
    the dot-named recipe variables alike) and asserts each is either
    an exec-tier family member (exact row or declared name pattern —
    the COMPILE./LINK./… dot families are pattern members), or a name
    adjudicated out below WITH a rationale. A make release that adds
    a rule variable fails here and gets adjudicated instead of
    silently escaping the belts. Skips hermetically where make is not
    installed.
    """

    # Referenced default-database names adjudicated OUT of the family.
    # Every row needs a reason that holds on the hostile-input lanes.
    # (Empty today: every referenced name is a member. F77/F77FLAGS
    # never appear here — they are DEFINED defaults no rule
    # references; the surface's completeness note adjudicates them.)
    _ADJUDICATED_OUT: dict = {}

    # Dot-named recipe variables (``COMPILE.c``, ``LINK.o``, ``LEX.l``
    # …) are first-class database references, env-overridable at the
    # SAME precedence as CC (environment origin beats default origin —
    # ``COMPILE.c=<cmd>`` replaces the entire compile recipe). An
    # ``[A-Z_]``-only extraction silently dropped the whole class out
    # of this oracle's universe.
    _REF_RE = re.compile(r"\$[({]([A-Za-z][A-Za-z0-9_.]*)[)}]")

    def test_every_referenced_rule_variable_is_covered(self):
        import shutil
        import subprocess

        make = shutil.which("make")
        if make is None:
            pytest.skip("make not installed")
        proc = subprocess.run(
            [make, "-p", "-f", os.devnull],
            capture_output=True, text=True, timeout=60,
            # Scrubbed env: the operator's MAKEFLAGS/GNUMAKEFLAGS (or
            # any exported variable) must not perturb the DATABASE
            # this oracle transcribes.
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                 "LC_ALL": "C"},
        )
        # `make -p` with no targets exits non-zero after printing the
        # database; the marker is the contract, not the exit code.
        if "# Make data base" not in proc.stdout:
            pytest.skip("unrecognised make -p output shape")
        referenced = set(self._REF_RE.findall(proc.stdout))
        uncovered = {
            name for name in referenced
            if name not in CREDENTIAL_EXEC_REDIRECT_ENV_VARS
            and not is_credential_env_pattern_member(name)
            and name not in self._ADJUDICATED_OUT
        }
        assert uncovered == set(), (
            "default-rule database references escaped the family — "
            f"adjudicate them (member or _ADJUDICATED_OUT): {sorted(uncovered)}"
        )

    # Variable NAMES the default database DEFINES (assignment lines in
    # the `make -p` dump: `NAME = …` / `NAME := …` / `NAME ?= …`).
    # Same [A-Za-z]-start rule as _REF_RE (dot-prefixed specials like
    # .VARIABLES are make-internal, not env surface).
    _DEF_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_.]*)\s*[:+?]{0,3}=",
                         re.MULTILINE)

    def test_every_env_option_injecting_variable_is_covered(self):
        """Behavioral arm for the env-read-only class.

        The reference arm above is structurally blind to names make
        CONSUMES from the environment without ever referencing them as
        ``$(VAR)`` — GNUMAKEFLAGS perturbs every make run yet appears
        in the database only as a definition, never a reference.

        Universe (mechanical): every variable name the default
        database DEFINES, extracted from the same ``make -p`` dump the
        reference arm transcribes. Predicate (behavioral): set the
        name — alone, in an otherwise-scrubbed environment — to a
        no-op option word (``--eval=$(info <marker>)``, no whitespace,
        so word-splitting carriers still deliver it) and observe
        whether make consumed the value AS OPTIONS: the marker prints
        only when the value reached make's flag parsing, which is the
        exact wrapper power the belts must refuse. Every injector must
        be an exec-tier family member (exact row or pattern).
        """
        import shutil
        import subprocess

        make = shutil.which("make")
        if make is None:
            pytest.skip("make not installed")
        base_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "LC_ALL": "C"}
        proc = subprocess.run(
            [make, "-p", "-f", os.devnull],
            capture_output=True, text=True, timeout=60, env=base_env,
        )
        if "# Make data base" not in proc.stdout:
            pytest.skip("unrecognised make -p output shape")
        defined = sorted(set(self._DEF_RE.findall(proc.stdout)))
        # Non-vacuity of the UNIVERSE: the database must define the
        # names this arm exists for, or the extraction regressed.
        assert "MAKEFLAGS" in defined
        assert "GNUMAKEFLAGS" in defined

        injectors = set()
        for name in defined:
            marker = f"U_ENV_OPT_INJECT_{name}"
            env = dict(base_env)
            env[name] = f"--eval=$(info {marker})"
            probe = subprocess.run(
                [make, "-f", os.devnull],
                capture_output=True, text=True, timeout=30, env=env,
            )
            if marker in probe.stdout or marker in probe.stderr:
                injectors.add(name)
        # Non-vacuity of the PREDICATE: GNU make documents both option
        # carriers as environment-consumed; a probe that stops firing
        # means the mechanic changed and this arm needs re-derivation,
        # not silence.
        assert {"MAKEFLAGS", "GNUMAKEFLAGS"} <= injectors, injectors
        uncovered = {
            name for name in injectors
            if name not in CREDENTIAL_EXEC_REDIRECT_ENV_VARS
            and not is_credential_env_pattern_member(name)
            and name not in self._ADJUDICATED_OUT
        }
        assert uncovered == set(), (
            "environment option-injecting make variables escaped the "
            f"family — adjudicate them: {sorted(uncovered)}"
        )

    def test_adjudicated_out_rows_are_live(self):
        # A row for a name the database no longer references is stale.
        for name in self._ADJUDICATED_OUT:
            assert name not in CREDENTIAL_EXEC_REDIRECT_ENV_VARS, name
