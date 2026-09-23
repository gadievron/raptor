"""Canonical credential-env vocabulary — the single source of truth.

Environment-variable names that carry credential material, point at
credential/config files, or redirect credential acquisition / build
execution through an attacker-suppliable executable. Every
strip/allowlist/blocklist surface that reasons about credential-family
names consumes THIS module; no consumer keeps a private copy of the
family (the closure test
``core/security/tests/test_credential_env_closure.py`` walks the
consumer surfaces and asserts vocabulary consumption).

Stdlib-only on purpose: ``core.config`` imports from ``core.security``
at class-definition time, and the trust gate (``cc_trust``) must work
even on degraded installs where ``core.config`` cannot import — this
module must be importable from anywhere with zero dependency risk.

Three tiers, because consumers differ in what they may block:

* ``CREDENTIAL_BEARING_ENV_VARS`` — the value IS the secret.
* ``CREDENTIAL_FILE_POINTER_ENV_VARS`` — the value names a file/dir
  (or selects a profile) that credentials are read from; several of
  the pointed-to formats can name a helper COMMAND the SDK executes
  (AWS ``credential_process``, kubeconfig ``users[].user.exec``,
  docker ``credsStore``, gcloud external-account executables).
* ``CREDENTIAL_EXEC_REDIRECT_ENV_VARS`` — the value itself names a
  program/command executed during credential acquisition or tool
  operation, or injects flags that can name one.

The build-tool members of the pointer/exec tiers are NOT hand-listed:
they are DERIVED from :data:`BUILD_ECOSYSTEM_ENV_SURFACES` — one
declaration per ecosystem, transcribed from the tool's OWN env-surface
documentation, split into the three powers every package/build tool
exposes (config redirect, tool/binary override, flags injection). A
new ecosystem is a new surface entry; a new member is a row in its
ecosystem's surface, never a loose name in a tier set. Name PATTERNS
(``CARGO_TARGET_<triple>_RUNNER``) are first-class surface members and
join the hostile-input match via
:func:`is_credential_env_pattern_member` /
:func:`is_credential_redirect_shaped`.

``CREDENTIAL_ENV_FAMILY`` is the union — the right set for
hostile-input filters (repo-supplied settings/env scanning, build-
metadata env filtering), where NO member has a legitimate reason to
appear.

``CREDENTIAL_GENERAL_BLOCKLIST_VARS`` is the family minus the
documented runtime re-admits (``GENERAL_BLOCKLIST_EXEMPT_VARS``) —
the right increment for general-purpose blocklists that also filter
RAPTOR's OWN child environments (``RaptorConfig.DANGEROUS_ENV_VARS``
and the sandbox ``strict_env`` sweep that consumes it), where a
handful of members are deliberately carried by trusted lanes.
"""

from __future__ import annotations

from typing import NamedTuple

# --- Tier 1: the value IS the secret -------------------------------
#
# First-party Claude/Anthropic authentication material. Grouped as a
# tuple because two consumers need exactly this trio in order-stable
# form: the cc_adapter alternate-cloud pop (Bedrock/Vertex children
# have no use for first-party auth) and the proxy-mode strip (the
# dispatcher gateway mints the only credential a proxy-mode child may
# hold). CLAUDE_CODE_OAUTH_TOKEN is the ``claude setup-token``
# long-lived OAuth credential — same posture as ANTHROPIC_API_KEY /
# ANTHROPIC_AUTH_TOKEN everywhere both are handled.
ANTHROPIC_FIRST_PARTY_AUTH_VARS: tuple[str, ...] = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
)

# Cloud/CLI members whose value is the secret itself. Ecosystem
# package managers contribute their own bearing members through the
# surfaces below (COMPOSER_AUTH, NPM_CONFIG__AUTH).
_BASE_CREDENTIAL_BEARING_ENV_VARS: frozenset[str] = frozenset({
    *ANTHROPIC_FIRST_PARTY_AUTH_VARS,
    # Rides arbitrary headers (including Authorization overrides /
    # gateway secrets) onto every Anthropic API request.
    "ANTHROPIC_CUSTOM_HEADERS",
    # AWS static credential material (SigV4 trio + the Bedrock
    # bearer token).
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK",
})

# --- Tier 2 base: cloud/SDK/tool credential+config pointers --------
#
# Package-manager config pointers live in the ecosystem surfaces
# below; this base set is the cloud-SDK / network-tool remainder.
_BASE_CREDENTIAL_FILE_POINTER_ENV_VARS: frozenset[str] = frozenset({
    # botocore executes `credential_process = <cmd>` from the pointed
    # config; AWS_PROFILE selects which profile (and thus which
    # credential_process) applies — a selector with the same power.
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_PROFILE",
    # google-auth: service-account key path, or an external-account
    # JSON whose credential_source.executable.command is run when
    # GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES permits (tier 3).
    "GOOGLE_APPLICATION_CREDENTIALS",
    # gcloud config dir — credential store + helper configuration.
    "CLOUDSDK_CONFIG",
    # kubeconfig `users[].user.exec` runs an arbitrary command for
    # credential acquisition on any kubectl invocation.
    "KUBECONFIG",
    # docker CLI config dir — credsStore/credHelpers entries invoke
    # `docker-credential-<helper>` binaries.
    "DOCKER_CONFIG",
    # curl/wget credential files and the config dirs they live under
    # (a wgetrc carries http_password / proxy_password and proxy
    # redirects — same class as NETRC).
    "NETRC",
    "CURL_HOME",
    "WGETRC",
    # Azure credential material on disk: the az CLI config dir (token
    # cache + credential store) and the client-certificate path used
    # for service-principal auth by the Azure SDKs.
    "AZURE_CONFIG_DIR",
    "AZURE_CLIENT_CERTIFICATE_PATH",
})

# --- Tier 3 base: cloud/VCS exec redirects --------------------------
_BASE_CREDENTIAL_EXEC_REDIRECT_ENV_VARS: frozenset[str] = frozenset({
    # git runs these to obtain credentials / reach remotes.
    "GIT_ASKPASS",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_PROXY_COMMAND",
    # ssh (and everything that shells out to it) runs this to prompt
    # for passwords when no tty is attached.
    "SSH_ASKPASS",
    # gcloud runs this interpreter for every invocation — an
    # exec-redirect sibling of the CLOUDSDK_CONFIG pointer above.
    "CLOUDSDK_PYTHON",
    # Arms google-auth external-account executable credentials.
    "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES",
})


# --- Per-ecosystem build-tool env surfaces ---------------------------
#
# One entry per package/build ecosystem RAPTOR's lanes can touch,
# transcribed from the tool's own environment-variable documentation
# and split by power:
#
#   * ``credential_bearing`` — the value is the secret (tier 1).
#   * ``config_redirect``    — points the tool at an attacker
#     config/manifest/home whose content carries credentials,
#     registry redirects, or executed hooks (tier 2).
#   * ``tool_override``      — names a program/assembly the tool
#     executes or loads (compiler, wrapper, runner, shell, plugin,
#     credential provider) (tier 3).
#   * ``flags_injection``    — free-form option strings the tool
#     prepends; every listed member can smuggle an exec redirect
#     (``-toolexec``, ``-javaagent:``, ``-C linker=``, ``/logger:``,
#     ``-lib``, included-makefile recipes) (tier 3).
#   * ``tool_override_patterns`` — name FAMILIES with a variable
#     middle segment (``CARGO_TARGET_<triple>_RUNNER``); matched by
#     :func:`is_credential_env_pattern_member`.
#
# ``source`` names the upstream documentation the surface was
# transcribed from; ``transcribed`` pins WHEN and against WHICH
# sections, so a later audit can diff the surface against the source
# mechanically instead of re-deriving from scratch; ``completeness``
# records what that source lists that is deliberately NOT a member
# (and why). Both prose fields are REQUIRED — an ecosystem with zero
# members is an explicit adjudication, never an accident of defaults.
# Standing documented-out classes, applied per surface:
#
#   * registry/index redirect names (PIP_INDEX_URL, GOPROXY,
#     NPM_CONFIG_REGISTRY, BUNDLE_MIRROR_OF): supply-chain redirect
#     without a direct exec/credential primitive on RAPTOR's lanes.
#   * toolchain-home names (JAVA_HOME, GOROOT, DOTNET_ROOT, M2_HOME,
#     ANT_HOME, POETRY_HOME, RUSTUP_HOME): out of the FAMILY because
#     the traced-build lane deliberately CARRIES them
#     (``BUILD_SYSTEMS`` ``env_detect`` auto-detection) — but they are
#     exec-grade when a SCANNED REPO's settings supply them (the host
#     launcher execs ``$JAVA_HOME/bin/java`` at operator power), so
#     the settings-scan lane blocks the whole class via
#     :data:`TOOLCHAIN_HOME_ENV_VARS` below.
#   * cache/output-dir names (GOPATH, GOBIN, NUGET_PACKAGES,
#     CARGO_TARGET_DIR): write-location redirect only.
#   * language-RUNTIME injection names (NODE_OPTIONS, PYTHONPATH,
#     RUBYOPT, JAVA_TOOL_OPTIONS): homed in the runtime-injection
#     family (``RaptorConfig.DANGEROUS_ENV_VARS`` and cc_trust's
#     standalone fallback), not re-homed here.

class EnvNamePattern(NamedTuple):
    """A family-member NAME PATTERN with a variable middle segment.

    Matches ``<prefix><middle><suffix>`` with a non-empty middle,
    case-folded. ``example`` is a concrete documented instance (used
    by tests as the behavioral probe value).
    """

    prefix: str
    suffix: str
    example: str


class BuildEcosystemEnvSurface(NamedTuple):
    """One ecosystem's documented env surface, split by power."""

    ecosystem: str
    source: str
    transcribed: str
    completeness: str
    credential_bearing: frozenset[str] = frozenset()
    config_redirect: frozenset[str] = frozenset()
    tool_override: frozenset[str] = frozenset()
    flags_injection: frozenset[str] = frozenset()
    tool_override_patterns: tuple[EnvNamePattern, ...] = ()


BUILD_ECOSYSTEM_ENV_SURFACES: tuple[BuildEcosystemEnvSurface, ...] = (
    BuildEcosystemEnvSurface(
        ecosystem="npm",
        source=("npm CLI docs: config (every config key is settable as "
                "NPM_CONFIG_<key>; keys _auth, userconfig, globalconfig, "
                "script-shell, node-gyp); yarn berry docs: configuration "
                "settings (every yarnrc key settable as YARN_<KEY>; keys "
                "yarnPath, plugins)"),
        transcribed=("2026-09-15; npm docs/using-npm/config full key "
                     "walk; yarnpkg configuration reference full key "
                     "walk"),
        credential_bearing=frozenset({
            # npm config `_auth`: a base64 basic-auth blob — the
            # secret itself, env-spelled.
            "NPM_CONFIG__AUTH",
        }),
        config_redirect=frozenset({
            # .npmrc redirects: registry + _authToken lines, plus
            # script-affecting knobs. globalconfig is the exact-power
            # per-machine twin of userconfig.
            "NPM_CONFIG_USERCONFIG",
            "NPM_CONFIG_GLOBALCONFIG",
            # yarn berry: alternate .yarnrc.yml name — the pointed
            # file can declare `plugins:` (JS loaded into yarn).
            "YARN_RC_FILENAME",
        }),
        tool_override=frozenset({
            # The shell npm executes for every run-script/lifecycle
            # hook; the value is a program path.
            "NPM_CONFIG_SCRIPT_SHELL",
            # The node-gyp script npm executes for every native-addon
            # build — same program-path power as script-shell.
            "NPM_CONFIG_NODE_GYP",
            # The python interpreter node-gyp executes for every
            # native-addon build (npm config `python`) — the same
            # program-path power as node-gyp itself.
            "NPM_CONFIG_PYTHON",
            # npm config `shell` (npm explore) and `editor` (npm
            # edit) each name a program npm executes on the operator
            # subcommand — the per-tool respellings of blocked
            # SHELL/EDITOR power.
            "NPM_CONFIG_SHELL",
            "NPM_CONFIG_EDITOR",
            # yarn berry: yarnPath names a Yarn release JS file that
            # the launcher EXECUTES on every yarn invocation.
            "YARN_YARN_PATH",
        }),
        completeness=(
            "NPM_CONFIG_REGISTRY / YARN_REGISTRY / YARN_NPM_REGISTRY_SERVER: "
            "registry-redirect class, documented out. Scoped-registry auth "
            "spellings (npm_config_//<host>/:_authtoken and the top-level "
            "_authToken key): credential material bound to a registry "
            "redirect — inert without one, documented out with that class. "
            "NODE_OPTIONS / NODE_PATH: Node runtime-injection family, "
            "homed in DANGEROUS_ENV_VARS. pnpm reads the npm_config_* "
            "names — covered by the npm members. npm normalises TWO "
            "axes in the config-key portion: case AND '-' vs '_' "
            "(npm_config_script-shell is honoured as script-shell), so "
            "hostile-lane consumers must match via fold_env_candidate, "
            "never by case-fold alone. npm_config_onload-script: "
            "legacy module-load hook removed from modern npm (>=7) — "
            "documented out with the no-current-consumer reason; "
            "re-adjudicate if npm<7 hosts ever join the support set."
        ),
    ),
    BuildEcosystemEnvSurface(
        ecosystem="python",
        source=("pip docs: Configuration (PIP_CONFIG_FILE; every option as "
                "PIP_<OPTION>); poetry docs: Configuration (POETRY_* env, "
                "POETRY_CONFIG_DIR); setuptools has no exec-grade env"),
        transcribed=("2026-09-15; pip topics/configuration + cli option "
                     "env-var mapping; poetry docs/configuration env "
                     "list; setuptools/distutils config docs (no env "
                     "member found)"),
        config_redirect=frozenset({
            "PIP_CONFIG_FILE",
            # poetry config dir: config.toml + auth.toml (registry
            # credentials) — the pip-config twin.
            "POETRY_CONFIG_DIR",
        }),
        completeness=(
            "PIP_INDEX_URL / PIP_EXTRA_INDEX_URL / PIP_FIND_LINKS / "
            "PIP_TRUSTED_HOST / POETRY_REPOSITORIES_*_URL: registry-"
            "redirect class, documented out. POETRY_HTTP_BASIC_*_PASSWORD: "
            "caught by the credential name grammar (PASSWORD segment). "
            "PYTHONPATH / PYTHONSTARTUP / PYTHONUSERBASE: runtime-"
            "injection family, homed in DANGEROUS_ENV_VARS. POETRY_HOME: "
            "toolchain-home class."
        ),
    ),
    BuildEcosystemEnvSurface(
        ecosystem="cargo",
        source=("cargo book: Environment variables Cargo reads, plus the "
                "config env spellings CARGO_<SECTION>_<KEY> "
                "(build.rustc*, build.rustflags, target.<triple>.*)"),
        transcribed=("2026-09-15; cargo reference/environment-variables "
                     "'Environment variables Cargo reads' + "
                     "reference/config env sections"),
        config_redirect=frozenset({
            # config.toml + credentials.toml live here; config.toml
            # can set every override below.
            "CARGO_HOME",
        }),
        tool_override=frozenset({
            # cargo substitutes these binaries for every compile /
            # doc build; the CARGO_BUILD_* names are the env
            # spellings of the same config keys.
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTDOC",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTDOC",
        }),
        flags_injection=frozenset({
            # `-C linker=<prog>` makes every rustc flag string an
            # exec redirect; the ENCODED forms are the
            # 0x1f-separated spellings cargo itself emits.
            "RUSTFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTDOCFLAGS",
            "CARGO_BUILD_RUSTDOCFLAGS",
            "CARGO_ENCODED_RUSTDOCFLAGS",
        }),
        tool_override_patterns=(
            # Per-target env config: the middle segment is the target
            # triple, so these are name FAMILIES, not names. RUNNER
            # executes on `cargo run`/`cargo test`; LINKER on every
            # link; per-target RUSTFLAGS is the flags twin.
            EnvNamePattern(
                "CARGO_TARGET_", "_RUNNER",
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
            ),
            EnvNamePattern(
                "CARGO_TARGET_", "_LINKER",
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
            ),
            EnvNamePattern(
                "CARGO_TARGET_", "_RUSTFLAGS",
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
            ),
        ),
        completeness=(
            "CARGO_REGISTRY_TOKEN / CARGO_REGISTRIES_*_TOKEN: caught by "
            "the credential name grammar (TOKEN segment). "
            "CARGO_REGISTRIES_*_INDEX: registry-redirect class, "
            "documented out. CARGO_TARGET_DIR: cache/output-dir class. "
            "CARGO_TARGET_<triple>_LINKER suffix does not collide with "
            "CARGO_TARGET_DIR (no _LINKER/_RUNNER/_RUSTFLAGS tail). "
            "RUSTUP_HOME (rustup shim resolves toolchain binaries from "
            "it): toolchain-home class, blocked on the settings-scan "
            "lane via TOOLCHAIN_HOME_ENV_VARS; RUSTUP_TOOLCHAIN selects "
            "among installed toolchains only, documented out."
        ),
    ),
    BuildEcosystemEnvSurface(
        ecosystem="go",
        source="go command docs: `go help environment` env inventory",
        transcribed=("2026-09-15; `go help environment` full inventory "
                     "walk (general-purpose + cgo blocks)"),
        config_redirect=frozenset({
            # Points `go` at an alternate env config file, which
            # persists every other knob on this surface (GOFLAGS,
            # GOPROXY, CC, ...).
            "GOENV",
        }),
        flags_injection=frozenset({
            # GOFLAGS is prepended to every go command line and can
            # carry `-toolexec=<cmd>` (run around every toolchain
            # invocation). The CGO_* flag strings reach the C
            # compiler/linker driver (`-fplugin=`, `-Wl,` spellings).
            "GOFLAGS",
            "CGO_CFLAGS",
            "CGO_CPPFLAGS",
            "CGO_CXXFLAGS",
            "CGO_FFLAGS",
            "CGO_LDFLAGS",
        }),
        completeness=(
            "CC/CXX/PKG_CONFIG/AR/FC (cgo executed-program overrides, all "
            "in the `go help environment` inventory) are homed on the "
            "`native` surface — make/cmake/autotools honour the same "
            "names. GOPROXY / GOSUMDB / GONOSUMDB / GOPRIVATE / "
            "GOINSECURE: registry-redirect class, documented out. GOROOT: "
            "toolchain-home class, blocked on the settings-scan lane via "
            "TOOLCHAIN_HOME_ENV_VARS (traced-build env_detect carries "
            "it). GOPATH / GOBIN / GOCACHE / GOMODCACHE / GOTMPDIR: "
            "cache/output-dir class. GOTOOLCHAIN: resolves via PATH "
            "(blocked separately) or a sumdb-verified download. GODEBUG: "
            "runtime knob, no exec/credential primitive."
        ),
    ),
    BuildEcosystemEnvSurface(
        ecosystem="composer",
        source="composer docs: 03-cli.md#environment-variables",
        transcribed=("2026-09-15; getcomposer 03-cli env-vars section, "
                     "full list walk"),
        credential_bearing=frozenset({
            # Inline auth store: the value is a JSON blob of registry
            # credentials (http-basic / bearer / github-oauth) — the
            # secret itself, not a pointer to one.
            "COMPOSER_AUTH",
        }),
        config_redirect=frozenset({
            # Global config dir: auth.json (credentials) + config.json
            # (repository redirects, allow-plugins).
            "COMPOSER_HOME",
            # Selects the composer.json manifest itself — the pointed
            # file's `scripts` hooks execute on install/update.
            "COMPOSER",
        }),
        completeness=(
            "COMPOSER_CACHE_DIR / COMPOSER_BIN_DIR / COMPOSER_VENDOR_DIR: "
            "cache/output-dir class, documented out. PHPRC / "
            "PHP_INI_SCAN_DIR: PHP runtime-injection family, homed in "
            "DANGEROUS_ENV_VARS."
        ),
    ),
    BuildEcosystemEnvSurface(
        ecosystem="maven",
        source=("Maven docs: mvn launcher env (MAVEN_OPTS, MAVEN_ARGS); "
                "Maven Wrapper docs (MVNW_*, MAVEN_USER_HOME)"),
        transcribed=("2026-09-15; maven configure.html launcher env "
                     "section; maven-wrapper usage env list"),
        config_redirect=frozenset({
            # Wrapper distribution install dir + user config home —
            # a planted distribution there is executed by mvnw.
            "MAVEN_USER_HOME",
        }),
        tool_override=frozenset({
            # mvnw downloads the Maven distribution zip from this URL
            # and executes it (checksum pinning is opt-in per repo).
            "MVNW_REPOURL",
        }),
        flags_injection=frozenset({
            # JVM options for the Maven process itself (-javaagent:).
            "MAVEN_OPTS",
            # Prepended mvn arguments: `-s <settings.xml>` redirects
            # the whole config (mirrors reroute plugin jars),
            # `--toolchains` redirects toolchain executables.
            "MAVEN_ARGS",
        }),
        completeness=(
            "M2_HOME: toolchain-home class, blocked on the settings-scan "
            "lane via TOOLCHAIN_HOME_ENV_VARS (traced-build carries "
            "toolchain homes). MVNW_USERNAME / MVNW_PASSWORD: caught by "
            "the credential name grammar (PASSWORD segment; the username "
            "half is inert alone). JAVA_TOOL_OPTIONS / _JAVA_OPTIONS / "
            "JDK_JAVA_OPTIONS / CLASSPATH: JVM runtime-injection family, "
            "homed in DANGEROUS_ENV_VARS."
        ),
    ),
    BuildEcosystemEnvSurface(
        ecosystem="gradle",
        source="Gradle user guide: Environment variables",
        transcribed=("2026-09-15; gradle userguide build_environment "
                     "'Environment variables' section, full list walk"),
        config_redirect=frozenset({
            # init scripts (executed code) + credential stores.
            "GRADLE_USER_HOME",
        }),
        flags_injection=frozenset({
            # JVM options for the Gradle client/daemon (-javaagent:).
            "GRADLE_OPTS",
            # Gradle's launcher also reads the JAVA_OPTS convention.
            "JAVA_OPTS",
        }),
        completeness=(
            "JAVA_HOME: toolchain-home class, blocked on the settings-"
            "scan lane via TOOLCHAIN_HOME_ENV_VARS (traced-build "
            "env_detect carries it). Wrapper distributionUrl is repo-file "
            "config (gradle/wrapper/gradle-wrapper.properties), not env. "
            "JVM runtime-injection names homed in DANGEROUS_ENV_VARS."
        ),
    ),
    BuildEcosystemEnvSurface(
        ecosystem="ant",
        source="Apache Ant manual: running Ant (ANT_OPTS / ANT_ARGS)",
        transcribed=("2026-09-15; ant manual running.html env section, "
                     "full list walk"),
        flags_injection=frozenset({
            # JVM options for the Ant process (-javaagent:).
            "ANT_OPTS",
            # Prepended ant arguments: `-lib <dir>` loads attacker
            # jars into Ant's classloader.
            "ANT_ARGS",
        }),
        completeness=(
            "ANT_HOME: toolchain-home class, blocked on the settings-scan "
            "lane via TOOLCHAIN_HOME_ENV_VARS. The detector's own "
            "ANT_OPTS memory bump is refused by the build-metadata gate "
            "like the MAVEN_OPTS/GRADLE_OPTS bumps already were — "
            "accepted over-refusal on a hostile-input lane."
        ),
    ),
    BuildEcosystemEnvSurface(
        ecosystem="dotnet",
        source=("dotnet host env docs (DOTNET_STARTUP_HOOKS, "
                "DOTNET_HOST_PATH, DOTNET_ADDITIONAL_DEPS, "
                "DOTNET_SHARED_STORE); MSBuild docs (MSBuildSDKsPath); "
                "NuGet docs: CLI environment variables, cross-platform "
                "plugins, credential providers"),
        transcribed=("2026-09-15; dotnet core-runtime + SDK env-var "
                     "reference full walk; MSBuild reserved/env "
                     "properties; NuGet CLI env-vars + plugin discovery "
                     "+ credential-provider discovery pages"),
        config_redirect=frozenset({
            # Assembly-substitution pair: additional deps.json files
            # merged into every app's dependency graph, and extra
            # store locations they resolve from. Weaker than the
            # startup-hooks member (needs matching assembly identity)
            # but the same repo-controls-what-the-host-loads lane.
            "DOTNET_ADDITIONAL_DEPS",
            "DOTNET_SHARED_STORE",
        }),
        tool_override=frozenset({
            # Semicolon list of managed assemblies whose
            # StartupHook.Initialize runs at startup of EVERY .NET
            # process under the shared host — including the SDK's own
            # MSBuild/restore processes on `dotnet build`.
            "DOTNET_STARTUP_HOOKS",
            # Redirects MSBuild SDK resolution; an attacker SDK dir's
            # Sdk.props/Sdk.targets auto-import into every build.
            # Documented mixed-case spelling kept: hostile-input
            # consumers match case-folded, and the general-blocklist
            # sweep needs the spelling MSBuild documents.
            "MSBuildSDKsPath",
            # NuGet discovers and EXECUTES the listed files as plugin
            # processes (the cross-platform credential-provider
            # mechanism) during restore.
            "NUGET_PLUGIN_PATHS",
            "NUGET_NETFX_PLUGIN_PATHS",
            "NUGET_NETCORE_PLUGIN_PATHS",
            # Legacy .NET-Framework credential-provider discovery dir
            # — nuget.exe launches what it finds there.
            "NUGET_CREDENTIALPROVIDERS_PATH",
            # nuget.exe loads extension assemblies from this dir.
            "NUGET_EXTENSIONS_PATH",
            # Absolute path to the dotnet host executable that SDK /
            # MSBuild tooling invokes for child processes.
            "DOTNET_HOST_PATH",
        }),
        flags_injection=frozenset({
            # Extra msbuild arguments on nuget.exe restore —
            # `/logger:<assembly>` loads and executes managed code.
            "NUGET_RESTORE_MSBUILD_ARGS",
        }),
        completeness=(
            "DOTNET_ROOT (and its arch-suffixed variants): toolchain-home "
            "class, blocked on the settings-scan lane via "
            "TOOLCHAIN_HOME_ENV_VARS (traced-build env_detect carries "
            "it). NUGET_PACKAGES / NUGET_HTTP_CACHE_PATH / "
            "NUGET_FALLBACK_PACKAGES: cache/output-dir class. MSBuild "
            "additionally reads ANY environment variable as a project "
            "property — an unbounded surface no enumeration can close; "
            "the members here are the documented exec-grade resolution "
            "overrides, and the residual is accepted on the hostile-input "
            "lanes."
        ),
    ),
    BuildEcosystemEnvSurface(
        ecosystem="rubygems",
        source=("RubyGems docs: `gem help environment` (GEMRC, GEM_HOME, "
                "GEM_PATH, RUBYGEMS_GEMDEPS); Bundler docs: bundle "
                "config env names (BUNDLE_*)"),
        transcribed=("2026-09-15; `gem help environment` full inventory "
                     "walk; bundler bundle-config env-name mapping"),
        config_redirect=frozenset({
            # gemrc list: sources + gem command defaults.
            "GEMRC",
            # Gem load/install roots: a planted gem dir executes at
            # `require` time.
            "GEM_HOME",
            "GEM_PATH",
            # A Gemfile is evaluated Ruby, executed on any `bundle`
            # invocation.
            "BUNDLE_GEMFILE",
            # RubyGems' own gem-deps pointer: the named gem.deps.rb /
            # Gemfile is EVALUATED RUBY at startup of any
            # RubyGems-enabled ruby process — a strictly wider
            # trigger than the bundler-only twin above.
            "RUBYGEMS_GEMDEPS",
            # Bundler home: config + PLUGINS (auto-loaded Ruby).
            "BUNDLE_USER_HOME",
            # Replaces ./.bundle: a planted config there can set
            # BUNDLE_GEMFILE and every other bundler knob — the same
            # powers one indirection later.
            "BUNDLE_APP_CONFIG",
        }),
        tool_override_patterns=(
            # Per-gem native-extension build flags
            # (`bundle config build.<gem>` env spelling) — flag
            # injection into the extconf/compile step.
            EnvNamePattern(
                "BUNDLE_BUILD__", "", "BUNDLE_BUILD__NOKOGIRI",
            ),
        ),
        completeness=(
            "BUNDLE_MIRROR_OF / gem sources / RUBYGEMS_HOST: "
            "registry-redirect class, documented out. GEM_SPEC_CACHE: "
            "cache/output-dir class. RUBYOPT / RUBYLIB: Ruby "
            "runtime-injection family, homed in DANGEROUS_ENV_VARS. "
            "rake reads no exec-grade env of its own beyond the Ruby "
            "runtime family (Rakefiles are repo code, in scope for "
            "the sandbox, not the env belts)."
        ),
    ),
    BuildEcosystemEnvSurface(
        ecosystem="native",
        source=("GNU make manual: 'Variables Used by Implicit Rules' "
                "(the full executed-program + flags catalogs), "
                "'Communicating Options to a Sub-make' (the "
                "env-consumed option carriers MAKEFLAGS/GNUMAKEFLAGS/"
                "MFLAGS), MAKEFILES; CMake docs: environment variables "
                "(CMAKE_TOOLCHAIN_FILE, CMAKE_PREFIX_PATH, "
                "CMAKE_PROGRAM_PATH, CMAKE_<LANG>_COMPILER_LAUNCHER, "
                "CC/CXX); pkg-config as consumed by autotools "
                "PKG_CHECK_MODULES / CMake FindPkgConfig / meson / cgo; "
                "autoconf manual (M4); autotools/meson/cgo honour the "
                "same implicit-variable names"),
        transcribed=("2026-09-15; make manual 10.3 program+flags "
                     "catalogs, completed against every variable the "
                     "default-rule database references — that "
                     "cross-check is EXECUTABLE: the unit suite runs "
                     "`make -p -f /dev/null`, extracts the $(VAR) "
                     "references mechanically, and asserts exec-tier "
                     "coverage; 2026-09-22, make manual 5.7.3 option "
                     "carriers (MAKEFLAGS/GNUMAKEFLAGS/MFLAGS) — make "
                     "consumes these from the ENVIRONMENT without any "
                     "$(VAR) reference, so they are outside the "
                     "reference-derived universe; the unit suite's "
                     "env option-injection arm probes every "
                     "universe name (dot-prefixed specials included "
                     "— make imports the whole environ) behaviorally "
                     "under a no-makefile startup, a recipe-bearing "
                     "dry run (recipe-argv construction expands "
                     "names startup never touches — IFS, "
                     ".SHELLFLAGS), and a library-prerequisite dry "
                     "run (-l search expands .LIBPATTERNS) and "
                     "asserts the injectors are members; "
                     "cmake envvar manual "
                     "full walk; `go help environment` cgo block"),
        tool_override=frozenset({
            # The full executed-program catalog of make's implicit
            # rules (each value is a program the matching rule runs),
            # completed against the default-rule database — the
            # database cross-check is an executable unit-suite oracle.
            # CC / CXX / PKG_CONFIG / AR / FC are also honoured by
            # cmake, autotools configure, meson and cgo.
            "AR", "AS", "CC", "CO", "CPP", "CTANGLE", "CWEAVE", "CXX",
            "FC", "GET", "LD", "LEX", "LINT", "M2C", "MAKEINFO",
            "OBJC", "PC",
            "RM", "TANGLE", "TEX", "TEXI2DVI", "WEAVE", "YACC",
            # Recursive-make redirection: recipes exec $(MAKE), whose
            # default definition is $(MAKE_COMMAND) — both names are
            # env-overridable executed-program variables.
            "MAKE", "MAKE_COMMAND",
            # autoconf/automake run $M4 to expand configure sources.
            "M4",
            # pkg-config resolution: the value is a program executed
            # by configure/cmake/meson/cgo probes.
            "PKG_CONFIG",
            # make INCLUDES the named makefiles before the repo's own
            # — recipe injection into every make run.
            "MAKEFILES",
            # A toolchain file is executed CMake script.
            "CMAKE_TOOLCHAIN_FILE",
            # find_package/find_program roots: an attacker prefix's
            # FooConfig.cmake is executed CMake script at configure —
            # same power as the toolchain file.
            "CMAKE_PREFIX_PATH",
            "CMAKE_PROGRAM_PATH",
        }),
        flags_injection=frozenset({
            # MAKEFLAGS can carry variable definitions (CC=<prog>);
            # the flag strings reach their drivers (`-fplugin=`,
            # `-Wl,--plugin`, `@file`). The list is the make manual's
            # flags catalog for the program vars above.
            "MAKEFLAGS",
            # make's other env-consumed option carriers (manual 5.7.3,
            # 'Communicating Options to a Sub-make'). GNUMAKEFLAGS is
            # appended to MAKEFLAGS before makefiles are parsed — the
            # SAME power as MAKEFLAGS one name over: an
            # `--eval=$(shell <cmd>)` word executes at parse time
            # (even under `-n`), and `CC=<prog>` / `COMPILE.c=<cmd>`
            # words resurrect the program/recipe overrides above
            # through an otherwise-unfiltered wrapper. Exec power
            # argues tool_override-tier, but the whole belt refuses
            # every tier equally and MAKEFLAGS itself is homed here —
            # same home, same rationale. MFLAGS is the historical
            # spelling of the option word: GNU make 4.x no longer
            # consumes it from the environment (behaviorally probed),
            # but its ONLY documented meaning is option carriage and
            # older/other make implementations honour it — admitting
            # it grants nothing legitimate. None of the three appears
            # as a $(VAR) reference in the default-rule database, so
            # the reference-derived cross-check is structurally blind
            # to this class; the env option-injection oracle arm
            # covers it behaviorally.
            "GNUMAKEFLAGS",
            "MFLAGS",
            # Expansion-exec class (probe-verified on GNU make 4.4):
            # make EXPANDS these env-origin values when it consumes
            # them, and expansion runs functions — an environment
            # `VPATH=$(shell <cmd>)` executes at STARTUP, before any
            # rule. MAKEOVERRIDES is additionally spliced into
            # MAKEFLAGS handling, so `MAKEOVERRIDES=CC=<prog>` rides
            # the same program-override primitive as MAKEFLAGS (it is
            # also absent from the `make -p` database dump, which is
            # why the reference oracle could never see it — the
            # binary-token universe of the option-injection arm
            # does). VPATH / GPATH were previously adjudicated out as
            # search-path knobs with "no direct exec primitive"; the
            # expansion probe refuted that.
            "MAKEOVERRIDES",
            "VPATH",
            "GPATH",
            # Recipe-context member of the same expansion-exec class
            # (probe-verified on GNU make 4.4): make expands the
            # env-origin IFS value while CONSTRUCTING each recipe's
            # command argv (deciding shell vs fast path), so
            # `IFS=$(shell <cmd>)` executes as soon as any target has
            # a recipe — INCLUDING under `-n`, which dry-run lanes
            # assume is parse-only; `IFS=$(file >…)` writes files
            # with no shell at all. Startup-context probes (no
            # makefile, no recipe) never see it: the behavioral
            # oracle arm probes both contexts. Also independently
            # homed in the DANGEROUS_ENV_VARS blocklists (shell
            # word-splitting injection) — membership here puts the
            # make-expansion power on the same belt as VPATH/GPATH
            # rather than leaving it to a coincidental second home.
            "IFS",
            # Dot-prefixed make specials in the same expansion-exec
            # class (probe-verified on GNU make 4.4). GNU make
            # imports the ENTIRE environ, dot-named keys included —
            # POSIX shells cannot export such names, but env dicts
            # (the repo-metadata lanes these belts guard) can carry
            # any key. Each expands its env-origin value in its own
            # context:
            #   .EXTRA_PREREQS — expanded per TARGET (make >= 4.3);
            #     `$(shell <cmd>)` executes even under `-n`, no
            #     special makefile shape needed.
            #   .LIBPATTERNS — expanded during `-l` prerequisite
            #     search; `$(shell <cmd>)` executes under `-n` when
            #     any target names a `-lfoo` prerequisite.
            #   .SHELLFLAGS — expanded while building each recipe's
            #     shell argv; the bare `$(shell)` spelling
            #     self-recurses and crashes make (DoS spelling of the
            #     same member), the `$(eval .SHELLFLAGS:=-c)` reassign
            #     bypass executes `$(shell <cmd>)` on a real recipe
            #     run.
            ".EXTRA_PREREQS",
            ".LIBPATTERNS",
            ".SHELLFLAGS",
            "ARFLAGS", "ASFLAGS", "CFLAGS", "COFLAGS", "CPPFLAGS",
            "CXXFLAGS", "DEFFLAGS", "FFLAGS", "GFLAGS", "LDFLAGS",
            "LDLIBS", "LFLAGS", "LINTFLAGS", "M2FLAGS",
            "MAKEINFO_FLAGS", "MODFLAGS", "OBJCFLAGS", "PFLAGS",
            "RFLAGS", "TEXI2DVI_FLAGS", "YFLAGS",
            # Deprecated alias the default link recipes still
            # interpolate beside LDLIBS — same linker-input power.
            "LOADLIBES",
            # Recipe-argument variables the default rules interpolate
            # into executed command lines (OUTPUT_OPTION defaults to
            # `-o $@`; the others default empty) — env-settable flag
            # injection by the same standard as CFLAGS.
            "OUTPUT_OPTION", "SCCS_OUTPUT_OPTION",
            "TARGET_ARCH", "TARGET_MACH",
        }),
        tool_override_patterns=(
            # CMake runs the launcher program around every compile /
            # link of the language — RUSTC_WRAPPER-power, and the
            # language segment varies, so these are name families.
            EnvNamePattern(
                "CMAKE_", "_COMPILER_LAUNCHER",
                "CMAKE_C_COMPILER_LAUNCHER",
            ),
            EnvNamePattern(
                "CMAKE_", "_LINKER_LAUNCHER",
                "CMAKE_C_LINKER_LAUNCHER",
            ),
            # make's dot-named RECIPE variables: the default database
            # defines the entire command line of every built-in rule
            # as ``COMPILE.<suffix>`` / ``LINK.<suffix>`` / … and the
            # rules interpolate them directly into executed recipes —
            # env origin beats default origin, so ``COMPILE.c=<cmd>``
            # replaces the whole compile step (a strictly stronger
            # primitive than CC, which only names the program). The
            # language suffix varies per make release (``.c`` ``.cc``
            # ``.mod`` ``.def`` …, case-significant), so these are
            # name families; matching is case-folded like every other
            # pattern, which covers both ``COMPILE.c`` and
            # ``COMPILE.C``. The unit suite's executable database
            # cross-check derives the concrete member list from
            # ``make -p`` and asserts every referenced dotted name is
            # pattern-covered.
            EnvNamePattern("COMPILE.", "", "COMPILE.c"),
            EnvNamePattern("LINK.", "", "LINK.o"),
            EnvNamePattern("LEX.", "", "LEX.l"),
            EnvNamePattern("LINT.", "", "LINT.c"),
            EnvNamePattern("PREPROCESS.", "", "PREPROCESS.F"),
            EnvNamePattern("YACC.", "", "YACC.y"),
        ),
        completeness=(
            "Dot-named recipe variables (COMPILE.c / LINK.o / LEX.l "
            "class): pattern members via the COMPILE./LINK./LEX./"
            "LINT./PREPROCESS./YACC. prefix families above — exact "
            "rows would chase make releases (and case-significant "
            "suffix spellings) by hand; the executable database "
            "cross-check keeps the family honest against the "
            "installed make. "
            "Env-read-only names (MAKEFLAGS / GNUMAKEFLAGS / MFLAGS / "
            "MAKEFILES class): consumed by make directly from the "
            "environment, never referenced as $(VAR) in the default "
            "database — OUTSIDE the reference-derived oracle's "
            "universe, so membership is transcribed from manual "
            "5.7.3 and kept honest by the behavioral env "
            "option-injection oracle arm. The F77-style "
            "'defined-but-unreferenced = inert' adjudication does "
            "NOT generalize to this class (GNUMAKEFLAGS is "
            "defined-unreferenced and live). "
            "Loader-redirect names (LD_PRELOAD family) and locale/"
            "temp-dir names are homed in DANGEROUS_ENV_VARS. "
            "F77 / F77FLAGS: default-database entries defined via "
            "FC/FFLAGS that no default recipe references — inert for "
            "the built-in rules, documented out (autoconf's "
            "AC_PROG_F77 honours F77 when a repo's configure selects "
            "Fortran 77, but a repo-authored configure already "
            "executes arbitrary code inside the sandbox). "
            "CMAKE_INCLUDE_PATH / CMAKE_LIBRARY_PATH / CMAKE_GENERATOR: "
            "search-path / generator-selection class, no direct exec "
            "primitive, documented out. SHELL: make ignores its "
            "environment origin (probe-verified). MAKE_TMPDIR: "
            "consumed as a RAW path string, never expanded "
            "(probe-verified — make echoes an invalid value verbatim "
            "and falls back to the default temp dir). VPATH / GPATH / "
            "MAKEOVERRIDES were documented out here as non-program "
            "knobs until the expansion probe showed make expands "
            "their env values (functions run — `$(shell …)` executes "
            "at startup); they are flags_injection members now. "
            "Recipe-context expansion class: names expanded only "
            "while make constructs a recipe's command argv are "
            "INVISIBLE to a no-makefile startup probe — IFS and "
            ".SHELLFLAGS are the members (both expand under `-n` / "
            "recipe construction), belted above. Dot-prefixed "
            "specials are env surface too: make imports the whole "
            "environ, and env dicts can carry dot-named keys POSIX "
            "shells cannot export — .EXTRA_PREREQS / .LIBPATTERNS / "
            ".SHELLFLAGS are the probe-verified expanders, belted "
            "above; .RECIPEPREFIX / .DEFAULT_GOAL / .ONESHELL / "
            ".INCLUDE_DIRS probed inert from the environment (no "
            "expansion observed — value consumed raw or ignored). "
            "The oracle arm's universe admits dot-shaped names and "
            "probes startup, recipe-construction, and library-"
            "prerequisite-search contexts, so a make release adding "
            "an expander in any of those contexts fails the sweep "
            "instead of escaping it. meson "
            "consumes the same CC/CXX/*FLAGS/PKG_CONFIG convention — no "
            "meson-specific exec-grade env documented beyond it. "
            "RAPTOR lanes that deliberately inject CFLAGS/RUSTFLAGS "
            "into sandboxed builds declare env_caller_filtered at the "
            "spawn (the documented escape for intentional primitives)."
        ),
    ),
)


def _surface_union(field: str) -> frozenset[str]:
    out: set[str] = set()
    for surface in BUILD_ECOSYSTEM_ENV_SURFACES:
        out.update(getattr(surface, field))
    return frozenset(out)


CREDENTIAL_BEARING_ENV_VARS: frozenset[str] = (
    _BASE_CREDENTIAL_BEARING_ENV_VARS
    | _surface_union("credential_bearing")
)

CREDENTIAL_FILE_POINTER_ENV_VARS: frozenset[str] = (
    _BASE_CREDENTIAL_FILE_POINTER_ENV_VARS
    | _surface_union("config_redirect")
)

CREDENTIAL_EXEC_REDIRECT_ENV_VARS: frozenset[str] = (
    _BASE_CREDENTIAL_EXEC_REDIRECT_ENV_VARS
    | _surface_union("tool_override")
    | _surface_union("flags_injection")
)

#: Every declared name pattern, across all ecosystem surfaces.
CREDENTIAL_ENV_NAME_PATTERNS: tuple[EnvNamePattern, ...] = tuple(
    pattern
    for surface in BUILD_ECOSYSTEM_ENV_SURFACES
    for pattern in surface.tool_override_patterns
)

#: The full family — for hostile-input filters (repo settings env
#: scanning, build-metadata env filtering). No member of this set has
#: a legitimate reason to be set by scanned-repo content. Pattern
#: members are matched by :func:`is_credential_env_pattern_member`
#: (folded into :func:`is_credential_redirect_shaped`, which those
#: same hostile-input filters already apply).
CREDENTIAL_ENV_FAMILY: frozenset[str] = (
    CREDENTIAL_BEARING_ENV_VARS
    | CREDENTIAL_FILE_POINTER_ENV_VARS
    | CREDENTIAL_EXEC_REDIRECT_ENV_VARS
)

# --- Toolchain-home class (settings-scan lane only) ------------------
#
# Directories a host launcher/resolver EXECUTES binaries from:
# `mvn`/`gradle`/`ant` exec ``$JAVA_HOME/bin/java``, the go tool execs
# ``$GOROOT/pkg/tool/...``, the dotnet resolver executes from
# ``$DOTNET_ROOT``, the rustup shim from ``$RUSTUP_HOME``. A scanned
# repo's settings env supplying one points the OPERATOR SESSION's next
# launcher invocation at a repo-shipped binary — with PATH itself
# blocked, this is the surviving launcher-redirect primitive on that
# lane, so cc_trust's settings scan blocks the whole class.
#
# Deliberately NOT in CREDENTIAL_ENV_FAMILY and NOT in the general
# blocklist: operators legitimately set these, and the traced-build
# lane AUTO-DETECTS and carries them (``BUILD_SYSTEMS`` ``env_detect``
# → core/build/toolchain.py) — family membership would strip the
# lane's own passthrough. The census closure test pins both relations
# (env_detect ⊆ this class; this class ∩ family = ∅).
TOOLCHAIN_HOME_ENV_VARS: frozenset[str] = frozenset({
    "JAVA_HOME",
    "GOROOT",
    "DOTNET_ROOT",
    "ANT_HOME",
    "M2_HOME",
    "POETRY_HOME",
    "RUSTUP_HOME",
})

# --- Config-home redirect class (settings-scan lane only) ------------
#
# Directories config-consuming tools resolve their OWN config trees
# from. Same power class as the long-blocked HOME: a repo-supplied
# settings env repointing one makes the operator session's next tool
# invocation read attacker-authored config — and config IS exec on
# these surfaces (CC settings.json: apiKeyHelper/hooks/permissions;
# XDG_CONFIG_HOME: git/config alias `!sh` + credential.helper,
# pip.conf, gh config; XDG_DATA_HOME/XDG_CACHE_HOME: template/hook
# and loader-cache trees several tools execute or import from).
#
# source= freedesktop.org basedir-spec 0.8 (XDG_CONFIG_HOME,
#   XDG_DATA_HOME, XDG_STATE_HOME, XDG_CACHE_HOME; XDG_CONFIG_DIRS /
#   XDG_DATA_DIRS are the search-path plural forms with the same
#   redirect power) + Claude Code settings docs (CLAUDE_CONFIG_DIR
#   repoints CC's own config dir wholesale).
# transcribed= 2026-09-22; basedir-spec full variable walk; CC env
#   docs walk; zsh startup-files section (ZDOTDIR).
# completeness= XDG_RUNTIME_DIR: documented out — consumers require
#   it to already exist with 0700 ownership, and it carries sockets,
#   not executed config. Per-tool config-FILE pointers
#   (GIT_CONFIG_GLOBAL, PIP_CONFIG_FILE, AWS_CONFIG_FILE, ...) are
#   homed in DANGEROUS_ENV_VARS / the credential-env family; this
#   class is the config-HOME (whole-tree) spelling only.
#
# Settings-scan lane only, like TOOLCHAIN_HOME_ENV_VARS: operators
# legitimately export XDG_* on their own hosts; only a scanned repo's
# settings env has no business setting them.
CONFIG_HOME_REDIRECT_ENV_VARS: frozenset[str] = frozenset({
    "CLAUDE_CONFIG_DIR",
    "XDG_CONFIG_HOME",
    "XDG_CONFIG_DIRS",
    "XDG_DATA_HOME",
    "XDG_DATA_DIRS",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    # zsh's config home (zsh docs: startup files): every zsh start
    # sources $ZDOTDIR/.zshenv — the zsh spelling of the blocked
    # BASH_ENV/ENV power via the config-HOME axis this class owns.
    "ZDOTDIR",
})

# --- BUILD_SYSTEMS census --------------------------------------------
#
# Every build-system type the detector inventory
# (core/build/build_detector.BuildDetector.BUILD_SYSTEMS) can emit
# maps to the ecosystem surface that adjudicates its env family. The
# census closure test walks the inventory against this map, so adding
# a build system WITHOUT adjudicating its env surface fails CI —
# ecosystem coverage is structural, not a per-name chase. Surfaces
# with no BUILD_SYSTEMS row (cargo, composer) cover lanes outside the
# detector (sca resolvers, corpus builds); extra surfaces are fine,
# missing ones are not. The map itself is trusted adjudication: the
# census can verify totality in both directions, but pointing a build
# system at a semantically WRONG surface is a review-time judgement no
# mechanical check catches — change rows deliberately.
BUILD_SYSTEM_ECOSYSTEM_MAP: dict[str, str] = {
    "maven": "maven",
    "gradle": "gradle",
    "ant": "ant",
    "poetry": "python",
    "pip": "python",
    "setuptools": "python",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "gomod": "go",
    "cmake": "native",
    "autotools": "native",
    "meson": "native",
    "make": "native",
    "dotnet": "dotnet",
    "msbuild": "dotnet",
    "bundler": "rubygems",
    "rake": "rubygems",
}

# --- Documented runtime re-admits -----------------------------------
#
# Family members some TRUSTED RAPTOR lane legitimately carries into a
# child environment that later crosses a DANGEROUS_ENV_VARS-consuming
# filter (the sandbox strict_env sweep re-filters caller-supplied env
# by that list). These stay OUT of the general-blocklist increment;
# hostile-input lanes block them via CREDENTIAL_ENV_FAMILY instead.
#
# Carrier lanes (each named so the exemption is auditable):
#   * cc_adapter env-mode children (run_untrusted_networked,
#     strict_env=True): first-party auth on API-key / setup-token
#     installs (ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN /
#     CLAUDE_CODE_OAUTH_TOKEN, plus operator ANTHROPIC_CUSTOM_HEADERS
#     riding the backend overlay), the Bedrock AWS passthrough names
#     (_CC_AWS_PASSTHROUGH_NAMES: AWS_PROFILE / AWS_CONFIG_FILE /
#     AWS_SHARED_CREDENTIALS_FILE) and minted/static AWS credential
#     material for children whose own chain is sandbox-dead.
#   * proxy-mode children: the minted scoped ANTHROPIC_AUTH_TOKEN is
#     the child's ONLY credential by contract.
#   * the go autobuild lane (core/dataflow/cvefix_walk): injects
#     GOFLAGS=-mod=mod into its sandboxed build env, which crosses
#     run_untrusted_networked's strict_env=True sweep — an
#     unexempted GOFLAGS would be silently stripped there and
#     module fetch would fail closed on repos with go.sum gaps.
GENERAL_BLOCKLIST_EXEMPT_VARS: frozenset[str] = frozenset({
    *ANTHROPIC_FIRST_PARTY_AUTH_VARS,
    "ANTHROPIC_CUSTOM_HEADERS",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_PROFILE",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "GOFLAGS",
})

#: The increment general-purpose blocklists take from the family:
#: every member here is safe to strip from ANY child environment —
#: no RAPTOR runtime lane carries them (verified per-member when the
#: exemption list above was drawn; GIT_ASKPASS/GIT_SSH pins from
#: RaptorConfig.GIT_ENV_VARS survive because every strict_env sweep
#: exempts values matching those pins, and the lanes that deliberately
#: inject build flags — corpus builds layering CFLAGS/RUSTFLAGS —
#: declare env_caller_filtered at the spawn instead of crossing the
#: strict_env sweep).
CREDENTIAL_GENERAL_BLOCKLIST_VARS: frozenset[str] = (
    CREDENTIAL_ENV_FAMILY - GENERAL_BLOCKLIST_EXEMPT_VARS
)

# --- Name-shape grammar ---------------------------------------------
#
# Belt over the explicit sets: catches family-shaped names the
# enumeration doesn't know yet (a future CLAUDE_CODE_*_TOKEN, a new
# provider's *_API_KEY). Segment-exact on underscore-split so
# GPG_PUBKEY / SSLKEYLOGFILE-style names don't false-positive.
#
# Plural TOKENS is deliberately ABSENT: real credential names are
# effectively always singular (*_TOKEN), while plural TOKENS names
# count things (CLAUDE_CODE_MAX_OUTPUT_TOKENS / MAX_THINKING_TOKENS /
# MAX_MCP_OUTPUT_TOKENS — documented, commonly committed settings
# knobs). Including it flags those common legitimate keys on every
# consumer surface; excluding it costs nothing observed (no known
# credential is named *_TOKENS, and the explicit sets keep covering
# enumerated members). Two-direction pins live in the unit tests.
# Plural KEYS/SECRETS/... stay: multi-secret blobs genuinely use them
# and no common tooling knob collides.
_CREDENTIAL_NAME_SEGMENTS: frozenset[str] = frozenset({
    "TOKEN",
    "KEY", "KEYS", "APIKEY",
    "SECRET", "SECRETS",
    "CREDENTIAL", "CREDENTIALS",
    "PASSWORD", "PASSWORDS", "PASSWD",
    # GPG_PASSPHRASE-class names: the passphrase IS the credential
    # (armours a key at rest); no common tooling knob collides with
    # the segment.
    "PASSPHRASE",
})

# Documented benign operator knobs whose names collide with the
# grammar and are exempted by exact name: the KEY segment in
# CLAUDE_CODE_API_KEY_HELPER_TTL_MS belongs to "apiKeyHelper" (the
# value is a refresh interval in milliseconds, never credential
# material), and KEY itself is load-bearing for *_API_KEY — a
# carve-out, not a segment change. Kept deliberately tiny: every
# entry must be a documented knob whose VALUE is inert.
_CREDENTIAL_SHAPE_EXEMPT_KNOBS: frozenset[str] = frozenset({
    "CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
})

# Additional segments that mark credential-REDIRECT shapes (config /
# helper-exec pointers) for hostile-input lanes only — too broad for
# general child-env sweeps (plenty of benign *_CONFIG_FILE tooling
# knobs exist in operator environments).
_REDIRECT_NAME_SUFFIXES: tuple[str, ...] = (
    "_CONFIG_FILE",
    "_CREDENTIALS_FILE",
    "_ASKPASS",
)


def is_credential_shaped(name: str) -> bool:
    """True when *name* looks like it carries credential material.

    Case-insensitive, segment-exact on underscore split: any segment
    equal to TOKEN/KEY/SECRET/CREDENTIAL/PASSWORD (and common
    variants) marks the name. ``ANTHROPIC_API_KEY``,
    ``CLAUDE_CODE_OAUTH_TOKEN`` and ``AWS_SECRET_ACCESS_KEY`` match;
    ``GPG_PUBKEY``, ``SSLKEYLOGFILE`` and the documented
    ``CLAUDE_CODE_MAX_OUTPUT_TOKENS`` / ``…_API_KEY_HELPER_TTL_MS``
    settings knobs do not.
    """
    upper = name.upper()
    if upper in _CREDENTIAL_SHAPE_EXEMPT_KNOBS:
        return False
    return any(
        seg in _CREDENTIAL_NAME_SEGMENTS
        for seg in upper.split("_")
    )


def is_credential_env_pattern_member(name: str) -> bool:
    """True when *name* matches a declared family NAME PATTERN.

    Case-insensitive. Pattern members (``CARGO_TARGET_<triple>_RUNNER``,
    ``BUNDLE_BUILD__<gem>``) are first-class family citizens: they
    cannot live in the exact-name sets (the middle segment varies), so
    every surface that matches family membership on hostile or
    caller-supplied input must apply this predicate beside the set
    check. The middle segment must be non-empty — a bare
    prefix+suffix concatenation is not a documented member.
    """
    upper = name.upper()
    for pattern in CREDENTIAL_ENV_NAME_PATTERNS:
        if (
            upper.startswith(pattern.prefix)
            and upper.endswith(pattern.suffix)
            and len(upper) > len(pattern.prefix) + len(pattern.suffix)
        ):
            return True
    return False


def is_credential_redirect_shaped(name: str) -> bool:
    """Shape rule for HOSTILE-INPUT lanes (repo-supplied env keys).

    Everything :func:`is_credential_shaped` matches, plus config-file
    / askpass-style redirect suffixes (``AWS_CONFIG_FILE``-shaped
    names), plus the declared family name patterns
    (``CARGO_TARGET_<triple>_RUNNER``-shaped names). Deliberately not
    used on general child-env sweeps — benign operator tooling
    legitimately uses ``*_CONFIG_FILE`` knobs; repo-supplied settings
    env has no such excuse.
    """
    if is_credential_shaped(name):
        return True
    upper = name.upper()
    if any(upper.endswith(suffix) for suffix in _REDIRECT_NAME_SUFFIXES):
        return True
    return is_credential_env_pattern_member(name)


# --- Model-traffic redirect endpoints -------------------------------
#
# NOT part of CREDENTIAL_ENV_FAMILY: ``ANTHROPIC_BASE_URL`` is a
# documented LLM-lane re-admit (``LLM_ROUTING_ENV_VARS``) and the
# proxy-mode dispatcher itself SETS gateway base URLs on its children
# — family membership would put these names in general blocklists
# that trusted routing lanes must carry them through. This is a shape
# rule for the two symmetric consumers that reason about
# model-traffic redirection:
#
#   * cc_trust's settings-env scan (hostile input): a repo-supplied
#     endpoint name repoints model traffic at an attacker host —
#     prompt/source exfiltration, and on bearer-token installs
#     verbatim credential exfiltration. The CLI honours a DIFFERENT
#     base-URL name per provider mode (a Bedrock install ignores
#     ``ANTHROPIC_BASE_URL`` and reads
#     ``ANTHROPIC_BEDROCK_MANTLE_BASE_URL`` / the per-cloud
#     ``ANTHROPIC_*_BASE_URL`` variants), the JS AWS SDK honours
#     ``AWS_ENDPOINT_URL`` / ``AWS_ENDPOINT_URL_<SERVICE>``, and the
#     ``CLAUDE_CODE_SKIP_*`` flags flip the CLI's auth mode at
#     whatever endpoint won — blocking only the exact primary name
#     leaves the whole variant family open.
#   * cc_adapter's proxy-mode strip: operator endpoint pins must not
#     ride the backend overlay into a proxy-mode child — the caller
#     sets the one true gateway route (and the skip-auth flags THIS
#     mode needs) after the strip.

def is_model_traffic_redirect_shaped(name: str) -> bool:
    """True when *name* is a model-traffic endpoint/auth-mode knob.

    Case-insensitive. Covers the per-provider base-URL family
    (``ANTHROPIC_BASE_URL``, ``ANTHROPIC_BEDROCK[_MANTLE]_BASE_URL``,
    ``ANTHROPIC_VERTEX_BASE_URL``, future variants), the JS AWS SDK
    endpoint overrides (``AWS_ENDPOINT_URL``,
    ``AWS_ENDPOINT_URL_BEDROCK_RUNTIME``, per-service variants), and
    the CLI auth-mode flips (``CLAUDE_CODE_SKIP_*``).
    """
    upper = name.upper()
    if upper.startswith("ANTHROPIC_") and "BASE_URL" in upper:
        return True
    if upper.startswith("AWS_ENDPOINT_URL"):
        return True
    return upper.startswith("CLAUDE_CODE_SKIP_")


def is_function_injection_shaped(name: str) -> bool:
    """True when *name* is shaped like an exported-shell-function key.

    bash (post-Shellshock) imports ``BASH_FUNC_<name>%%`` environment
    entries as shell functions at startup, and function lookup
    precedes builtin lookup — one such key makes every later-spawned
    bash resolve ``<name>`` to the attacker's function (PATH-grade
    exec; it can even shadow ``unset`` itself). Derivational rather
    than an enumerated pair of spellings: legitimate env NAMES are
    portable identifiers (``[A-Za-z_][A-Za-z0-9_]*``), so any
    candidate carrying the ``BASH_FUNC_`` head or the function-
    encoding punctuation (``%``, ``(``, ``)``) in its NAME is the
    injection shape, whichever historical bash encoding
    (``BASH_FUNC_x%%``, ``BASH_FUNC_x()``) produced it.

    Hostile-input lanes only (repo-supplied settings env keys).
    """
    if name.upper().startswith("BASH_FUNC_"):
        return True
    return any(c in name for c in "%()")


def fold_env_candidate(name: str) -> str:
    """Normalise a HOSTILE-LANE env-name candidate before matching.

    Case-fold AND fold ``-`` to ``_``. Consumers normalise more axes
    than case alone: npm treats ``-`` and ``_`` as interchangeable in
    the config-key portion of ``npm_config_<key>`` names (live-
    verified: ``npm_config_script-shell=/x npm config get script-shell``
    → ``/x``), so ``npm_config_script-shell`` is the same exec-redirect
    member as ``NPM_CONFIG_SCRIPT_SHELL`` to the consumer while being
    invisible to an exact-name match. No declared family member is
    dash-bearing, so folding candidates onto the underscore spelling
    is loss-free for the vocabulary and closes the whole dash-
    respelling axis at one chokepoint instead of per-member.

    Hostile-input lanes only (repo-supplied settings env keys):
    general child-env sweeps match the exact names their consumers
    read and must not widen.
    """
    return name.upper().replace("-", "_")
