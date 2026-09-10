# RAPTOR Devcontainer
# Autonomous Offensive/Defensive Research Framework
#
# This container provides all dependencies for the RAPTOR security research framework.
# Based on comprehensive audit of all agents, commands, skills, and packages.

FROM mcr.microsoft.com/devcontainers/python:3-3.14-bookworm AS raptor-base

# Some corporate and hardened networks block plain HTTP while allowing HTTPS.
# Debian's Bookworm base image still carries http:// mirror URIs; normalize
# them before the first apt invocation so builds do not fail on port 80.
RUN find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) \
        -exec sed -i \
        -e 's|http://deb.debian.org|https://deb.debian.org|g' \
        -e 's|http://security.debian.org|https://security.debian.org|g' \
        {} +

# The base image's `node` devcontainer-feature install path added a stale
# yarn apt source (NO_PUBKEY 62D54FD4003F6525, breaks apt-get update) AND
# the yarn 1.x package itself (/usr/bin/yarn). Remove both so the later
# locked npm closure doesn't collide on aarch64 builds.
RUN rm -f /etc/apt/sources.list.d/yarn.list \
    && (apt-get -y remove yarn || echo "yarn not installed - skipping removal")

# ============================================================================
# SYSTEM DEPENDENCIES
# Organized by component that needs them
# ============================================================================

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install -y --no-install-recommends \
    #
    # --- Core Tools (all scripts, packages) ---
    python3-pip \
    python3-venv \
    #
    # --- Git (recon, static-analysis, crash-analysis-agent, raptor_agentic) ---
    git \
    #
    # --- Build Tools (function-tracing skill, crash-analysis agents, exploit validation) ---
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    autoconf \
    automake \
    libtool \
    libtool-bin \
    clang-format \
    #
    # --- GDB (crash-analyzer-agent, binary_analysis package, rr-debugger skill) ---
    gdb \
    gdb-multiarch \
    #
    # --- Binary Analysis (binary_analysis package) ---
    binutils \
    file \
    #
    # --- Sandbox mount-ns (newuidmap/newgidmap for non-root user-ns) ---
    uidmap \
    util-linux \
    #
    # --- Network Tools (web package, github-forensics skills) ---
    curl \
    wget \
    #
    # --- rr Debugger Dependencies (crash-analysis agents - Linux x86_64 only) ---
    # rr itself installed separately below
    libcapnp-dev \
    #
    # --- TLS / distro detection (curl, nodesource, playwright deps installer) ---
    ca-certificates \
    lsb-release \
    # --- Misc ---
    jq \
    unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# HASH-LOCKED PYTHON ENVIRONMENT
# ============================================================================

# Generated for CPython 3.14 on Linux amd64. The lock contains the complete
# standard devcontainer closure: RAPTOR runtime/dev packages, web support,
# optional Python integrations, and Semgrep. --no-deps prevents pip from
# resolving anything outside the checked-in, hash-verified closure.
COPY containers/requirements-build.lock /tmp/raptor/requirements-build.lock
COPY containers/requirements-base.lock /tmp/raptor/requirements-base.lock
COPY containers/verify-all-tools.py /usr/local/bin/raptor-verify-all-tools

RUN chmod 0755 /usr/local/bin/raptor-verify-all-tools

RUN python3 -m pip install --no-cache-dir --require-hashes --no-deps \
        --only-binary=:all: \
        -r /tmp/raptor/requirements-build.lock

RUN python3 -m pip install --no-cache-dir --no-build-isolation \
        --require-hashes --no-deps \
        -r /tmp/raptor/requirements-base.lock \
    && python3 -m pip check

# ============================================================================
# RR DEBUGGER (rr-debugger skill, crash-analysis agents)
# Linux x86_64 only - provides deterministic record-replay debugging
# NOTE: Requires --privileged container flag and kernel parameter configuration
# ============================================================================

RUN arch="$(dpkg --print-architecture)" \
    && case "${arch}" in \
        amd64) \
            apt-get update \
            && apt-get install -y --no-install-recommends rr=5.6.0-3+b1 \
            && apt-get clean \
            && rm -rf /var/lib/apt/lists/* \
            ;; \
        *) echo "rr is unavailable on ${arch}; skipping in the base image" ;; \
    esac

# Configure kernel for rr (automatically done in privileged container)
# If rr kernel config fails, run with devcontainer --privileged flag
RUN echo "# To enable rr, the devcontainer needs --privileged flag" \
    && echo "# Run: echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid" \
    && echo "# Or enter with: bin/raptor-container shell --privileged"

# ============================================================================
# AFL++ FUZZER (fuzzing package, fuzz/raptor-fuzz commands)
# ============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    afl++ \
    afl++-clang \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    || echo "AFL++ not available - skipping"

ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

# Install Playwright browser + system deps via Playwright's own dep installer.
# Replaces a hand-rolled apt list that drifted out of sync with upstream Chromium deps.
RUN install -d -m 0755 -o root -g vscode "${PLAYWRIGHT_BROWSERS_PATH}" \
    && apt-get update \
    && python -m playwright install --with-deps chromium \
    && chown -R root:vscode "${PLAYWRIGHT_BROWSERS_PATH}" \
    && chmod -R a+rX "${PLAYWRIGHT_BROWSERS_PATH}" \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ============================================================================
# LOCKED NODE TOOLCHAIN
# Claude Code is required to run RAPTOR via bin/raptor. Yarn and pnpm are
# available for target builds. npm ci verifies the checked-in registry
# integrities, and package scripts are disabled except for Claude's explicit
# local postinstall, which selects the already-locked platform package.
# ============================================================================

# Capture-then-execute the nodesource setup script so a curl failure isn't
# silently swallowed by the pipeline (curl | bash ignores curl's exit status).
# Node 24 is the current stable release, and is supported by the latest Claude CLI.
ARG CLAUDE_CODE_VERSION=2.1.263
RUN curl -fsSL https://deb.nodesource.com/setup_24.x -o /tmp/nodesource_setup.sh \
    && bash /tmp/nodesource_setup.sh \
    && rm /tmp/nodesource_setup.sh \
    && apt-get install -y --no-install-recommends nodejs=24.20.0-1nodesource1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV NPM_CONFIG_UPDATE_NOTIFIER=false

COPY containers/npm/base/package.json containers/npm/base/package-lock.json \
    /opt/raptor/npm/base/
RUN npm ci --ignore-scripts --include=optional --omit=dev --no-audit --no-fund \
        --prefix /opt/raptor/npm/base \
    && node /opt/raptor/npm/base/node_modules/@anthropic-ai/claude-code/install.cjs \
    && node -e "if (require('/opt/raptor/npm/base/node_modules/@anthropic-ai/claude-code/package.json').version !== '2.1.263') process.exit(1)" \
    && node -e "if (require('/opt/raptor/npm/base/node_modules/yarn/package.json').version !== '1.22.22') process.exit(1)" \
    && node -e "if (require('/opt/raptor/npm/base/node_modules/pnpm/package.json').version !== '11.8.0') process.exit(1)" \
    && ln -sf /opt/raptor/npm/base/node_modules/.bin/claude /usr/local/bin/claude \
    && ln -sf /opt/raptor/npm/base/node_modules/.bin/yarn /usr/local/bin/yarn \
    && ln -sf /opt/raptor/npm/base/node_modules/.bin/yarnpkg /usr/local/bin/yarnpkg \
    && ln -sf /opt/raptor/npm/base/node_modules/.bin/pnpm /usr/local/bin/pnpm \
    && ln -sf /opt/raptor/npm/base/node_modules/.bin/pnpx /usr/local/bin/pnpx

RUN raptor-verify-all-tools \
    --check-version "${CLAUDE_CODE_VERSION}" claude --version

# ============================================================================
# ENVIRONMENT CONFIGURATION
# ============================================================================

ENV PATH="/workspaces/raptor/bin:${PATH}"
ENV GIT_TERMINAL_PROMPT=0
ENV PYTHONUNBUFFERED=1
# The build stage retains the historical import path so existing expensive
# layers remain cacheable. The two exposed runtime targets override it below
# before users enter the image.
ENV PYTHONPATH="/workspaces/raptor:/workspaces/raptor/packages"

# ============================================================================
# WORKSPACE
# ============================================================================

WORKDIR /workspaces/raptor

# Used only by bin/raptor-container's Docker path to map the host UID/GID.
# The normal devcontainer path still starts directly as vscode.
COPY containers/raptor-container-entrypoint /usr/local/bin/raptor-container-entrypoint
RUN chmod 0755 /usr/local/bin/raptor-container-entrypoint

# ============================================================================
# RUNTIME USER
# ============================================================================
# Default to the non-root vscode user from the base image (UID 1000).
# vscode has passwordless sudo for tools that genuinely need root (e.g. rr in
# --privileged containers). All build steps above run as root by inheritance.
USER vscode

RUN python -c "from playwright.sync_api import sync_playwright; playwright = sync_playwright().start(); browser = playwright.chromium.launch(headless=True); page = browser.new_page(); page.set_content('<title>raptor-playwright-smoke</title>'); assert page.title() == 'raptor-playwright-smoke'; browser.close(); playwright.stop()"

CMD ["bash"]

# ============================================================================
# STANDARD DEVCONTAINER (explicit target)
# ============================================================================

# Keep this target before every all-tools stage. The legacy Docker builder
# evaluates earlier stages even when --target is used, so placing the standard
# target here guarantees `--target raptor-devcontainer` cannot encounter the
# later CodeQL acceptance gate. Supported wrappers, devcontainers, and CI jobs
# always select one of the two named targets explicitly.
# A build without --target intentionally continues to raptor-all-tools and is
# therefore still subject to the acceptance and amd64-only gates below.
FROM raptor-base AS raptor-devcontainer

ENV RAPTOR_DIR=/workspaces/raptor
ENV PYTHONPATH=/workspaces/raptor

CMD ["bash"]

# ============================================================================
# ALL TOOLS (explicit opt-in target; requires CodeQL acceptance)
# ============================================================================

FROM raptor-base AS raptor-all-tools-build

USER root

COPY containers/all-tools-manifest.json /usr/local/share/raptor/all-tools-manifest.json
COPY containers/cargo-fuzz-smoke/Cargo.lock /usr/local/share/raptor/cargo-fuzz-smoke.Cargo.lock
COPY containers/install-all-tools-native.sh /usr/local/libexec/raptor-install-all-tools-native
RUN chmod 0755 /usr/local/libexec/raptor-install-all-tools-native

ARG ACCEPT_CODEQL_TERMS=0
ARG TEMURIN_RELEASE=jdk-21.0.12.1%2B1
ARG TEMURIN_VERSION=21.0.12.1_1
ARG TEMURIN_AMD64_SHA256=ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94
ARG TEMURIN_ARM64_SHA256=23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223
ARG GHIDRA_VERSION=12.1.3
ARG GHIDRA_BUILD_DATE=20260817
ARG GHIDRA_SHA256=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54
ARG GRADLE_VERSION=9.7.1
ARG GRADLE_SHA256=acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a
ARG JOERN_VERSION=4.0.622
ARG JOERN_AMD64_SHA256=d559b569b6180726c2b5b7a5b9b25753c1cbf42c8143ba11311df0d47b2a40a6
ARG JOERN_ARM64_SHA256=fceac538dfbc11b7833878532428bdd255ba2fc89762c98d99577edc4c780a1a
ARG GCLOUD_VERSION=583.0.0
ARG GCLOUD_AMD64_SHA256=84c5e4798836bda13aa82c3e84fa1acd0c4e4ca5318f7141052e3a5a26a7cc97
ARG GCLOUD_ARM64_SHA256=8ce6287e01e54b53d2e9618d124b62ac85efe5a093904ae027b17f2057030662
ARG OLLAMA_VERSION=0.33.3
ARG OLLAMA_AMD64_SHA256=c13cea8f3389db4145f8a6cb88d1747242a48639d7c13e3bda7c1ebdc6eebb2f
ARG OLLAMA_ARM64_SHA256=4425a112af999ae6572c1ce211fbabeaca7bab23ed5860972acdfc0cc2358420

# Fail before downloading any all-tools assets. CodeQL 2.26.4 publishes an
# official Linux amd64 bundle but no Linux arm64 bundle.
RUN arch="$(dpkg --print-architecture)" \
    && if [ "${ACCEPT_CODEQL_TERMS}" != "1" ]; then \
        echo "CodeQL download requires explicit acceptance of https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md" >&2; \
        echo "Build through bin/raptor-container with --all-tools --accept-codeql-terms." >&2; \
        exit 64; \
    fi \
    && case "${arch}" in \
        amd64) ;; \
        *) \
            echo "CodeQL bundle 2.26.4 is unsupported on architecture ${arch}; only linux/amd64 is published." >&2; \
            exit 65; \
            ;; \
    esac

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install -y --no-install-recommends \
    ant \
    bison \
    clang \
    diffstat \
    flex \
    fontconfig \
    lcov \
    libasound2 \
    libclang-rt-dev \
    libfreetype6 \
    libmenhir-ocaml-dev \
    libparmap-ocaml-dev \
    libpcre-ocaml-dev \
    libpcre2-dev \
    libxi6 \
    libxrender1 \
    libxtst6 \
    lldb \
    ltrace \
    llvm \
    menhir \
    ninja-build \
    ocaml \
    ocaml-findlib \
    patch \
    pkg-config \
    python3-dev \
    strace \
    valgrind \
    zstd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# GitHub Copilot CLI. Claude Code is inherited from the canonical base stage.
COPY containers/npm/all-tools/package.json \
    containers/npm/all-tools/package-lock.json \
    /opt/raptor/npm/all-tools/
RUN npm ci --ignore-scripts --include=optional --omit=dev --no-audit --no-fund \
        --prefix /opt/raptor/npm/all-tools \
    && node -e "if (require('/opt/raptor/npm/all-tools/node_modules/@github/copilot/package.json').version !== '1.0.83') process.exit(1)" \
    && node -e "if (require('/opt/raptor/npm/all-tools/node_modules/detect-libc/package.json').version !== '2.1.2') process.exit(1)" \
    && ln -sf /opt/raptor/npm/all-tools/node_modules/.bin/copilot \
        /usr/local/bin/copilot

# Use the official CodeQL Action bundle, not the standalone CLI archive. The
# bundle carries the matching language query packs and is checksum-pinned.
RUN codeql_url="$(jq -er '.tools.codeql.url' /usr/local/share/raptor/all-tools-manifest.json)" \
    && codeql_sha256="$(jq -er '.tools.codeql.sha256' /usr/local/share/raptor/all-tools-manifest.json)" \
    && codeql_version="$(jq -er '.tools.codeql.version' /usr/local/share/raptor/all-tools-manifest.json)" \
    && curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
        "${codeql_url}" -o /tmp/codeql-bundle.tar.zst \
    && printf '%s  %s\n' "${codeql_sha256}" /tmp/codeql-bundle.tar.zst > /tmp/codeql.sha256 \
    && sha256sum -c /tmp/codeql.sha256 \
    && tar --no-same-owner --use-compress-program=unzstd \
        -xf /tmp/codeql-bundle.tar.zst -C /opt \
    && test -x /opt/codeql/codeql \
    && test -d /opt/codeql/qlpacks \
    && ln -s /opt/codeql/codeql /usr/local/bin/codeql \
    && printf 'CodeQL %s terms explicitly accepted at image build time.\n' \
        "${codeql_version}" > /opt/codeql/.raptor-terms-accepted \
    && rm -f /tmp/codeql-bundle.tar.zst /tmp/codeql.sha256

# Ghidra requires a JDK 21 runtime. Use upstream Temurin binaries on both
# supported container architectures instead of a distro JDK fallback.
RUN arch="$(dpkg --print-architecture)" \
    && case "${arch}" in \
        amd64) jdk_arch=x64; jdk_sha="${TEMURIN_AMD64_SHA256}" ;; \
        arm64) jdk_arch=aarch64; jdk_sha="${TEMURIN_ARM64_SHA256}" ;; \
        *) echo "Unsupported architecture for Temurin: ${arch}" >&2; exit 1 ;; \
    esac \
    && jdk_file="OpenJDK21U-jdk_${jdk_arch}_linux_hotspot_${TEMURIN_VERSION}.tar.gz" \
    && curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
        "https://github.com/adoptium/temurin21-binaries/releases/download/${TEMURIN_RELEASE}/${jdk_file}" \
        -o "/tmp/${jdk_file}" \
    && printf '%s  %s\n' "${jdk_sha}" "/tmp/${jdk_file}" > /tmp/temurin.sha256 \
    && sha256sum -c /tmp/temurin.sha256 \
    && mkdir -p /usr/lib/jvm/temurin-21-jdk \
    && tar --no-same-owner -xzf "/tmp/${jdk_file}" \
        -C /usr/lib/jvm/temurin-21-jdk --strip-components=1 \
    && ln -sf /usr/lib/jvm/temurin-21-jdk/bin/java /usr/local/bin/java \
    && ln -sf /usr/lib/jvm/temurin-21-jdk/bin/javac /usr/local/bin/javac \
    && rm -f "/tmp/${jdk_file}" /tmp/temurin.sha256

ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk

RUN ghidra_file="ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD_DATE}.zip" \
    && curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${ghidra_file}" \
        -o "/tmp/${ghidra_file}" \
    && printf '%s  %s\n' "${GHIDRA_SHA256}" "/tmp/${ghidra_file}" > /tmp/ghidra.sha256 \
    && sha256sum -c /tmp/ghidra.sha256 \
    && unzip -q "/tmp/${ghidra_file}" -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
    && ln -s /opt/ghidra/ghidraRun /usr/local/bin/ghidra \
    && ln -s /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless \
    && rm -f "/tmp/${ghidra_file}" /tmp/ghidra.sha256

# Current upstream Gradle is a fallback for targets without a wrapper.
RUN curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
        "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
        -o /tmp/gradle.zip \
    && printf '%s  %s\n' "${GRADLE_SHA256}" /tmp/gradle.zip > /tmp/gradle.sha256 \
    && sha256sum -c /tmp/gradle.sha256 \
    && unzip -q /tmp/gradle.zip -d /opt \
    && ln -s "/opt/gradle-${GRADLE_VERSION}" /opt/gradle \
    && ln -s /opt/gradle/bin/gradle /usr/local/bin/gradle \
    && rm -f /tmp/gradle.zip /tmp/gradle.sha256

RUN arch="$(dpkg --print-architecture)" \
    && case "${arch}" in \
        amd64) joern_arch=x86_64; joern_sha="${JOERN_AMD64_SHA256}" ;; \
        arm64) joern_arch=arm64; joern_sha="${JOERN_ARM64_SHA256}" ;; \
        *) echo "Unsupported architecture for Joern: ${arch}" >&2; exit 1 ;; \
    esac \
    && joern_file="joern-cli-linux-${joern_arch}.zip" \
    && curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
        "https://github.com/joernio/joern/releases/download/v${JOERN_VERSION}/${joern_file}" \
        -o "/tmp/${joern_file}" \
    && printf '%s  %s\n' "${joern_sha}" "/tmp/${joern_file}" > /tmp/joern.sha256 \
    && sha256sum -c /tmp/joern.sha256 \
    && mkdir -p /opt/joern \
    && unzip -q "/tmp/${joern_file}" -d /opt/joern \
    && for tool in \
        joern joern-export joern-flow joern-parse joern-scan joern-slice \
        c2cpg.sh ghidra2cpg javasrc2cpg jimple2cpg kotlin2cpg php2cpg \
        pysrc2cpg rubysrc2cpg; do \
        ln -s "/opt/joern/joern-cli/${tool}" "/usr/local/bin/${tool}"; \
    done \
    && chown -R vscode:vscode /opt/joern \
    && rm -f "/tmp/${joern_file}" /tmp/joern.sha256

# The archive contains gcloud, gsutil, and bq. It is installed without login
# state, ADC files, or any service-account material.
RUN arch="$(dpkg --print-architecture)" \
    && case "${arch}" in \
        amd64) gcloud_arch=x86_64; gcloud_sha="${GCLOUD_AMD64_SHA256}" ;; \
        arm64) gcloud_arch=arm; gcloud_sha="${GCLOUD_ARM64_SHA256}" ;; \
        *) echo "Unsupported architecture for Google Cloud CLI: ${arch}" >&2; exit 1 ;; \
    esac \
    && gcloud_file="google-cloud-cli-${GCLOUD_VERSION}-linux-${gcloud_arch}.tar.gz" \
    && curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
        "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/${gcloud_file}" \
        -o "/tmp/${gcloud_file}" \
    && printf '%s  %s\n' "${gcloud_sha}" "/tmp/${gcloud_file}" > /tmp/gcloud.sha256 \
    && sha256sum -c /tmp/gcloud.sha256 \
    && tar --no-same-owner -xzf "/tmp/${gcloud_file}" -C /opt \
    && ln -s /opt/google-cloud-sdk/bin/gcloud /usr/local/bin/gcloud \
    && ln -s /opt/google-cloud-sdk/bin/bq /usr/local/bin/bq \
    && ln -s /opt/google-cloud-sdk/bin/gsutil /usr/local/bin/gsutil \
    && rm -f "/tmp/${gcloud_file}" /tmp/gcloud.sha256

RUN /usr/local/libexec/raptor-install-all-tools-native

COPY containers/requirements-all-tools.lock /tmp/raptor/requirements-all-tools.lock

# The standard image uses z3 4.15. The all-tools variant deliberately
# replaces it with claripy's 4.13 pin so `import angr` works in RAPTOR's
# main interpreter and symbolic analysis is actually reachable. The final lock
# contains the complete post-override environment, including amd64-only Atheris.
RUN python3 -m pip install --no-cache-dir --no-build-isolation \
        --require-hashes --no-deps \
        -r /tmp/raptor/requirements-all-tools.lock \
    && python3 -c "import angr, z3; from importlib.metadata import version; assert version('z3-solver') == '4.13.0.0'; assert z3.get_version_string() == '4.13.0'" \
    && python3 -m pip check \
    && rm -rf /tmp/raptor

# Install the checksum-verified release archive directly. Unlike Ollama's convenience
# installer this neither probes the host GPU nor installs kernel drivers.
RUN arch="$(dpkg --print-architecture)" \
    && case "${arch}" in \
        amd64) ollama_arch=amd64; ollama_sha="${OLLAMA_AMD64_SHA256}" ;; \
        arm64) ollama_arch=arm64; ollama_sha="${OLLAMA_ARM64_SHA256}" ;; \
        *) echo "Unsupported architecture for Ollama: ${arch}" >&2; exit 1 ;; \
    esac \
    && ollama_file="ollama-linux-${ollama_arch}.tar.zst" \
    && curl -fL --retry 5 --retry-all-errors --retry-delay 2 \
        "https://github.com/ollama/ollama/releases/download/v${OLLAMA_VERSION}/${ollama_file}" \
        -o "/tmp/${ollama_file}" \
    && printf '%s  %s\n' "${ollama_sha}" "/tmp/${ollama_file}" > /tmp/ollama.sha256 \
    && sha256sum -c /tmp/ollama.sha256 \
    && tar --no-same-owner --use-compress-program=unzstd \
        -xf "/tmp/${ollama_file}" -C /usr/local \
    && test -x /usr/local/bin/ollama \
    && rm -rf /root/.ollama /home/vscode/.ollama \
    && rm -f "/tmp/${ollama_file}" /tmp/ollama.sha256

ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV JOERN_HOME=/opt/joern/joern-cli
ENV CLOUDSDK_ROOT_DIR=/opt/google-cloud-sdk
ENV CLOUDSDK_PYTHON=/usr/local/bin/python3
ENV CLOUDSDK_CORE_DISABLE_PROMPTS=1
ENV CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=1
ENV MAVEN_HOME=/opt/maven
ENV RUSTUP_HOME=/opt/rustup
ENV RAPTOR_ALL_TOOLS_MANIFEST=/usr/local/share/raptor/all-tools-manifest.json
ENV PWNLIB_NOTERM=1
ENV RAPTOR_ALL_TOOLS=1
ENV PATH="/usr/lib/jvm/temurin-21-jdk/bin:/usr/local/bin:/opt/cargo/bin:/usr/local/go/bin:/opt/maven/bin:/opt/gradle/bin:/opt/ghidra:/opt/ghidra/support:/opt/joern/joern-cli:/opt/google-cloud-sdk/bin:/opt/codeql:/workspaces/raptor/bin:${PATH}"

RUN raptor-verify-all-tools

USER vscode

RUN raptor-verify-all-tools --runtime-probes

CMD ["bash"]

# Runtime-only import path: packages/semgrep must not shadow the installed
# Semgrep distribution when the checkout is mounted.
FROM raptor-all-tools-build AS raptor-all-tools

ENV RAPTOR_DIR=/workspaces/raptor
ENV PYTHONPATH=/workspaces/raptor

CMD ["bash"]
