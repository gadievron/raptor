# RAPTOR Devcontainer
# Autonomous Offensive/Defensive Research Framework
#
# This container provides all dependencies for the RAPTOR security research framework.
# Based on comprehensive audit of all agents, commands, skills, and packages.

FROM mcr.microsoft.com/devcontainers/python:3-3.14-bookworm

# The base image's `node` devcontainer-feature install path added a stale
# yarn apt source (NO_PUBKEY 62D54FD4003F6525, breaks apt-get update) AND
# the yarn 1.x package itself (/usr/bin/yarn). Remove both so the later
# `npm install -g yarn@1.22.22` step doesn't collide on aarch64 builds.
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
# SEMGREP (static-analysis, scan, raptor-scan, agentic commands)
# ============================================================================

COPY --from=ghcr.io/astral-sh/uv:0.7 /uv /usr/local/bin/uv
COPY .devcontainer/install-python-notices.py /usr/local/libexec/install-python-notices.py
COPY .devcontainer/refresh-python-notices.py /usr/local/libexec/refresh-python-notices.py
COPY .devcontainer/opentelemetry-notices/ /usr/share/doc/raptor-opentelemetry-notices/
COPY .devcontainer/semgrep-notices/ /usr/share/doc/raptor-semgrep-notices/
RUN uv tool install --no-cache semgrep==1.177.0 \
    && /root/.local/share/uv/tools/semgrep/bin/python /usr/local/libexec/refresh-python-notices.py \
        --evidence-root /usr/share/doc --installed-environment \
        --if-version-changed \
    && /root/.local/share/uv/tools/semgrep/bin/python /usr/local/libexec/install-python-notices.py --skip-absent \
        --evidence /usr/share/doc/raptor-opentelemetry-notices \
    && /root/.local/share/uv/tools/semgrep/bin/python /usr/local/libexec/install-python-notices.py --skip-absent \
        --evidence /usr/share/doc/raptor-semgrep-notices

# ============================================================================
# RR DEBUGGER (rr-debugger skill, crash-analysis agents)
# Linux x86_64 only - provides deterministic record-replay debugging
# NOTE: Requires --privileged container flag and kernel parameter configuration
# ============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends rr=5.9.0-9 \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    || echo "rr not available on this architecture - skipping"

# Configure kernel for rr (automatically done in privileged container)
# If rr kernel config fails, run with devcontainer --privileged flag
RUN echo "# To enable rr, the devcontainer needs --privileged flag" \
    && echo "# Run: echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid" \
    && echo "# Or use devcontainer.json with: \"runArgs\": [\"--privileged\"]"

# ============================================================================
# AFL++ FUZZER (fuzzing package, fuzz/raptor-fuzz commands)
# ============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    afl++ \
    afl++-clang \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    || echo "AFL++ not available - skipping"

# ============================================================================
# CODEQL CLI — operator-side first-use installation, not bundled in the image
# Version, release asset sizes, and SHA-256 pins live in the JSON manifest.
# ============================================================================

COPY .devcontainer/codeql-bootstrap.py /usr/local/libexec/raptor-codeql-bootstrap
COPY .devcontainer/github-release-pins.json /usr/local/libexec/github-release-pins.json
RUN chmod 0755 /usr/local/libexec/raptor-codeql-bootstrap \
    && ln -s /usr/local/libexec/raptor-codeql-bootstrap /usr/local/bin/codeql

# ============================================================================
# PYTHON DEPENDENCIES
# ============================================================================

COPY pyproject.toml uv.lock /tmp/
COPY .devcontainer/python-notices/ /usr/share/doc/raptor-python-notices/

RUN bash -eo pipefail -c \
    'uv export --locked --no-hashes --project /tmp --extra web \
     | uv pip install --system --no-cache -r -' \
    && python3 /usr/local/libexec/refresh-python-notices.py \
        --evidence-root /usr/share/doc --installed-environment --if-version-changed \
    && python3 /usr/local/libexec/install-python-notices.py --skip-absent

# Retain the source-release notice omitted from pydocstyle's wheel.
# Reinstall the existing version so metadata and notice share this layer.
COPY .devcontainer/pydocstyle-notices/ /usr/share/doc/raptor-pydocstyle-notices/
RUN uv pip install --python /usr/local/py-utils/venvs/pydocstyle/bin/python \
        --no-cache --no-deps --reinstall --no-build pydocstyle==6.3.0 \
    && /usr/local/py-utils/venvs/pydocstyle/bin/python /usr/local/libexec/refresh-python-notices.py \
        --evidence-root /usr/share/doc --installed-environment --if-version-changed \
    && /usr/local/py-utils/venvs/pydocstyle/bin/python /usr/local/libexec/install-python-notices.py --skip-absent \
        --evidence /usr/share/doc/raptor-pydocstyle-notices

# Use Debian's unbranded Chromium and its package-maintained copyright inventory.
# Playwright's default download on amd64 is Google Chrome for Testing.
RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /root/.cache/ms-playwright

COPY .devcontainer/check-browser.py /usr/local/libexec/check-browser.py

# ============================================================================
# CLAUDE CLI (claude-code npm package)
# Required to run RAPTOR via bin/raptor
# ============================================================================

# Capture-then-execute the nodesource setup script so a curl failure isn't
# silently swallowed by the pipeline (curl | bash ignores curl's exit status).
# Node 24 is the current stable release, and is supported by the latest Claude CLI.
COPY .devcontainer/npm-notices/ /usr/share/doc/raptor-npm-notices/
COPY .devcontainer/corepack-notices/ /usr/share/doc/raptor-corepack-notices/
COPY .devcontainer/install-npm-notices.py /usr/local/libexec/install-npm-notices.py
COPY .devcontainer/refresh-npm-notices.py /usr/local/libexec/refresh-npm-notices.py

# Install upstream npm explicitly to retain its bundled dependency notices,
# which are omitted from the npm tree shipped in the NodeSource package.
RUN curl -fsSL https://deb.nodesource.com/setup_24.x -o /tmp/nodesource_setup.sh \
    && bash /tmp/nodesource_setup.sh \
    && rm /tmp/nodesource_setup.sh \
    && apt-get install -y --no-install-recommends nodejs=24.21.0-1nodesource1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && npm install -g --prefix /usr npm@11.19.0 --ignore-scripts --no-audit --no-fund \
    && python3 /usr/local/libexec/refresh-npm-notices.py \
        --package-root /usr/lib/node_modules/npm --evidence /usr/share/doc/raptor-npm-notices \
    && python3 /usr/local/libexec/install-npm-notices.py \
    && python3 /usr/local/libexec/refresh-npm-notices.py \
        --package-root /usr/lib/node_modules/corepack --evidence /usr/share/doc/raptor-corepack-notices \
    && python3 /usr/local/libexec/install-npm-notices.py \
        --package-root /usr/lib/node_modules/corepack \
        --evidence /usr/share/doc/raptor-corepack-notices \
    && npm install -g @anthropic-ai/claude-code@2.1.269

# ============================================================================
# JS PACKAGE MANAGERS (npm-managed yarn — apt source + package removed above)
# ============================================================================

COPY .devcontainer/pnpm-notices/ /usr/share/doc/raptor-pnpm-notices/
COPY .devcontainer/prune-linux-extras.py /usr/local/libexec/prune-linux-extras.py

RUN npm install -g yarn@1.22.22 pnpm@11.11.0 \
    && python3 /usr/local/libexec/prune-linux-extras.py \
        --pnpm-root /usr/lib/node_modules/pnpm --nvm-root /usr/local/share/nvm \
    && python3 /usr/local/libexec/refresh-npm-notices.py \
        --package-root /usr/lib/node_modules/pnpm --evidence /usr/share/doc/raptor-pnpm-notices \
    && python3 /usr/local/libexec/install-npm-notices.py \
        --package-root /usr/lib/node_modules/pnpm \
        --evidence /usr/share/doc/raptor-pnpm-notices

# Playwright supports a preinstalled Node. Share the runtime maintained for the CLI.
ENV PLAYWRIGHT_NODEJS_PATH=/usr/bin/node
COPY .devcontainer/use-system-node.py /usr/local/libexec/use-system-node.py
RUN python3 /usr/local/libexec/use-system-node.py

# Remove packaging helpers that can only run on Windows. Publication squashes
# all layers, including the base, so deleted executables are not distributed.
COPY .devcontainer/prune-windows-helpers.py /usr/local/libexec/prune-windows-helpers.py
RUN python3 /usr/local/libexec/prune-windows-helpers.py

# Retain version-matched release notices for tools outside package metadata.
COPY LICENSE /usr/share/doc/raptor/LICENSE
COPY .devcontainer/native_build_inventory.py /usr/local/libexec/native_build_inventory.py
COPY .devcontainer/cargo_notice_inventory.py /usr/local/libexec/cargo_notice_inventory.py
COPY .devcontainer/collect-native-notices.py /usr/local/libexec/collect-native-notices.py
RUN python3 /usr/local/libexec/collect-native-notices.py
COPY .devcontainer/collect-npm-native-notices.py /usr/local/libexec/collect-npm-native-notices.py
RUN python3 /usr/local/libexec/collect-npm-native-notices.py

# ============================================================================
# ENVIRONMENT CONFIGURATION
# ============================================================================

ENV PATH="/workspaces/raptor/bin:${PATH}"
ENV GIT_TERMINAL_PROMPT=0
ENV PYTHONUNBUFFERED=1
ENV RAPTOR_WEB_BROWSER_EXECUTABLE=/usr/bin/chromium
# Ensure python can import repo packages when container runs
# Adds repo root and `packages/` so `import core`, `import binary_analysis`, etc. work
ENV PYTHONPATH="/workspaces/raptor:/workspaces/raptor/packages"

# ============================================================================
# WORKSPACE
# ============================================================================

WORKDIR /workspaces/raptor

# ============================================================================
# RUNTIME USER
# ============================================================================
# Default to the non-root vscode user from the base image (UID 1000).
# vscode has passwordless sudo for tools that genuinely need root (e.g. rr in
# --privileged containers). All build steps above run as root by inheritance.
USER vscode

CMD ["bash"]
