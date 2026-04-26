# RAPTOR Devcontainer
# Autonomous Offensive/Defensive Research Framework
#
# This container provides all dependencies for the RAPTOR security research framework.
# Based on comprehensive audit of all agents, commands, skills, and packages.

FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

# The base image ships a stale yarn apt source without its GPG key,
# which breaks apt-get update (NO_PUBKEY 62D54FD4003F6525).
RUN rm -f /etc/apt/sources.list.d/yarn.list

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
    # --- Network Tools (web package, github-forensics skills) ---
    curl \
    wget \
    #
    # --- rr Debugger Dependencies (crash-analysis agents - Linux x86_64 only) ---
    # rr itself installed separately below
    libcapnp-dev \
    #
    # --- Playwright / Browser dependencies (for packages/web playwright support) ---
    fonts-liberation \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libc6 \
    libcairo2 \
    libcap2 \
    libcups2 \
    libdbus-1-3 \
    libexpat1 \
    libfontconfig1 \
    libgcc1 \
    libgconf-2-4 \
    libgdk-pixbuf2.0-0 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxrender1 \
    libxss1 \
    libxtst6 \
    lsb-release \
    ca-certificates \
    # --- Misc ---
    jq \
    unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# SEMGREP (static-analysis, scan, raptor-scan, agentic commands)
# ============================================================================

RUN pip install --no-cache-dir semgrep

# ============================================================================
# RR DEBUGGER (rr-debugger skill, crash-analysis agents)
# Linux x86_64 only - provides deterministic record-replay debugging
# NOTE: Requires --privileged container flag and kernel parameter configuration
# ============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends rr \
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
# CODEQL CLI (codeql package, codeql command)
# Downloaded from GitHub releases
# ============================================================================

ARG CODEQL_VERSION=2.15.5
RUN mkdir -p /opt/codeql \
    && curl -L "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" -o /tmp/codeql.zip \
    && unzip /tmp/codeql.zip -d /opt \
    && rm /tmp/codeql.zip \
    && ln -s /opt/codeql/codeql /usr/local/bin/codeql

# ============================================================================
# PYTHON DEPENDENCIES
# ============================================================================

COPY requirements.txt requirements-dev.txt /tmp/
# Also copy package-specific requirements so they can be installed explicitly if desired
COPY packages/web/requirements.txt /tmp/packages-web-requirements.txt

RUN pip install --no-cache-dir -r /tmp/requirements-dev.txt

# Install web package dependencies (includes playwright)
RUN pip install --no-cache-dir -r /tmp/packages-web-requirements.txt

# Install Playwright browser binaries
RUN python -m playwright install

# ============================================================================
# CLAUDE CLI (claude-code npm package)
# Required to run RAPTOR via bin/raptor
# ============================================================================

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && npm install -g @anthropic-ai/claude-code

# ============================================================================
# JS PACKAGE MANAGERS (yarn replaced apt source removed above)
# ============================================================================

RUN npm install -g yarn pnpm

# ============================================================================
# ENVIRONMENT CONFIGURATION
# ============================================================================

ENV PATH="/opt/codeql:${PATH}"
ENV GIT_TERMINAL_PROMPT=0
ENV PYTHONUNBUFFERED=1
# Ensure python can import repo packages when container runs
# Adds repo root and `packages/` so `import core`, `import binary_analysis`, etc. work
ENV PYTHONPATH="/workspaces/raptor:/workspaces/raptor/packages:${PYTHONPATH}"

# ============================================================================
# WORKSPACE
# ============================================================================

WORKDIR /workspaces/raptor
