# RAPTOR Devcontainer
# Autonomous Offensive/Defensive Research Framework
#
# This container provides all dependencies for the RAPTOR security research framework.
# Based on comprehensive audit of all agents, commands, skills, and packages.

FROM mcr.microsoft.com/devcontainers/python:1-3.12-bullseye

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
# ============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends rr \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    || echo "rr not available on this architecture - skipping"

# Configure kernel for rr (needs to be done at runtime with --privileged)
# echo 1 > /proc/sys/kernel/perf_event_paranoid

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
RUN pip install --no-cache-dir -r /tmp/requirements-dev.txt

# ============================================================================
# ENVIRONMENT CONFIGURATION
# ============================================================================

ENV PATH="/opt/codeql:${PATH}"
ENV GIT_TERMINAL_PROMPT=0
ENV PYTHONUNBUFFERED=1

# ============================================================================
# WORKSPACE
# ============================================================================

WORKDIR /workspaces/raptor
