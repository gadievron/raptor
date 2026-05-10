# ZKPoX Phase 0 — reproducible bench environment.
#
# Purpose: produce numbers that can be compared apples-to-apples with
# whatever GitHub Actions ubuntu-latest runs in CI. Mac numbers in
# zkpox-phase0-findings.md are the conservative anchor; this image's
# numbers are the realistic CI floor.
#
# Style mirrors .devcontainer/Dockerfile (sectioned, version-pinned,
# apt-list cleanup after each install). Pins below match versions.txt.
#
# Build:
#   docker build -t zkpox-phase0 docs/research/zkpox-phase0/
#
# Bench inside the container (mount the repo so the harness sources are visible):
#   docker run --rm -v "$PWD:/work" -w /work/docs/research/zkpox-phase0 \
#       zkpox-phase0 bash -lc 'cargo prove --version && ./run-tests.sh'

# Pin platform: SP1 ships an x86_64 cargo-prove binary; ubuntu:24.04 on
# Apple Silicon would otherwise pull arm64 and sp1up would fail. CI
# (GitHub Actions ubuntu-latest) is amd64 anyway, so this also keeps
# image numbers comparable across hosts.
FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

# ============================================================================
# SYSTEM DEPENDENCIES
# ============================================================================
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        # Core tools
        ca-certificates curl wget jq unzip xz-utils \
        # VCS / scripts
        git bash \
        # C build (for native sanity check) and RISC-V cross-compile via clang
        build-essential \
        # LLVM with RISC-V backend (Ubuntu 24.04 ships LLVM 18 by default)
        clang llvm \
        # Python (witness generator + bench scripts)
        python3 python3-pip \
        # libssl/libcurl/pkg-config required by various Rust crates we transit
        libssl-dev pkg-config \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ============================================================================
# AGE — vendor-key encryption layer for the disclosure envelope (Task 7)
# Comes from Ubuntu's repos in 24.04+; pinned via the manifest.
# ============================================================================
RUN apt-get update && apt-get install -y --no-install-recommends age \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ============================================================================
# GO — required by sp1-recursion-gnark-ffi for the Groth16 proof wrap
# Phase 0 doesn't generate Groth16 wraps yet, but pulling go now keeps
# the image in sync with what versions.txt records and avoids a second
# install when the wrap step lands in Phase 1.
# ============================================================================
ARG GO_VERSION=1.26.3
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:${PATH}"

# ============================================================================
# RUST — pinned to the same channel as the Mac bench host
# rustup is installed system-wide so non-root users don't need their own copy.
# ============================================================================
ARG RUST_VERSION=1.95.0
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
ENV PATH="/usr/local/cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --default-toolchain "${RUST_VERSION}" --profile minimal \
    && chmod -R a+w /usr/local/rustup /usr/local/cargo

# ============================================================================
# SP1 — `cargo-prove` plus the custom `succinct` rustup toolchain
# Pinned to v6.1.0 to match versions.txt; sp1up downloads the Linux x86_64
# binary by default, which is what GitHub Actions ubuntu-latest also gets.
# ============================================================================
ARG SP1_VERSION=v6.1.0
RUN curl -fsSL https://sp1up.succinct.xyz | bash \
    && /root/.sp1/bin/sp1up --version "${SP1_VERSION#v}" \
    && cp -r /root/.sp1 /opt/sp1 \
    && chmod -R a+rx /opt/sp1
ENV PATH="/opt/sp1/bin:${PATH}"

# ============================================================================
# PYTHON DEPS — keep light; only what the Phase-0 scripts need.
# tlock-rs is invoked as a binary, not a Python package, so no Python ZK deps.
# ============================================================================
RUN pip3 install --no-cache-dir --break-system-packages \
        pynacl

# ============================================================================
# WORKSPACE
# ============================================================================
WORKDIR /work

# Smoke test — assert toolchain availability at image build time so a
# broken pin trips here, not during bench.
RUN rustc --version \
    && cargo --version \
    && cargo prove --version \
    && clang --version | head -2 \
    && age --version \
    && go version
