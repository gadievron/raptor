# CI dependency image — the locked default development environment is baked in
# unit-test tiers skip the per-job venv build + artifact download. That
# fan-out (one venv download per tier × ~14 tiers) is what queues under
# a concurrent-runner cap; running the tiers inside this image removes
# it. Rebuilt by .github/workflows/ci-deps-image.yml whenever
# pyproject.toml and uv.lock (or this Dockerfile) change.
#
# Base pinned to bookworm to match the devcontainer
# (mcr.microsoft.com/devcontainers/python:3-3.14-bookworm, glibc 2.36)
# so platform-sensitive wheels resolve identically — notably z3-solver
# 4.15.4.0's manylinux_2_34 wheel (see the cap rationale in
# pyproject.toml). PYTHON_VERSION here must track tests.yml's
# env.PYTHON_VERSION (3.14).
FROM python:3.14.7-slim-bookworm

# OCI labels surface on the GHCR package page. `description` is the only
# per-package text GHCR renders (it has no per-image README upload — the
# package page otherwise shows the repo's main README), so use it to make
# clear this image is internal CI plumbing, not a RAPTOR distributable.
LABEL org.opencontainers.image.source="https://github.com/gadievron/raptor" \
      org.opencontainers.image.title="raptor-ci-deps" \
      org.opencontainers.image.description="RAPTOR INTERNAL CI build-cache image (GitHub Actions unit-test tiers). NOT a RAPTOR distributable or end-user artifact — do not pull or depend on this image."

# git is required by actions/checkout when this image is used as a
# container-job base — the slim base ships none, and checkout fails
# without it. coccinelle provides /usr/bin/spatch for the source_intel
# tier's real-spatch E2E tests. jq is required by the sage tier's
# boot-payload capture roundtrip tests (libexec/raptor-sage-setup's
# capture_boot_payload extracts the payload with jq; the tests skip
# without it). ca-certificates is already present in the slim image.
# Tiers that require heavier system tooling (sandbox namespaces,
# radare2/gcc) stay on the runner rather than bloating this image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git coccinelle jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/raptor-ci

# Copy only the manifests first so the dependency layer cache survives
# source-only changes to the repo.
COPY pyproject.toml uv.lock ./

ENV UV_PROJECT_ENVIRONMENT=/opt/raptor-ci/.venv
ENV VIRTUAL_ENV=/opt/raptor-ci/.venv
ENV PATH="/opt/raptor-ci/.venv/bin:${PATH}"

RUN pip install --no-cache-dir uv==0.12.6 \
    && uv sync --locked \
    && sha256sum pyproject.toml uv.lock > /etc/raptor-ci-deps.hash

# Build-time smoke import: fail the IMAGE build (not downstream CI) if a
# pinned dependency can't import on this base.
RUN python -c "import pytest, requests, pydantic, yaml, bs4, z3, defusedxml, packaging, tabulate, typer, instructor"
