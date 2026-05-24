# CI dependency image — requirements-dev.txt baked in so the Python
# unit-test tiers skip the per-job venv build + artifact download. That
# fan-out (one venv download per tier × ~14 tiers) is what queues under
# a concurrent-runner cap; running the tiers inside this image removes
# it. Rebuilt by .github/workflows/ci-deps-image.yml whenever
# requirements*.txt (or this Dockerfile) change.
#
# Base pinned to bookworm to match the devcontainer
# (mcr.microsoft.com/devcontainers/python:1-3.12-bookworm, glibc 2.36)
# so platform-sensitive wheels resolve identically — notably z3-solver
# 4.15.4.0's manylinux_2_34 wheel (see the cap rationale in
# requirements-dev.txt). PYTHON_VERSION here must track tests.yml's
# env.PYTHON_VERSION (3.12).
FROM python:3.12-slim-bookworm

# git is required by actions/checkout when this image is used as a
# container-job base — the slim base ships none, and checkout fails
# without it. ca-certificates is already present in the slim image.
# Kept to the single tool checkout needs; tiers that require heavier
# system tooling (sandbox namespaces, radare2/gcc) stay on the runner
# rather than bloating this image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/raptor-ci

# Copy only the manifests first so the dependency layer cache survives
# source-only changes to the repo.
COPY requirements.txt requirements-dev.txt ./

RUN pip install --no-cache-dir -r requirements-dev.txt

# Build-time smoke import: fail the IMAGE build (not downstream CI) if a
# pinned dependency can't import on this base.
RUN python -c "import pytest, requests, pydantic, yaml, bs4, z3, defusedxml, packaging, tabulate, typer, instructor"
