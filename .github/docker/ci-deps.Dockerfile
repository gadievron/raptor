# CI dependency image — pyproject/poetry.lock plus the transitional
# requirements-dev.txt compatibility export baked in so the Python
# unit-test tiers skip the per-job venv build + artifact download. That
# fan-out (one venv download per tier × ~14 tiers) is what queues under
# a concurrent-runner cap; running the tiers inside this image removes
# it. Rebuilt by .github/workflows/ci-deps-image.yml whenever
# pyproject.toml, poetry.lock, requirements*.txt (or this Dockerfile) change.
#
# Base pinned to bookworm to match the devcontainer
# (mcr.microsoft.com/devcontainers/python:3-3.14-bookworm, glibc 2.36)
# so platform-sensitive wheels resolve identically — notably z3-solver
# 4.15.4.0's manylinux_2_34 wheel (see the cap rationale in
# poetry.lock / requirements-dev.txt). PYTHON_VERSION here must track tests.yml's
# env.PYTHON_VERSION (3.14).

# --- coccinelle build stage --------------------------------------------
# spatch is built from the pinned upstream release rather than apt'd,
# for two reasons that both broke the engine tier's rule tests:
#
#   1. Version floor. Debian bookworm ships coccinelle 1.1.1, below the
#      floor RAPTOR's rule-set is authored against
#      (packages/coccinelle/runner.py MIN_SPATCH_VERSION = 1.3 — the
#      prefix-attribute rules only parse from 1.3).
#   2. Python scripting init. Every shipped .cocci rule reports through
#      an @script:python finalizer. spatch resolves its scripting
#      interpreter at run time (pyml): with no baked path it takes the
#      first `python` on PATH — in this image /usr/local/bin/python
#      (3.14) — then dlopens that interpreter's libpython and fails on
#      a symbol removed in modern CPython
#      (_PyObject_NextNotImplemented), after which it soldiers on WITH
#      SCRIPTING DISABLED and exit code 0: every positive rule fixture
#      silently yields zero findings while negatives pass vacuously.
#
# So: build the pinned 1.3.0 (== MIN_SPATCH_VERSION) with
# --with-python=/usr/bin/python3 — an absolute interpreter path is used
# verbatim by pyml, immune to /usr/local PATH shadowing — and give the
# runtime stage Debian's python3 + libpython3.11 (the shared library is
# NOT in the python3 dependency closure and pyml dlopens it; without it
# scripting dies the same silent death). The runtime canary below fails
# the IMAGE build if any future base/toolchain drift reintroduces the
# silent-zero mode.
#
# Same base as the runtime stage, so the binary is compiled against the
# exact glibc it runs on. The OCaml build adds minutes on 4-vCPU runners
# (the image workflow's timeout is sized for it), weekly +
# on-manifest-change only (that workflow builds uncached anyway).
FROM python:3.14.7-slim-bookworm AS coccinelle-build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git ca-certificates ocaml ocaml-findlib make gcc \
        autoconf automake pkg-config patch python3 \
    && rm -rf /var/lib/apt/lists/*

# Pin by commit id, not tag name: tags are movable, git object ids are
# not. This is the commit the 1.3.0 tag pointed at when the pin was
# taken; a moved tag fails the build here.
RUN git clone --depth 1 --branch 1.3.0 \
        https://github.com/coccinelle/coccinelle /tmp/coccinelle \
    && test "$(git -C /tmp/coccinelle rev-parse HEAD)" \
        = "e1906ad639c5eeeba2521639998eafadf989b0ac"

RUN cd /tmp/coccinelle \
    && ./autogen \
    && ./configure --enable-python --with-python=/usr/bin/python3 \
        --prefix=/usr/local \
    && make -j"$(nproc)" \
    && make install DESTDIR=/tmp/coccinelle-dest

# --- runtime stage -----------------------------------------------------
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
# without it. jq is required by the sage tier's boot-payload capture
# roundtrip tests (libexec/raptor-sage-setup's capture_boot_payload
# extracts the payload with jq; the tests skip without it).
# python3 + libpython3.11 are spatch's scripting runtime (see the build
# stage: the interpreter path is baked, and the shared library must be
# installed explicitly — it is not pulled in by python3).
# ca-certificates is already present in the slim image. Tiers that
# require heavier system tooling (sandbox namespaces, radare2/gcc) stay
# on the runner rather than bloating this image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git jq python3 libpython3.11 \
    && rm -rf /var/lib/apt/lists/*

# spatch for the engine tier's per-rule fixture tests and the
# source_intel tier's real-spatch E2E tests. The binary is standalone
# (libc/libm only); lib/coccinelle carries standard.h/.iso and the
# coccilib python package spatch injects into script rules.
COPY --from=coccinelle-build /tmp/coccinelle-dest/usr/local/bin/spatch /usr/local/bin/spatch
COPY --from=coccinelle-build /tmp/coccinelle-dest/usr/local/lib/coccinelle/ /usr/local/lib/coccinelle/

# Build-time scripting canary: fail the IMAGE build (not downstream CI)
# unless spatch both matches AND reports through @script:python — the
# breakage mode this stage exists to prevent is spatch dropping python
# scripting at init and still exiting 0, which turns every rule's
# positive fixtures into silent zero-finding runs.
RUN set -eux; \
    printf '%s\n' \
        '@r@' \
        'position p;' \
        '@@' \
        'chroot(...)@p;' \
        '' \
        '@script:python depends on r@' \
        'p << r.p;' \
        '@@' \
        'print("COCCIRESULT:canary")' \
        > /tmp/canary.cocci; \
    printf 'int main(void)\n{\n    chroot("/jail");\n    return 0;\n}\n' \
        > /tmp/canary.c; \
    spatch --version; \
    spatch --sp-file /tmp/canary.cocci /tmp/canary.c --no-show-diff \
        | grep -qx 'COCCIRESULT:canary'; \
    rm -f /tmp/canary.cocci /tmp/canary.c

WORKDIR /opt/raptor-ci

# Copy only the manifests first so the dependency layer cache survives
# source-only changes to the repo.
COPY pyproject.toml poetry.lock requirements.txt requirements-dev.txt ./

RUN pip install --no-cache-dir -r requirements-dev.txt \
    && sha256sum requirements.txt requirements-dev.txt > /etc/raptor-ci-deps.hash

# Build-time smoke import: fail the IMAGE build (not downstream CI) if a
# pinned dependency can't import on this base.
RUN python -c "import pytest, requests, pydantic, yaml, bs4, z3, defusedxml, packaging, tabulate, typer, instructor"
