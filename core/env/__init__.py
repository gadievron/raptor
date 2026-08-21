"""Environment provisioning API: specs, runtime handles, verification.

RAPTOR consumers (/validate reproduction builds, /fuzz instrumented
builds, /crash-analysis recipe variants, the cve-env facade) need the
same thing: *a running instance of specific software at a specific
version, with evidence that it is the right software and that it
works*. This package is that capability, decomposed as:

  * :mod:`core.env.spec` — ``EnvironmentSpec``: the declarative
    description (source, version pin, build/toolchain variant, run
    surface, network policy, verify plan, oracle markers).
  * :mod:`core.env.store` — the disk-first spec store
    (``environment-spec.json``): a verified build writes the spec that
    produced it; a later run re-provisions from it.
  * :mod:`core.env.handle` — ``RuntimeHandle``: the one seam between
    "an environment exists" and "where it runs". ``DockerHandle`` is
    the product tier (a compatible docker image/container, the original
    cve-env deliverable); the sandbox tier (first-class observability:
    witness outcomes, syscall traces, mechanical egress containment)
    plugs in behind the same five methods.
  * :mod:`core.env.verify` — the environment oracle: the check DAG
    (status / http / logs / stability / exec / http-request / tcp)
    executed through a ``RuntimeHandle``, with plan canonicalization,
    LLM-alias normalization, and the version-assertion / functional-
    smoke injectors.

Policy boundary: same as ``core.container`` — no operator printing, no
LLM-facing hint text baked in (hint/sanitize hooks are caller-supplied),
no cross-call state.
"""

from core.env.handle import (
    DockerHandle,
    RuntimeHandle,
    SandboxHandle,
    sandbox_rootfs_supported,
)

__all__ = [
    "DockerHandle",
    "RuntimeHandle",
    "SandboxHandle",
    "sandbox_rootfs_supported",
]
