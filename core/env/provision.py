"""provision(spec) → a live, verified Environment.

The one entry point RAPTOR consumers call: hand in an
:class:`~core.env.spec.EnvironmentSpec`, get back a running instance
behind a :class:`~core.env.handle.RuntimeHandle` with the spec's verify
plan already adjudicated. The image is ALWAYS produced through the
docker toolchain (that is the product deliverable); the runtime is a
choice — ``runtime="docker"`` (default, product tier) runs it under
the host daemon with a published loopback port, ``runtime="sandbox"``
(witness tier) exports the image to a rootfs and runs it under the
RAPTOR sandbox.

Source kinds covered here: ``image`` (digest-pinned ref) and
``dockerfile`` (text built into a local image). ``compose`` stacks and
``repo`` source builds keep richer flows in their existing surfaces
(:mod:`core.container.compose`, cve-env's source_build planner) — a
spec of those kinds is refused with a clear reason rather than
half-provisioned.
"""

from __future__ import annotations

import logging
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.container.build import build_image
from core.container.containers import launch_container
from core.container.export import export_rootfs
from core.container.lifecycle import (
    remove_labeled_containers,
    remove_labeled_images,
)
from core.env.handle import DockerHandle, RuntimeHandle, SandboxHandle
from core.env.spec import EnvironmentSpec
from core.env.store import save_run_spec
from core.env.verify import VerifyHooks, verify_plan

logger = logging.getLogger(__name__)

#: Ownership label every provisioned artifact carries; the value is the
#: per-provision nonce so cleanup is exact-scope.
OWNER_LABEL = "raptor-env.id"


@dataclass
class Environment:
    """A provisioned, possibly-verified environment instance."""

    spec: EnvironmentSpec
    handle: RuntimeHandle
    image_ref: str
    provision_id: str
    verify_result: dict[str, Any] | None = None

    @property
    def tier(self) -> str:
        return self.handle.tier

    def verified(self) -> bool:
        return bool(self.verify_result and self.verify_result.get("passed"))

    def teardown(self) -> None:
        """Tear down the instance and remove provision-scoped artifacts."""
        self.handle.teardown()
        remove_labeled_containers(OWNER_LABEL, self.provision_id)
        remove_labeled_images(OWNER_LABEL, self.provision_id)


@dataclass
class ProvisionOutcome:
    ok: bool
    environment: Environment | None = None
    reason: str = ""  # "" | unsupported_source | build_failed |
    #                   launch_failed | export_failed | verify_failed
    reason_class: str = "ok"
    detail: str = ""
    extras: dict[str, Any] = field(default_factory=dict)


def provision(
    spec: EnvironmentSpec,
    *,
    runtime: str = "docker",
    verify: bool = True,
    fail_on_verify: bool = True,
    output_dir: str | Path | None = None,
    workdir: str | Path | None = None,
    hooks: VerifyHooks | None = None,
) -> ProvisionOutcome:
    """Provision ``spec`` on the chosen runtime and adjudicate its plan.

    ``verify=True`` runs the spec's verify plan through the handle
    (version literal = ``spec.version``); with ``fail_on_verify`` the
    instance is torn down and the outcome reports ``verify_failed``,
    otherwise the environment is returned with ``verify_result``
    attached for the caller to weigh. ``output_dir`` (a run directory)
    receives the run-local ``environment-spec.json``. ``workdir`` hosts
    build contexts and exported rootfs trees (a private tmpdir when
    omitted).
    """
    if runtime not in ("docker", "sandbox"):
        raise ValueError(f"unknown runtime {runtime!r}")
    provision_id = uuid.uuid4().hex[:12]
    labels = {OWNER_LABEL: provision_id}
    work = Path(workdir) if workdir else Path(
        tempfile.mkdtemp(prefix="raptor-env-"))

    # 1. Materialize an image ref.
    kind = spec.source.kind
    if kind == "image":
        image_ref = spec.source.image_ref
        if not image_ref:
            return ProvisionOutcome(
                ok=False, reason="unsupported_source", reason_class="unknown",
                detail="source.kind=image requires source.image_ref",
            )
    elif kind == "dockerfile":
        if not spec.source.dockerfile:
            return ProvisionOutcome(
                ok=False, reason="unsupported_source", reason_class="unknown",
                detail="source.kind=dockerfile requires source.dockerfile",
            )
        image_ref = f"raptor-env-local:{provision_id}"
        ctx = work / "build-context"
        ctx.mkdir(parents=True, exist_ok=True)
        built = build_image(
            context_dir=str(ctx),
            tag=image_ref,
            dockerfile_text=spec.source.dockerfile,
            labels=labels,
        )
        if not built.ok:
            return ProvisionOutcome(
                ok=False, reason="build_failed",
                reason_class=built.reason_class,
                detail=built.stderr_tail[-1000:],
            )
    else:
        return ProvisionOutcome(
            ok=False, reason="unsupported_source", reason_class="unknown",
            detail=(
                f"source.kind={kind!r} is not provisioned here — compose "
                "stacks go through core.container.compose; repo source "
                "builds keep their planner surface"
            ),
        )

    # 2. Instantiate the runtime.
    handle: RuntimeHandle
    if runtime == "docker":
        launch = launch_container(
            image=image_ref,
            container_port=spec.run.port or 80,
            name_prefix="raptor-env",
            labels=labels,
            env=spec.run.env_dict() or None,
            local_prefixes=("raptor-env-local",),
        )
        if not launch.ok:
            return ProvisionOutcome(
                ok=False, reason="launch_failed",
                reason_class=launch.reason_class,
                detail=launch.stderr[-1000:],
            )
        handle = DockerHandle(
            launch.container_id,
            host_ip=launch.host_ip,
            host_port=launch.host_port,
            owner_label=(OWNER_LABEL, provision_id),
        )
    else:  # sandbox
        rootfs = work / "rootfs"
        exported = export_rootfs(image_ref, rootfs)
        if not exported.ok:
            return ProvisionOutcome(
                ok=False, reason="export_failed",
                reason_class=exported.reason_class,
                detail=exported.stderr[-1000:],
            )
        cfg = exported.config
        env = dict(spec.run.env_dict())
        if cfg is not None:
            for pair in cfg.env:
                key, _, value = pair.partition("=")
                env.setdefault(key, value)
        handle = SandboxHandle(
            rootfs,
            env=env or None,
            workdir=(spec.run.workdir
                     or (cfg.workdir if cfg is not None else "")),
        )

    environment = Environment(
        spec=spec,
        handle=handle,
        image_ref=image_ref,
        provision_id=provision_id,
    )

    # 3. Adjudicate the spec's verify plan.
    if verify and spec.verify_plan:
        result = verify_plan(
            handle,
            spec.verify_plan,
            version_literal=spec.version,
            hooks=hooks or VerifyHooks(),
        )
        environment.verify_result = result
        if not result.get("passed") and fail_on_verify:
            environment.teardown()
            return ProvisionOutcome(
                ok=False, reason="verify_failed", reason_class="unknown",
                detail=str(result.get("reason") or ""),
                extras={"verify_result": result},
            )

    if output_dir is not None:
        try:
            save_run_spec(spec, output_dir)
        except OSError as exc:  # spec record is evidence, not the result
            logger.warning("could not write run-local spec: %s", exc)

    return ProvisionOutcome(ok=True, environment=environment)
