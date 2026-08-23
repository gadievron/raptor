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
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.container.build import build_image
from core.container.containers import create_internal_network, launch_container
from core.container.export import export_rootfs
from core.container.lifecycle import (
    remove_labeled_containers,
    remove_labeled_images,
    remove_labeled_networks,
)
from core.env.handle import DockerHandle, RuntimeHandle, SandboxHandle
from core.env.store import save_run_spec
from core.env.verify import VerifyHooks, verify_plan
from core.run.scratch import keepalive_register, keepalive_unregister

if TYPE_CHECKING:
    from core.env.spec import EnvironmentSpec

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
    #: Work dir the provisioner created itself (mkdtemp) — removed at
    #: teardown. None when the caller supplied ``workdir`` (caller owns it).
    owned_workdir: Path | None = None

    @property
    def tier(self) -> str:
        return self.handle.tier

    def verified(self) -> bool:
        return bool(self.verify_result and self.verify_result.get("passed"))

    def teardown(self) -> None:
        """Tear down the instance and remove provision-scoped artifacts."""
        self.handle.teardown()
        remove_labeled_containers(OWNER_LABEL, self.provision_id)
        remove_labeled_networks(OWNER_LABEL, self.provision_id)
        remove_labeled_images(OWNER_LABEL, self.provision_id)
        if self.owned_workdir is not None:
            keepalive_unregister(self.owned_workdir)
            shutil.rmtree(self.owned_workdir, ignore_errors=True)


@dataclass
class ProvisionOutcome:
    ok: bool
    environment: Environment | None = None
    reason: str = ""  # "" | unsupported_source | unsupported_network_policy |
    #                   build_failed | network_failed | launch_failed |
    #                   export_failed | verify_failed
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

    The spec's :class:`~core.env.spec.NetworkPolicy` is enforced on
    the docker runtime: ``mode="isolated"`` (default) launches on a
    per-provision ``--internal`` network, with the endpoint at the
    container's own network address — no LAN / metadata / Internet /
    cross-network reach, though the host's bridge gateway address
    remains reachable (see the NetworkPolicy docstring for the exact
    residual); ``mode="unrestricted"`` uses the default bridge with a
    published loopback port. Non-empty ``egress_hosts`` and unknown modes are
    refused (``unsupported_network_policy``) — there is no host-scoped
    enforcement mechanism yet, and silently granting broader access
    would falsify the declared policy. The sandbox runtime blocks
    network regardless.

    ``verify=True`` runs the spec's verify plan through the handle
    (version literal = ``spec.version``); with ``fail_on_verify`` the
    instance is torn down and the outcome reports ``verify_failed``,
    otherwise the environment is returned with ``verify_result``
    attached for the caller to weigh. ``output_dir`` (a run directory)
    receives the run-local ``environment-spec.json``. ``workdir`` hosts
    build contexts and exported rootfs trees; when omitted a private
    tmpdir is created, owned by the provisioner — removed on every
    failure path and by ``Environment.teardown()``. Failure outcomes
    never leak artifacts: provision-labeled containers/images and the
    owned work dir are cleaned up before returning.
    """
    if runtime not in ("docker", "sandbox"):
        msg = f"unknown runtime {runtime!r}"
        raise ValueError(msg)

    # 0. Pure validation — refuse before creating any artifact so the
    # refusal paths have nothing to clean up.
    kind = spec.source.kind
    if kind == "image":
        if not spec.source.image_ref:
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
    else:
        return ProvisionOutcome(
            ok=False, reason="unsupported_source", reason_class="unknown",
            detail=(
                f"source.kind={kind!r} is not provisioned here — compose "
                "stacks go through core.container.compose; repo source "
                "builds keep their planner surface"
            ),
        )
    net_mode = spec.network.mode
    if net_mode not in ("isolated", "unrestricted"):
        return ProvisionOutcome(
            ok=False, reason="unsupported_network_policy",
            reason_class="unknown",
            detail=(
                f"network.mode={net_mode!r} is not supported "
                "(isolated | unrestricted)"
            ),
        )
    if spec.network.egress_hosts:
        return ProvisionOutcome(
            ok=False, reason="unsupported_network_policy",
            reason_class="unknown",
            detail=(
                "host-scoped egress_hosts enforcement is not implemented "
                "on any runtime — drop egress_hosts (isolated = no "
                "egress), or declare network.mode='unrestricted' "
                "explicitly if the environment genuinely needs egress"
            ),
        )

    provision_id = uuid.uuid4().hex[:12]
    labels = {OWNER_LABEL: provision_id}
    created_work = workdir is None
    # Hand-rolled (not scratch_dir): ownership transfers to the
    # Environment (removed at teardown / provision failure), outliving
    # this function. The raptor-env- prefix is listed in
    # core.run.tmp_reaper's static tuple, so a SIGKILLed provision
    # strands nothing past the age floor — and the keepalive below is
    # what makes that listing safe: a live environment's work dir can
    # sit mtime-quiet for days (a sandbox rootfs's mtime froze at
    # export), so the owner refreshes it until teardown.
    work = Path(workdir) if workdir else Path(
        tempfile.mkdtemp(prefix="raptor-env-"))
    if created_work:
        keepalive_register(work)

    def _fail(**kw: Any) -> ProvisionOutcome:
        """Failure outcome + exact-scope cleanup. A launch that failed
        AFTER ``docker run`` succeeded (e.g. ``no_host_port``) leaves a
        RUNNING container behind; every provision-labeled artifact is
        removed here, along with the provisioner-owned work dir."""
        remove_labeled_containers(OWNER_LABEL, provision_id)
        remove_labeled_networks(OWNER_LABEL, provision_id)
        remove_labeled_images(OWNER_LABEL, provision_id)
        if created_work:
            keepalive_unregister(work)
            shutil.rmtree(work, ignore_errors=True)
        return ProvisionOutcome(ok=False, **kw)

    # 1. Materialize an image ref.
    if kind == "image":
        image_ref = spec.source.image_ref
    else:  # dockerfile
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
            return _fail(
                reason="build_failed",
                reason_class=built.reason_class,
                detail=built.stderr_tail[-1000:],
            )

    # 2. Instantiate the runtime.
    handle: RuntimeHandle
    if runtime == "docker":
        # Thread the spec's network policy to the daemon: isolated =
        # a per-provision --internal network (no egress; the endpoint
        # is the container's own address on it), unrestricted = the
        # default bridge with a published loopback port.
        network_name: str | None = None
        if net_mode == "isolated":
            network_name = f"raptor-env-net-{provision_id}"
            # Predictable host-side bridge name (rpenv-<id>, IFNAMSIZ-
            # bounded): one static operator-installed INPUT rule on the
            # rpenv-+ interface prefix then closes the container->
            # host-gateway residual for every provision, past and
            # future — no per-provision firewall authority needed (see
            # docs/cve-env.md, "Closing the host-gateway residual").
            net_ok, net_err = create_internal_network(
                network_name, labels=labels,
                bridge_name=f"rpenv-{provision_id[:9]}")
            if not net_ok:
                return _fail(
                    reason="network_failed", reason_class="unknown",
                    detail=net_err,
                )
        launch = launch_container(
            image=image_ref,
            container_port=spec.run.port or 80,
            name_prefix="raptor-env",
            labels=labels,
            env=spec.run.env_dict() or None,
            local_prefixes=("raptor-env-local",),
            network=network_name,
            publish=(net_mode != "isolated"),
        )
        if not launch.ok:
            return _fail(
                reason="launch_failed",
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
            return _fail(
                reason="export_failed",
                reason_class=exported.reason_class,
                detail=exported.stderr[-1000:],
            )
        cfg = exported.config
        env = dict(spec.run.env_dict())
        if cfg is not None:
            for pair in cfg.env:
                key, _, value = pair.partition("=")
                env.setdefault(key, value)
        try:
            handle = SandboxHandle(
                rootfs,
                env=env or None,
                workdir=(spec.run.workdir
                         or (cfg.workdir if cfg is not None else "")),
            )
        except (RuntimeError, ValueError) as exc:
            # "failures are data": the rootfs-mode preflight refusing is
            # a launch failure, and the exported tree must not leak.
            return _fail(
                reason="launch_failed", reason_class="unknown",
                detail=str(exc)[:1000],
            )

    environment = Environment(
        spec=spec,
        handle=handle,
        image_ref=image_ref,
        provision_id=provision_id,
        owned_workdir=(work if created_work else None),
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
            environment.teardown()  # also removes the owned work dir
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
