"""EnvironmentSpec — the declarative description of an environment.

A spec answers, in one JSON-serializable object, everything a
provisioner needs: WHERE the software comes from (a digest-pinned
image, a Dockerfile, a compose stack, or a source repo at a ref), WHAT
version it must be, HOW to build it (including the toolchain variant —
compiler, injected flags, instrumentation, debug info — so consumers
can rebuild the same environment with a mitigation matrix or coverage
instrumentation), HOW it runs (surface, port, env), what it may reach
(egress policy), and HOW to prove it is right (a verify plan for the
:mod:`core.env.verify` engine, plus free-form oracle markers).

Serialization is additive-tolerant both ways: ``from_dict`` ignores
unknown keys (a newer writer's spec still loads) and ``to_dict`` emits
only the current schema. ``spec_version`` records the writer's schema
generation for future migrations.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

SPEC_VERSION = 1

SourceKind = Literal["image", "dockerfile", "compose", "repo"]
RunSurface = Literal["http", "tcp", "stdin", "none"]


def _known(cls: type, data: dict[str, Any]) -> dict[str, Any]:
    """Filter ``data`` to the dataclass's fields (additive tolerance)."""
    names = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
    return {k: v for k, v in data.items() if k in names}


@dataclass(frozen=True)
class SourceSpec:
    """Where the software comes from. One kind, one populated group."""

    kind: SourceKind = "image"
    image_ref: str = ""      # kind=image — digest-pinned preferred
    dockerfile: str = ""     # kind=dockerfile — full Dockerfile text
    compose: str = ""        # kind=compose — compose YAML text
    repo_url: str = ""       # kind=repo
    ref: str = ""            # kind=repo — tag / sha / branch

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SourceSpec":
        return cls(**_known(cls, data))


@dataclass(frozen=True)
class ToolchainSpec:
    """Recorded toolchain identity for reproducible / variant rebuilds.

    Consumers rebuild the SAME environment with a different variant:
    a mitigation matrix (injected CFLAGS/LDFLAGS), sanitizer or
    coverage instrumentation, or debug info for binary-oracle joins.
    Recording the identity is what makes ``rebuild_same_toolchain``
    meaningful — pad/offset resolution downstream depends on the
    original compiler, not just the source version.
    """

    cc: str = ""
    cflags: tuple[str, ...] = ()
    ldflags: tuple[str, ...] = ()
    instrumentation: tuple[str, ...] = ()  # e.g. ("asan",), ("coverage",)
    debug: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolchainSpec":
        d = _known(cls, data)
        for key in ("cflags", "ldflags", "instrumentation"):
            if key in d and isinstance(d[key], list):
                d[key] = tuple(d[key])
        return cls(**d)


@dataclass(frozen=True)
class BuildSpec:
    """How to build. Empty ``command`` = buildless (image runs as-is)."""

    command: str = ""
    workdir: str = ""
    toolchain: ToolchainSpec | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BuildSpec":
        d = _known(cls, data)
        tc = d.get("toolchain")
        if isinstance(tc, dict):
            d["toolchain"] = ToolchainSpec.from_dict(tc)
        return cls(**d)


@dataclass(frozen=True)
class RunSpec:
    """How the environment runs and is reached."""

    surface: RunSurface = "http"
    port: int = 0                     # container-side service port
    env: tuple[tuple[str, str], ...] = ()
    entrypoint: tuple[str, ...] = ()  # override; () = image default
    workdir: str = ""

    def env_dict(self) -> dict[str, str]:
        return dict(self.env)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RunSpec":
        d = _known(cls, data)
        if isinstance(d.get("env"), dict):
            d["env"] = tuple(sorted(d["env"].items()))
        elif isinstance(d.get("env"), list):
            d["env"] = tuple(tuple(pair) for pair in d["env"])
        if isinstance(d.get("entrypoint"), list):
            d["entrypoint"] = tuple(d["entrypoint"])
        return cls(**d)


@dataclass(frozen=True)
class NetworkPolicy:
    """Egress policy for the provisioned environment. Empty = no egress."""

    egress_hosts: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkPolicy":
        d = _known(cls, data)
        if isinstance(d.get("egress_hosts"), list):
            d["egress_hosts"] = tuple(d["egress_hosts"])
        return cls(**d)


@dataclass
class EnvironmentSpec:
    """The full declarative environment description."""

    name: str
    source: SourceSpec = field(default_factory=SourceSpec)
    version: str = ""            # the version pin the oracle asserts
    cve_id: str = ""             # optional CVE binding
    build: BuildSpec = field(default_factory=BuildSpec)
    run: RunSpec = field(default_factory=RunSpec)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    verify_plan: list[dict[str, Any]] = field(default_factory=list)
    markers: dict[str, Any] = field(default_factory=dict)  # oracle markers
    notes: str = ""
    spec_version: int = SPEC_VERSION

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # env as a dict reads better on disk; from_dict accepts both.
        d["run"]["env"] = self.run.env_dict()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EnvironmentSpec":
        d = _known(cls, data)
        if "name" not in d or not d["name"]:
            raise ValueError("EnvironmentSpec requires a name")
        if isinstance(d.get("source"), dict):
            d["source"] = SourceSpec.from_dict(d["source"])
        if isinstance(d.get("build"), dict):
            d["build"] = BuildSpec.from_dict(d["build"])
        if isinstance(d.get("run"), dict):
            d["run"] = RunSpec.from_dict(d["run"])
        if isinstance(d.get("network"), dict):
            d["network"] = NetworkPolicy.from_dict(d["network"])
        return cls(**d)

    @classmethod
    def from_json(cls, text: str) -> "EnvironmentSpec":
        return cls.from_dict(json.loads(text))
