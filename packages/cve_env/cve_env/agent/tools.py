"""The 10-tool belt the agent calls during one CVE build.

Each tool is an MCP tool registered via :func:`claude_agent_sdk.tool`;
the SDK drives the tool-use cycle, runs each handler in-process, and
feeds the result back to the agent. ``ALL_TOOLS`` is the registered
list -- ``test_tool_schemas.py`` asserts its shape as a CI gate so a tool
can never be silently unregistered at run time.

Tool taxonomy:

* **Deterministic shortcut** (zero-LLM inside the tool): ``vulhub_lookup``,
  ``image_resolve``, ``arch_decide``.
* **Build/run/verify plumbing**: ``dockerfile_gen``, ``docker_build``,
  ``docker_run``, ``verify``, ``source_build``.
* **Terminal**: ``give_up`` -- agent emits ``{reason}`` and the loop
  exits with ``Outcome(status="unresolvable")``.
"""

from __future__ import annotations

import dataclasses
import functools
import json
import tempfile
from collections.abc import Callable
from typing import Annotated, Any

from claude_agent_sdk import SdkMcpTool, tool

from cve_env.agent import _activity
from cve_env.tools import arch as _arch
from cve_env.tools import docker_build as _docker_build
from cve_env.tools import docker_compose_up as _docker_compose_up
from cve_env.tools import docker_run as _docker_run
from cve_env.tools import dockerfile_gen as _dockerfile_gen
from cve_env.tools import github_fetch as _github_fetch
from cve_env.tools import image_resolve as _image_resolve
from cve_env.tools import nvd_lookup as _nvd_lookup
from cve_env.tools import run_in_container as _run_in_container
from cve_env.tools import source_build as _source_build
from cve_env.tools import verify as _verify

TOOL_NAMES: tuple[str, ...] = (
    "nvd_lookup",
    "github_fetch",
    "image_resolve",
    "dockerfile_gen",
    "source_build",
    "docker_build",
    "docker_run",
    "docker_compose_up",
    "run_in_container",
    "verify",
    "give_up",
)
"""Canonical ordered list of tool names. Change here + in ALL_TOOLS below.

``web_fetch`` and ``arch_decide`` are not registered as MCP handlers:
``image_resolve`` makes the arch decision inline, and NVD + github_fetch
cover the research need. ``cve_env/tools/web_fetch.py`` is KEPT — it's used
internally by ``nvd_lookup`` and ``github_fetch`` for the actual HTTP GETs."""


def _ok(payload: dict[str, Any]) -> dict[str, Any]:
    """Wrap a JSON-serializable payload in the MCP content envelope."""
    return {"content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}]}


# -- nvd_lookup -----------------------------------------------------------


# Guard against re-calling nvd_lookup mid-CVE. The agent can re-research
# after a verify failure (calling nvd_lookup repeatedly) instead of
# iterating on build/run/verify. The prompt's anti-thrash rule is passive
# ("do NOT call more than once") but doesn't prevent confused recovery loops.
#
# A 1-call guard is too strict: a legitimate recovery scenario (agent hits an
# external API refusal, then attempts an nvd_lookup recovery a few turns
# later) would be blocked. The threshold is 2 — still catches thrash patterns
# (3+ calls) but allows one recovery call after a transient interruption
# (refusal, network blip, etc.). Beyond the 2nd call the guard fires; the
# agent must then commit to build/run/verify or give_up.
_NVD_LOOKUP_COUNT_THIS_CVE: int = 0
_NVD_LOOKUP_THRESHOLD: int = 2

# The GitHub repo URL extracted from this CVE's nvd_lookup references (if
# any), stashed so image_resolve's no_image path can hand the agent a
# concrete source_build candidate. Per-CVE; reset below.
_LAST_CVE_GITHUB_REPO: str = ""

# Per-CVE state registry. See note in docker_run.py for the contract.
_RESET_GLOBALS: tuple[str, ...] = (
    "_NVD_LOOKUP_COUNT_THIS_CVE",
    "_LAST_CVE_GITHUB_REPO",
)


def reset_nvd_lookup_state() -> None:
    """Clear the per-CVE nvd_lookup count + stashed repo. The agent loop
    calls this at the start of each new CVE.
    """
    global _NVD_LOOKUP_COUNT_THIS_CVE, _LAST_CVE_GITHUB_REPO  # noqa: PLW0603 -- per-CVE state
    _NVD_LOOKUP_COUNT_THIS_CVE = 0
    _LAST_CVE_GITHUB_REPO = ""


# Per-CVE tool-state reset registry. Every tool module that carries per-CVE
# state registers its reset here, so build() resets them all via
# reset_all_tool_state() instead of hand-wired calls that a new tool is easy
# to forget. **ADD ANY NEW TOOL'S PER-CVE RESET TO THIS TUPLE.**
_PER_CVE_RESET_HANDLERS: tuple[Callable[[], None], ...] = (
    _docker_run.reset_failed_attempts,
    _docker_compose_up.reset_active_stacks,
    _image_resolve.reset_rate_limit_budget,
    reset_nvd_lookup_state,
    _docker_build.reset_docker_build_state,
)


def reset_all_tool_state() -> None:
    """Reset ALL per-CVE tool module state. Called once at the start of each
    ``build()``."""
    for handler in _PER_CVE_RESET_HANDLERS:
        handler()


def _reference_urls(payload: dict[str, Any]) -> list[str]:
    """Collect reference URLs from a nvd_lookup payload across both schemas:
    ``references`` (list of ``{"url": ...}`` dicts or bare strings) and
    ``references_urls`` (list of strings). Used by :func:`_extract_github_repo`.
    """
    urls: list[str] = []
    refs = payload.get("references")
    if isinstance(refs, list):
        for r in refs:
            if isinstance(r, dict) and isinstance(r.get("url"), str):
                urls.append(r["url"])
            elif isinstance(r, str):
                urls.append(r)
    refs_urls = payload.get("references_urls")
    if isinstance(refs_urls, list):
        urls.extend(u for u in refs_urls if isinstance(u, str))
    return urls


def _extract_github_repo(payload: dict[str, Any]) -> str:
    """Return the canonical ``https://github.com/<owner>/<repo>`` of the FIRST
    github.com reference in the nvd_lookup payload, or "". Used to hand
    image_resolve's no_image path a concrete source_build candidate (the
    give_up(no_image)-without-source_build class). Uses ``_reference_urls``
    for URL extraction.
    """
    for url in _reference_urls(payload):
        if "://" not in url:
            continue
        host, _, rest = url.split("://", 1)[1].partition("/")
        if host.lower().removeprefix("www.") != "github.com":
            continue
        parts = [p for p in rest.split("/") if p]
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
            repo = repo.removesuffix(".git")
            # Skip non-repo github paths (advisories, gists, etc.).
            if owner.lower() in {"advisories", "gist", "orgs", "sponsors"}:
                continue
            return f"https://github.com/{owner}/{repo}"
    return ""


def _detect_kernel_cve(payload: dict[str, Any]) -> str:
    """Kernel quick-fail pre-screen. Returns the matched Linux-kernel CPE
    string when the CVE's affected components are EXCLUSIVELY the Linux
    kernel (CPE vendor=``linux`` product=``linux_kernel``), else "".

    Rationale: Docker containers SHARE the host kernel — an image cannot
    boot a specific vulnerable kernel version, so a kernel CVE has no
    buildable/verifiable artifact in this container-build harness. The agent
    reaches ``unresolvable`` on these via its own reasoning anyway; this
    pre-screen just makes that deterministic and a turn faster. Scope is
    LINUX-KERNEL-ONLY; the conservative "exclusively linux_kernel, no other
    vendor/product" gate avoids false-positives on userspace CVEs that
    merely list the kernel as a platform CPE. The agent is steered to the
    EXISTING ``give_up(reason='arch_incompatible')`` — no new status/enum.
    """
    cpes = payload.get("cpes")
    if not isinstance(cpes, list):
        return ""
    kernel_cpe = ""
    has_other_component = False
    for cpe in cpes:
        if not isinstance(cpe, dict):
            continue
        vendor = (cpe.get("vendor") or "").lower()
        product = (cpe.get("product") or "").lower()
        if vendor == "linux" and product == "linux_kernel":
            kernel_cpe = cpe.get("cpe") or "cpe:2.3:o:linux:linux_kernel"
        elif vendor or product:
            has_other_component = True
    if kernel_cpe and not has_other_component:
        return kernel_cpe
    return ""


@tool(
    "nvd_lookup",
    "Fetch the NVD record for a CVE (live, unauthenticated). Returns "
    "description, CVSS severity, CPE entries (vendor/product/version), "
    "and reference URLs. Use this first to ground the agent on what the "
    "CVE is actually about. **Phase 35.4 (updated 39.4a): 2-call cap "
    "per CVE — the 3rd call returns ok=false. One re-call is allowed "
    "for legitimate recovery (e.g. after an API refusal or transport "
    "blip); a 3rd is treated as thrashing. The CVE record is in your "
    "context; re-using it is usually the right move when verify fails — "
    "iterate on build/run/verify or call give_up.** **It may include "
    "`kernel_unsupported_hint` if the CVE is Linux-kernel-only (containers "
    "share the host kernel, not reproducible) — read and call "
    "`give_up(reason='arch_incompatible')` immediately.**",
    {"cve_id": Annotated[str, "the CVE identifier, e.g. CVE-2018-7600"]},
)
async def nvd_lookup(args: dict[str, Any]) -> dict[str, Any]:
    global _NVD_LOOKUP_COUNT_THIS_CVE, _LAST_CVE_GITHUB_REPO  # noqa: PLW0603 -- per-CVE state
    if _NVD_LOOKUP_COUNT_THIS_CVE >= _NVD_LOOKUP_THRESHOLD:
        return _ok(
            {
                "ok": False,
                "blocked": True,
                "reason": (
                    f"nvd_lookup called {_NVD_LOOKUP_COUNT_THIS_CVE} times "
                    f"already for this CVE — threshold is "
                    f"{_NVD_LOOKUP_THRESHOLD} (Phase 35.4 guard, updated "
                    "39.4a). The CVE record is in your context above; "
                    "re-using it is the right move when verify fails. "
                    "Anti-thrash rule: your next calls MUST be docker_build "
                    "/ docker_run / verify / give_up. Do NOT re-research "
                    "a third time."
                ),
                "next_step_hint": (
                    "scroll up to your prior nvd_lookup result(s). Then "
                    "pick: (a) docker_build with a corrected Dockerfile, "
                    "(b) docker_run with different image/platform, "
                    "(c) verify with a different plan, or (d) give_up if "
                    "stuck"
                ),
            }
        )
    payload = _nvd_lookup.nvd_lookup_payload(str(args["cve_id"]))
    _NVD_LOOKUP_COUNT_THIS_CVE += 1
    # Stash a github repo from references (if any) so image_resolve's
    # no_image path can hand the agent a source_build candidate. Keep a
    # previously-found repo if this call has none.
    _LAST_CVE_GITHUB_REPO = _extract_github_repo(payload) or _LAST_CVE_GITHUB_REPO
    # Kernel quick-fail pre-screen: Linux-kernel CVEs cannot be reproduced in
    # a container (containers share the host kernel). Steer to an immediate
    # give_up with the existing arch_incompatible reason.
    if _detect_kernel_cve(payload):
        payload["kernel_unsupported_hint"] = (
            "⓿ Linux-kernel CVE: the only affected component is the Linux "
            "kernel (CPE vendor=linux product=linux_kernel). Docker "
            "containers SHARE the host kernel — an image cannot boot a "
            "specific vulnerable kernel version, so there is NO buildable or "
            "verifiable artifact for this CVE in a container-build harness. "
            "STOP — your next call MUST be give_up(reason='arch_incompatible', "
            "detail='Linux kernel CVE; containers share the host kernel, not "
            "reproducible in a Docker container')."
        )
    return _ok(payload)


# -- github_fetch ---------------------------------------------------------


@tool(
    "github_fetch",
    "Fetch a file OR list a directory from a public GitHub repo via the "
    "Contents API. For files: returns decoded content. For directories: "
    "returns a list of entries. Use this to retrieve e.g. vulhub compose "
    "files (owner=vulhub, repo=vulhub, path=<product>/<cve>/docker-compose.yml) "
    "or upstream source files. Set GITHUB_TOKEN env to raise the rate limit.",
    {
        "owner": Annotated[str, "GitHub org/user, e.g. 'vulhub'"],
        "repo": Annotated[str, "repo name, e.g. 'vulhub'"],
        "path": Annotated[str, "repo-relative path to file or directory"],
        "ref": Annotated[
            str,
            "optional git ref (branch/tag/SHA); default is the repo's default branch",
        ],
    },
)
async def github_fetch(args: dict[str, Any]) -> dict[str, Any]:
    payload = _github_fetch.github_fetch_payload(
        owner=str(args["owner"]),
        repo=str(args["repo"]),
        path=str(args["path"]),
        ref=str(args.get("ref") or ""),
    )
    return _ok(payload)


# -- image_resolve (Day 6 landing) ---------------------------------------


@tool(
    "image_resolve",
    "Probe container registries for an image matching the given product/version "
    "that is native to the host architecture. Returns a digest-pinned pullable "
    "ref or an 'arch_incompatible' signal so the agent can escalate to source_build.",
    {
        "product": Annotated[str, "normalized product name, e.g. 'drupal'"],
        "version": Annotated[str, "exact version string, e.g. '8.5.0'"],
        "host_arch": Annotated[str, "host architecture, e.g. 'arm64' or 'amd64'"],
    },
)
async def image_resolve(args: dict[str, Any]) -> dict[str, Any]:
    host = _arch.detect_host_arch()
    payload = _image_resolve.image_resolve_to_payload(
        product=str(args["product"]),
        version=str(args["version"]),
        host_arch=str(args.get("host_arch") or host.arch),
        rosetta_available=host.rosetta_available,
    )
    # No image found, but this CVE's nvd_lookup references had a GitHub repo
    # → hand the agent a concrete source_build candidate so it escalates
    # instead of give_up(no_image) without ever trying source_build despite a
    # public repo. Structural assist (mirrors the proprietary/kernel hint
    # pattern); does NOT auto-build.
    if (
        payload.get("decision") == "not_found"
        and not payload.get("image_ref")
        and _LAST_CVE_GITHUB_REPO
    ):
        payload["source_build_candidate"] = _LAST_CVE_GITHUB_REPO
        payload["next_step_hint"] = (
            f"⓿ No prebuilt image, but a GitHub repo for this CVE exists: "
            f"{_LAST_CVE_GITHUB_REPO}. Before give_up(no_image), call "
            f"source_build(source_url='{_LAST_CVE_GITHUB_REPO}', product=..., "
            "version=...) to clone + build the vulnerable version from source. "
            "Only give_up(no_image) if source_build also fails."
        )
    return _ok(payload)


def _maybe_fuse_build(payload: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    """Fuse render→build. On a CLEAN render, build immediately so the agent
    doesn't quit in the render→build gap — a seam with poor prompt
    follow-through and no agent judgment needed (the dockerfile is fully
    formed; just build it).

    Smart default: auto-build only when there are NO copy_ops (the FROM+RUN
    common case — an empty/auto-created context suffices, and docker_build R1
    auto-mkdirs it). copy_ops / source overlays need a staged context, so they
    stay render-only unless the agent passes build=True explicitly. Opt out any
    time with build=False. Surfaces the build outcome under payload["build"] so
    the agent sees the result + next step in the SAME turn.
    """
    if not payload.get("ok"):
        return payload
    build_arg = args.get("build")
    has_copy_ops = bool(args.get("copy_ops"))
    do_build = (not has_copy_ops) if build_arg is None else bool(build_arg)
    if not do_build:
        return payload
    ctx = str(args.get("context_dir") or "").strip()
    if not ctx:
        ctx = tempfile.mkdtemp(prefix="cve-env-dfgbuild-")
    result = _docker_build.docker_build(
        context_dir=ctx,
        image_tag=str(args.get("image_tag") or ""),
        dockerfile_text=str(payload.get("dockerfile_text") or ""),
        cve_id=_CURRENT_CVE_ID,  # label image for per-CVE cleanup
    )
    fused = dict(payload)
    fused["context_dir"] = ctx
    fused["build"] = {
        "ok": result.ok,
        "image_tag": result.image_tag,
        "exit_code": result.exit_code,
        "reason": result.reason,
        "reason_class": result.reason_class,
        "stderr_tail": result.stderr_tail,
        "suggested_patch": result.suggested_patch,
        "next_step_hint": result.next_step_hint,
    }
    fused["next_step_hint"] = (
        f"build OK (image={result.image_tag!r}) — call docker_run(image="
        f"{result.image_tag!r}) then verify. Do NOT stop here."
        if result.ok
        else (
            f"fused auto-build FAILED ({result.reason}): {result.next_step_hint} "
            "Fix the Dockerfile (dockerfile_gen again) or stage context, then retry."
        )
    )
    return fused


# -- dockerfile_gen (Day 5 landing) --------------------------------------


@tool(
    "dockerfile_gen",
    "Render a Dockerfile from structured input. Enforces P6 (<=10 apt packages), "
    "P14 (digest-pinned base image), and P17 (no privilege-escalating directives). "
    "Pass `copy_ops=[{src,dst}]` to overlay plugin/extension source onto a base "
    "image (e.g., WordPress plugin, Drupal module). "
    "Pass `cve_named_packages=[...]` to lock the CVE's headline + transitive "
    "package names into the validator: any bare `apt install <pkg>` of those "
    "packages becomes a HARD reject (P20) — version pin is required. Also "
    "rejects `apt-get update` without same-line `=<version>` pin (P21). "
    "Returns the Dockerfile text plus a validator report.",
    {
        "base_image": Annotated[str, "base image ref; must be digest-pinned"],
        "install_steps": Annotated[
            list[str], "ordered list of shell commands for RUN stanzas"
        ],
        "workdir": Annotated[str, "WORKDIR value, e.g. '/app'"],
        "cmd": Annotated[list[str], "CMD vector, e.g. ['nginx', '-g', 'daemon off;']"],
        "ports": Annotated[list[int], "EXPOSE ports, e.g. [80, 443]"],
        "copy_ops": Annotated[
            list[dict[str, str]],
            "list of {src, dst} pairs rendered as COPY directives; src is "
            "context-relative, dst is absolute. Use to install a plugin into "
            "a CMS base image (e.g. WordPress + plugin overlay).",
        ],
        "cve_named_packages": Annotated[
            list[str],
            "package names the CVE specifically references (headline + "
            "transitive deps from nvd_lookup, e.g. ['log4j-core', 'spring-"
            "beans']). Bare apt install of these is HARD-rejected (P20). "
            "Empty list = back-compat (Phase 20.2 soft warnings only).",
        ],
        "apt_unsafe": Annotated[
            bool,
            "Phase 37.4: bypass GPG signature + valid-until checks for "
            "apt-get update/install. Use this when a previous docker_build "
            "failed with stderr `At least one invalid signature was "
            "encountered` (Debian bullseye on mirror.gcr.io is the most "
            "common case). ONLY for disposable build containers; never in "
            "production. Default: False.",
        ],
        "build": Annotated[
            bool,
            "b1: build the rendered Dockerfile immediately (fuse render→build, "
            "saving a turn and closing the gap where agents quit after gen). "
            "DEFAULT: True when there are no copy_ops (FROM+RUN case — an empty "
            "context suffices), False when copy_ops are present (stage the COPY "
            "context first, then this builds). Set explicitly to override. The "
            "build result is returned under the `build` field.",
        ],
        "context_dir": Annotated[
            str,
            "build context dir for the fused build (auto-created if missing). "
            "Omit for FROM+RUN Dockerfiles (a temp context is used); set it when "
            "copy_ops reference staged files. Ignored when build is False.",
        ],
        "image_tag": Annotated[
            str,
            "image tag for the fused build (e.g. 'cve-env-local:CVE-2024-1234'); "
            "auto-generated when empty. Use it in the follow-up docker_run.",
        ],
    },
)
async def dockerfile_gen(args: dict[str, Any]) -> dict[str, Any]:
    for _field in (
        "install_steps", "cmd", "ports", "apt_packages", "copy_ops", "cve_named_packages"
    ):
        _val = args.get(_field)
        if _val is not None and not isinstance(_val, list):
            return _ok(
                {"ok": False, "issues": [f"{_field} must be a list, got {type(_val).__name__}"]}
            )
    payload = _dockerfile_gen.render_to_payload(
        base_image=str(args["base_image"]),
        install_steps=list(args.get("install_steps") or []),
        workdir=str(args.get("workdir") or "/app"),
        cmd=list(args.get("cmd") or []),
        ports=list(args.get("ports") or []),
        apt_packages=list(args.get("apt_packages") or []),
        copy_ops=list(args.get("copy_ops") or []),
        cve_named_packages=list(args.get("cve_named_packages") or []),
        apt_unsafe=bool(args.get("apt_unsafe") or False),
    )
    payload = _maybe_fuse_build(payload, args)
    return _ok(payload)


# -- source_build (Week 2 landing) ---------------------------------------


@tool(
    "source_build",
    "Clone an upstream GitHub repo at the vulnerable version tag, "
    "discover a Dockerfile (or a build-config hint like maven/npm), and "
    "return the checkout path + Dockerfile text. Use when image_resolve "
    "reports 'not_found' but the upstream has a public GitHub repo. "
    "Progressive clone cascade (depth=1 -> adaptive -> full) + codeload "
    "tarball archive fallback. Result's next_step_hint tells you whether "
    "to call docker_build directly or scaffold via dockerfile_gen first. "
    "GitHub-only; non-GitHub URLs return ok=false.",
    {
        "source_url": Annotated[
            str,
            "public GitHub URL of the upstream repo "
            "(https://, git://, git+https, git@ all accepted)",
        ],
        "product": Annotated[
            str,
            "normalized product name, used to name the local checkout dir",
        ],
        "version": Annotated[
            str,
            "exact vulnerable version string (e.g. '1.5' or '5.4.2') -- "
            "matched against repo tags via 4-tier priority",
        ],
    },
)
async def source_build(args: dict[str, Any]) -> dict[str, Any]:
    payload = _source_build.source_build_payload(
        source_url=str(args["source_url"]),
        product=str(args["product"]),
        version=str(args["version"]),
    )
    # Fuse source_build → docker_build — the sibling seam to the
    # dockerfile_gen→build fuse. When source_build returns ok=true WITH a
    # Dockerfile + clone, build it immediately against the clone
    # (context_dir=repo_dir) in the same call, so the agent can't
    # quit-one-call-short on the render→build gap. A build_config-only payload
    # (no dockerfile_text) is left for the agent to dockerfile_gen against the
    # clone (which then fuses). Reuses _maybe_fuse_build.
    if payload.get("ok") and payload.get("dockerfile_text") and payload.get("repo_dir"):
        payload = _maybe_fuse_build(
            payload, {"context_dir": payload["repo_dir"], "build": True}
        )
    return _ok(payload)


# -- docker_build (Day 5 landing) ----------------------------------------


@tool(
    "docker_build",
    "Run 'docker build' on a context directory. Returns the exit code, the last "
    "~200 log lines, and -- if the failure matches a known dependency-missing "
    "regex -- a 'suggested_patch' hint listing apt_packages to add to the "
    "next dockerfile_gen call. **Phase 37.3 build-loop guard: if the same "
    "image_tag previously returned a suggested_patch, this call is BLOCKED "
    "(returns ok=false, blocked=true) — you MUST call dockerfile_gen with the "
    "suggested apt_packages before retrying docker_build.**",
    {
        "context_dir": Annotated[str, "path to the Docker build context"],
        "dockerfile_text": Annotated[
            str,
            "optional: raw Dockerfile text; if omitted, uses context_dir/Dockerfile",
        ],
        "image_tag": Annotated[str, "tag to assign the built image, e.g. 'cve-env-local:build'"],
    },
)
async def docker_build(args: dict[str, Any]) -> dict[str, Any]:
    result = _docker_build.docker_build(
        context_dir=str(args["context_dir"]),
        image_tag=str(args.get("image_tag") or ""),
        dockerfile_text=args.get("dockerfile_text") or None,
        platform=args.get("platform") or None,
        cve_id=_CURRENT_CVE_ID,  # label image for per-CVE cleanup
    )
    return _ok(
        {
            "ok": result.ok,
            "image_tag": result.image_tag,
            "exit_code": result.exit_code,
            "logs_tail": result.logs_tail,
            "stderr_tail": result.stderr_tail,
            "suggested_patch": result.suggested_patch,
            "reason": result.reason,
            "reason_class": result.reason_class,
            "next_step_hint": result.next_step_hint,
            "blocked": result.blocked,  # build-loop guard
        }
    )


# -- docker_run ----------------------------------------------------------


@tool(
    "docker_run",
    "Launch a single container with hardened defaults (cap-drop ALL, "
    "no-new-privileges, ephemeral 127.0.0.1 port). Returns container_id and "
    "the allocated host_port. Failures return a structured reason "
    "(no_image, no_host_port, etc.) -- not an exception.",
    {
        "image": Annotated[str, "image reference to run"],
        "container_port": Annotated[int, "the service port inside the container, e.g. 80"],
        "run_id": Annotated[str, "bench run identifier, used as a container label"],
        "cve_id": Annotated[str, "CVE ID, used as a container label"],
        "platform": Annotated[
            str, "optional: explicit --platform value, e.g. 'linux/amd64'"
        ],
    },
)
async def docker_run(args: dict[str, Any]) -> dict[str, Any]:
    image = str(args["image"])
    container_port = int(args["container_port"])
    result = _docker_run.docker_run(
        image=image,
        container_port=container_port,
        run_id=str(args.get("run_id", "")),
        cve_id=str(args.get("cve_id", "")),
        platform=args.get("platform") or None,
    )
    payload: dict[str, Any] = {
        "ok": result.ok,
        "container_id": result.container_id,
        "host_ip": result.host_ip,
        "host_port": result.host_port,
        "container_port": result.container_port,
        "reason": result.reason,
        "reason_class": result.reason_class,
        "logs_tail": result.logs_tail,
        "stderr": result.stderr,
        "next_step_hint": result.next_step_hint,
    }
    return _ok(payload)


# -- docker_compose_up ---------------------------------------------------


@tool(
    "docker_compose_up",
    "Bring up a multi-service vulhub compose stack. Use this when "
    "`github_fetch` returned a docker-compose.yml with multiple services, "
    "volume mounts, or a custom `command:` -- these can't be launched via "
    "single-container `docker_run`. First `github_fetch` the compose file, "
    "save it locally (e.g. via a Dockerfile_gen-less write), then pass its "
    "path. Returns the primary service's container_id + host_port so you "
    "can proceed to `verify` or `run_in_container`. Ports are rewritten to "
    "127.0.0.1:0 (P18 invariant); teardown is automatic per CVE.",
    {
        "compose_yaml_path": Annotated[
            str,
            "absolute path to a docker-compose.yml on the local filesystem",
        ],
        "cve_id": Annotated[
            str,
            "CVE identifier; used as the deterministic compose project name",
        ],
        "platform": Annotated[
            str,
            "optional --platform value (e.g. 'linux/amd64' for Rosetta on arm64)",
        ],
    },
)
async def docker_compose_up(args: dict[str, Any]) -> dict[str, Any]:
    payload = _docker_compose_up.docker_compose_up_payload(
        compose_yaml_path=str(args["compose_yaml_path"]),
        cve_id=str(args["cve_id"]),
        platform=args.get("platform") or None,
    )
    return _ok(payload)


# -- run_in_container ----------------------------------------------------


@tool(
    "run_in_container",
    "Execute a shell command inside an already-launched container via "
    "`docker exec`. Use this AFTER `docker_run` to probe vulnerabilities "
    "that are not HTTP-observable: Redis RESP (`redis-cli eval ...`), "
    "local setuid CVEs (compile PoC, run it, check euid), database "
    "protocols, anything needing in-container inspection. Returns "
    "exit_code + stdout + stderr (capped). Invariants: no --privileged, "
    "no user override; runs as whatever user the image uses.",
    {
        "container_id": Annotated[
            str,
            "the container id returned by docker_run",
        ],
        "command": Annotated[
            str,
            "shell command; runs via `sh -c`, so pipes / redirects / env vars work",
        ],
        "timeout_seconds": Annotated[
            int,
            "max seconds to wait for the command; clamped to [1, 300]",
        ],
        "workdir": Annotated[
            str,
            "optional working directory inside the container (empty = image default)",
        ],
    },
)
async def run_in_container(args: dict[str, Any]) -> dict[str, Any]:
    payload = _run_in_container.run_in_container_payload(
        container_id=str(args["container_id"]),
        command=str(args["command"]),
        timeout_seconds=float(args.get("timeout_seconds") or 30.0),
        workdir=str(args.get("workdir") or ""),
    )
    return _ok(payload)


# -- verify --------------------------------------------------------------


@tool(
    "verify",
    "Run a verification plan. Check types: container_status (auto-prepended "
    "if missing), http_check (passive: records response_size_bytes; fails "
    "on empty-body 200s), log_check, stability_wait (auto-bumped to 120s "
    "for JVM images), exec_check (wraps run_in_container; passes iff "
    "exit_code + optional stdout match — Redis RESP via redis-cli, sudo/"
    "polkit PoCs, DB wire), http_request_check (active: POSTs/GETs an "
    "active payload and asserts the response contains an expected "
    "response marker — OGNL/SpEL injection, command injection, Spring4Shell-"
    "class), and tcp_probe_check (active raw-TCP probe — sends bytes/hex, "
    "asserts response marker; use for Redis RESP, MySQL handshake, SMTP "
    "banner, SSH version, Memcached, Postgres startup, raw-RTSP/SIP — no "
    "in-container client tool needed). "
    "Returns {passed, results, reason}. Lifecycle-only 'Up' detection is banned.",
    {
        "container_id": Annotated[str, "container id from docker_run"],
        "host_ip": Annotated[str, "host bind IP, usually '127.0.0.1'"],
        "host_port": Annotated[int, "host port from docker_run"],
        "plan": Annotated[
            list[dict[str, Any]],
            "ordered list of check dicts; each has a 'type' "
            "(container_status|http_check|log_check|stability_wait|"
            "exec_check|http_request_check|tcp_probe_check) and its args",
        ],
    },
)
async def verify(args: dict[str, Any]) -> dict[str, Any]:
    plan = args["plan"]
    if not isinstance(plan, list):
        return _ok({
            "passed": False,
            "results": [],
            "reason": (
                f"verify: plan must be a list, got {type(plan).__name__} — "
                "agent may have passed json.dumps(plan) instead of plan"
            ),
        })
    result = _verify.verify(
        container_id=str(args["container_id"]),
        host_ip=str(args["host_ip"]),
        host_port=int(args["host_port"]),
        plan=plan,
        cve_version=_CURRENT_CVE_VERSION,
    )
    return _ok(result)


# Per-build CVE version context for the verify tool. Set by
# ``agent.loop.build()`` from ``cve.version`` before the agent runs. Read by
# the verify wrapper above so the runtime injector can fill in
# ``expected_stdout_contains`` when the agent omits the version literal.
# Module-level state is the simplest threading: the agent doesn't need to
# pass cve_version, and the MCP tool registry doesn't need argument changes.
_CURRENT_CVE_VERSION: str = ""


def set_cve_version_context(version: str) -> None:
    """Register the CVE version for the next verify() call.

    Build() invokes this once at run start with ``cve.version``. The verify
    tool wrapper reads it and passes it to the runtime injector.
    """
    global _CURRENT_CVE_VERSION
    _CURRENT_CVE_VERSION = version or ""


# Module-level current-CVE id, set by build() at run start, read by the
# docker_build wrappers so every built image is labeled
# ``cve-env.cve-id=<id>`` (parity with docker_run containers) WITHOUT depending
# on the agent to pass cve_id. Enables exact per-CVE result-image cleanup.
_CURRENT_CVE_ID: str = ""


def set_cve_id_context(cve_id: str) -> None:
    """Register the CVE id for the docker_build image label (mirrors
    set_cve_version_context). Build() invokes this once at run start."""
    global _CURRENT_CVE_ID
    _CURRENT_CVE_ID = cve_id or ""


# -- give_up (terminal) --------------------------------------------------


@tool(
    "give_up",
    "Terminal signal: the agent cannot reach verify.passed for this CVE. "
    "Calling this stops the loop with Outcome(status='unresolvable'). "
    "Use when stuck -- NEVER thrash. "
    "'reason' enum: "
    "no_image | proprietary | unresolvable_metadata | arch_incompatible | "
    "budget. "
    "Runtime classifiers may also set these reasons (you do not emit them, "
    "but they appear in audit JSONLs + Outcome.give_up_reason): "
    "silent_end_turn (was silent_end_turn_p0x, Phase 24A rename), "
    "stuck_after_launch_intervention (Phase 8.4 era — currently dormant), "
    "no_image_without_resolve (Phase 7.4 CF-4), "
    "refusal_persistent (Phase 7.5 CF-6), "
    "max_tool_attempts_<tool> (Phase 12.5 attempts cap), "
    "stage_budget_exhausted_<stage> (Phase 12.3 hard mode).",
    {
        "reason": Annotated[
            str,
            "enum: no_image | proprietary | unresolvable_metadata | "
            "arch_incompatible | budget",
        ],
        "detail": Annotated[str, "free-form explanation for the audit log"],
    },
)
async def give_up(args: dict[str, Any]) -> dict[str, Any]:
    return _ok(
        {
            "terminal": True,
            "reason": str(args.get("reason", "")),
            "detail": str(args.get("detail", "")),
        }
    )


# -- registry ------------------------------------------------------------


_RAW_TOOLS: list[SdkMcpTool[Any]] = [
    nvd_lookup,
    github_fetch,
    image_resolve,
    dockerfile_gen,
    source_build,
    docker_build,
    docker_run,
    docker_compose_up,
    run_in_container,
    verify,
    give_up,
]


def _with_activity_tracking(t: SdkMcpTool[Any]) -> SdkMcpTool[Any]:
    """Stamp tool start/end into :mod:`cve_env.agent._activity` so the
    connectivity idle-watchdog (``llm._run_query_once``) EXCLUDES tool-execution
    time. The SDK is silent during a long in-process tool call, so without this a
    legitimate 600-900s build would trip the breaker. Only ``handler`` is
    wrapped; name/description/input_schema are preserved (the CI shape gate and
    every tool's contract are unchanged)."""
    orig = t.handler

    @functools.wraps(orig)
    async def _tracked(*args: Any, **kwargs: Any) -> Any:
        _activity.tool_start()
        try:
            return await orig(*args, **kwargs)
        finally:
            _activity.tool_end()

    return dataclasses.replace(t, handler=_tracked)


ALL_TOOLS: list[SdkMcpTool[Any]] = [_with_activity_tracking(t) for t in _RAW_TOOLS]
"""Canonical list -- the CI gate asserts len == 11 and schema validity. Handlers
are wrapped for tool-activity tracking; the tool shape is unchanged."""


def get_tool_by_name(name: str) -> SdkMcpTool[Any]:
    """Lookup a tool by short name (not the ``mcp__<server>__<name>`` form)."""
    for t in ALL_TOOLS:
        if t.name == name:
            return t
    msg = f"no tool registered with name {name!r}"
    raise KeyError(msg)
