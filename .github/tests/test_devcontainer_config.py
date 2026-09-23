"""Devcontainer configuration shape pins.

The devcontainer is where operators run RAPTOR against untrusted
repos with their real credentials mounted in — its config IS security
posture, so the load-bearing shapes are pinned here rather than
trusted to review:

* every home-directory mount must target the ``remoteUser``'s home —
  a mount under another user's home is dead weight AT BEST (the
  intended consumer never reads it) and credential exposure at worst
  (readable via sudo while never serving its purpose);
* the Dockerfile's runtime USER and devcontainer ``remoteUser`` must
  agree, or the home-mount rule above pins the wrong home.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEVCONTAINER = REPO_ROOT / ".devcontainer" / "devcontainer.json"
DOCKERFILE = REPO_ROOT / ".devcontainer" / "Dockerfile"


def _load_devcontainer() -> dict:
    """Parse the JSONC devcontainer file (full-line // comments)."""
    text = DEVCONTAINER.read_text(encoding="utf-8")
    text = re.sub(r"^\s*//.*$", "", text, flags=re.MULTILINE)
    return json.loads(text)


def _mount_fields(mount: str) -> dict[str, str]:
    fields = {}
    for part in mount.split(","):
        key, _, value = part.partition("=")
        fields[key.strip()] = value.strip()
    return fields


def test_remote_user_matches_dockerfile_runtime_user():
    cfg = _load_devcontainer()
    remote_user = cfg.get("remoteUser", "root")
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    users = re.findall(r"^USER\s+(\S+)", dockerfile, flags=re.MULTILINE)
    assert users, "Dockerfile declares no runtime USER"
    assert users[-1] == remote_user, (
        f"devcontainer remoteUser={remote_user!r} but the Dockerfile's "
        f"runtime USER is {users[-1]!r} — the home-mount pins below "
        "would police the wrong home directory"
    )


def test_home_mounts_target_the_remote_users_home():
    """A host credential directory mounted under the WRONG user's home
    is never read by the intended consumer (fresh unauthenticated
    state every container) while the operator's real credentials sit
    readable elsewhere in the container. The ~/.claude mount once
    targeted /root/.claude with remoteUser=vscode — dead credential
    mount in a container that analyzes untrusted repos."""
    cfg = _load_devcontainer()
    remote_user = cfg.get("remoteUser", "root")
    home = "/root" if remote_user == "root" else f"/home/{remote_user}"
    offenders = []
    for mount in cfg.get("mounts", []):
        fields = _mount_fields(mount)
        target = fields.get("target", "")
        if target.startswith(("/root/", "/home/")) and not (
            target == home or target.startswith(home + "/")
        ):
            offenders.append(target)
    assert not offenders, (
        f"mount target(s) {offenders} live under a home directory that "
        f"is not remoteUser {remote_user!r}'s home ({home}) — the "
        "intended consumer resolves ~ there and will never read them"
    )


def test_default_run_args_are_not_privileged():
    """RAPTOR's own threat model treats scanned repos as hostile
    (SECURITY: UNTRUSTED REPOS; the sandbox machinery). Under
    ``--privileged`` + passwordless sudo + host-secret bind mounts, a
    single in-container escalation is host-equivalent BY CONFIGURATION
    — the sandbox layers defend the host only because the container
    boundary they back onto exists. --privileged is the documented
    OPT-IN rr recording profile (a local runArgs edit), never the
    default posture."""
    cfg = _load_devcontainer()
    run_args = cfg.get("runArgs", [])
    assert "--privileged" not in run_args, (
        "the default devcontainer posture regressed to --privileged; "
        "rr recording is an opt-in local edit, not the default"
    )


def test_claude_mount_serves_the_cli_user():
    """Direction pin for the fix itself: the ~/.claude mount exists
    and lands where the claude CLI (running as remoteUser) resolves
    ``~/.claude``."""
    cfg = _load_devcontainer()
    remote_user = cfg.get("remoteUser", "root")
    home = "/root" if remote_user == "root" else f"/home/{remote_user}"
    claude_targets = [
        _mount_fields(m).get("target", "")
        for m in cfg.get("mounts", [])
        if ".claude" in m
    ]
    assert claude_targets, "the ~/.claude mount disappeared entirely"
    assert claude_targets == [f"{home}/.claude"], claude_targets
