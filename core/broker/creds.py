"""Credential resolution for broker transports.

Supports multiple auth strategies, resolved in priority order per
system entry.  Credentials are NEVER persisted in the inventory —
they're resolved at connect-time from the operator's environment.

Resolution chain (first match wins):

  SSH:
    1. Explicit key file (--key) — passphrase from agent or prompt
    2. ssh-agent (SSH_AUTH_SOCK) — pre-loaded keys, no passphrase needed
    3. Environment password (RAPTOR_BROKER_PASS_<ALIAS> or RAPTOR_BROKER_PASS)
    4. Keyring / OS credential store (macOS Keychain, GNOME Keyring, Windows Credential Manager)
    5. sshpass (password piped to ssh for subprocess paths like rsync)
    6. SSH_ASKPASS (for non-interactive / CI environments)
    7. Interactive prompt (getpass) — last resort, TTY required

  WinRM:
    1. Environment password (RAPTOR_BROKER_PASS_<ALIAS> or RAPTOR_BROKER_PASS)
    2. Keyring / OS credential store
    3. Kerberos ticket (kinit — no password needed)
    4. CredSSP with NTLM (password from env or keyring)
    5. Interactive prompt (getpass)

  Key passphrase:
    1. ssh-agent (key already loaded)
    2. Environment (RAPTOR_BROKER_KEYPASS_<ALIAS> or RAPTOR_BROKER_KEYPASS)
    3. Keyring (stored under service="raptor-broker", username=<alias>-keypass)
    4. Interactive prompt

The env-var names are deterministic: alias is uppercased with hyphens
replaced by underscores.  ``ci-linux`` → ``RAPTOR_BROKER_PASS_CI_LINUX``.
"""

from __future__ import annotations

import getpass
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class AuthMethod(Enum):
    SSH_AGENT = "ssh-agent"
    KEY_FILE = "key-file"
    PASSWORD_ENV = "password-env"
    PASSWORD_KEYRING = "password-keyring"
    PASSWORD_SSHPASS = "password-sshpass"
    SSH_ASKPASS = "ssh-askpass"
    PASSWORD_PROMPT = "password-prompt"
    KERBEROS = "kerberos"


@dataclass(frozen=True)
class ResolvedCredential:
    """Credential resolved at connect-time — never persisted."""
    method: AuthMethod
    password: Optional[str] = None
    key_passphrase: Optional[str] = None


def _env_key(alias: str) -> str:
    """Normalise alias to env-var suffix: ``ci-linux`` → ``CI_LINUX``."""
    return alias.upper().replace("-", "_").replace(" ", "_")


def _env_password(alias: str) -> Optional[str]:
    """Check RAPTOR_BROKER_PASS_<ALIAS>, then RAPTOR_BROKER_PASS."""
    specific = os.environ.get(f"RAPTOR_BROKER_PASS_{_env_key(alias)}")
    if specific:
        return specific
    return os.environ.get("RAPTOR_BROKER_PASS")


def _env_key_passphrase(alias: str) -> Optional[str]:
    """Check RAPTOR_BROKER_KEYPASS_<ALIAS>, then RAPTOR_BROKER_KEYPASS."""
    specific = os.environ.get(f"RAPTOR_BROKER_KEYPASS_{_env_key(alias)}")
    if specific:
        return specific
    return os.environ.get("RAPTOR_BROKER_KEYPASS")


def _keyring_password(alias: str) -> Optional[str]:
    """Try the OS keyring (macOS Keychain, GNOME Keyring, Windows Credential Manager)."""
    try:
        import keyring
        pw = keyring.get_password("raptor-broker", alias)
        if pw:
            logger.debug("password for %s resolved from OS keyring", alias)
            return pw
    except Exception:
        pass
    return None


def _keyring_key_passphrase(alias: str) -> Optional[str]:
    try:
        import keyring
        pp = keyring.get_password("raptor-broker", f"{alias}-keypass")
        if pp:
            logger.debug("key passphrase for %s resolved from OS keyring", alias)
            return pp
    except Exception:
        pass
    return None


def _ssh_agent_available() -> bool:
    """Check if ssh-agent is running and has keys loaded."""
    sock = os.environ.get("SSH_AUTH_SOCK")
    if not sock:
        return False
    try:
        proc = subprocess.run(
            ["ssh-add", "-l"],
            capture_output=True, text=True, timeout=5,
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _sshpass_available() -> bool:
    return shutil.which("sshpass") is not None


def _has_tty() -> bool:
    return sys.stdin.isatty()


def _kerberos_ticket_valid() -> bool:
    """Check if a Kerberos TGT is available and not expired."""
    try:
        proc = subprocess.run(
            ["klist", "-s"],
            capture_output=True, timeout=5,
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _prompt_password(alias: str, purpose: str = "password") -> Optional[str]:
    """Interactive prompt — only works with a TTY."""
    if not _has_tty():
        return None
    try:
        return getpass.getpass(
            f"[broker] Enter {purpose} for {alias}: "
        )
    except (EOFError, KeyboardInterrupt):
        return None


def store_in_keyring(alias: str, password: str, *, is_keypass: bool = False) -> bool:
    """Store a credential in the OS keyring for future use."""
    try:
        import keyring
        key = f"{alias}-keypass" if is_keypass else alias
        keyring.set_password("raptor-broker", key, password)
        logger.info("stored credential for %s in OS keyring", alias)
        return True
    except Exception as exc:
        logger.warning("failed to store in keyring: %s", exc)
        return False


# ── SSH credential resolution ────────────────────────────────────────

def resolve_ssh_credential(
    alias: str,
    *,
    has_key_file: bool = False,
) -> ResolvedCredential:
    """Resolve SSH credentials for *alias*, walking the chain."""

    key_passphrase = _resolve_key_passphrase(alias) if has_key_file else None

    if _ssh_agent_available():
        logger.info("using ssh-agent for %s", alias)
        return ResolvedCredential(
            method=AuthMethod.SSH_AGENT,
            key_passphrase=key_passphrase,
        )

    pw = _env_password(alias)
    if pw:
        logger.info("using env-var password for %s", alias)
        return ResolvedCredential(
            method=AuthMethod.PASSWORD_ENV,
            password=pw,
            key_passphrase=key_passphrase,
        )

    pw = _keyring_password(alias)
    if pw:
        logger.info("using keyring password for %s", alias)
        return ResolvedCredential(
            method=AuthMethod.PASSWORD_KEYRING,
            password=pw,
            key_passphrase=key_passphrase,
        )

    if os.environ.get("SSH_ASKPASS"):
        logger.info("SSH_ASKPASS set — deferring to askpass for %s", alias)
        return ResolvedCredential(
            method=AuthMethod.SSH_ASKPASS,
            key_passphrase=key_passphrase,
        )

    pw = _prompt_password(alias)
    if pw:
        return ResolvedCredential(
            method=AuthMethod.PASSWORD_PROMPT,
            password=pw,
            key_passphrase=key_passphrase,
        )

    return ResolvedCredential(
        method=AuthMethod.SSH_AGENT,
        key_passphrase=key_passphrase,
    )


def _resolve_key_passphrase(alias: str) -> Optional[str]:
    """Resolve the passphrase for an encrypted SSH key."""
    if _ssh_agent_available():
        return None

    pp = _env_key_passphrase(alias)
    if pp:
        return pp

    pp = _keyring_key_passphrase(alias)
    if pp:
        return pp

    return _prompt_password(alias, purpose="SSH key passphrase")


# ── WinRM credential resolution ─────────────────────────────────────

def resolve_winrm_credential(alias: str, auth_method: str) -> ResolvedCredential:
    """Resolve WinRM credentials for *alias*."""

    if auth_method == "kerberos" and _kerberos_ticket_valid():
        logger.info("using Kerberos ticket for %s", alias)
        return ResolvedCredential(method=AuthMethod.KERBEROS)

    pw = _env_password(alias)
    if pw:
        logger.info("using env-var password for %s", alias)
        return ResolvedCredential(method=AuthMethod.PASSWORD_ENV, password=pw)

    pw = _keyring_password(alias)
    if pw:
        logger.info("using keyring password for %s", alias)
        return ResolvedCredential(method=AuthMethod.PASSWORD_KEYRING, password=pw)

    pw = _prompt_password(alias)
    if pw:
        return ResolvedCredential(method=AuthMethod.PASSWORD_PROMPT, password=pw)

    from core.broker.transport import TransportError
    raise TransportError(
        f"no WinRM credential found for {alias} — set "
        f"RAPTOR_BROKER_PASS_{_env_key(alias)} or store in "
        f"OS keyring with: raptor broker store-cred {alias}"
    )


# ── sshpass wrapper for subprocess SSH (rsync, scp) ──────────────────

def sshpass_prefix(credential: ResolvedCredential) -> list[str]:
    """Return the sshpass command prefix for subprocess-based SSH.

    If the credential has a password and sshpass is available, returns
    ['sshpass', '-e'] and sets SSHPASS in the env (caller must pass
    the returned env dict).  Otherwise returns [] (fall through to
    agent or askpass).
    """
    if credential.password and _sshpass_available():
        return ["sshpass", "-e"]
    return []


def sshpass_env(credential: ResolvedCredential) -> dict[str, str]:
    """Return env-var additions for sshpass.  Merge into subprocess env."""
    if credential.password and _sshpass_available():
        return {"SSHPASS": credential.password}
    if credential.password and os.environ.get("SSH_ASKPASS"):
        return {"SSH_ASKPASS_PASSWORD": credential.password}
    return {}


def ssh_askpass_env(credential: ResolvedCredential) -> dict[str, str]:
    """Return SSH_ASKPASS env setup for non-interactive password passing.

    When sshpass isn't available but we have a password, sets up a
    minimal SSH_ASKPASS script that echoes the password.  This works
    in CI environments without a TTY.
    """
    if not credential.password:
        return {}
    if _sshpass_available():
        return {}

    import tempfile
    import stat

    script = tempfile.NamedTemporaryFile(
        mode="w", prefix="raptor-askpass-", suffix=".sh",
        delete=False,
    )
    script.write("#!/bin/sh\n")
    script.write(f'echo "{credential.password}"\n')
    script.close()
    os.chmod(script.name, stat.S_IRWXU)

    return {
        "SSH_ASKPASS": script.name,
        "SSH_ASKPASS_REQUIRE": "force",
        "DISPLAY": os.environ.get("DISPLAY", ":0"),
    }
