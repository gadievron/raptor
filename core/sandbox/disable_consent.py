"""Consent resolution for the CLI sandbox disable (`--no-sandbox`).

`--no-sandbox` / `--sandbox none` is reachable by anything that can
compose a command line — including an LLM session assembling a
`python3 raptor.py ...` invocation — and it is globally authoritative
once set. This module supplies the gate that
`core.sandbox.cli._set_cli_state("none")` consults: the disable is a
REQUEST for tier NONE, honoured only when a consent of matching
authority exists. Without one the request is refused loudly (never
silently re-enabled, never downgraded — a refusal, so the operator's
intent is never quietly inverted).

Consent sources, in precedence order:

1. **Operator at a terminal (per-run).** Process stdin AND stderr are
   interactive TTYs → the flag was plausibly typed by the operator.
   Returns ``"interactive-tty"``. A Bash-tool-composed child inside an
   LLM session gets PIPE fds and fails this probe by construction.
   Probe errors are treated as non-interactive (fail closed).
2. **Launcher/CI-minted nonce (per-invocation).** ``RAPTOR_NO_SANDBOX_NONCE``
   carries a 128-bit hex nonce that must match a mode-0600, uid-owned
   consent file under the invoking user's home. A boolean env var would
   be attacker-typable data (any argv/env composition could set it);
   the nonce is only valid when a matching file exists on disk, so
   forgery requires a home-directory file write with knowledge of the
   nonce — something argv/env composition alone cannot provide.
   Returns ``"nonce"``.

There is deliberately NO standing project consent ("off" is a debug
posture, not a host condition — the project `sandbox-floor` registry
rule "never none" stays exactly as is) and trust markers grant nothing
here (they assert repo provenance, not host-risk acceptance).

Security invariants for the env var:

- It must NOT be added to ``RaptorConfig.SAFE_ENV_ALLOWLIST`` — a
  scanned repo or spawned target must never inherit consent ambiently.
  Propagation across RAPTOR's own worker spine is site-specific and
  explicit (:func:`export_disable_consent`), only from a parent that
  itself holds an accepted consent.
- It IS a member of ``TARGET_ENV_STRIP_SET`` — target-bound envs
  (code under analysis) never see it.
- The consent-file directory derives from ``pwd.getpwuid(...)``, never
  ``$HOME`` — an env-overridden HOME would let a composed command point
  validation at an attacker-staged directory (e.g. inside the scanned
  repo, where the attacker CAN write files).

The unguarded mint path for CI / operators lives OUTSIDE runtime
source by design: ``core/sandbox/scripts/mint-no-sandbox-nonce`` (dev
tool) and the test-suite conftest fixture. The only in-runtime mint is
:func:`export_disable_consent`, which refuses to mint unless the
current process already holds an ACCEPTED consent — it can extend an
existing grant across a spawn boundary, never create one from nothing.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import pwd
import secrets
import stat
import time
from collections.abc import MutableMapping
from pathlib import Path

from . import state

logger = logging.getLogger(__name__)

# Env var carrying the nonce. Never allowlisted in get_safe_env();
# member of TARGET_ENV_STRIP_SET (pinning tests hold both directions).
NONCE_ENV_VAR = "RAPTOR_NO_SANDBOX_NONCE"

# Nonce length: exactly 32 lowercase-hex chars = 128 bits.
# Shorter would start to matter against offline guessing of the
# digest-derived filename (an attacker who can compose env vars gets
# unlimited offline tries at matching an existing consent file);
# longer buys nothing — 128 bits is already far beyond brute force —
# and makes the operator-visible value clumsier to relay. Format is
# pinned exactly (not "at least") so validation is a constant-shape
# comparison with no parser surface.
NONCE_HEX_LEN = 32

# Consent-file freshness window, seconds. A file older than this no
# longer consents. Shorter would make the mint-then-run operator
# window uncomfortably tight (a CI job may queue for minutes between
# the mint step and the RAPTOR invocation); longer approaches the
# standing consent the sandbox-floor registry rule ("never none")
# exists to prevent — per-invocation consent must stay perishable.
# The nonce is deliberately MULTI-USE within the window, not
# consume-on-validation: one exported consent legitimately covers
# several spine children validating independently (the agentic parent
# extends the SAME still-valid nonce into both the scanner and the
# CodeQL-agent child envs, and each child's gate re-validates it), so
# single-use would refuse the second child mid-run. The accepted
# bound: any same-uid process inside the TTL can reuse a live nonce;
# the uid-owner + mode-0600 + TTL checks are the containment.
NONCE_FILE_TTL_S = 600.0

# Upper bound on the consent file size we are willing to read. The
# legitimate content is one 64-char digest line; 4096 bytes is
# generous slack for trailing whitespace while still refusing to
# slurp an arbitrarily large planted file. Lower would be brittle
# against harmless editor artifacts (trailing newline variants);
# higher serves no legitimate content.
NONCE_FILE_MAX_BYTES = 4096

# Consent-source labels stamped into state / sandbox_info.
CONSENT_INTERACTIVE = "interactive-tty"
CONSENT_NONCE = "nonce"

# Single-line refusal: names the flags, why they are gated, and both
# escape hatches (--audit, and the real consent route). The consent
# route is named by DOCUMENTATION ANCHOR, never by runnable
# mint-script path: the refusal is delivered to whoever composed the
# invocation, and for a refused non-interactive composer a
# copy-pasteable mint command is a bypass recipe. Ergonomics
# direction: the legitimate operator pays one docs lookup; security
# direction: the composer gains no runnable path from the refusal
# itself. (A pinned test holds the no-recipe direction — the script
# path must not reappear here.)
REFUSAL_MESSAGE = (
    "--no-sandbox / --sandbox none refused: disabling the sandbox runs "
    "untrusted target code bare, so it needs matching-authority consent "
    "— an interactive terminal on stdin+stderr, or a minted "
    "RAPTOR_NO_SANDBOX_NONCE (mint procedure: docs/sandbox.md, "
    "\"Disabling the sandbox\") — and this invocation has neither. To "
    "debug enforcement without going bare, keep the sandbox and pass "
    "--audit (logs what enforcement would have blocked)."
)

_HEX_DIGITS = frozenset("0123456789abcdef")


def _consents_dir() -> Path:
    """Directory holding no-sandbox consent files.

    Derived from the passwd database, NOT ``$HOME``: HOME is plain
    env data, so a composed command line could carry
    ``HOME=/scanned/repo/x`` and point validation at a directory the
    attacker can write to. The passwd entry for the current euid is
    kernel-account truth that argv/env composition cannot move.
    """
    home = pwd.getpwuid(os.geteuid()).pw_dir
    return Path(home) / ".local" / "share" / "raptor" / "consents.d"


def _nonce_digest(nonce: str) -> str:
    """Full SHA-256 hex digest of the nonce string."""
    return hashlib.sha256(nonce.encode("ascii")).hexdigest()


def _nonce_filename(nonce: str) -> str:
    """Consent filename for a nonce: digest-derived so a directory
    listing never reveals the presentable value."""
    return f"no-sandbox.{_nonce_digest(nonce)[:32]}"


def _nonce_format_ok(nonce: str) -> bool:
    """Exact-shape check: 32 lowercase-hex chars, nothing else."""
    return (
        isinstance(nonce, str)
        and len(nonce) == NONCE_HEX_LEN
        and all(c in _HEX_DIGITS for c in nonce)
    )


def _nonce_file_consents(path: Path, nonce: str) -> bool:
    """Validate one consent file against a presented nonce. Fail closed.

    Checks, in order: O_NOFOLLOW open (a symlink at the consent path
    is refused, not followed — a same-uid convenience symlink is not a
    consent), regular file, owned by the current euid, no group/other
    permission bits, bounded size, fresh mtime, and content equal to
    the full SHA-256 digest of the presented nonce (constant-time
    compare). Storing the digest — not the nonce — means the file
    alone (a leaked backup, a copied home directory) can never be
    replayed as the env var.
    """
    try:
        fd = os.open(
            str(path),
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError:
        return False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return False
        if st.st_uid != os.geteuid():
            return False
        if st.st_mode & 0o077:
            # Group/other-accessible consent files are refused: a
            # loosely-permissioned file is not evidence the account
            # owner minted it.
            return False
        if st.st_size > NONCE_FILE_MAX_BYTES:
            return False
        age = time.time() - st.st_mtime
        # Negative age (mtime in the future) fails closed too — a
        # legitimate mint is always in the past on the same host.
        if not (0 <= age <= NONCE_FILE_TTL_S):
            return False
        content = os.read(fd, NONCE_FILE_MAX_BYTES).decode(
            "ascii", errors="replace").strip()
        return hmac.compare_digest(content, _nonce_digest(nonce))
    except OSError:
        return False
    finally:
        os.close(fd)


def _presented_nonce_valid(nonce: str) -> bool:
    """True when the presented env-var nonce matches a valid, fresh,
    uid-owned consent file. Any error → False (fail closed)."""
    try:
        if not _nonce_format_ok(nonce):
            return False
        return _nonce_file_consents(
            _consents_dir() / _nonce_filename(nonce), nonce)
    except Exception:  # noqa: BLE001 — consent resolution must fail closed
        return False


def resolve_disable_consent() -> str | None:
    """Resolve the consent source for a CLI sandbox disable.

    Returns ``"interactive-tty"``, ``"nonce"``, or ``None`` (refuse).
    Precedence mirrors ``resolve_untrusted_floor``: the operator at a
    terminal outranks the minted nonce. Every probe failure resolves
    toward None — non-interactive, fail closed.
    """
    try:
        if os.isatty(0) and os.isatty(2):
            return CONSENT_INTERACTIVE
    except Exception:  # noqa: BLE001 — TTY probe errors are non-interactive
        pass
    nonce = os.environ.get(NONCE_ENV_VAR)
    if nonce is not None and _presented_nonce_valid(nonce):
        return CONSENT_NONCE
    return None


def _sweep_expired(consents_dir: Path) -> None:
    """Best-effort removal of expired consent files (mint-time
    housekeeping — per-spawn mints would otherwise accumulate)."""
    try:
        now = time.time()
        for entry in consents_dir.iterdir():
            if not entry.name.startswith("no-sandbox."):
                continue
            try:
                st = entry.lstat()
                if not stat.S_ISREG(st.st_mode):
                    continue
                if now - st.st_mtime > NONCE_FILE_TTL_S:
                    entry.unlink()
            except OSError:
                continue
    except OSError:
        pass


def _mint_nonce(consents_dir: Path | None = None) -> str:
    """Mint a fresh nonce + consent file; returns the nonce.

    Module-private: the only runtime caller is
    :func:`export_disable_consent`, which is guarded on an already-
    accepted consent. The unguarded CI/operator mint path lives
    outside runtime source (core/sandbox/scripts/, tests conftest).
    """
    d = consents_dir if consents_dir is not None else _consents_dir()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    _sweep_expired(d)
    nonce = secrets.token_hex(NONCE_HEX_LEN // 2)
    path = d / _nonce_filename(nonce)
    fd = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(fd, (_nonce_digest(nonce) + "\n").encode("ascii"))
    finally:
        os.close(fd)
    return nonce


def export_disable_consent(env: MutableMapping[str, str]) -> None:
    """Extend this process's ACCEPTED disable consent to one child env.

    RAPTOR pipeline parents (e.g. the agentic orchestrator) spawn
    scanner workers with ``stdout/stderr=PIPE`` and a
    ``get_safe_env()``-scrubbed environment, forwarding the sandbox
    flags on the worker command line. The worker's own gate then sees
    neither a TTY nor the parent's nonce — so a parent that already
    holds an accepted consent injects a valid nonce into the specific
    child env here. This is consent PROPAGATION, not creation: when
    the current process is not in the accepted-disable state, this
    function does nothing (it can never mint a grant from nothing).

    Reuses the parent's own env nonce when it is still valid (the
    CI lane), otherwise mints a fresh file (the interactive-TTY lane,
    and the CI lane after the parent's nonce aged out mid-run).
    """
    if not (state._cli_sandbox_disabled
            and state._cli_sandbox_disable_consent):
        return
    nonce = os.environ.get(NONCE_ENV_VAR)
    if nonce is None or not _presented_nonce_valid(nonce):
        nonce = _mint_nonce()
    env[NONCE_ENV_VAR] = nonce


def passthrough_nonce_env(env: MutableMapping[str, str]) -> None:
    """Forward an inherited nonce var to one child env, verbatim.

    For RAPTOR spine processes that scrub the child environment via
    ``get_safe_env()`` but do NOT parse the sandbox flags themselves
    (``raptor.py`` forwards argv to ``raptor_<mode>.py``, which does
    the parsing): the scrub would silently drop a CI-minted nonce
    before it reaches the process that runs the gate. Copying the
    variable grants nothing by itself — consent still requires the
    matching uid-owned consent file, which the CHILD validates — so
    this is capability forwarding along RAPTOR's own worker spine,
    not an allowlist entry (the var stays out of SAFE_ENV_ALLOWLIST;
    generic/target-bound children never inherit it).
    """
    nonce = os.environ.get(NONCE_ENV_VAR)
    if nonce is not None:
        env[NONCE_ENV_VAR] = nonce
