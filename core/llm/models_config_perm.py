"""Permission posture for the operator's ``models.json``.

``models.json`` carries inline API keys when the operator uses the
``api_key`` field, and TWO independent loaders read the identical file
($RAPTOR_CONFIG when set, else ``~/.config/raptor/models.json``):

* the dispatcher credential seeder
  (``core.llm.dispatcher.auth.seed_from_config``), and
* the direct model-config loader
  (``core.llm.detection._read_config_models``, reached through
  ``core.llm.config._get_configured_models`` by every ``--model`` run,
  the default-primary resolution, and ``raptor-llm-ask``).

Both must apply ONE gate with identical semantics — a fail-closed
refusal on only one of them just moves the exposure onto the other
loader's consumers. This module is that single implementation:

* group/other-readable mode (any ``0o077`` bit) + inline ``api_key``
  entries → :class:`WorldReadableModelsConfigError` naming the exact
  ``chmod 600`` remedy and the override env;
* ``RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON=1`` (exactly ``"1"``) →
  load with a loud acknowledged-override warning;
* loose mode with NO inline keys → hygiene warning only;
* private (0600) file → silent.

Key VALUES never appear in any message. This is a leaf module (stdlib
only) so both the dispatcher package and the detection/config chain can
import it without cycles.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


class WorldReadableModelsConfigError(RuntimeError):
    """``models.json`` is group/other-readable AND carries inline API
    keys — another local UID can read the credentials off disk.

    Raised by both loaders' permission gates instead of silently
    loading the exposed keys. The message carries the exact
    ``chmod 600`` remedy and the
    ``RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON=1`` override so an
    operator is never bricked without an escape hatch."""


# Operator consent env for loading a group/other-readable models.json
# that carries inline API keys. Value must be exactly "1" — a consent
# this sharp should never be truthy-parsed.
_ALLOW_WORLD_READABLE_ENV = "RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON"


# (config path, warning kind) pairs already warned about. The direct
# loader (``_read_config_models``) runs many times per process, so the
# hygiene and acknowledged-override warnings would otherwise spam once
# per config read. REFUSALS are never deduplicated — fail-closed must
# fail closed every time.
_warned: set[tuple[str, str]] = set()


def _warn_once(kind: str, config_path: Path, message: str,
               *args: object) -> None:
    key = (str(config_path), kind)
    if key in _warned:
        return
    _warned.add(key)
    logger.warning(message, *args)


def loose_mode_bits(config_path: Path) -> int | None:
    """The file's mode (``0o777``-masked) when any group/other bit is
    set, else ``None``.

    ``None`` also on Windows (POSIX bits don't have the same meaning)
    and on stat failure (a missing/unreadable file surfaces naturally
    on the subsequent read). ``Path.stat`` follows symlinks, so the
    verdict is about the TARGET the keys actually live in.
    """
    if sys.platform == "win32":
        return None
    try:
        st = config_path.stat()
    except OSError:
        return None
    if st.st_mode & 0o077:
        return st.st_mode & 0o777
    return None


def refuse_exposed_inline_keys(
    config_path: Path, loose_mode: int, entries: list,
) -> None:
    """Fail closed on a group/other-readable models.json that carries
    inline API keys.

    * No inline keys → hygiene warning only (``chmod 600`` advice);
      nothing sensitive is in the file, so refusing would be pure
      friction for routing-only configs.
    * Inline keys + ``RAPTOR_ALLOW_WORLD_READABLE_MODELS_JSON=1`` →
      loud acknowledged-override warning, then load. The consent env
      exists so an operator on a box where the mode is deliberate
      (single-user container, ACL-managed share) is never bricked.
    * Inline keys, no consent → :class:`WorldReadableModelsConfigError`
      with the exact remedy. Key VALUES never appear in the message.

    Warnings print once per (path, kind) per process; the refusal is
    raised on every call.
    """
    carries_keys = any(
        isinstance(e, dict) and isinstance(e.get("api_key"), str)
        and e.get("api_key")
        for e in entries
    )
    if not carries_keys:
        _warn_once(
            "hygiene", config_path,
            "models.json at %s is mode %04o — it carries no inline "
            "API keys today, but would expose them to other local "
            "users if added. Consider `chmod 600 %s`.",
            config_path, loose_mode, config_path,
        )
        return
    if os.environ.get(_ALLOW_WORLD_READABLE_ENV) == "1":
        _warn_once(
            "override", config_path,
            "models.json at %s is mode %04o and carries inline API "
            "keys readable by other local users — loading anyway "
            "because %s=1 is set. `chmod 600 %s` and drop the "
            "override to close the exposure.",
            config_path, loose_mode, _ALLOW_WORLD_READABLE_ENV,
            config_path,
        )
        return
    raise WorldReadableModelsConfigError(
        f"refusing to load credentials from {config_path}: the file "
        f"is mode {loose_mode:04o} (group/other-readable) and carries "
        f"inline API keys — any local user can read them. Fix: "
        f"`chmod 600 {config_path}`. To accept the exposure "
        f"deliberately (e.g. single-user container), set "
        f"{_ALLOW_WORLD_READABLE_ENV}=1."
    )


__all__ = [
    "WorldReadableModelsConfigError",
    "loose_mode_bits",
    "refuse_exposed_inline_keys",
]
