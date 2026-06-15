"""Regression guard for the env-supplied-warning spam ferr079
surfaced on PR #777.

When a caller supplies ``env=`` to ``sandbox()``, the sandbox logged a
WARNING saying "Pass strict_env=True to ... strip DANGEROUS_ENV_VARS".
Pre-fix the warning fired regardless of whether the caller HAD already
passed ``strict_env=True`` — operators got the warning ~12× per scan
run while doing the documented mitigation, with no way to silence.

Gate the warning on ``not strict_env``: callers who have opted into
the safe-rebound get quiet output. Callers without strict_env still
see the warning (they should — env= without the strip is the
genuine bypass case the warning exists to surface).

Tests drive a real ``profile="none"`` sandbox (no kernel engagement,
fast) so the env-handling block is exercised end-to-end, and patch
``logger.warning`` to capture what would have been emitted."""

import sys as _sys
import pytest as _pytest
pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals",
)

from unittest.mock import patch


def _run_envcheck(strict_env: bool):
    """Run a ``profile="none"`` sandbox with a caller-supplied ``env=``
    and the given ``strict_env``. Captures every ``logger.warning``
    call made during the run and returns the formatted messages.

    profile="none" means no kernel sandbox engagement — the child
    just exec's /usr/bin/true. Fast, no real-sandbox cost; the env-
    handling block we're testing still runs."""
    from core.sandbox import context as ctx

    captured: list[str] = []

    def _capture(msg, *args, **kwargs):
        try:
            captured.append(msg % args if args else msg)
        except Exception:
            captured.append(str(msg))

    with patch.object(ctx.logger, "warning", side_effect=_capture):
        with ctx.sandbox(profile="none") as run:
            try:
                run(
                    ["/usr/bin/true"],
                    env={"FOO": "bar"},
                    strict_env=strict_env,
                    text=True, capture_output=True,
                )
            except Exception:
                # Anything past the env-handling block is fine — the
                # warning fires (or correctly doesn't) before kernel
                # engagement.
                pass
    return captured


class TestEnvWarningSilencedUnderStrictEnv:
    """The ``strict_env=True`` documented-mitigation must silence
    the env-supplied warning. Pre-fix the warning fired regardless."""

    def test_warning_fires_when_strict_env_false(self):
        msgs = _run_envcheck(strict_env=False)
        env_warning_count = sum(
            1 for m in msgs if "get_safe_env() not applied" in m
        )
        assert env_warning_count >= 1, (
            "expected the env-supplied warning to fire when "
            "strict_env=False (caller has not opted into the "
            f"documented mitigation); captured: {msgs}"
        )

    def test_warning_silenced_when_strict_env_true(self):
        msgs = _run_envcheck(strict_env=True)
        env_warning_count = sum(
            1 for m in msgs if "get_safe_env() not applied" in m
        )
        assert env_warning_count == 0, (
            "expected the env-supplied warning to be silenced when "
            "strict_env=True (the warning literally tells callers to "
            "pass strict_env=True as the mitigation; firing it after "
            f"they comply is contradictory noise); captured: {msgs}"
        )
