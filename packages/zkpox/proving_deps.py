"""Availability probe + guard for the Tier 2/3 ZKPoX proving stack.

Single source of truth for "is the heavy ZK proving toolchain
installed here?" — consumed by both the runtime (the future
``prove`` / ``verify`` entry points, which guard on
:func:`require_proving_stack`) and tests (which skip on
``not proving_stack_available()``).

The point is to keep the dependency-free tiers importable. Tiers
0/1 (eligibility, bundles) and 1.5 (reproduction) ship today and
must keep importing on a box with none of the proving stack
present. So the heavy deps (SP1 / RISC-V toolchain) are NEVER
imported at module load — they're probed here, and the actual
imports live lazily inside the prove/verify code paths that
``require_proving_stack`` gates. Importing ``packages.zkpox`` stays
cheap; only *invoking* a Tier 2/3 operation can fail on missing
deps.

This module is deliberately separate from the (not-yet-landed)
prover implementation: ``proving_deps`` is the gate, a future
``prover`` / ``proving`` module is the SP1 guts. Keeping them apart
means the gate can ship — and tests can reference it — before the
prover exists.
"""

from __future__ import annotations

import functools
import shutil

# SP1's prover ships its toolchain as a cargo subcommand (`cargo
# prove`, binary `cargo-prove`). This is the cheapest reliable
# "is the stack here?" signal. When the Tier 2/3 prover lands it
# should confirm / extend this set (e.g. add a RISC-V target check
# or a python-binding import) — erring toward "unavailable" when
# uncertain is correct, since a false "available" would make the
# prover refuse on a genuinely-equipped box only after doing work.
_PROVING_BINARIES = ("cargo-prove",)


class ProvingStackUnavailable(RuntimeError):
    """Raised when a Tier 2/3 operation (prove / verify) is invoked
    on a host without the proving toolchain installed."""


@functools.lru_cache(maxsize=1)
def proving_stack_available() -> bool:
    """``True`` iff the SP1 / RISC-V proving toolchain is usable here.

    Cached: the answer can't change within a process, and the probe
    (PATH lookups, eventually a subprocess / import) isn't free.
    Call :func:`proving_stack_available.cache_clear` in tests that
    monkeypatch the underlying probe.
    """
    return all(shutil.which(b) is not None for b in _PROVING_BINARIES)


def require_proving_stack() -> None:
    """Guard for the prove / verify entry points.

    Raises :class:`ProvingStackUnavailable` with an actionable
    message when the stack is absent — so the dependency-free tiers
    stay importable and only an actual Tier 2/3 invocation surfaces
    the missing-deps error.
    """
    if not proving_stack_available():
        raise ProvingStackUnavailable(
            "ZKPoX Tier 2/3 proving requires the SP1 / RISC-V "
            "proving toolchain, which isn't installed on this host. "
            "Tiers 0/1 and 1.5 (eligibility, bundle assembly, native "
            "reproduction) do not need it and continue to work. "
            "Install the proving toolchain to enable `prove` / "
            "`verify`."
        )
