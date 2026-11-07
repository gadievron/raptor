"""Shared strict backend checks and early scan preflight.

The context and CLI share requirements and diagnostics. Capability checks are
not a replacement for enforcement checks when an actual child is started.
"""
from __future__ import annotations

import argparse
import sys

from .errors import SandboxSetupError
from .profiles import PROFILES


def strict_backend_error(*, use_sandbox: bool, use_mount: bool,
                         requires_mount: bool, seccomp_profile: object) -> SandboxSetupError | None:
    from . import seccomp as _seccomp

    if not use_sandbox and sys.platform == "darwin":
        msg = (
            "sandbox profile 'strict' requires the seatbelt "
            "backend, but sandbox-exec is unavailable or failed "
            "its smoke test on this host"
        )
        return SandboxSetupError(
            msg,
            "verify /usr/bin/sandbox-exec exists and can run a "
            "minimal profile; or explicitly choose a profile "
            "that degrades gracefully (e.g. `--sandbox full`). "
            "RAPTOR will not silently downgrade for you.",
        )
    # Linux: collect EVERY unmet strict requirement before
    # raising. Constrained hosts frequently miss several at once
    # (no userns implies no mount-ns; minimal runners lack
    # libseccomp too), and raising on the first check hid the
    # rest — the operator fixed one gate only to hit the next
    # run-through, and the later gates' diagnostics were
    # unobservable wherever an earlier gate also fired. One
    # abort names everything missing.
    unmet: list[tuple[str, str]] = []
    if not use_sandbox:
        from .probes import ENGAGE_FAIL_INSTRUCTIONS
        unmet.append((
            "namespace isolation, but user namespaces are "
            "unavailable on this host",
            ENGAGE_FAIL_INSTRUCTIONS + " For profile 'strict' "
            "specifically, `--sandbox full` is the explicit "
            "step-down: it degrades to Landlock + seccomp with "
            "warnings instead of aborting.",
        ))
    if sys.platform != "darwin" and requires_mount and not use_mount:
        from .probes import mount_unavailable_reason
        condition, fix = mount_unavailable_reason()
        unmet.append((
            "mount-namespace isolation for target/output, "
            f"but {condition}",
            fix + " Or explicitly choose a profile that degrades "
            "gracefully (e.g. `--sandbox full`). RAPTOR will not "
            "silently downgrade for you.",
        ))
    # strict's resolved profile requests a seccomp filter; when
    # libseccomp is absent/broken the filter builder returns None
    # and both spawn paths silently run FILTERLESS — the AF_UNIX
    # blocklist, the io_uring/keyring/bpf blocks and the UDP
    # block all vanish under a profile sold as fail-closed. The
    # engagement report mentioned it; nothing aborted. Require a
    # working libseccomp up front, like the namespace/mount gates
    # above.
    if (sys.platform != "darwin" and seccomp_profile
            and not _seccomp.check_seccomp_available()):
        unmet.append((
            "a seccomp filter, but libseccomp is unavailable or "
            "non-functional on this host — the syscall blocklist "
            "would silently not engage",
            "install libseccomp (libseccomp2 package) so the "
            "filter can load, or explicitly choose a profile that "
            "degrades gracefully (e.g. `--sandbox full`). RAPTOR "
            "will not silently downgrade for you.",
        ))
    if len(unmet) == 1:
        return SandboxSetupError(
            f"sandbox profile 'strict' requires {unmet[0][0]}",
            unmet[0][1],
        )
    if unmet:
        missing = "; ".join(
            f"({i}) {m}" for i, (m, _f) in enumerate(unmet, 1))
        fixes = " ".join(
            f"({i}) {f}" for i, (_m, f) in enumerate(unmet, 1))
        return SandboxSetupError(
            f"sandbox profile 'strict' has {len(unmet)} unmet "
            f"requirements on this host — it requires {missing}",
            fixes,
        )

    return None


def preflight_scan_cli(argv: list[str]) -> None:
    """Check an explicitly requested strict scan before target/worker work.

    Other profiles keep their existing behavior. No host identity, environment
    marker, outer sandbox flag or frontend name selects the policy here.
    """
    options = argv[:argv.index('--')] if '--' in argv else argv
    if '--help' in options or '-h' in options:
        return
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--sandbox', choices=sorted(PROFILES))
    group.add_argument('--no-sandbox', action='store_true')
    args, _ = parser.parse_known_args(options)
    if args.sandbox != 'strict':
        return

    from . import probes
    if sys.platform == 'darwin':
        use_sandbox = probes.check_seatbelt_available()
        use_mount = False
    else:
        use_sandbox = probes.check_net_available()
        use_mount = use_sandbox and probes.check_mount_available()
    error = strict_backend_error(
        use_sandbox=use_sandbox, use_mount=use_mount, requires_mount=True,
        seccomp_profile=PROFILES['strict']['seccomp'],
    )
    if error is not None:
        raise error
