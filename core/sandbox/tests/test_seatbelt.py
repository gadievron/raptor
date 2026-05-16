"""SBPL profile generation tests — cross-platform.

These tests exercise ``core.sandbox.seatbelt.build_profile`` purely as
string generation; they don't invoke ``sandbox-exec`` so they run on
Linux too. The macOS-only end-to-end tests (which need the kernel
Sandbox.kext to enforce the profile) live in test_macos_spawn.py.

Coverage focus matches the spike-validated facts in seatbelt.py:
  * `(allow default)` baseline (not deny-default)
  * ``os.path.realpath()`` applied to write_exceptions paths
  * ``(deny X (require-not (subpath Y)))`` deny-with-exception idiom
  * Audit mode replaces deny with ``(allow X (with report))``
  * Network deny + egress proxy port allowance
"""

from __future__ import annotations

import os

from core.sandbox import seatbelt


def test_baseline_is_allow_default():
    """Pure deny-default SIGABRTs modern macOS binaries before dyld can
    load libSystem (spike #1 result rc=-6). We MUST emit allow-default
    + targeted denies; regressing to deny-default would silently break
    every sandboxed call on macOS."""
    p = seatbelt.build_profile()
    assert "(allow default)" in p
    # Defensive: never accidentally emit a hard deny-default.
    assert "(deny default)" not in p


def test_version_pragma_first():
    """SBPL requires (version 1) before any rule. Out-of-order or
    missing version pragma rejects the profile."""
    lines = seatbelt.build_profile().splitlines()
    assert lines[0] == "(version 1)"


def test_write_exceptions_use_realpath(tmp_path):
    """Spike #3: SBPL (subpath ...) matches the canonical resolved
    path. On macOS, /tmp resolves to /private/tmp via a symlink; if we
    pass the symlink path, the write-allowlist exception silently
    fails to match. tmp_path under pytest is typically already a
    realpath, but this test asserts that whatever we pass IS the
    realpath that ends up in the profile."""
    output = str(tmp_path / "out")
    os.makedirs(output, exist_ok=True)
    p = seatbelt.build_profile(output=output)
    expected = os.path.realpath(output)
    assert f'(subpath "{expected}")' in p


def test_write_exceptions_include_private_tmp(tmp_path):
    """The /tmp default mirrors Linux Landlock's default /tmp in
    writable_paths — many tools materialise temp files there. Spike
    confirmed /private/tmp is the canonical realpath; emitting /tmp
    directly would not match. Only emitted when write-isolation is
    engaged (any of output/writable_paths/target/restrict_reads)."""
    p = seatbelt.build_profile(output=str(tmp_path))
    assert '(subpath "/private/tmp")' in p


def test_writable_paths_appended():
    """Caller-supplied writable_paths join the default exception
    list (alongside output and /private/tmp)."""
    extra = "/some/writable/dir"
    p = seatbelt.build_profile(writable_paths=[extra])
    assert f'(subpath "{extra}")' in p


def test_writable_paths_dedup(tmp_path):
    """A path passed in BOTH output= and writable_paths= must not
    appear twice — duplicate (subpath ...) clauses parse fine but
    needlessly bloat the profile and obscure the diff."""
    output = str(tmp_path / "out")
    os.makedirs(output, exist_ok=True)
    p = seatbelt.build_profile(output=output, writable_paths=[output])
    real = os.path.realpath(output)
    assert p.count(f'(subpath "{real}")') == 1


def test_enforcement_uses_require_not_idiom(tmp_path):
    """Spike #2: plain ordering `(deny X)(allow X subpath)` doesn't
    work — explicit deny outranks subsequent allow. The (deny X
    (require-not Y)) clause is the canonical SBPL way to express
    "deny X except where Y matches"."""
    p = seatbelt.build_profile(output=str(tmp_path))
    assert "(deny file-write* (require-not" in p


def test_multi_path_uses_require_any_for_union_semantics(tmp_path):
    """SBPL idioms tried + verified on macOS 26.4.1:

      (a) (require-not (subpath A) (subpath B))
            → sandbox-exec REJECTS: "too many arguments to require-
              not". `require-not` is UNARY.
      (b) (deny X (require-not A) (require-not B))
            → parses but semantics are OR-on-the-deny:
              ≡ deny X UNLESS (A AND B)  ← intersection
              Wrong: writes inside A get denied unless they're ALSO
              inside B.
      (c) (deny X (require-not (require-any A B)))
            → CORRECT: `require-any` is multi-arg, so the inner
              expression is "A OR B"; require-not negates to NOT
              (A OR B); deny when neither matches; allow if in
              either A OR B. This is the Landlock-equivalent
              "writable_paths is a union" semantic.

    This test catches regressions back to (a) or (b) by asserting
    structurally on the output."""
    output = str(tmp_path / "out")
    extra = str(tmp_path / "extra")
    import os
    os.makedirs(output, exist_ok=True)
    os.makedirs(extra, exist_ok=True)
    p = seatbelt.build_profile(output=output, writable_paths=[extra])
    # Must use (require-not (require-any ...)) — exactly one
    # require-any wrapping all the subpaths.
    assert "(require-not (require-any " in p, (
        f"expected (require-not (require-any ...)) idiom; got:\n{p}"
    )
    # Three exception paths: /private/tmp + output + extra → all
    # three (subpath ...) must live inside ONE require-any clause.
    import re
    require_any_match = re.search(
        r"\(require-any\s+((?:\(subpath [^)]+\)\s*)+)\)", p
    )
    assert require_any_match, "no (require-any (subpath ...) ...) found"
    inside = require_any_match.group(1)
    assert inside.count("(subpath ") == 3, (
        f"expected 3 subpaths inside require-any, got: {inside}"
    )
    # Regression catch for form (b): we should NOT see multiple
    # (require-not ...) clauses on the same deny (each holding one
    # subpath) — that was the OR-semantics bug.
    assert p.count("(require-not (subpath ") == 0, (
        "found bare (require-not (subpath ...)) — the OR-semantics "
        f"bug pattern. Profile:\n{p}"
    )


def test_audit_mode_replaces_deny_with_report():
    """Spike #4: (allow file-write* (with report)) makes writes
    succeed AND emit kernel sandbox log entries that LogStreamer
    captures. In audit mode we MUST NOT emit a (deny file-write*) —
    that would block writes despite "audit means observe". audit_mode
    only triggers the replace when write-isolation would have engaged
    (output= here engages it)."""
    p = seatbelt.build_profile(audit_mode=True, output="/tmp/out")
    assert "(allow file-write* (with report))" in p
    assert "(deny file-write*" not in p


def test_audit_mode_alone_omits_write_clause():
    """audit_mode=True with no fs-isolation kwargs produces NO file-
    write clause at all. The (allow default) baseline already permits
    writes; replacing a non-existent deny is a no-op. Matches the
    network-only-equivalent semantics where writes are unrestricted."""
    p = seatbelt.build_profile(audit_mode=True)
    assert "file-write*" not in p


def test_audit_mode_does_not_emit_write_deny():
    """Defensive: even with output= and writable_paths= set, audit
    mode must NOT emit a deny clause — those args become
    informational (operators see them in profile dumps; kernel
    enforcement is replaced by reporting)."""
    p = seatbelt.build_profile(
        output="/tmp",
        writable_paths=["/some/dir"],
        audit_mode=True,
    )
    assert "(deny file-write*" not in p


def test_block_network_emits_deny_network():
    p = seatbelt.build_profile(block_network=True)
    assert "(deny network*)" in p


def test_no_block_network_omits_deny_network():
    p = seatbelt.build_profile(block_network=False)
    assert "(deny network*)" not in p


def test_egress_proxy_implies_block_with_port_allow():
    """use_egress_proxy=True is shorthand for "block all network
    except the loopback proxy port". Profile must (a) deny network*
    and (b) re-allow network-outbound to localhost:<proxy_port>."""
    p = seatbelt.build_profile(use_egress_proxy=True, proxy_port=4567)
    assert "(deny network*)" in p
    assert "(allow network-outbound" in p
    assert 'localhost:4567' in p


def test_network_deny_then_allow_idiom_pinned():
    """Pin the (deny network*) + (allow network-outbound ...)
    pattern. Verified end-to-end on macOS 26.4.1 — the more-
    specific allow overrides the broader deny for network rules
    (different from file-* rules where explicit deny outranks any
    subsequent allow). Apple's own SBPL profiles use this idiom.

    A future refactor that "defensively" wraps network in a
    `(deny network* (require-not (require-any ...)))` clause —
    matching the file-write pattern — works equivalently but is
    less idiomatic. Keep this test green to catch accidental
    inversion (e.g., emitting the allow BEFORE the deny, which
    DOES break — `(allow network-outbound)` followed by
    `(deny network*)` blocks the proxy port)."""
    p = seatbelt.build_profile(use_egress_proxy=True, proxy_port=4567)
    lines = [l.strip() for l in p.splitlines() if l.strip()]
    deny_idx = next(i for i, l in enumerate(lines)
                    if l == "(deny network*)")
    allow_idxs = [i for i, l in enumerate(lines)
                   if l.startswith("(allow network-outbound")]
    assert allow_idxs, "no allow-network-outbound clause emitted"
    # The allow MUST come after the deny so the more-specific
    # later rule wins. Inverting the order silently blocks the
    # proxy port — caught by this assertion.
    assert all(i > deny_idx for i in allow_idxs), (
        f"allow-network-outbound clauses must follow (deny "
        f"network*); deny at line {deny_idx}, allows at {allow_idxs}"
    )


def test_egress_proxy_emits_both_v4_and_v6():
    """The HTTPS_PROXY env we set is hostname-based; depending on
    resolver order (which we don't control inside the child) the
    child may connect via tcp4 or tcp6. Both must be allowed."""
    p = seatbelt.build_profile(use_egress_proxy=True, proxy_port=4567)
    assert "tcp4" in p
    assert "tcp6" in p


def test_allowed_tcp_ports_emitted():
    """Caller-supplied port allowlist (e.g. allowed_tcp_ports=[443])
    becomes (allow network-outbound (remote tcp "*:443")) clauses."""
    p = seatbelt.build_profile(
        block_network=True,
        allowed_tcp_ports=[443, 8443],
    )
    assert '"*:443"' in p
    assert '"*:8443"' in p


def test_restrict_reads_emits_deny_read_with_exceptions(tmp_path):
    """restrict_reads=True mirrors the Linux read-allowlist behaviour
    (Landlock's path_beneath denies reads outside the listed dirs).
    Profile must emit:
      1. `(allow file-read-metadata)` so path traversal works
         everywhere (stat/readdir on any inode is permissive — just
         metadata, not content).
      2. `(deny file-read-data (require-not ...))` with the
         system-dirs allowlist + output + readable_paths.
    The split prevents readdir-of-/ leaking the top-level directory
    listing (info leak) while keeping dyld + standard tools
    functional."""
    output = str(tmp_path / "out")
    os.makedirs(output, exist_ok=True)
    p = seatbelt.build_profile(
        output=output,
        restrict_reads=True,
        readable_paths=["/opt/myapp"],
    )
    assert "(allow file-read-metadata)" in p
    assert "(deny file-read-data (require-not" in p
    assert '(subpath "/usr")' in p
    assert '(subpath "/opt/myapp")' in p


def test_restrict_reads_audit_mode_emits_allow_with_report():
    """Audit mode + restrict_reads: log-don't-block, same idea as
    writes. Each unauthorised read becomes an audit record."""
    p = seatbelt.build_profile(restrict_reads=True, audit_mode=True)
    assert "(allow file-read* (with report))" in p
    assert "(deny file-read*" not in p


def test_restrict_reads_off_omits_read_deny():
    """Default (restrict_reads=False) must NOT emit any file-read*
    clause — reads are unrestricted by the (allow default) baseline."""
    p = seatbelt.build_profile()
    assert "file-read*" not in p


def test_quote_sbpl_escapes_quotes_and_backslashes():
    """Defensive: a path containing " or \\ must be safely quoted so
    it doesn't break the surrounding (subpath "...") expression. SBPL
    uses backslash-escapes inside double-quoted strings."""
    assert seatbelt._quote_sbpl('plain') == '"plain"'
    assert seatbelt._quote_sbpl('with "quote"') == '"with \\"quote\\""'
    assert seatbelt._quote_sbpl('with\\backslash') == '"with\\\\backslash"'


def test_quote_sbpl_rejects_control_chars():
    """SBPL injection guard: a path with newline / NUL / any control
    character must be rejected, not naively escaped. SBPL parser is
    whitespace-sensitive — `\\n` closes the s-expression and lets an
    attacker-controlled path inject a fresh clause that overrides
    the deny. Caught before the string ever reaches sandbox-exec."""
    import pytest
    with pytest.raises(ValueError, match="control character"):
        seatbelt._quote_sbpl("/tmp/x\n(allow file-write*)")
    with pytest.raises(ValueError, match="control character"):
        seatbelt._quote_sbpl("/tmp/x\x00")
    with pytest.raises(ValueError, match="control character"):
        seatbelt._quote_sbpl("/tmp/x\t")
    with pytest.raises(ValueError, match="control character"):
        seatbelt._quote_sbpl("/tmp/x\r")


def test_build_profile_rejects_path_with_newline():
    """End-to-end: an attacker-controlled output= with embedded
    newline must fail loudly, not silently produce an injected
    profile. The build_profile entry funnels through _quote_sbpl
    for every path-bearing clause."""
    import pytest
    with pytest.raises(ValueError, match="control character"):
        seatbelt.build_profile(output="/tmp/x\n(allow file-write*)")
    with pytest.raises(ValueError, match="control character"):
        seatbelt.build_profile(writable_paths=["/tmp/x\nevil"])


def test_realpath_or_none_handles_falsy():
    assert seatbelt._realpath_or_none(None) is None
    assert seatbelt._realpath_or_none("") is None


def test_realpath_or_none_canonicalises_symlink(tmp_path):
    """The whole point of _realpath_or_none — symlink targets are
    resolved before SBPL emission."""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real_dir)
    resolved = seatbelt._realpath_or_none(str(link))
    assert resolved == os.path.realpath(str(real_dir))


def test_target_does_not_appear_in_write_exceptions(tmp_path):
    """target= is a read-only engagement marker; it must NOT make
    the path writable. (Reads are allowed by the allow-default
    baseline — target's purpose is engagement signalling, not
    permission grant.)"""
    target = str(tmp_path / "target")
    os.makedirs(target, exist_ok=True)
    p = seatbelt.build_profile(target=target)
    real = os.path.realpath(target)
    # The deny clause's exception list must NOT include target.
    # We check by extracting the require-not clause and confirming.
    assert f'(subpath "{real}")' not in p


def test_empty_inputs_produce_permissive_profile():
    """No kwargs at all → no write-deny clause emitted. Matches the
    Linux semantics for `--sandbox network-only` / `--sandbox none`
    profiles where Landlock is disabled and writes are unrestricted.
    Without this gate, the macOS path would over-restrict
    network-only mode (writes blocked outside /private/tmp)."""
    p = seatbelt.build_profile()
    assert p.startswith("(version 1)\n(allow default)\n")
    # No write isolation engaged → no file-write deny.
    assert "file-write*" not in p


def test_network_only_equivalent_omits_write_deny():
    """Profile parity: Linux `--sandbox network-only` engages
    block_network=True with use_landlock=False. The macOS equivalent
    (block_network=True with no fs args) must NOT emit the file-write
    deny — otherwise the macOS profile is strictly more restrictive
    than its Linux namesake, breaking the operator's "network-only"
    contract."""
    p = seatbelt.build_profile(block_network=True)
    assert "(deny network*)" in p
    assert "file-write*" not in p


def test_writable_paths_alone_engages_write_deny():
    """Caller-supplied writable_paths is a positive signal that they
    want fs isolation — engage the write-deny even without output=."""
    p = seatbelt.build_profile(writable_paths=["/some/path"])
    assert "(deny file-write*" in p
    assert '(subpath "/some/path")' in p


def test_restrict_reads_engages_write_deny_too():
    """If a caller wants reads restricted, they almost certainly want
    writes restricted too — otherwise the child can write a binary
    then exec it, defeating the read-allowlist's secret-protection
    purpose."""
    p = seatbelt.build_profile(restrict_reads=True)
    assert "(deny file-write*" in p


def test_sandbox_kext_sender_constant():
    """The senderImagePath constant is exported from seatbelt.py for
    seatbelt_audit.py to import. Both modules must use the same
    string — divergence would silently break audit log filtering."""
    assert (seatbelt.SANDBOX_KEXT_SENDER ==
            "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox")


# --- seccomp_profile-equivalent SBPL hardening ------------------------

def test_seccomp_profile_none_omits_process_info_deny():
    """Default (no seccomp_profile) leaves the (allow default)
    process introspection alone. Tools like ps, top, lldb that
    introspect other processes must still work in this mode."""
    p = seatbelt.build_profile()
    assert "process-info" not in p


def test_seccomp_profile_full_emits_process_info_deny():
    """Linux's "full" seccomp blocks ptrace. Closest macOS analogue
    is denying introspection of OTHER processes' pidinfo / pidfdinfo.
    `(target others)` keeps self-introspection working."""
    p = seatbelt.build_profile(seccomp_profile="full")
    assert "(deny process-info-pidinfo (target others))" in p
    assert "(deny process-info-pidfdinfo (target others))" in p


def test_seccomp_profile_none_string_omits_deny():
    """`seccomp_profile="none"` is the explicit "no syscall filter"
    sentinel — must NOT engage the macOS hardening either."""
    p = seatbelt.build_profile(seccomp_profile="none")
    assert "process-info" not in p


def test_seccomp_profile_with_audit_mode_uses_report():
    """Under audit mode, process-info denies become (allow ...
    (with report)) so introspection succeeds AND emits an audit
    record — same observe-don't-block pattern as file writes."""
    p = seatbelt.build_profile(seccomp_profile="full", audit_mode=True)
    assert "(allow process-info* (with report))" in p
    assert "(deny process-info" not in p


def test_seccomp_profile_debug_omits_introspection_denies():
    """Linux's `--sandbox debug` is "full minus ptrace block" so
    gdb/rr can attach to the sandboxed target. The macOS analogue
    must keep process-info-* on `target others` unrestricted so
    lldb / sample / dtrace can introspect — same intent both
    platforms. Regression catch: any earlier behaviour where
    "debug" engaged the same hardening as "full" silently broke
    the debugger UX on macOS."""
    p = seatbelt.build_profile(seccomp_profile="debug")
    assert "(deny process-info-pidinfo" not in p
    assert "(deny process-info-pidfdinfo" not in p


def test_seccomp_profile_full_distinct_from_debug():
    """Pin the distinction: full engages introspection denies,
    debug does not. If someone refactors and accidentally collapses
    them, this test catches it."""
    full = seatbelt.build_profile(seccomp_profile="full")
    debug = seatbelt.build_profile(seccomp_profile="debug")
    assert "(deny process-info-pidinfo" in full
    assert "(deny process-info-pidinfo" not in debug


# --- audit_verbose (Phase 2c) ------------------------------------------

def test_audit_verbose_off_omits_extended_audit():
    """Default (audit_mode=False, audit_verbose=False) → no extended
    audit category clauses. Regression catch."""
    p = seatbelt.build_profile()
    assert "mach-lookup" not in p
    assert "process-exec" not in p
    assert "process-fork" not in p
    assert "signal" not in p


def test_audit_verbose_requires_audit_mode():
    """audit_verbose alone (without audit_mode) is operator confusion
    — same constraint Linux enforces. The build_profile silently
    skips the verbose clauses if audit_mode is not also True."""
    p = seatbelt.build_profile(audit_verbose=True)
    assert "(allow file-read-data (with report))" not in p
    assert "(allow mach-lookup (with report))" not in p


def test_audit_verbose_with_audit_mode_emits_extended_set():
    """audit_mode + audit_verbose → emit (allow X (with report)) for
    each extended category. These ride alongside the file-write
    (with report) from audit_mode."""
    p = seatbelt.build_profile(audit_mode=True, audit_verbose=True,
                                output="/tmp/x")
    # audit_mode clause still present
    assert "(allow file-write* (with report))" in p
    # extended categories
    assert "(allow file-read-data (with report))" in p
    assert "(allow mach-lookup (with report))" in p
    assert "(allow process-exec* (with report))" in p
    assert "(allow process-fork (with report))" in p
    assert "(allow signal (with report))" in p


def test_restrict_reads_dev_is_narrow_not_wholesale():
    """Parity with Linux: /dev is NOT allowlisted as a subpath.
    Linux's restrict_reads default deliberately excludes /dev to
    keep /dev/shm out of scope; on macOS the equivalent posix-shm
    surface lives under /private/var/folders/.../C/shm. Wholesale
    /dev read access exposes that surface to a sandboxed child.
    Specific /dev character devices (null/zero/urandom/etc.) ARE
    granted as literals."""
    p = seatbelt.build_profile(restrict_reads=True, output="/tmp/x")
    assert '(subpath "/dev")' not in p, (
        "/dev should not be wholesale-allowlisted under "
        "restrict_reads — narrow to specific files"
    )
    # The narrow allow-list should still let dyld + standard tools
    # find the character devices they expect.
    for needed in ("/dev/null", "/dev/urandom", "/dev/random",
                    "/dev/tty"):
        assert f'(literal "{needed}")' in p, (
            f"missing expected /dev literal {needed!r}"
        )


def test_audit_verbose_includes_high_volume_categories():
    """Once seatbelt_audit.LogStreamer enforces the per-category
    skip-budget, high-volume categories (file-read-metadata,
    process-info-*, iokit-open, sysctl-read) become safe to emit:
    their JSONL contribution is bounded by AuditBudget's per-cat
    caps + sampling (see core.sandbox.audit_budget.DEFAULT_*) and
    operators see a budget_exceeded marker when the cap fires.
    Regression catch for accidentally stripping the high-volume
    categories back out."""
    p = seatbelt.build_profile(audit_mode=True, audit_verbose=True,
                                output="/tmp/x")
    assert "(allow file-read-metadata (with report))" in p
    assert "(allow process-info* (with report))" in p
    assert "(allow iokit-open (with report))" in p
    assert "(allow sysctl-read (with report))" in p


def test_audit_verbose_compatible_with_restrict_reads():
    """When restrict_reads=True + audit_mode=True, the
    restrict-reads branch already emits (allow file-read* (with
    report)). audit_verbose adds (allow file-read-data (with
    report)) — both clauses can coexist in the profile (SBPL
    handles duplicate (allow ... (with report)) cleanly)."""
    p = seatbelt.build_profile(audit_mode=True, audit_verbose=True,
                                restrict_reads=True, output="/tmp/x")
    assert "(allow file-read* (with report))" in p
    assert "(allow file-read-data (with report))" in p
