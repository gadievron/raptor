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
    # Three dir exception paths: /private/tmp + output + extra as
    # (subpath ...) plus device-node (literal ...) entries, all
    # inside ONE require-any clause.
    import re
    require_any_match = re.search(
        r"\(require-any\s+((?:\((?:subpath|literal) [^)]+\)\s*)+)\)", p
    )
    assert require_any_match, "no (require-any ...) found"
    inside = require_any_match.group(1)
    assert inside.count("(subpath ") == 3, (
        f"expected 3 subpaths inside require-any, got: {inside}"
    )
    assert "(literal \"/dev/null\")" in inside, (
        f"/dev/null literal missing from require-any: {inside}"
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
    lines = [line.strip() for line in p.splitlines() if line.strip()]
    deny_idx = next(i for i, line in enumerate(lines)
                    if line == "(deny network*)")
    allow_idxs = [i for i, line in enumerate(lines)
                   if line.startswith("(allow network-outbound")]
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


def test_egress_proxy_lane_port_never_gets_wildcard_rule():
    """The proxy lane port is folded into allowed_tcp_ports by the
    context layer (TCP-only path — always taken on darwin), so
    pre-fix the builder emitted BOTH the loopback-scoped lane rules
    AND a wildcard `(remote tcp "*:<laneport>")` for the same port —
    letting a child read the port from HTTPS_PROXY and dial
    attacker-host:<laneport> directly, bypassing the hostname
    allowlist and proxy telemetry. The loopback tcp4/tcp6 rules
    already cover the lane; the wildcard must be suppressed for the
    lane port while caller-declared non-lane ports keep theirs."""
    lane = 4567
    p = seatbelt.build_profile(
        use_egress_proxy=True,
        proxy_port=lane,
        allowed_tcp_ports=[lane, 8443],
    )
    # Loopback-scoped lane rules stay (both address families).
    assert f'(remote tcp4 "localhost:{lane}")' in p
    assert f'(remote tcp6 "localhost:{lane}")' in p
    # No any-address wildcard for the lane port.
    assert f'"*:{lane}"' not in p
    # A declared non-lane port keeps its wildcard rule.
    assert '(allow network-outbound (remote tcp "*:8443"))' in p


def test_egress_proxy_lane_only_ports_list_emits_no_wildcard():
    """The production darwin shape: allowed_tcp_ports == [lane_port]
    exactly (context.py replaces the caller list with the lane).
    The profile must contain NO wildcard network-outbound rule at
    all — only the loopback pair."""
    lane = 4567
    p = seatbelt.build_profile(
        use_egress_proxy=True,
        proxy_port=lane,
        allowed_tcp_ports=[lane],
    )
    assert '(remote tcp "*:' not in p
    assert f'localhost:{lane}' in p
    assert "(deny network*)" in p


def test_allowed_tcp_ports_emitted():
    """Caller-supplied port allowlist (e.g. allowed_tcp_ports=[443])
    becomes (allow network-outbound (remote tcp "*:443")) clauses."""
    p = seatbelt.build_profile(
        block_network=True,
        allowed_tcp_ports=[443, 8443],
    )
    assert '"*:443"' in p
    assert '"*:8443"' in p


def test_ports_alone_emit_scoped_tcp_deny():
    """A standalone allowed_tcp_ports config must emit a network
    section (was: silently allow-default on macOS while Linux Landlock
    enforced the same kwargs). The deny is scoped to outbound TCP so
    UDP/DNS and bind/listen stay untouched (listening is unrestricted
    by design)."""
    p = seatbelt.build_profile(block_network=False, use_egress_proxy=False,
                               allowed_tcp_ports=[443, 8443])
    assert '(deny network-outbound (remote tcp "*:*"))' in p
    assert '(allow network-outbound (remote tcp "*:443"))' in p
    assert '(allow network-outbound (remote tcp "*:8443"))' in p
    # Scoped deny only — bind/listen and UDP stay untouched.
    assert "(deny network*)" not in p


def test_block_network_with_ports_branch_unchanged():
    p = seatbelt.build_profile(block_network=True,
                               allowed_tcp_ports=[443])
    assert "(deny network*)" in p
    assert '(allow network-outbound (remote tcp "*:443"))' in p


def test_no_network_kwargs_no_network_section():
    p = seatbelt.build_profile(block_network=False,
                               use_egress_proxy=False)
    assert "deny network" not in p


def test_restrict_reads_emits_deny_read_with_exceptions(tmp_path):
    """restrict_reads=True mirrors the Linux read-allowlist behaviour
    (Landlock's path_beneath denies reads outside the listed dirs).
    Profile must emit:
      1. `(allow file-read-metadata)` so path traversal works on the
         system prefixes (dyld stats every component at image load;
         the home tree is then narrowed — see the home-metadata tests below).
      2. `(deny file-read-data (require-not ...))` with the
         system-dirs allowlist + output + readable_paths."""
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


# --- Home-tree metadata narrowing -------------------------------------
#
# Read-restricted shapes deny file-read-metadata under /Users and
# re-allow exactly the /Users-resident subset of the data-read
# allowlist. Everything here is generation-level; enforcement is
# adjudicated by a live macOS probe run (home-tree existence-oracle
# and stat-detail probes expected to flip to denied on the
# read-restricted shapes; home readdir — measured already-denied
# live on current macOS — stays denied).

_HOME_DENY = '(deny file-read-metadata (subpath "/Users"))'


def _data_read_grants(profile: str) -> tuple[list, list]:
    """Extract (subpaths, literals) from the file-read-data deny's
    require-any exception clause."""
    import re
    m = re.search(
        r"\(deny file-read-data \(require-not \(require-any (.*)"
        r"\)\)\)", profile,
    )
    assert m, f"no file-read-data deny found in:\n{profile}"
    inside = m.group(1)
    return (re.findall(r'\(subpath "([^"]*)"\)', inside),
            re.findall(r'\(literal "([^"]*)"\)', inside))


def _home_metadata_allow_subpaths(profile: str) -> list:
    """Extract the subpaths of the filtered file-read-metadata allow
    (the home-tree re-allow line; the universal `(allow file-read-metadata)`
    line is bare and audit_verbose's `(with report)` form carries no
    subpath filter — neither matches)."""
    import re
    lines = [line for line in profile.splitlines()
             if line.startswith("(allow file-read-metadata (subpath ")]
    assert len(lines) <= 1, lines
    if not lines:
        return []
    return re.findall(r'\(subpath "([^"]*)"\)', lines[0])


def test_home_meta_deny_present_in_restrict_reads_shapes():
    """Every read-restricted enforcement profile carries the /Users
    metadata deny — including when no grant lives under /Users (a
    home-tree-free run leaks nothing and reads nothing there)."""
    p = seatbelt.build_profile(output="/private/scratch/out",
                               restrict_reads=True)
    assert _HOME_DENY in p
    # No grant under /Users → no filtered metadata re-allow at all.
    assert _home_metadata_allow_subpaths(p) == []


def test_home_meta_deny_skipped_when_grant_covers_home_root():
    """A data-read grant covering the home root itself ("/" or
    "/Users", via any grant kwarg) must SKIP the narrowing: emitting
    the deny anyway would make metadata NARROWER than data-read
    across the granted tree (the /Users filter on the re-allow list
    would miss an ancestor-shaped grant), silently breaking
    stat-before-open inside it. The superset invariant holds by
    falling back to the universal metadata allow."""
    for kwargs in (
        {"readable_paths": ["/"]},
        {"readable_paths": ["/Users"]},
        {"target": "/Users"},
        {"writable_paths": ["/Users/"]},
    ):
        p = seatbelt.build_profile(output="/private/scratch/out",
                                   restrict_reads=True, **kwargs)
        assert "(deny file-read-metadata" not in p, (kwargs, p)
        assert "(allow file-read-metadata)" in p, kwargs
    # Near-miss guard: a sibling path sharing the prefix ("/Users2")
    # does NOT cover the home root — the deny must stay.
    p = seatbelt.build_profile(output="/private/scratch/out",
                               readable_paths=["/Users2"],
                               restrict_reads=True)
    assert _HOME_DENY in p


def test_home_meta_allows_mirror_home_grants_exact_path_set():
    """The filtered metadata allow mirrors the data-read allowlist's
    /Users-resident grants EXACTLY: output, writable_paths,
    readable_paths, target-when-under-home. Non-home grants must not
    ride along (they are already metadata-open via the universal
    allow — re-listing them obscures the diff)."""
    p = seatbelt.build_profile(
        output="/Users/op/raptor-out/run1",
        writable_paths=["/Users/op/raptor-out/shared"],
        readable_paths=["/Users/op/corpora", "/opt/myapp"],
        target="/Users/op/target-repo",
        restrict_reads=True,
    )
    assert _HOME_DENY in p
    assert sorted(_home_metadata_allow_subpaths(p)) == sorted([
        "/Users/op/raptor-out/run1",
        "/Users/op/raptor-out/shared",
        "/Users/op/corpora",
        "/Users/op/target-repo",
    ])


def test_home_meta_clause_shape_and_order():
    """Clause SHAPE is load-bearing (measured live on macOS
    26.x): `(target others)`-filtered denies and `require-not`
    exception forms measured broken/inert live; deny-then-allow with
    OR-ing filters on one allow measured correct. Pin the shape:
      universal metadata allow → /Users deny → filtered re-allow,
    with no require-not anywhere on the metadata clauses."""
    p = seatbelt.build_profile(output="/Users/op/out",
                               restrict_reads=True)
    lines = [line.strip() for line in p.splitlines() if line.strip()]
    universal = lines.index("(allow file-read-metadata)")
    deny = lines.index(_HOME_DENY)
    allow = next(i for i, line in enumerate(lines)
                 if line.startswith("(allow file-read-metadata ("))
    assert universal < deny < allow, (universal, deny, allow)
    for line in lines:
        if "file-read-metadata" in line:
            assert "require-not" not in line, line
            assert "(target " not in line, line


def test_home_meta_is_superset_of_home_data_reads():
    """THE invariant: every path the profile grants file-read-data on
    under /Users must have file-read-metadata coverage, or
    stat-before-open patterns break on it. Derived mechanically from
    the emitted profile (grants parsed from the data deny's exception,
    coverage checked against the metadata re-allow), so any future
    grant source added to read_exceptions is covered by construction
    or fails here."""
    p = seatbelt.build_profile(
        output="/Users/op/raptor-out/run1",
        writable_paths=["/Users/op/raptor-out/shared", "/private/w"],
        readable_paths=["/Users/op/corpora", "/opt/myapp"],
        target="/Users/op/target-repo",
        restrict_reads=True,
    )
    subpaths, literals = _data_read_grants(p)
    meta = _home_metadata_allow_subpaths(p)
    for grant in subpaths:
        if grant == "/Users" or grant.startswith("/Users/"):
            assert any(grant == m or grant.startswith(m + "/")
                       for m in meta), (grant, meta)
    # The literal grants ("/" + /dev nodes) must never live under the
    # home tree — a /Users literal in the data allowlist would need a
    # matching metadata literal the generator doesn't emit.
    for lit in literals:
        assert not lit.startswith("/Users"), lit


def test_home_meta_fake_home_and_tmp_scratch_ride_the_output_grant():
    """The fake-home layout ({output}/.home — HOME + XDG dirs, see
    _macos_spawn) and the spawn-layer TMPDIR scratch ({output}/.tmp) live
    under the output dir, so the output subpath grant covers their
    metadata by SBPL subpath semantics. Pin that the output grant is
    present whenever output sits under /Users — losing it silently
    breaks stat() inside the child's own HOME/TMPDIR."""
    out = "/Users/op/raptor-out/run1"
    p = seatbelt.build_profile(output=out, restrict_reads=True,
                               fake_home=True,
                               exclude_tmp_baseline=True)
    assert out in _home_metadata_allow_subpaths(p)


def test_home_meta_absent_outside_restrict_reads_shapes():
    """The narrowing belongs to the read-restricted family ONLY.
    Permissive shapes stay byte-identical: no metadata clause of any
    kind without restrict_reads, and audit mode keeps its
    observe-don't-block allow-with-report form."""
    # Write isolation without read restriction — no metadata clauses.
    p = seatbelt.build_profile(output="/Users/op/out")
    assert "file-read-metadata" not in p
    # Fully permissive.
    assert "file-read-metadata" not in seatbelt.build_profile()
    # Audit mode: observe, never deny.
    p = seatbelt.build_profile(output="/Users/op/out",
                               restrict_reads=True, audit_mode=True)
    assert "(deny file-read-metadata" not in p
    assert "(allow file-read* (with report))" in p


def test_home_meta_tree_root_constant():
    """The deny is scoped to the exported constant — seatbelt_audit /
    kit tooling may key on it; drift would silently unscope the
    narrowing."""
    assert seatbelt.MACOS_HOME_TREE_ROOT == "/Users"


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
    """Linux's "full" seccomp blocks ptrace; the macOS analogue denies
    introspection of OTHER processes. The deny must cover the WHOLE
    process-info* family: the earlier narrow pidinfo/pidfdinfo pair
    left process-info-listpids open (proc_listallpids() enumerated
    every host pid) and the narrow pidinfo deny itself proved
    ineffective against proc_name() on current macOS (26.6.2).
    The clause SHAPE is load-bearing: a `(target others)`-filtered
    deny proved inert live on current macOS — the attested pattern is
    a bare family deny followed by a `(target self)` allow (later
    allow wins for this family), which keeps self-introspection
    working."""
    p = seatbelt.build_profile(seccomp_profile="full")
    assert "(deny process-info*)" in p
    assert "(allow process-info* (target self))" in p
    # Ordering pin: the self allow must FOLLOW the family deny —
    # this family relies on later-allow-wins (like network*, unlike
    # file-*). An inverted emission silently loses self-allowance.
    lines = [line.strip() for line in p.splitlines() if line.strip()]
    d = lines.index("(deny process-info*)")
    a = lines.index("(allow process-info* (target self))")
    assert a > d, (d, a)
    # The inert filtered-deny shape must not come back.
    assert "(target others)" not in p
    # The narrow forms are subsumed — regressing back to them would
    # silently reopen listpids enumeration.
    assert "(deny process-info-pidinfo" not in p
    assert "(deny process-info-pidfdinfo" not in p


def test_seccomp_profile_full_allows_same_sandbox_introspection():
    """A parent must be able to watch and signal the processes it
    spawned inside the sandbox: self-only broke the JVM's
    ProcessHandleImpl.isAlive0 (sysctl kern.proc.pid.<child> +
    proc_pidinfo, both gated by process-info*) and kill(own_child).
    `(target same-sandbox)` is the measured scope — descendants and
    in-sandbox siblings yes, a separate sandbox instance or any host
    process no. Each allow must FOLLOW its family deny (later allow
    wins), and the broader `(target others)` must never appear."""
    p = seatbelt.build_profile(seccomp_profile="full")
    lines = [line.strip() for line in p.splitlines() if line.strip()]
    for family in ("process-info*", "signal"):
        allow = f"(allow {family} (target same-sandbox))"
        assert allow in lines, allow
        assert lines.index(allow) > lines.index(f"(deny {family})")
    assert "(target others)" not in p
    assert "(target children)" not in p


def test_legacy_strict_branch_allows_same_sandbox_signal():
    p = seatbelt.build_profile(seccomp_profile="debug",
                               profile_name="strict")
    lines = [line.strip() for line in p.splitlines() if line.strip()]
    assert (lines.index("(allow signal (target same-sandbox))")
            > lines.index("(deny signal)"))


def test_debug_profile_omits_same_sandbox_allows():
    """debug never denies the families, so it needs no carve-outs."""
    p = seatbelt.build_profile(seccomp_profile="debug")
    assert "same-sandbox" not in p


def test_seccomp_profile_full_emits_iokit_deny():
    """`(deny iokit-open)` rides the full profile: userland driver /
    device access is the macOS analogue of Linux's blocked
    device-capability escapes, and the 2026-08-15 probe battery
    showed the deny is free (clang/make/git/python/venv/tar all
    pass). The sibling candidate `(deny sysctl-write)` must NOT be
    emitted — it breaks Apple's linker and ensurepip."""
    p = seatbelt.build_profile(seccomp_profile="full")
    assert "(deny iokit-open)" in p
    assert "sysctl-write" not in p


def test_seccomp_profile_full_audit_reports_iokit():
    """Audit mode observes instead of blocking — iokit-open becomes
    allow-with-report alongside process-info*."""
    p = seatbelt.build_profile(seccomp_profile="full", audit_mode=True)
    assert "(allow iokit-open (with report))" in p
    assert "(deny iokit-open)" not in p


def test_debug_profile_omits_iokit_deny():
    """debug keeps debugger primitives functional — the introspection
    hardening set (incl. iokit-open) must not engage."""
    p = seatbelt.build_profile(seccomp_profile="debug")
    assert "iokit-open" not in p


def test_strict_profile_emits_macos_strict_extras():
    """profile_name='strict' carries the scoped signal deny, nvram
    deny, and the mach-lookup allowlist (now baseline for full too).
    All three passed the 2026-08-15 toolchain battery (mach even as a
    blanket deny)."""
    p = seatbelt.build_profile(seccomp_profile="full",
                               profile_name="strict")
    assert "(deny signal)" in p
    assert "(allow signal (target self))" in p
    assert "(deny nvram*)" in p
    assert "(deny mach-lookup (require-not (require-any" in p
    for svc in seatbelt.MACOS_STRICT_MACH_SERVICES:
        assert svc in p


def test_full_profile_carries_hardening_baseline():
    """The historical strict extras (signal / nvram / mach-lookup)
    are BASELINE for the full profile now: with mach-lookup open, a
    sandboxed child could have LaunchServices execute a helper
    unsandboxed (full escape, confirmed reachable on current macOS),
    and signal/nvram denies were battery-validated free. full must
    never regress to the permissive pre-hardening shape."""
    p = seatbelt.build_profile(seccomp_profile="full",
                               profile_name="full")
    assert "(deny signal)" in p
    assert "(allow signal (target self))" in p
    # Ordering pin (same later-allow-wins reliance as process-info):
    # the self allow must FOLLOW the family deny.
    lines = [line.strip() for line in p.splitlines() if line.strip()]
    assert (lines.index("(allow signal (target self))")
            > lines.index("(deny signal)"))
    assert "(deny nvram*)" in p
    assert "(deny mach-lookup (require-not (require-any" in p


def test_strict_legacy_branch_emits_deny_then_allow_self_signal():
    """The legacy strict-extras branch (profile_name='strict' with a
    seccomp profile outside the hardening set — unreached in
    production) must carry the same signal clause shape as the
    hardened baseline: the filtered-deny form it historically used is
    inert on current macOS."""
    p = seatbelt.build_profile(seccomp_profile="debug",
                               profile_name="strict")
    assert "(deny signal)" in p
    assert "(allow signal (target self))" in p
    lines = [line.strip() for line in p.splitlines() if line.strip()]
    assert (lines.index("(allow signal (target self))")
            > lines.index("(deny signal)"))
    assert "(target others)" not in p
    assert "(deny nvram*)" in p
    assert "(deny mach-lookup (require-not (require-any" in p


def test_strict_profile_equals_full_profile():
    """strict is the fail-closed profile and must never be WEAKER
    than full; with the hardening baseline in full, the two are
    identical at the SBPL layer. Byte-equality also proves the
    strict branch does not duplicate baseline clauses."""
    kwargs = dict(target="/t", output="/o", block_network=True,
                  seccomp_profile="full")
    full = seatbelt.build_profile(profile_name="full", **kwargs)
    strict = seatbelt.build_profile(profile_name="strict", **kwargs)
    assert full == strict
    # The untrusted shapes (restrict_reads=True, home-tree grants —
    # the family that carries the home-tree metadata narrowing) must stay
    # byte-identical between strict and default too.
    kwargs = dict(target="/Users/op/target-repo",
                  output="/Users/op/raptor-out/run1",
                  block_network=True, restrict_reads=True,
                  fake_home=True, exclude_tmp_baseline=True,
                  seccomp_profile="full")
    full = seatbelt.build_profile(profile_name="full", **kwargs)
    strict = seatbelt.build_profile(profile_name="strict", **kwargs)
    assert full == strict


def test_strict_mach_services_is_the_base_list():
    """The strict allowlist must be the same lookup-only base list —
    an earlier wider 'headroom' list retained launchservicesd /
    coreservicesd / SecurityServer / cfprefsd, i.e. the escape and
    persistence channels survived the strictest profile."""
    assert (seatbelt.MACOS_STRICT_MACH_SERVICES
            == seatbelt.MACOS_BASE_MACH_SERVICES)


def test_mach_allowlist_excludes_capability_daemons():
    """Pin the dropped services: each is a capability channel out of
    the sandbox (unsandboxed proxy execution, keychain, prefs
    persistence, fs monitoring, cross-sandbox signalling) — none may
    reappear in ANY emitted mach allowlist."""
    p = seatbelt.build_profile(seccomp_profile="full")
    for banned in (
        "com.apple.coreservices.launchservicesd",
        "com.apple.CoreServices.coreservicesd",
        "com.apple.SecurityServer",
        "com.apple.securityd.xpc",
        "com.apple.trustd",
        "com.apple.cfprefsd.daemon",
        "com.apple.cfprefsd.agent",
        "com.apple.FSEvents",
        "com.apple.system.notification_center",
    ):
        assert banned not in p, banned
        assert banned not in seatbelt.MACOS_BASE_MACH_SERVICES
    # The lookup-only infrastructure services survive.
    for kept in seatbelt.MACOS_BASE_MACH_SERVICES:
        assert f'(global-name "{kept}")' in p


def test_full_profile_sysctl_read_allowlist_deny():
    """sysctl-read allowlist-deny: KERN_PROCARGS2 reads the argv AND
    (for most non-Apple targets) the environment of any same-UID host
    process — a credential-exfiltration channel, confirmed reachable
    on current macOS. The deny closes it while the allowlist keeps
    the hardware/OS-identity names runtimes consult at startup."""
    p = seatbelt.build_profile(seccomp_profile="full")
    # Clause shape is load-bearing: the require-not exception form
    # never matched live on current macOS (every named sysctl was
    # denied, allowlist included) — the attested Apple shape is a
    # bare deny followed by filtered allows, later allow wins.
    assert "(deny sysctl-read)" in p
    assert "(deny sysctl-read (require-not" not in p
    lines = [line.strip() for line in p.splitlines() if line.strip()]
    d = lines.index("(deny sysctl-read)")
    allows = [i for i, line in enumerate(lines)
              if line.startswith("(allow sysctl-read ")]
    assert allows and all(i > d for i in allows), (d, allows)
    for prefix in seatbelt.MACOS_SYSCTL_READ_PREFIX_ALLOWLIST:
        assert f'(sysctl-name-prefix "{prefix}")' in p
    for name in seatbelt.MACOS_SYSCTL_READ_NAME_ALLOWLIST:
        assert f'(sysctl-name "{name}")' in p
    # The credential/fingerprint names must never be allowlisted.
    # (kern.hostname is NOT in this set: Darwin's uname(3) reads it
    # together with kern.ostype/osrelease/version and hw.machine and
    # fails entirely if any one is denied — census evidence from a
    # live macOS run; the allowlist carries the trade-off comment.)
    for banned in ("kern.proc.", "kern.procargs",
                   "kern.bootsessionuuid"):
        assert f'"{banned}' not in p, banned
    # Exact-name form too: the prefix checks above use a trailing
    # dot / open quote, which an exact "kern.proc" entry would evade.
    assert '(sysctl-name "kern.proc")' not in p
    assert '(sysctl-name "kern.hostname")' in p
    # sysctl-WRITE denial breaks Apple's linker + ensurepip — the
    # hardening must stay read-side only.
    assert "sysctl-write" not in p


def test_full_profile_ipc_shm_denies():
    """POSIX shm is not mediated by file-write* — shm_open of another
    same-UID process's segment succeeded under every write-isolated
    shape on current macOS. This is the /dev/shm-equivalent surface
    the Linux tier closes via mount-ns. Only the libSystem cfprefs
    read fast-path stays open."""
    p = seatbelt.build_profile(seccomp_profile="full")
    assert ('(deny ipc-posix-shm-read* (require-not '
            '(ipc-posix-name-prefix "apple.cfprefs.")))') in p
    assert "(deny ipc-posix-shm-write*)" in p
    assert "(deny ipc-sysv*)" in p


def test_full_profile_daemon_proxy_denies():
    """Belt-and-braces op-level denies over the mach allowlist drops:
    darwin notifications (host-wide signalling / covert channel),
    AppleEvents (automation of other apps), user-preference-write
    (`defaults write` persistence outside the write scope via the
    cfprefsd proxy)."""
    p = seatbelt.build_profile(seccomp_profile="full")
    assert "(deny darwin-notification-post)" in p
    assert "(deny appleevent-send)" in p
    assert "(deny user-preference-write)" in p


def test_hardening_absent_from_permissive_profiles():
    """The hardening set engages ONLY for seccomp_profile='full'
    (which full/strict/target_run all map to). debug keeps debugger
    primitives; none/network-only stay Linux-parity permissive."""
    for kwargs in (
        {},
        {"seccomp_profile": "debug"},
        {"seccomp_profile": "none"},
        {"seccomp_profile": "", "block_network": True},
    ):
        p = seatbelt.build_profile(**kwargs)
        for fragment in (
            "process-info", "iokit-open", "(deny signal", "nvram",
            "mach-lookup", "sysctl-read", "ipc-posix-shm", "ipc-sysv",
            "darwin-notification-post", "appleevent-send",
            "user-preference-write",
        ):
            assert fragment not in p, (kwargs, fragment)


def test_hardening_audit_duals_report_every_denied_family():
    """Audit mode observes instead of blocking: every family the
    enforcement branch denies must appear as (allow X (with report)),
    and no hardening deny may survive into the audit profile."""
    p = seatbelt.build_profile(seccomp_profile="full", audit_mode=True,
                               output="/tmp/x")
    for family in (
        "process-info*", "iokit-open", "signal", "nvram*",
        "mach-lookup", "sysctl-read", "ipc-posix-shm*", "ipc-sysv*",
        "darwin-notification-post", "appleevent-send",
        "user-preference-write",
    ):
        assert f"(allow {family} (with report))" in p, family
    for fragment in (
        "(deny process-info", "(deny iokit-open", "(deny signal",
        "(deny nvram", "(deny mach-lookup", "(deny sysctl-read",
        "(deny ipc-", "(deny darwin-notification-post",
        "(deny appleevent-send", "(deny user-preference-write",
    ):
        assert fragment not in p, fragment


def test_untrusted_default_shape_carries_full_hardening():
    """The floor shape (run_untrusted's darwin kwargs) must carry the
    complete hardening set alongside its read/write/network denies —
    the untrusted contract ('credential exfil blocked') depends on
    the mach/sysctl/shm/signal denies, not just the fs clauses."""
    p = seatbelt.build_profile(
        target="/t", output="/o", block_network=True,
        restrict_reads=True, readable_paths=["/usr"],
        writable_paths=[], fake_home=True, exclude_tmp_baseline=True,
        seccomp_profile="full", profile_name="full",
    )
    for clause in (
        "(deny process-info*)",
        "(allow process-info* (target self))",
        "(deny iokit-open)",
        "(deny signal)",
        "(allow signal (target self))",
        "(deny nvram*)",
        "(deny mach-lookup (require-not (require-any",
        "(deny sysctl-read)",
        "(allow sysctl-read (sysctl-name-prefix",
        "(allow sysctl-read (sysctl-name ",
        "(deny ipc-posix-shm-write*)",
        "(deny ipc-sysv*)",
        "(deny darwin-notification-post)",
        "(deny appleevent-send)",
        "(deny user-preference-write)",
        "(deny network*)",
        "(deny file-write*",
        "(deny file-read-data",
        '(deny file-read-metadata (subpath "/Users"))',
    ):
        assert clause in p, clause


def test_strict_extras_report_under_audit():
    """Audit observes instead of blocking, strict extras included."""
    p = seatbelt.build_profile(seccomp_profile="full",
                               profile_name="strict", audit_mode=True)
    assert "(allow mach-lookup (with report))" in p
    assert "(deny mach-lookup" not in p
    assert "(allow signal (with report))" in p


def test_restrict_reads_allows_homebrew_prefixes():
    """Homebrew trees must be readable under restrict_reads —
    Homebrew-installed interpreters die at dyld stage otherwise
    (observed: python3 "Library not loaded", bash via libreadline)."""
    p = seatbelt.build_profile(output="/tmp", restrict_reads=True)
    assert '(subpath "/opt/homebrew")' in p
    assert '(subpath "/usr/local")' in p


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
    must keep other-process process-info-* unrestricted so
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
    assert "(deny process-info*)" in full
    assert "(deny process-info*" not in debug


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


class TestExcludeTmpBaseline:
    """exclude_tmp_baseline strips the /private/tmp writable seed
    (Linux writable_paths=[] parity); the spawn layer pairs it with a
    TMPDIR redirect into {output}/.tmp. Enforcement semantics were
    validated live on an arm64 macOS host."""

    def test_seed_present_by_default(self):
        from core.sandbox.seatbelt import build_profile
        prof = build_profile(output="/x/out")
        assert '(subpath "/private/tmp")' in prof

    def test_seed_stripped_when_excluded(self):
        from core.sandbox.seatbelt import build_profile
        prof = build_profile(output="/x/out", exclude_tmp_baseline=True)
        assert '"/private/tmp"' not in prof
        # Output stays writable — that's where TMPDIR redirects.
        assert '(subpath "/x/out")' in prof


class TestFileTrustAnchorEnv:
    """A mach-lookup-restricted profile closes the keychain, so
    keychain-backed root discovery (OCaml ca-certs: Semgrep) comes back
    empty; the spawn layer hands the child a file bundle instead."""

    def test_hardened_profile_gets_bundle(self, monkeypatch, tmp_path):
        bundle = tmp_path / "cert.pem"
        bundle.write_text("x")
        monkeypatch.setattr(seatbelt, "MACOS_FILE_TRUST_ANCHORS",
                            str(bundle))
        p = seatbelt.build_profile(seccomp_profile="full")
        assert seatbelt.file_trust_anchor_env(p) == {
            "NIX_SSL_CERT_FILE": str(bundle)}

    def test_unrestricted_mach_gets_nothing(self, monkeypatch, tmp_path):
        bundle = tmp_path / "cert.pem"
        bundle.write_text("x")
        monkeypatch.setattr(seatbelt, "MACOS_FILE_TRUST_ANCHORS",
                            str(bundle))
        for kw in ({}, {"seccomp_profile": "debug"},
                   {"seccomp_profile": "full", "audit_mode": True}):
            p = seatbelt.build_profile(**kw)
            assert seatbelt.file_trust_anchor_env(p) == {}, kw

    def test_missing_bundle_gets_nothing(self, monkeypatch, tmp_path):
        monkeypatch.setattr(seatbelt, "MACOS_FILE_TRUST_ANCHORS",
                            str(tmp_path / "absent.pem"))
        p = seatbelt.build_profile(seccomp_profile="full")
        assert seatbelt.file_trust_anchor_env(p) == {}

    def test_not_an_openssl_trust_override(self):
        """The injected name must stay off the OpenSSL / requests /
        curl trust-override surface the env blocklist guards."""
        from core.config import RaptorConfig
        name = seatbelt.MACOS_FILE_TRUST_ANCHOR_ENV
        assert name not in ("SSL_CERT_FILE", "SSL_CERT_DIR",
                            "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")
        assert not RaptorConfig.is_dangerous_env_name(name)

    def test_bundle_readable_under_restrict_reads(self):
        p = seatbelt.build_profile(seccomp_profile="full",
                                   restrict_reads=True)
        assert '"/private/etc"' in p
        assert seatbelt.MACOS_FILE_TRUST_ANCHORS.startswith("/etc/")
