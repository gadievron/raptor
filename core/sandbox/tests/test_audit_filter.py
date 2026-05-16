"""Tests for audit-mode filtering — `audit` profile drops events that
would have been allowed under enforcement; `audit-verbose` logs them all.

Mocked tests of the filter logic (allowlist matching, path resolution,
write-intent detection, sockaddr decoding) plus an end-to-end test that
runs both profiles against the same workload and verifies the record
count differs in the expected direction.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path

import pytest

from core.sandbox import probes
from core.sandbox import ptrace_probe
from core.sandbox import tracer as tracer_mod
from core.sandbox import audit_budget


pytestmark = pytest.mark.skipif(
    not tracer_mod._is_supported_arch(),
    reason=f"tracer doesn't support {platform.machine()}",
)


class TestTracerCoversAllBlockedSyscalls:
    """Finding O: every syscall in seccomp's BLOCK_ALWAYS /
    BLOCK_UNLESS_DEBUG / _AUDIT_EXTRA_TRACE_SYSCALLS lists must
    have a name entry in the tracer's per-arch syscall table.
    Otherwise SCMP_ACT_TRACE fires, the tracer reads regs, looks
    up the syscall number, finds nothing, and writes a record with
    name=`unknown_<nr>` instead of the actual syscall name —
    operator can't act on it.

    Structural test: keeps the two sources from drifting silently
    when seccomp gains a new blocked syscall but the tracer table
    forgets to add it.
    """

    def test_x86_64_tracer_table_covers_seccomp_blocklist(self):
        from core.sandbox.seccomp import (
            _SECCOMP_BLOCK_ALWAYS,
            _SECCOMP_BLOCK_UNLESS_DEBUG,
            _AUDIT_EXTRA_TRACE_SYSCALLS,
        )
        from core.sandbox.tracer import _X86_64_SYSCALL_NAMES

        expected = (set(_SECCOMP_BLOCK_ALWAYS)
                    | set(_SECCOMP_BLOCK_UNLESS_DEBUG)
                    | set(_AUDIT_EXTRA_TRACE_SYSCALLS))
        known = set(_X86_64_SYSCALL_NAMES.values())
        missing = expected - known
        assert missing == set(), (
            f"x86_64 tracer table missing syscalls that seccomp "
            f"will TRACE under audit: {sorted(missing)}. Tracer "
            f"would write `unknown_<nr>` records — operator can't act "
            f"on them. Add to _X86_64_SYSCALL_NAMES."
        )

    def test_aarch64_tracer_table_covers_seccomp_blocklist(self):
        # NOTE: aarch64 has no `open` syscall (only `openat`), so
        # `open` is intentionally absent from _AARCH64_SYSCALL_NAMES.
        # We exclude it from the expected set on aarch64.
        from core.sandbox.seccomp import (
            _SECCOMP_BLOCK_ALWAYS,
            _SECCOMP_BLOCK_UNLESS_DEBUG,
            _AUDIT_EXTRA_TRACE_SYSCALLS,
        )
        from core.sandbox.tracer import _AARCH64_SYSCALL_NAMES

        expected = (set(_SECCOMP_BLOCK_ALWAYS)
                    | set(_SECCOMP_BLOCK_UNLESS_DEBUG)
                    | set(_AUDIT_EXTRA_TRACE_SYSCALLS))
        # aarch64 doesn't have plain `open` — only `openat`.
        expected.discard("open")
        known = set(_AARCH64_SYSCALL_NAMES.values())
        missing = expected - known
        assert missing == set(), (
            f"aarch64 tracer table missing syscalls that seccomp "
            f"will TRACE under audit: {sorted(missing)}. Tracer "
            f"would write `unknown_<nr>` records. Add to "
            f"_AARCH64_SYSCALL_NAMES (with the correct aarch64 "
            f"syscall numbers from include/uapi/asm-generic/unistd.h)."
        )


class TestAuditSystemRoMatchesContext:
    """Finding N: the audit-config _system_ro list in _spawn.py MUST
    match the system-ro list in context.py's restrict_reads default.
    Drift means audit either drops records for paths Landlock would
    have blocked, OR over-reports paths Landlock would have allowed.

    Parity is structural — both files hard-code the list. This test
    reads the source of context.py and tracer's _spawn.py audit
    block to confirm they agree.
    """

    def test_system_ro_lists_match(self):
        # Pull both literals via inspection rather than running the
        # functions (which require ptrace/landlock context).
        import inspect
        import re
        from core.sandbox import _spawn, context

        spawn_src = inspect.getsource(_spawn.run_sandboxed)
        ctx_src = inspect.getsource(context.sandbox)

        # Extract _system_ro tuple in spawn.
        spawn_m = re.search(
            r"_system_ro\s*=\s*\(\s*([^)]+)\)",
            spawn_src,
        )
        assert spawn_m, "could not find _system_ro literal in _spawn"
        spawn_paths = re.findall(r'"([^"]+)"', spawn_m.group(1))

        # Extract effective_read_paths default in context.
        ctx_m = re.search(
            r"effective_read_paths\s*=\s*\[\s*((?:\"[^\"]+\"[,\s]*)+)\]",
            ctx_src,
        )
        assert ctx_m, "could not find effective_read_paths in context"
        ctx_paths = re.findall(r'"([^"]+)"', ctx_m.group(1))

        assert set(spawn_paths) == set(ctx_paths), (
            f"_system_ro divergence — audit allowlist drift:\n"
            f"  spawn._system_ro: {sorted(spawn_paths)}\n"
            f"  context default:  {sorted(ctx_paths)}\n"
            f"  in spawn only:    {sorted(set(spawn_paths) - set(ctx_paths))}\n"
            f"  in context only:  {sorted(set(ctx_paths) - set(spawn_paths))}\n"
            f"Update one to match the other (and consider extracting "
            f"to a shared constant)."
        )


class TestTracerExitCodesAgreeAcrossDocs:
    """Finding DD: tracer's exit codes are documented in TWO
    docstrings (trace() and _cli_main()) plus the actual `return N`
    statements. spawn-side cleanup logic in _spawn.py inspects the
    code on tracer-fail to give operators a hint about the failure
    cause. Drift class:
      - implementation adds exit code 5 (e.g., bad audit_config) but
        docstrings don't list it → operator sees an undocumented
        code, can't act on it
      - docstring lists exit 6 but no return path uses it → false
        promise to operators

    Pin: every numeric return in tracer.py (return N, where N is a
    small int) must be documented in BOTH docstrings."""

    def test_actual_returns_match_docstrings(self):
        import inspect
        import re
        from core.sandbox import tracer

        src = inspect.getsource(tracer)
        # Find numeric returns: `return 0`, `return 1`, ... small ints
        # only (skip `return result_count` etc.).
        actual_codes = set()
        for m in re.finditer(r"return\s+(\d+)\b", src):
            n = int(m.group(1))
            if n < 10:  # exit codes are small
                actual_codes.add(n)

        # Extract documented codes from trace() and _cli_main()
        # docstrings.
        def docs_codes(fn) -> set:
            doc = inspect.getdoc(fn) or ""
            # Lines starting with N spaces then a digit then 1+ spaces
            # then text — matches the table format.
            return {int(m.group(1))
                    for m in re.finditer(
                        r"^\s+(\d+)\s+\w", doc, re.MULTILINE,
                    )}

        trace_doc = docs_codes(tracer.trace)
        cli_doc = docs_codes(tracer._cli_main)

        # _cli_main is the wrapper; it should document the union of
        # trace()'s codes plus its own. trace()'s codes should be a
        # SUBSET of _cli_main's docs.
        assert trace_doc.issubset(cli_doc), (
            f"trace() docstring documents exit codes {trace_doc} "
            f"that _cli_main's docstring doesn't include "
            f"({trace_doc - cli_doc}) — operators reading the CLI "
            f"docstring won't see them."
        )
        # Every actual return must be in _cli_main's docs.
        undocumented = actual_codes - cli_doc
        assert undocumented == set(), (
            f"actual `return` statements in tracer return codes "
            f"{sorted(undocumented)} that _cli_main's docstring "
            f"doesn't document. Operators / spawn-side handlers "
            f"can't interpret these codes."
        )
        # Every documented code must have an actual return.
        unused = cli_doc - actual_codes
        assert unused == set(), (
            f"_cli_main's docstring documents exit codes "
            f"{sorted(unused)} that no `return` statement actually "
            f"uses — false promise to consumers."
        )


class TestSeccompProfileDisableSemantics:
    """Finding EE: 'no seccomp' is signalled in three different
    forms across the modules:
      - context.py: `seccomp_profile = p["seccomp"] or None`
        (PROFILES["network-only"]["seccomp"] is "" → becomes None)
      - _spawn.py: `if not seccomp_profile:` AND `if seccomp_profile
        else None` (truthy check)
      - seccomp.py: `if profile == "none" or not profile`

    Pre-fix: seccomp.py only handled the literal string "none";
    the truthy check at _spawn covered the None / "" cases.
    Inconsistent contract — a future caller passing the raw
    profile name "none" (matching the docstring) would have hit
    the truthy branch in _spawn and called seccomp.py, which then
    correctly returned None — but the implicit two-place check
    was fragile.

    Now seccomp.py accepts ALL three disable forms. Lock the
    contract with explicit tests."""

    def test_none_string_disables_seccomp(self):
        from core.sandbox.seccomp import _make_seccomp_preexec
        # Caller passes the literal string "none" — must be treated
        # as disable, not as a profile name to look up.
        result = _make_seccomp_preexec("none")
        assert result is None

    def test_python_none_disables_seccomp(self):
        from core.sandbox.seccomp import _make_seccomp_preexec
        result = _make_seccomp_preexec(None)
        assert result is None

    def test_empty_string_disables_seccomp(self):
        from core.sandbox.seccomp import _make_seccomp_preexec
        # PROFILES["network-only"]["seccomp"] is the empty string;
        # context.py converts via `or None` but a future caller
        # might pass "" directly.
        result = _make_seccomp_preexec("")
        assert result is None


class TestJsonlFilenameConstantAgrees:
    """Finding CC: the tracer subprocess WRITES to a JSONL file
    named in tracer.py's _DENIALS_FILENAME; summary.py READS the
    same file using its DENIALS_FILE constant. Both default to
    `.sandbox-denials.jsonl` but the constants are duplicated.

    Drift class: summary refactors the filename (e.g., to
    `.audit-events.jsonl`) without updating the tracer →
      - tracer writes to old name
      - summary's summarize_and_write reads the new name (empty)
      - operator sees "0 denials" in sandbox-summary.json despite
        the workload tripping audit events
      - silent audit signal loss

    Pin both constants are byte-identical."""

    def test_tracer_and_summary_filename_constants_match(self):
        from core.sandbox.tracer import _DENIALS_FILENAME
        from core.sandbox.summary import DENIALS_FILE
        assert _DENIALS_FILENAME == DENIALS_FILE, (
            f"JSONL filename divergence: tracer writes "
            f"{_DENIALS_FILENAME!r}, summary reads {DENIALS_FILE!r}"
            f" — audit signal would silently land in a file the "
            f"summary aggregator never opens."
        )


class TestProxyEventResultVocabulary:
    """Finding BB: proxy emits ~10 distinct `result` strings on
    events. test_proxy_audit and test_e2e_sandbox filter events by
    these strings (e.g., `[e for e in events if e["result"] == "allowed"]`).
    Drift class:
      - Proxy emits a NEW result string but the canonical set
        (_PROXY_EVENT_RESULTS) doesn't list it → test queries that
        whitelist by canonical set silently miss the event.
      - Proxy renames an existing result (e.g., `denied_host` to
        `host_denied`) → all consumer filters break silently.

    Structural test scans proxy.py for `result="..."` literals
    inside event.update / dict construction, verifies every literal
    is in _PROXY_EVENT_RESULTS."""

    def test_every_emitted_result_is_in_canonical_set(self):
        import inspect
        import re
        from core.sandbox import proxy

        src = inspect.getsource(proxy)
        # Find all `result="literal"` and `"result": "literal"`
        # patterns in the proxy source.
        emitted = set()
        emitted.update(re.findall(
            r'result\s*=\s*"([a-z_]+)"', src,
        ))
        emitted.update(re.findall(
            r'"result"\s*:\s*"([a-z_]+)"', src,
        ))
        # Drop None placeholders ("result": None initial event dict)
        # and the local-variable assignment `result = "allowed"`
        # which wraps a previous `result="allowed"` literal already
        # captured.

        canonical = proxy._PROXY_EVENT_RESULTS
        unknown = emitted - canonical
        assert unknown == set(), (
            f"proxy emits result strings NOT in canonical "
            f"_PROXY_EVENT_RESULTS: {sorted(unknown)}. Add them "
            f"to the canonical set so test consumers filtering by "
            f"this vocabulary stay correct."
        )

    def test_canonical_set_has_no_dead_entries(self):
        # Reverse: anything in _PROXY_EVENT_RESULTS but never emitted
        # is dead-code in the canonical set. Either the proxy stopped
        # emitting it or it's documentation-only — either way, drift.
        import inspect
        import re
        from core.sandbox import proxy

        src = inspect.getsource(proxy)
        emitted = set()
        emitted.update(re.findall(
            r'result\s*=\s*"([a-z_]+)"', src,
        ))
        emitted.update(re.findall(
            r'"result"\s*:\s*"([a-z_]+)"', src,
        ))

        canonical = proxy._PROXY_EVENT_RESULTS
        dead = canonical - emitted
        assert dead == set(), (
            f"_PROXY_EVENT_RESULTS contains values the proxy never "
            f"emits: {sorted(dead)}. Either remove from the set or "
            f"investigate which code path stopped emitting."
        )


class TestSeccompIoctlCmdsMatchKernelUapi:
    """Finding Z: seccomp's blocked-ioctl-cmds (TIOCSTI, TIOCCONS,
    TIOCSCTTY) are hardcoded magic numbers. Wrong value → seccomp
    rule installs but never matches because the actual ioctl uses
    the right number → tty injection / console redirection
    silently UNblocked. Verify against Python's termios module
    (which exposes the kernel UAPI values)."""

    def test_tiocsti_matches_kernel(self):
        import termios
        from core.sandbox import seccomp
        assert seccomp._TIOCSTI == termios.TIOCSTI, (
            f"_TIOCSTI={seccomp._TIOCSTI:#x} != termios.TIOCSTI="
            f"{termios.TIOCSTI:#x} — tty injection ioctl block "
            f"would silently fail to engage"
        )

    def test_tioccons_matches_kernel(self):
        import termios
        from core.sandbox import seccomp
        assert seccomp._TIOCCONS == termios.TIOCCONS

    def test_tiocsctty_matches_kernel(self):
        import termios
        from core.sandbox import seccomp
        # TIOCSCTTY may not be defined as _TIOCSCTTY in seccomp;
        # check the constant by-name via reflection.
        if hasattr(seccomp, "_TIOCSCTTY"):
            assert seccomp._TIOCSCTTY == termios.TIOCSCTTY


class TestAtFdcwdValue:
    """AT_FDCWD = -100 is stable Linux UAPI from <fcntl.h>. Not
    exposed by Python stdlib. Pin via the fcntl.h header when
    available (skip otherwise)."""

    def test_at_fdcwd_matches_uapi_header(self):
        import re
        import pytest
        candidate_paths = [
            "/usr/include/fcntl.h",
            "/usr/include/x86_64-linux-gnu/bits/fcntl-linux.h",
            "/usr/include/bits/fcntl-linux.h",
            "/usr/include/asm-generic/fcntl.h",
        ]
        # Search for `#define AT_FDCWD` literal value in any of them.
        kernel_value = None
        for p in candidate_paths:
            try:
                with open(p) as f:
                    src = f.read()
            except (FileNotFoundError, PermissionError):
                continue
            m = re.search(
                r"#\s*define\s+AT_FDCWD\s+\(?\s*(-?\d+)", src,
            )
            if m:
                kernel_value = int(m.group(1))
                break
        if kernel_value is None:
            pytest.skip("no fcntl header with AT_FDCWD found")
        from core.sandbox import tracer
        assert tracer._AT_FDCWD == kernel_value, (
            f"_AT_FDCWD={tracer._AT_FDCWD} != UAPI={kernel_value}"
        )


class TestOpenFlagsMatchKernelUapi:
    """Finding Y: tracer's open(2) flag constants are hardcoded
    (_O_WRONLY, _O_RDWR, _O_CREAT, _O_TRUNC, _O_APPEND) but the
    canonical source is the kernel headers via Python's os module.

    Wrong value here → _is_write_intent misses the bit → write opens
    classified as reads → under restrict_reads=False mode, audit
    silently drops them (reads are "allowed"). Operator misses
    write-intent signal.

    Pin via comparison with os module (which reads kernel headers
    at Python install-time)."""

    def test_open_flags_match_os_module(self):
        import os
        from core.sandbox import tracer
        # Each constant must match os.O_*
        assert tracer._O_WRONLY == os.O_WRONLY, (
            f"_O_WRONLY={tracer._O_WRONLY:#o} != os.O_WRONLY="
            f"{os.O_WRONLY:#o}"
        )
        assert tracer._O_RDWR == os.O_RDWR
        assert tracer._O_CREAT == os.O_CREAT
        assert tracer._O_TRUNC == os.O_TRUNC
        assert tracer._O_APPEND == os.O_APPEND


class TestPtraceConstantsAcrossModules:
    """Finding X: _PTRACE_CONT = 7 is duplicated in ptrace_probe.py
    and tracer.py. Same Linux UAPI value but a typo in either would
    silently break behaviour:
      - probe with bad CONT: probe child stays stopped → probe times
        out / parent waitpid hangs / cache populated wrongly
      - tracer with bad CONT: every traced event fails to resume
        the tracee → all targets hang

    Pin parity. Considered extracting to a shared module but ptrace
    constants are stable kernel UAPI; cross-module test catches drift
    with no extraction overhead."""

    def test_ptrace_cont_value_matches_across_modules(self):
        from core.sandbox import ptrace_probe, tracer
        assert ptrace_probe._PTRACE_CONT == tracer._PTRACE_CONT, (
            f"_PTRACE_CONT divergence: ptrace_probe="
            f"{ptrace_probe._PTRACE_CONT}, tracer={tracer._PTRACE_CONT}"
        )

    def test_ptrace_traceme_present_in_probe(self):
        # ptrace_probe uses TRACEME (child volunteers); tracer uses
        # SEIZE (parent attaches). Both are stable UAPI; check probe
        # has the right TRACEME value (0).
        from core.sandbox import ptrace_probe
        assert ptrace_probe._PTRACE_TRACEME == 0


class TestArchSupportDivergence:
    """Finding W: tracer supports only x86_64 + aarch64; mount_ns
    supports 9 arches. This is INTENTIONAL — adding a new arch to
    the tracer needs both a syscall-number table AND a register-
    layout entry (~30 LOC per arch), and the project memory pins
    'x86_64-only by design; aarch64 trivial' for the tracer.

    Document the divergence as a structural test so a future
    contributor adding a new arch knows what to update — and so a
    contributor accidentally REMOVING aarch64 from mount_ns gets
    flagged."""

    EXPECTED_TRACER_ARCHES = {"x86_64", "aarch64"}

    def test_tracer_arches_are_subset_of_mount_ns_arches(self):
        from core.sandbox.tracer import _ARCH_INFO
        from core.sandbox.mount_ns import _PIVOT_ROOT_SYSCALL_NR
        tracer_arches = set(_ARCH_INFO.keys())
        mount_arches = set(_PIVOT_ROOT_SYSCALL_NR.keys())
        unsupported_in_mount = tracer_arches - mount_arches
        assert unsupported_in_mount == set(), (
            f"tracer supports arches that mount_ns doesn't: "
            f"{unsupported_in_mount}. The whole sandbox stack "
            f"would fail before tracer even attaches. Add to "
            f"_PIVOT_ROOT_SYSCALL_NR (with the arch's pivot_root "
            f"syscall number from arch/<arch>/syscall_64.tbl)."
        )

    def test_tracer_arch_set_matches_documented(self):
        # Pin the documented set so a contributor extending the
        # tracer to a new arch updates this test alongside their
        # _ARCH_INFO change.
        from core.sandbox.tracer import _ARCH_INFO
        actual = set(_ARCH_INFO.keys())
        assert actual == self.EXPECTED_TRACER_ARCHES, (
            f"tracer _ARCH_INFO arches {actual} != expected "
            f"{self.EXPECTED_TRACER_ARCHES}. If you added a new arch, "
            f"update this test's EXPECTED_TRACER_ARCHES set; if you "
            f"removed one, that's likely a regression."
        )


class TestTracerArgvContract:
    """Finding V: the tracer subprocess CLI is a positional contract
    between _spawn.py (constructs argv) and tracer._cli_main (parses
    argv). Positional ordering: <pid> <run_dir> <sync_fd> <config_path>.
    Drift class:
      - _spawn writes [pid, run_dir, sync_fd, config_path] but
        _cli_main reads in different order → silent argument confusion
        (config_path treated as sync_fd → bad-fd write fails silently)
      - One side adds a new arg before another → all subsequent args
        shift, OS exits 2 (usage error) at startup with no clear
        diagnostic.

    Pin the contract by inspecting both source ends."""

    def test_spawn_argv_matches_cli_main_parse(self):
        import inspect
        import re
        from core.sandbox import _spawn, tracer

        # Extract spawn's argv literal.
        spawn_src = inspect.getsource(_spawn.run_sandboxed)
        argv_block = re.search(
            r"tracer_argv\s*=\s*\[(.*?)\]",
            spawn_src, re.DOTALL,
        )
        assert argv_block, "tracer_argv literal not found in _spawn"
        # Pull the variable names that follow `str(...)`.
        spawn_args = re.findall(
            r"str\((\w+)\)", argv_block.group(1),
        )
        # Plus the optional appended config_path.
        if "tracer_argv.append" in spawn_src:
            spawn_args.append("_audit_config_path")

        # Extract _cli_main's positional parse.
        cli_src = inspect.getsource(tracer._cli_main)
        # Look for `args[0]`, `args[1]`, etc. assignments.
        cli_indexes = re.findall(
            r"=\s*int\(args\[(\d+)\]\)|=\s*Path\(args\[(\d+)\]\)|"
            r"=\s*args\[(\d+)\]\s*if",
            cli_src,
        )
        # Flatten + sort by index value.
        ordered = sorted(int(a or b or c) for (a, b, c) in cli_indexes)

        # Verify both ends use the same positional count.
        assert len(spawn_args) == len(ordered), (
            f"argv length mismatch: spawn writes {len(spawn_args)} "
            f"args ({spawn_args}), _cli_main reads {len(ordered)} "
            f"positions ({ordered})"
        )
        # Verify _cli_main reads in 0-based contiguous positions.
        assert ordered == list(range(len(ordered))), (
            f"_cli_main reads non-contiguous positions {ordered} — "
            f"would skip an argv slot. Expected [0,1,2,...]."
        )

    def test_argv_count_matches_documented_usage(self):
        # Module docstring + _cli_main docstring both document the
        # CLI shape. Keep them in sync with the actual implementation.
        from core.sandbox import tracer

        # _cli_main's argument count matches what the module
        # docstring at file top documents.
        # Both forms are accepted: the module docstring uses
        # <child_pid> while _cli_main uses <pid>. Either documents
        # the same positional slot.
        assert "<child_pid>" in tracer.__doc__ or "<pid>" in tracer.__doc__
        assert "<run_dir>" in tracer.__doc__
        assert "<sync_fd>" in tracer.__doc__
        assert "<config_path>" in tracer.__doc__, (
            "module docstring missing config_path — stale from before "
            "the audit-filter config was added"
        )


class TestDenialTypeStringsAgreeAcrossModules:
    """Finding U: the denial_type string vocabulary
    {"network", "write", "seccomp"} is duplicated across at least
    five modules:
      - tracer.py:_NAME_TO_TYPE values + _denial_type fallback
      - proxy.py: hard-coded "network" in record_denial call
      - observe.py: _BLOCKED_PATTERNS first column (categories)
      - summary.py:_suggested_fix per-type branches
      - tests/test_summary.py expectations

    Drift class: tracer emits "ssecomp" (typo), summary's by_type
    counts it under "ssecomp" instead of "seccomp", operator's
    aggregation breaks silently. Pin the canonical set here so
    drift is caught fast."""

    CANONICAL_TYPES = {"network", "write", "seccomp"}

    def test_tracer_name_to_type_values_within_canonical(self):
        from core.sandbox.tracer import _NAME_TO_TYPE
        invalid = set(_NAME_TO_TYPE.values()) - self.CANONICAL_TYPES
        assert invalid == set(), (
            f"tracer._NAME_TO_TYPE has values outside canonical "
            f"{self.CANONICAL_TYPES}: {invalid}. Aggregation in "
            f"summary's by_type will silently bucket them under "
            f"the unknown type."
        )

    def test_tracer_denial_type_default_is_canonical(self):
        from core.sandbox.tracer import _denial_type
        # Unmapped name → default. Must be in canonical set.
        assert _denial_type("unknown_999_arbitrary") in self.CANONICAL_TYPES

    def test_observe_blocked_pattern_categories_within_canonical(self):
        from core.sandbox import observe
        # _BLOCKED_PATTERNS is a list of (category, regex) tuples.
        cats = {pair[0] for pair in observe._BLOCKED_PATTERNS}
        invalid = cats - self.CANONICAL_TYPES
        assert invalid == set(), (
            f"observe._BLOCKED_PATTERNS has categories outside "
            f"canonical {self.CANONICAL_TYPES}: {invalid}. These "
            f"would propagate to record_denial(... type=<bad>) and "
            f"break summary aggregation."
        )

    def test_summary_suggested_fix_handles_all_canonical_types(self):
        # _suggested_fix has explicit branches for "network", "write",
        # "seccomp" + a generic fallback. Verify every canonical type
        # has a non-default suggestion (otherwise operator gets the
        # generic "review denial" message instead of actionable
        # guidance).
        from core.sandbox.summary import _suggested_fix
        generic = _suggested_fix("totally-unknown-type")
        for t in self.CANONICAL_TYPES:
            specific = _suggested_fix(t)
            assert specific != generic, (
                f"_suggested_fix({t!r}) returns the generic "
                f"fallback — operator gets no actionable hint for "
                f"this canonical type"
            )


class TestConftestSnapshotMatchesState:
    """Finding T: every mutable module-level state variable in
    core/sandbox/state.py must be either snapshotted by the conftest
    autouse fixture OR explicitly excluded with a documented reason.
    Drift means a future test mutates new state and silently leaks
    it into subsequent tests — the autouse fixture is the safety net.
    """

    # Names that are deliberately excluded from snapshotting. Update
    # this set ONLY with a comment explaining why; consider whether
    # the exclusion is still right.
    DOCUMENTED_EXCLUSIONS = {
        "_landlock_cache",  # forking probe; cache persists per-process
        # Snapshotted in conftest.py but via a separate dict-deep-copy
        # mechanism (saved_spec_cache = dict(mod._speculative_failure_cache))
        # rather than the state_names string list — the regex below
        # only catches string literals so this name is "excluded"
        # from the regex check despite being properly snapshotted.
        # Added by PR #265 (mount-ns auto-fallback per-cmd cache).
        "_speculative_failure_cache",
    }

    def test_every_state_var_is_snapshotted_or_excluded(self):
        import re
        from core.sandbox import state
        # Pull the snapshot list literal from conftest source.
        with open("core/sandbox/tests/conftest.py") as f:
            cf_src = f.read()
        snapshot_names = set(re.findall(
            r'"(_[a-z][a-z0-9_]*)"', cf_src,
        ))

        # Module-level mutable state: underscore-prefixed, not callable,
        # not a lock.
        mutable = set()
        for name in dir(state):
            if not name.startswith("_") or name.startswith("__"):
                continue
            val = getattr(state, name)
            if callable(val):
                continue
            if hasattr(val, "acquire"):  # threading.Lock / RLock
                continue
            mutable.add(name)

        missing = mutable - snapshot_names - self.DOCUMENTED_EXCLUSIONS
        assert missing == set(), (
            f"state.py has mutable vars NOT in conftest snapshot AND "
            f"not in DOCUMENTED_EXCLUSIONS: {sorted(missing)}. New "
            f"state without snapshot causes inter-test leakage. Either "
            f"add to conftest.py snapshot list, or add to "
            f"DOCUMENTED_EXCLUSIONS with a comment explaining why."
        )

        # Reverse direction: anything in DOCUMENTED_EXCLUSIONS must
        # actually exist in state — otherwise the exclusion is stale
        # cargo (silent permission to "leak" something that's not
        # there any more, but next time a name like that gets added
        # it's pre-excluded).
        stale_exclusions = self.DOCUMENTED_EXCLUSIONS - mutable
        assert stale_exclusions == set(), (
            f"DOCUMENTED_EXCLUSIONS contains names NOT in state.py: "
            f"{sorted(stale_exclusions)}. Remove the exclusion."
        )


class TestPtraceConstantsMatchKernelUapi:
    """Finding S: tracer's PTRACE_EVENT_* and PTRACE_O_* constants
    must match the Linux UAPI values in <linux/ptrace.h>. Wrong
    values would cause one of:
      - SEIZE with bad option mask → kernel rejects EINVAL → tracer
        fails, audit silently degrades to none
      - Event-code dispatch fires on the wrong condition → records
        for fork events get dispatched as seccomp events, etc.

    Cross-check against /usr/include/linux/ptrace.h when readable
    (most Linux dev environments). Skipped on systems where the
    header isn't installed."""

    def _read_uapi_constants(self):
        """Parse /usr/include/linux/ptrace.h. Returns dict of
        constant name → int value, or None if unreadable."""
        import re
        try:
            with open("/usr/include/linux/ptrace.h") as f:
                src = f.read()
        except (FileNotFoundError, PermissionError):
            return None

        constants = {}
        # First pass: simple int defines (PTRACE_EVENT_* and
        # PTRACE_O_TRACESYSGOOD).
        for m in re.finditer(
            r"#define\s+(PTRACE_EVENT_\w+)\s+(\d+)", src
        ):
            constants[m.group(1)] = int(m.group(2))
        # Second pass: bit-shift defines that reference
        # PTRACE_EVENT_* (e.g. TRACEFORK = 1 << EVENT_FORK).
        for m in re.finditer(
            r"#define\s+(PTRACE_O_\w+)\s+\(1 << PTRACE_EVENT_(\w+)\)",
            src,
        ):
            event_val = constants.get(f"PTRACE_EVENT_{m.group(2)}")
            if event_val is not None:
                constants[m.group(1)] = 1 << event_val
        # Third pass: literal bit-shifts (EXITKILL = 1 << 20).
        for m in re.finditer(
            r"#define\s+(PTRACE_O_\w+)\s+\(1 << (\d+)\)", src
        ):
            constants[m.group(1)] = 1 << int(m.group(2))
        return constants

    def test_event_codes_match_uapi(self):
        import pytest
        kernel = self._read_uapi_constants()
        if kernel is None:
            pytest.skip("/usr/include/linux/ptrace.h not readable")
        from core.sandbox import tracer
        for our_name, kernel_name in [
            ("_PTRACE_EVENT_FORK", "PTRACE_EVENT_FORK"),
            ("_PTRACE_EVENT_VFORK", "PTRACE_EVENT_VFORK"),
            ("_PTRACE_EVENT_CLONE", "PTRACE_EVENT_CLONE"),
            ("_PTRACE_EVENT_EXIT", "PTRACE_EVENT_EXIT"),
            ("_PTRACE_EVENT_SECCOMP", "PTRACE_EVENT_SECCOMP"),
        ]:
            our = getattr(tracer, our_name)
            theirs = kernel.get(kernel_name)
            assert our == theirs, (
                f"{our_name}={our} but kernel {kernel_name}={theirs}"
            )

    def test_option_flags_match_uapi(self):
        import pytest
        kernel = self._read_uapi_constants()
        if kernel is None:
            pytest.skip("/usr/include/linux/ptrace.h not readable")
        from core.sandbox import tracer
        for our_name, kernel_name in [
            ("_PTRACE_O_TRACEFORK", "PTRACE_O_TRACEFORK"),
            ("_PTRACE_O_TRACEVFORK", "PTRACE_O_TRACEVFORK"),
            ("_PTRACE_O_TRACECLONE", "PTRACE_O_TRACECLONE"),
            ("_PTRACE_O_TRACEEXIT", "PTRACE_O_TRACEEXIT"),
            ("_PTRACE_O_TRACESECCOMP", "PTRACE_O_TRACESECCOMP"),
            ("_PTRACE_O_EXITKILL", "PTRACE_O_EXITKILL"),
        ]:
            our = getattr(tracer, our_name)
            theirs = kernel.get(kernel_name)
            assert our == theirs, (
                f"{our_name}={our:#x} but kernel "
                f"{kernel_name}={theirs:#x}"
            )


class TestAuditExtrasHaveHandlers:
    """Finding R: every syscall in seccomp's _AUDIT_EXTRA_TRACE_SYSCALLS
    (open/openat/connect today) MUST have a corresponding handler in
    the tracer's dispatch — either _path_arg_index returns an int
    (path-deref) or _decode_sockaddr is invoked. Otherwise a future
    addition to _AUDIT_EXTRA_TRACE_SYSCALLS (e.g., 'accept') would
    cause SCMP_ACT_TRACE to fire but the tracer would write records
    with raw uint64 args and no meaningful decoding — operator can't
    act on them."""

    def test_every_audit_extra_has_a_handler(self):
        from core.sandbox.seccomp import _AUDIT_EXTRA_TRACE_SYSCALLS
        from core.sandbox.tracer import _path_arg_index
        import inspect

        # Per-syscall: must be either path-bearing (path_arg_index
        # returns int) OR have explicit handling in the dispatch
        # function. Today the only non-path one is connect, which
        # is decoded via decode_sockaddr — pin that explicit case.
        from core.sandbox import tracer
        dispatch_src = inspect.getsource(tracer._handle_waitpid_event)

        unhandled = []
        for syscall in _AUDIT_EXTRA_TRACE_SYSCALLS:
            has_path_handler = _path_arg_index(syscall) is not None
            # The connect handler dispatches by literal name match
            # in the dispatch function — look for `name == "<syscall>"`
            # or `name in (...)` containing the name.
            has_explicit_handler = (
                f'name == "{syscall}"' in dispatch_src
                or f"'{syscall}'" in dispatch_src
                or f'"{syscall}"' in dispatch_src
            )
            if not (has_path_handler or has_explicit_handler):
                unhandled.append(syscall)

        assert unhandled == [], (
            f"audit-extras without a tracer handler: {unhandled}. "
            f"These syscalls would TRACE under audit mode but the "
            f"tracer can't decode their args → operator sees "
            f"meaningless raw uint64 records. Add a handler to "
            f"_handle_waitpid_event (path-deref via _path_arg_index "
            f"OR sockaddr-decode via _decode_sockaddr OR a custom "
            f"per-syscall path)."
        )

    def test_audit_extras_have_denial_type_mapping(self):
        # Each audit-extra needs a sensible denial_type so summary
        # aggregation classifies it correctly (write/network/seccomp).
        from core.sandbox.seccomp import _AUDIT_EXTRA_TRACE_SYSCALLS
        from core.sandbox.tracer import _denial_type, _NAME_TO_TYPE

        valid_types = {"write", "network", "seccomp"}
        for syscall in _AUDIT_EXTRA_TRACE_SYSCALLS:
            t = _denial_type(syscall)
            assert t in valid_types, (
                f"{syscall!r} maps to denial_type={t!r} which isn't "
                f"a valid type. summary aggregation would by_type-"
                f"count it under an unknown bucket."
            )
            # And the mapping should be EXPLICIT (in _NAME_TO_TYPE),
            # not falling through to the default 'seccomp'. Default
            # is correct for ptrace/bpf/io_uring/etc., but path
            # syscalls should explicitly map to 'write' and connect
            # to 'network' so a future change of the default doesn't
            # silently re-classify them.
            assert syscall in _NAME_TO_TYPE, (
                f"audit-extra {syscall!r} relies on _denial_type's "
                f"default fallback → silently miscategorised if the "
                f"default ever changes. Add explicit entry to "
                f"_NAME_TO_TYPE."
            )


class TestAuditConfigSchemaAgree:
    """Finding Q: the audit-config JSON file is a contract between
    _spawn.py (writer) and tracer.py (reader). The two ends use
    disjoint key-name vocabularies — a typo on either end would
    silently disable a feature:
      - _spawn writes 'verbose', tracer reads 'verbose' → OK
      - if _spawn renamed to 'is_verbose' silently, tracer's
        .get('verbose') would always return None (falsy) → all
        sandboxes would run filtered, audit-verbose flag dead.

    Pin both ends agree on key names by reading both sources."""

    def test_audit_config_keys_match(self):
        import inspect
        import re
        from core.sandbox import _spawn, tracer

        spawn_src = inspect.getsource(_spawn.run_sandboxed)
        # Both the dispatch function (per-event filter logic) AND the
        # trace() entry point (which reads one-shot config like the
        # audit-budget cap at startup) must be considered — a key
        # consumed in either is a contract the writer must honour.
        tracer_dispatch = (inspect.getsource(tracer._handle_waitpid_event)
                            + inspect.getsource(tracer.trace))

        # Extract keys written: pattern `"key":` inside audit_config dict.
        # Find audit_config = { ... } block specifically.
        config_block = re.search(
            r"audit_config\s*=\s*\{([^}]+)\}", spawn_src, re.DOTALL,
        )
        assert config_block, "audit_config dict not found in _spawn"
        written_keys = set(re.findall(
            r'"([a-z_]+)"\s*:', config_block.group(1),
        ))

        # Extract keys read: pattern `audit_filter.get("key")` and
        # `audit_filter["key"]` in the tracer's dispatch function.
        # re.DOTALL so multi-line .get(\n  "key", default\n) calls
        # are captured (they exist in tracer.py for readability).
        read_keys = set()
        read_keys.update(re.findall(
            r'audit_filter\.get\(\s*"([a-z_]+)"', tracer_dispatch,
            re.DOTALL,
        ))
        read_keys.update(re.findall(
            r'audit_filter\[\s*"([a-z_]+)"\s*\]', tracer_dispatch,
            re.DOTALL,
        ))

        # Tracer must not read keys that aren't written (silent None
        # leads to silent feature loss).
        unmet = read_keys - written_keys
        assert unmet == set(), (
            f"tracer reads audit-config keys not written by _spawn: "
            f"{sorted(unmet)}. The .get() defaults silently mask "
            f"the typo — feature(s) silently disabled."
        )
        # Spawn writing keys tracer never reads is more benign (just
        # bytes wasted) but still flag it as drift.
        unused = written_keys - read_keys
        assert unused == set(), (
            f"_spawn writes audit-config keys tracer never reads: "
            f"{sorted(unused)}. Either remove from _spawn or wire "
            f"the tracer dispatch to consume them."
        )


class TestAfInetConstantsAgree:
    """Finding P: AF_INET / AF_INET6 are duplicated in seccomp.py
    (used to filter UDP socket() calls) and tracer.py
    (_decode_sockaddr uses them to identify connect() destinations).
    Both are stable Linux UAPI values, but a typo in either place
    would cause silent wrong behaviour:
      - seccomp typo: UDP block fails to engage on the typoed family
      - tracer typo: connect events to AF_INET6 logged as
        'unsupported family' instead of decoded ip:port

    Both literals must agree. Pin the values structurally."""

    def test_af_inet_matches_across_seccomp_and_tracer(self):
        # Read seccomp's literals via inspection (they're module-level
        # constants).
        from core.sandbox import seccomp
        from core.sandbox import tracer
        import inspect, re

        # tracer's _decode_sockaddr defines AF_INET/AF_INET6 as
        # function-local constants. Pull them via source.
        src = inspect.getsource(tracer._decode_sockaddr)
        af_inet_m = re.search(r"AF_INET\s*=\s*(\d+)", src)
        af_inet6_m = re.search(r"AF_INET6\s*=\s*(\d+)", src)
        assert af_inet_m and af_inet6_m, (
            "tracer._decode_sockaddr must define AF_INET/AF_INET6"
        )
        tracer_af_inet = int(af_inet_m.group(1))
        tracer_af_inet6 = int(af_inet6_m.group(1))

        assert seccomp._AF_INET == tracer_af_inet, (
            f"AF_INET mismatch: seccomp={seccomp._AF_INET}, "
            f"tracer={tracer_af_inet} — UDP block / sockaddr decode "
            f"would be inconsistent"
        )
        assert seccomp._AF_INET6 == tracer_af_inet6, (
            f"AF_INET6 mismatch: seccomp={seccomp._AF_INET6}, "
            f"tracer={tracer_af_inet6}"
        )

    def test_af_inet_values_match_kernel_uapi(self):
        # Belt-and-braces: pin against the Linux ABI values. These
        # haven't changed since AF_INET was introduced and are
        # part of POSIX. socket.AF_INET = 2, socket.AF_INET6 = 10
        # on Linux; pin against socket module which reads them from
        # the kernel headers at install time.
        import socket
        from core.sandbox import seccomp
        assert seccomp._AF_INET == socket.AF_INET
        assert seccomp._AF_INET6 == socket.AF_INET6


class TestPathInAllowlist:
    """Pure prefix-match logic — no syscalls, no I/O."""

    def test_exact_match(self):
        assert tracer_mod._path_in_allowlist("/usr", ["/usr"]) is True
        assert tracer_mod._path_in_allowlist("/usr", ["/etc"]) is False

    def test_prefix_match_with_separator(self):
        assert tracer_mod._path_in_allowlist(
            "/usr/lib/foo", ["/usr"]) is True
        assert tracer_mod._path_in_allowlist(
            "/usr/lib/foo", ["/usr/lib"]) is True

    def test_no_false_match_on_word_boundary(self):
        # Critical: /usr should NOT match /usrbin (different path).
        assert tracer_mod._path_in_allowlist("/usrbin", ["/usr"]) is False
        assert tracer_mod._path_in_allowlist("/etcdpasswd", ["/etc"]) is False
        # Trailing slash on prefix must not change behaviour.
        assert tracer_mod._path_in_allowlist("/usrbin", ["/usr/"]) is False

    def test_empty_allowlist(self):
        assert tracer_mod._path_in_allowlist("/anywhere", []) is False

    def test_empty_prefix_in_list_skipped(self):
        # An empty string in the allowlist must NOT match every path.
        assert tracer_mod._path_in_allowlist(
            "/etc", ["", "/usr"]) is False

    def test_multiple_prefixes(self):
        allow = ["/usr", "/lib", "/tmp"]
        assert tracer_mod._path_in_allowlist("/tmp/x", allow) is True
        assert tracer_mod._path_in_allowlist("/lib/y", allow) is True
        assert tracer_mod._path_in_allowlist("/home/z", allow) is False


class TestIsWriteIntent:
    def test_rdonly_is_not_write(self):
        # O_RDONLY = 0; no write bits.
        assert tracer_mod._is_write_intent(0) is False

    def test_wronly(self):
        assert tracer_mod._is_write_intent(0o0000001) is True

    def test_rdwr(self):
        assert tracer_mod._is_write_intent(0o0000002) is True

    def test_creat_implies_write(self):
        # O_CREAT (0o0000100) without explicit WRITE — kernel still
        # treats this as create-intent. We must too.
        assert tracer_mod._is_write_intent(0o0000100) is True

    def test_trunc_implies_write(self):
        assert tracer_mod._is_write_intent(0o0001000) is True

    def test_rdonly_with_unrelated_flags(self):
        # O_NONBLOCK / O_CLOEXEC etc. don't imply write.
        # 0o4000 = O_NONBLOCK on Linux — should NOT match.
        assert tracer_mod._is_write_intent(0o4000) is False


class TestResolveTraceePath:
    """Resolve relative paths via /proc/<pid>/cwd or /proc/<pid>/fd/<dirfd>.

    Uses our own PID — /proc/self/cwd works regardless of arch / kernel
    permissions. Demonstrates the resolution logic without needing a
    traced child."""

    def test_absolute_path_passed_through(self):
        # Absolute paths are normalised but not resolved.
        out = tracer_mod._resolve_tracee_path(
            os.getpid(), "/usr/bin/foo", -100,
        )
        assert out == "/usr/bin/foo"

    def test_absolute_path_normalisation(self):
        # `..` collapsed lexically.
        out = tracer_mod._resolve_tracee_path(
            os.getpid(), "/a/b/../c", -100,
        )
        assert out == "/a/c"

    def test_relative_path_via_cwd(self):
        # Relative path with AT_FDCWD: resolves via /proc/<pid>/cwd
        # which symlinks to the test process's cwd.
        cwd = os.getcwd()
        out = tracer_mod._resolve_tracee_path(
            os.getpid(), "subfile.txt", tracer_mod._AT_FDCWD,
        )
        # Should be cwd + filename
        assert out == os.path.normpath(os.path.join(cwd, "subfile.txt"))

    def test_relative_path_via_dirfd(self, tmp_path):
        # Relative path with real dirfd: resolves via
        # /proc/<pid>/fd/<dirfd>.
        d = tmp_path / "d"
        d.mkdir()
        fd = os.open(str(d), os.O_RDONLY)
        try:
            out = tracer_mod._resolve_tracee_path(
                os.getpid(), "child.txt", fd,
            )
            assert out == os.path.normpath(str(d / "child.txt"))
        finally:
            os.close(fd)

    def test_unreadable_proc_link_returns_path_unchanged(self, tmp_path):
        # Bogus dirfd → /proc/<pid>/fd/9999 doesn't exist → readlink
        # raises → fall back to input.
        out = tracer_mod._resolve_tracee_path(
            os.getpid(), "x.txt", 99999,
        )
        # Either resolves (if 9999 happens to exist) or returns "x.txt"
        # unchanged; we just assert no crash.
        assert isinstance(out, str)


class TestDecodeSockaddr:
    """Decode AF_INET / AF_INET6 sockaddr from the tracee. Uses our
    own process so process_vm_readv works without ptrace attach."""

    def test_decode_af_inet(self):
        import ctypes
        # Build a sockaddr_in: family=2 (AF_INET), port=443, addr=1.2.3.4
        # struct sockaddr_in: family (2), port (2 BE), addr (4)
        buf = bytes([2, 0]) + (443).to_bytes(2, "big") + bytes([1, 2, 3, 4])
        c_buf = ctypes.create_string_buffer(buf)
        result = tracer_mod._decode_sockaddr(
            os.getpid(), ctypes.addressof(c_buf), len(buf),
        )
        assert result is not None
        family, port, ip = result
        assert family == "AF_INET"
        assert port == 443
        assert ip == "1.2.3.4"

    def test_decode_af_inet6(self):
        import ctypes
        # struct sockaddr_in6: family (2), port (2 BE), flowinfo (4),
        # addr (16), scope_id (4)
        buf = (
            bytes([10, 0])  # family = 10 (AF_INET6)
            + (8080).to_bytes(2, "big")  # port
            + bytes([0, 0, 0, 0])  # flowinfo
            + bytes([0x20, 0x01, 0x0d, 0xb8] + [0]*12)  # 2001:db8::
            + bytes([0, 0, 0, 0])  # scope_id
        )
        c_buf = ctypes.create_string_buffer(buf)
        result = tracer_mod._decode_sockaddr(
            os.getpid(), ctypes.addressof(c_buf), len(buf),
        )
        assert result is not None
        family, port, ip = result
        assert family == "AF_INET6"
        assert port == 8080
        assert ip.startswith("2001:db8")

    def test_unsupported_family_returns_none(self):
        import ctypes
        # AF_UNIX = 1
        buf = bytes([1, 0]) + bytes([0]*4)
        c_buf = ctypes.create_string_buffer(buf)
        result = tracer_mod._decode_sockaddr(
            os.getpid(), ctypes.addressof(c_buf), len(buf),
        )
        assert result is None

    def test_null_addr_returns_none(self):
        assert tracer_mod._decode_sockaddr(os.getpid(), 0, 0) is None

    def test_too_short_returns_none(self):
        # addrlen < 4 means we can't even read the family.
        assert tracer_mod._decode_sockaddr(os.getpid(), 0x1000, 2) is None


class TestFilterDispatchSeccomp:
    """End-to-end of _handle_waitpid_event with audit_filter set —
    verify the filter drops/keeps events as designed."""

    def _make_arch_info(self, syscall_nr_for_openat: int = 257):
        # x86_64 default; aarch64 uses 56 for openat.
        return tracer_mod._ARCH_INFO[tracer_mod._ARCH]

    def _seccomp_event_status(self) -> int:
        import signal
        return ((tracer_mod._PTRACE_EVENT_SECCOMP << 16)
                | (signal.SIGTRAP << 8) | 0x7f)

    def _common_helpers(self, syscall_name="openat",
                        syscall_args=None, path_returned="/etc/hostname"):
        """Build a fake-helpers dict for the dispatch test."""
        nr_x86_64 = 257
        nr_aarch64 = 56
        nr = nr_x86_64 if tracer_mod._ARCH == "x86_64" else nr_aarch64
        if syscall_args is None:
            syscall_args = [tracer_mod._AT_FDCWD & 0xffffffffffffffff,
                            0x1000, 0, 0, 0, 0]
        recorded = []

        def fake_ptrace_cont(pid, sig=0): return True
        def fake_read_regs(pid, ai): return b"\x00" * ai["user_regs_size"]
        def fake_decode_syscall(regs, ai): return nr, list(syscall_args)
        def fake_read_tracee_string(pid, addr, max_bytes=4096):
            return path_returned
        def fake_get_event_msg(pid): return None
        def fake_write_record(run_dir, name, n, args, target_pid, path=None,
                              *, filename=None, mode_field=None,
                              nonce=None):
            recorded.append({"name": name, "path": path,
                             "filename": filename,
                             "mode_field": mode_field,
                             "nonce": nonce})
            return True
        def fake_resolve_path(pid, path, dirfd):
            # Pretend resolution succeeded with the input path.
            return path if path.startswith("/") else f"/cwd/{path}"
        def fake_decode_sockaddr(pid, addr, addrlen):
            return ("AF_INET", 443, "1.2.3.4")

        return {
            "ptrace_cont": fake_ptrace_cont,
            "read_regs": fake_read_regs,
            "decode_syscall": fake_decode_syscall,
            "read_tracee_string": fake_read_tracee_string,
            "get_event_msg": fake_get_event_msg,
            "write_record": fake_write_record,
            "resolve_path": fake_resolve_path,
            "decode_sockaddr": fake_decode_sockaddr,
            "_recorded": recorded,
        }

    def test_filtered_drops_path_in_allowlist(self):
        # /etc is in the read allowlist → openat /etc/hostname filtered.
        helpers = self._common_helpers(path_returned="/etc/hostname")
        audit_filter = {
            "verbose": False,
            "writable_paths": ["/tmp"],
            "read_allowlist": ["/etc", "/usr", "/tmp"],
            "allowed_tcp_ports": [],
        }
        traced = {1000}
        budget = audit_budget.AuditBudget()
        tracer_mod._handle_waitpid_event(
            1000, self._seccomp_event_status(),
            traced, 1000, self._make_arch_info(),
            Path("/tmp"), budget,
            audit_filter=audit_filter,
            **{k: v for k, v in helpers.items() if not k.startswith("_")},
        )
        # Record dropped by the audit filter (path matched the
        # allowlist) BEFORE reaching the budget — write_record never
        # called and budget.total_records stays at 0.
        assert helpers["_recorded"] == []
        assert budget.total_records == 0

    def test_filtered_keeps_path_outside_allowlist(self):
        # /home/user/.ssh/id_rsa is NOT in the allowlist → recorded.
        helpers = self._common_helpers(path_returned="/home/user/.ssh/id_rsa")
        audit_filter = {
            "verbose": False,
            "writable_paths": ["/tmp"],
            "read_allowlist": ["/etc", "/usr", "/tmp"],
            "allowed_tcp_ports": [],
        }
        traced = {1000}
        budget = audit_budget.AuditBudget()
        tracer_mod._handle_waitpid_event(
            1000, self._seccomp_event_status(),
            traced, 1000, self._make_arch_info(),
            Path("/tmp"), budget,
            audit_filter=audit_filter,
            **{k: v for k, v in helpers.items() if not k.startswith("_")},
        )
        assert len(helpers["_recorded"]) == 1
        assert helpers["_recorded"][0]["path"] == "/home/user/.ssh/id_rsa"
        assert budget.total_records == 1

    def test_verbose_keeps_everything(self):
        # Same allowlisted path as test_filtered_drops_path_in_allowlist,
        # but verbose=True → record kept (verbose disables filter).
        helpers = self._common_helpers(path_returned="/etc/hostname")
        audit_filter = {
            "verbose": True,
            "writable_paths": ["/tmp"],
            "read_allowlist": ["/etc", "/usr", "/tmp"],
            "allowed_tcp_ports": [],
        }
        traced = {1000}
        budget = audit_budget.AuditBudget()
        tracer_mod._handle_waitpid_event(
            1000, self._seccomp_event_status(),
            traced, 1000, self._make_arch_info(),
            Path("/tmp"), budget,
            audit_filter=audit_filter,
            **{k: v for k, v in helpers.items() if not k.startswith("_")},
        )
        # Verbose mode bypasses the allowlist filter — the record IS
        # written. write_record fake records into helpers["_recorded"].
        assert len(helpers["_recorded"]) == 1, (
            f"verbose=True should keep the record; got "
            f"{helpers['_recorded']!r}"
        )
        assert budget.total_records == 1

    def test_no_filter_keeps_everything(self):
        # audit_filter=None → no filtering (legacy/default behaviour).
        helpers = self._common_helpers(path_returned="/etc/hostname")
        traced = {1000}
        budget = audit_budget.AuditBudget()
        tracer_mod._handle_waitpid_event(
            1000, self._seccomp_event_status(),
            traced, 1000, self._make_arch_info(),
            Path("/tmp"), budget,
            audit_filter=None,
            **{k: v for k, v in helpers.items() if not k.startswith("_")},
        )
        # No filter → record kept regardless of path.
        assert len(helpers["_recorded"]) == 1
        assert budget.total_records == 1


class TestEndToEndAuditVsAuditVerbose:
    """Real run: same workload under `audit` and `audit-verbose`,
    verify record counts differ in the expected direction."""

    @staticmethod
    def _prereqs_ok():
        if not probes.check_net_available():
            return False, "user namespaces unavailable"
        if not ptrace_probe.check_ptrace_available():
            return False, "ptrace unavailable"
        if not probes.check_mount_available():
            return False, "mount-ns unavailable"
        return True, ""

    def test_filtered_drops_more_than_verbose(self, tmp_path):
        ok, reason = self._prereqs_ok()
        if not ok:
            pytest.skip(reason)
        if not os.path.exists("/usr/bin/python3"):
            pytest.skip("/usr/bin/python3 not present")

        from core.sandbox._spawn import run_sandboxed

        run_filtered = tmp_path / "filtered"
        run_filtered.mkdir()
        run_verbose = tmp_path / "verbose"
        run_verbose.mkdir()

        # `python -c "pass"` opens many files in /usr/lib/... — all
        # legitimate, all in the system allowlist. Filtered audit
        # should produce 0 records; verbose should produce many.
        cmd = ["/usr/bin/python3", "-c", "pass"]

        def _run(rd, verbose):
            return run_sandboxed(
                cmd,
                target=str(tmp_path), output=str(tmp_path),
                block_network=False, nproc_limit=0, limits={},
                writable_paths=[str(tmp_path)], readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile="full", seccomp_block_udp=False,
                env=None, cwd=None, timeout=15,
                audit_mode=True, audit_run_dir=str(rd),
                audit_verbose=verbose,
            )

        r1 = _run(run_filtered, verbose=False)
        r2 = _run(run_verbose, verbose=True)
        assert r1.returncode == 0
        assert r2.returncode == 0

        # Filtered: 0 or near-zero records (python opens only system
        # paths).
        f_jsonl = run_filtered / tracer_mod._DENIALS_FILENAME
        f_count = (sum(1 for _ in open(f_jsonl)) if f_jsonl.exists()
                   else 0)
        # Verbose: many records (Python startup is open-heavy).
        v_jsonl = run_verbose / tracer_mod._DENIALS_FILENAME
        assert v_jsonl.exists()
        v_count = sum(1 for _ in open(v_jsonl))

        # Verbose should have at least 5x more records than filtered.
        # (Real ratio is more like 30-100x; 5x is a lower bound.)
        assert v_count >= max(5 * f_count, 5), (
            f"audit-verbose should produce many more records than "
            f"audit (filtered): filtered={f_count}, verbose={v_count}"
        )
