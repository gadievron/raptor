"""Shared taxonomy of function-name categories with security significance.

One source of truth for "dangerous string function", "exec sink", "parser
entry point", etc. — consumers (packages/binary_analysis,
packages/exploit_feasibility) compose the union they need from these
primitive frozensets. Replaces three previously-divergent lists:

  - packages/binary_analysis/radare2_understand._DANGEROUS_IMPORTS
  - packages/exploit_feasibility/constants.{COMMON,INPUT,STRING_TERMINATING}_FUNCTIONS
  - packages/binary_analysis/radare2_understand._DANGEROUS_MACOS_SUBSTRINGS

Curation policy (why some "obvious" entries are missing):

  - **Ubiquitous functions are deliberately excluded from the categories
    that drive fuzz-prioritisation signal.** `malloc`, `realloc`, `free`,
    `open`, `fopen`, `read`, `write`, `printf`, `fprintf`, `vprintf`
    appear in essentially every binary — if every binary "imports a
    dangerous function" then the signal value is zero. These functions
    are added back where they ARE useful (e.g. `COMMON_FUNCTIONS` for
    ROP target enumeration in exploit_feasibility) by the consumer's
    composition, not by this module.

  - **The CVE-shape determines category, not the function family.**
    `snprintf` is in `FORMAT_STRING_FUNCS` rather than
    `STRING_OVERFLOW_FUNCS` because its dominant CVE shape is
    format-string when the format is tainted; the bounded-size param
    actually prevents the classic overflow.

  - **"Safe" variants are NOT in the dangerous categories.** Microsoft's
    `wcscpy_s` / `wcsncpy_s` (`_s` suffix = explicit size param) and
    safe temp-file APIs (`tmpfile`, `mkstemp`) are deliberately omitted.
    Banned-by-design APIs (`mktemp`, `tempnam`) ARE included.

  - **Category membership is closed-list, not pattern-matched.** macOS
    Swift/ObjC symbols use substring matching (see
    `MACOS_DANGEROUS_SUBSTRINGS`) because demangled Swift names embed
    type/parameter info that breaks exact equality. Everything else is
    plain function-name equality.

Per-consumer compositions live in the consumer files
(`packages/binary_analysis/radare2_understand.py`,
`packages/exploit_feasibility/constants.py`) so the consumer's intent
is visible at the use site.
"""

from __future__ import annotations

# === Bounded-string functions with classic overflow CVE shapes ===
# Note: snprintf/vsnprintf and their wide-char cousins are NOT here —
# their dominant CVE shape is format-string (see FORMAT_STRING_FUNCS),
# not overflow. The bounded-size param actually prevents the classic
# CWE-120 overflow.
STRING_OVERFLOW_FUNCS: frozenset[str] = frozenset({
    # No bounds checking at all
    "strcpy", "strcat", "sprintf", "vsprintf",
    "gets",  # banned by C11 Annex K, still found in legacy code

    # Bounded but off-by-one / no-NUL-termination CVEs are common
    "strncpy", "strncat",

    # BSD variants — same risk shape as strcpy
    "stpcpy", "stpncpy",

    # Wide-char variants — overflow patterns identical to char* siblings
    "wcscpy", "wcsncpy", "wcscat", "wcsncat",

    # Windows ANSI/Unicode equivalents — Microsoft has both
    # safe (`_s` suffix) and unsafe variants. The unsafe ones below
    # have the same risk shape as strcpy.
    "lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW",
})


# === scanf-family parsing ===
# Format-string driven input parsing — overlaps conceptually with
# FORMAT_STRING_FUNCS (when the format is tainted) and with INTEGER_
# PARSE_FUNCS (when %d / %u is the only parser). Kept as own category
# because the analysis pattern differs from atoi/strto* (scanf has its
# own bounded vs unbounded %s rules).
SCAN_FAMILY_FUNCS: frozenset[str] = frozenset({
    "scanf", "vscanf", "sscanf", "fscanf", "vsscanf", "vfscanf",
    "wscanf", "swscanf",
})


# === Size-tainted memory copy operations ===
# memcpy is itself ubiquitous, but the pattern
# `memcpy(buf, attacker_data, attacker_size)` is THE classic CVE so
# the import IS signal — every binary uses memcpy, but a binary that
# uses memcpy on caller-supplied size is worth fuzzing more aggressively.
MEMORY_COPY_FUNCS: frozenset[str] = frozenset({
    "memcpy", "memmove", "bcopy",
    # Wide-char variants
    "wmemcpy", "wmemmove",
})


# === Format-string sinks (rare/distinguishing only) ===
# printf / fprintf / vprintf are DELIBERATELY EXCLUDED — they're
# ubiquitous so importing them is zero signal. Consumers that need
# exhaustive format-string detection (e.g. exploit_feasibility's
# format-string constraint analysis) should compose this set with
# the common-ones in their own file.
#
# snprintf / vsnprintf are included here (not in STRING_OVERFLOW)
# because their dominant CVE shape is format-string-when-tainted,
# not overflow (the size param prevents the overflow).
FORMAT_STRING_FUNCS: frozenset[str] = frozenset({
    "vfprintf",
    "syslog",
    "snprintf", "vsnprintf",

    # BSD format-string wrappers — frequently called with user input
    "err", "errx", "warn", "warnx",

    # Apple equivalents (macOS / iOS native code)
    "NSLog", "CFLog", "os_log", "os_log_with_type",

    # Windows ANSI/Unicode wsprintf — format-string variants of
    # sprintf. (Windows safe variants like StringCchPrintf are NOT
    # included — explicit size param.)
    "wsprintfA", "wsprintfW",
})


# === Process execution / command injection sinks ===
EXEC_FUNCS: frozenset[str] = frozenset({
    "system", "popen",
    "execl", "execv", "execlp", "execvp", "execle", "execve",
    "posix_spawn", "posix_spawnp",
    "fexecve", "execvpe",

    # Windows
    "CreateProcessA", "CreateProcessW",
    "CreateProcessAsUserA", "CreateProcessAsUserW",
    "CreateProcessWithLogonW",
    "ShellExecuteA", "ShellExecuteW",
    "ShellExecuteExA", "ShellExecuteExW",
    "WinExec",
})


# === Size-tainted allocation ===
# malloc / realloc REMOVED (ubiquitous). Strong-signal entries:
#   calloc:  nmemb * size integer-overflow CWE-190 → CWE-122
#   alloca:  stack-allocation CWE-770, unbounded if size is tainted
# The remaining entries are uncommon enough that the import is still
# signal even though their individual CVE history is thinner.
ALLOC_FUNCS: frozenset[str] = frozenset({
    "calloc",
    "alloca",
    "posix_memalign", "aligned_alloc",
    "valloc", "memalign", "pvalloc",
})


# === Network ingestion / server-side indicators ===
# read REMOVED (ubiquitous; network ingestion uses recv* explicitly).
# accept / bind / listen are server-side markers — different semantic
# from recv* but bundled together because both answer "is this binary
# doing network I/O" (fuzz-priority interest is similar).
NETWORK_INGEST_FUNCS: frozenset[str] = frozenset({
    "recv", "recvfrom", "recvmsg", "recvmmsg",
    "accept", "bind", "listen",
    # OpenSSL
    "SSL_read", "BIO_read",
})


# === Stream / file input (non-ubiquitous variants) ===
# Buffered line/delimiter input + non-trivial fd-level reads. The
# ubiquitous variants (read, fread, fopen) are excluded per the
# module-wide policy — they're in every binary so their import is
# zero fuzz-priority signal. The variants kept here are deliberate
# choices: someone using getline/getdelim is doing structured parsing,
# someone using pread/readv is doing positional or scatter-gather I/O,
# someone using fgets is reading bounded lines (common in CLI parsers
# and network protocol handlers). gets() lives in STRING_OVERFLOW_FUNCS
# (banned API) and is therefore excluded here to keep categories
# disjoint.
STREAM_INPUT_FUNCS: frozenset[str] = frozenset({
    "fgets", "fgetws",
    "getline", "getdelim",
    "pread", "preadv", "readv",
})


# === Process boundary inputs (env) ===
# argv / envp are MAIN parameters, not function calls — they appear
# in source code but not in import tables, so they're outside this
# module's grain (function-name catalog). The function-call shaped
# attacker-controlled equivalent is plain getenv. secure_getenv and
# getauxval are NOT here — they're context markers, not sources
# (see PROCESS_BOUNDARY_MARKERS below).
PROCESS_BOUNDARY_FUNCS: frozenset[str] = frozenset({
    "getenv",
})


# === IPC primitives where less-privileged peers can write ===
# Shared memory + message queues. Deliberately excluded:
#   * mmap — most usage is file-backed read-only, not attacker-
#     controlled shared memory, and you cannot distinguish from the
#     call site alone (CVE-shape-determines-category policy).
#   * shm_open — returns an fd; the actual attacker-data read goes
#     through mmap (excluded above) or read (ubiquitous), so flagging
#     shm_open alone yields a category with no live read primitive.
#   * pipe / mkfifo — setup primitives, not read primitives. The
#     actual attacker-data read happens via read() on the resulting
#     fd (ubiquitous).
IPC_FUNCS: frozenset[str] = frozenset({
    "shmat", "shmget",
    "mq_receive", "mq_timedreceive",
    "msgrcv",
})


# === Runtime privilege manipulation / sandbox escape ===
# Symbols a worm / rootkit payload typically links against to
# elevate privilege, escape namespace isolation, or load kernel
# code at install time.  These are not normal capabilities for a
# package's native dependency; their presence in a published
# tarball is a strong supply-chain signal under Phase 3
# binary-in-package detection.
#
# Not used as a taint source — used as a SHAPE classifier in
# :mod:`core.binary.fingerprint` so consumers (the binary-in-package
# evidence generator, drift detection, composite scoring's BINARY
# family promotion) can flag binaries that import these symbols.
#
# Deliberately EXCLUDED — too ubiquitous to be signal:
#   * ``clone`` / ``clone3`` — libpthread links transitively; any
#     threaded program imports them
#   * ``prctl`` — used by glibc internals for thread naming and
#     by many normal programs (rust binaries, go binaries)
#   * ``fork`` / ``execve`` — already in EXEC_FUNCS; the supply-
#     chain signal there is the EXEC bucket, not duplicated here
RUNTIME_PRIVILEGE_FUNCS: frozenset[str] = frozenset({
    # POSIX privilege manipulation — rare in normal package binaries
    "setuid", "setgid", "seteuid", "setegid",
    "setresuid", "setresgid", "setreuid", "setregid",
    "setfsuid", "setfsgid",
    "capset",
    # Linux namespace / container primitives — only container tools
    # import these directly; a published npm/PyPI package binary
    # doing so is anomalous.
    "unshare", "setns",
    "chroot", "pivot_root",
    "mount", "umount", "umount2",
    # eBPF / kernel-side execution — extremely rare in legit deps
    "bpf",
    "bpf_prog_load",
    "bpf_create_map", "bpf_map_create",
    # Kernel module load — only kernel-driver tools
    "init_module", "finit_module", "delete_module",
    # Kexec — replace running kernel
    "kexec_load", "kexec_file_load",
    # Process tracing (rootkit hide / debugger interpose).
    # Legitimate debuggers (gdb / lldb / strace) do import it,
    # but none of those should ship in a normal package tarball.
    "ptrace",
    "setdomainname", "sethostname",
})


# === Kernel tracing / observability hijack ===
# Symbols associated with kernel-level tracing, performance
# counters, or cross-process memory inspection — the substrate
# rootkits use to interpose on other processes (read secrets,
# inject code) without ptrace's user-visible signal.
KERNEL_TRACE_FUNCS: frozenset[str] = frozenset({
    # Performance / tracing subsystem
    "perf_event_open",
    # Cross-process memory access
    "process_vm_readv", "process_vm_writev",
    # User-faulting (memory page fault interception)
    "userfaultfd",
    # Kernel-side keyring access
    "add_key", "request_key", "keyctl",
})


# === Kernel / userspace boundary (kernel-side only) ===
# Functions called by KERNEL CODE (drivers, syscalls, kernel modules)
# to read attacker-controlled data from less-privileged userspace.
# These do NOT appear in user-space binary import tables, so the
# binary-fingerprint and fuzz-priority consumers ignore them; the
# value is for source-code analysis of kernel modules and driver
# audits where userspace pointers are the canonical L1 source. The
# `_*` / `__` prefixes are kept because Linux kernel symbol naming
# uses them at the call site (no need for fortified() expansion).
#
# Covers three sub-families:
#   1. Bare-copy primitives (copy_from_user, get_user, raw / inatomic)
#   2. Allocator wrappers that copy in one call (memdup_user et al.)
#   3. iovec / pages interfaces for scatter-gather + DMA paths
KERNEL_USERSPACE_FUNCS: frozenset[str] = frozenset({
    # Bare copies
    "copy_from_user", "_copy_from_user",
    "raw_copy_from_user", "__copy_from_user_inatomic",
    "get_user", "__get_user",
    "strncpy_from_user", "strnlen_user",
    # Allocator wrappers (alloc + copy_from_user in one call)
    "memdup_user", "memdup_user_nul",
    "vmemdup_user",
    "strndup_user",
    # iovec / pages — scatter-gather, DMA-adjacent
    "import_iovec", "import_single_range",
    "_copy_from_iter", "copy_from_iter_full",
    "get_user_pages", "get_user_pages_fast",
})


# === Device-control entry points (driver command interfaces) ===
# ioctl-style entry points often carry attacker-supplied command values
# or request structs. They are function-name shaped, unlike argv/envp,
# so they belong in the shared catalog. Source-side scanners may treat
# them as L1 context; import/fuzz-priority consumers can opt in only when
# this signal is meaningful for their target class.
DEVICE_CONTROL_FUNCS: frozenset[str] = frozenset({
    "ioctl", "unlocked_ioctl", "compat_ioctl",
})


# === Process boundary markers (suid-context signal) ===
# NOT a source set — separate to avoid contaminating consumers that
# expect "attacker-controlled input lands here". These are *signals*
# that the author was aware of suid safety (or that suid context
# matters). Their *return values* are either NULL (secure_getenv in
# suid) or kernel-supplied (getauxval). A static analyser uses these
# to weight the suspicion of co-located plain getenv calls, not as
# direct taint sources.
PROCESS_BOUNDARY_MARKERS: frozenset[str] = frozenset({
    "secure_getenv",
    "getauxval",
})


# === High-CVE-density parser entry points ===
# The biggest single signal source for fuzz prioritisation. A binary
# that imports any of these is processing structured external input
# and is worth aggressive coverage.
#
# SEED SET + DATA PACK. The literal below is a marked seed set (<= 9
# exemplars, one per format category) documenting the pattern; the
# library catalog bulk lives in the CVE-corpus-derived data pack
# ``data/packs/parser_apis.json`` (per-name library + CVE provenance),
# refreshed by ``libexec/raptor-parser-pack-harvest`` — growing this
# category means harvesting or editing pack DATA, never this literal.
# ``PARSER_FUNCS`` is the seeds<pack union, so consumers keep a single
# name for the whole category.
PARSER_SEED_FUNCS: frozenset[str] = frozenset({
    "yyparse",           # parser-generator output (yacc/bison)
    "XML_Parse",         # XML (expat)
    "json_loads",        # JSON (jansson)
    "d2i_X509",          # ASN.1/DER (OpenSSL)
    "luaL_loadstring",   # embedded scripting (Lua)
    "png_read_info",     # image (libpng)
    "jpeg_read_header",  # image (libjpeg)
    "inflate",           # compression (zlib)
    "ZSTD_decompress",   # compression (zstd)
})


def _load_parser_pack() -> frozenset[str]:
    """Names from the parser_apis data pack. Missing/malformed pack →
    empty set (consumers run on seeds alone); never raises."""
    import json as _json
    import logging as _logging
    from pathlib import Path as _Path

    pack_path = (
        _Path(__file__).resolve().parent
        / "data" / "packs" / "parser_apis.json"
    )
    try:
        raw = _json.loads(pack_path.read_text(encoding="utf-8"))
        names = {
            e.get("name")
            for e in raw.get("entries", [])
            if isinstance(e, dict)
        }
        return frozenset(
            n for n in names
            if isinstance(n, str) and n.isidentifier()
        )
    except (OSError, ValueError, AttributeError):
        _logging.getLogger(__name__).warning(
            "parser_apis pack unavailable at %s; PARSER_FUNCS runs on "
            "seeds only", pack_path,
        )
        return frozenset()


PARSER_FUNCS: frozenset[str] = PARSER_SEED_FUNCS | _load_parser_pack()


# === Integer parsing (CWE-190 / -191 hints) ===
# atoi family: no overflow checking, classic source of integer bugs
# strto* family: overflow detectable via errno but the "didn't check
#   errno" pattern is common — the import is still signal.
# Float parsing (atof / strto[d,f,ld]) is DELIBERATELY EXCLUDED —
# float-overflow CVE pattern is fundamentally different from integer
# overflow and doesn't usually map to memory corruption.
INTEGER_PARSE_FUNCS: frozenset[str] = frozenset({
    "atoi", "atol", "atoll",
    "strtoul", "strtol", "strtoull", "strtoll",
})


# === TOCTOU + path-traversal pattern markers ===
# Includes the BANNED-BY-DESIGN temp-file APIs (mktemp, tempnam) which
# CWE-377-guarantee a race condition by construction. tmpfile and
# mkstemp are NOT here — they're race-free when used correctly.
# stat / lstat / chdir excluded — too common to signal anything.
TOCTOU_FUNCS: frozenset[str] = frozenset({
    "access", "faccessat",
    "realpath", "readlink", "readlinkat",
    "chroot",
    "mktemp", "tempnam",
})


# === macOS Swift / Objective-C dangerous symbols ===
# Different match semantics from the above — Swift symbol mangling
# embeds type/parameter info so exact-equality match misses real call
# sites. Consumers must do `substring in demangled_name` checking,
# not `name in MACOS_DANGEROUS_SUBSTRINGS`.
#
# Grouped by security category so consumers (surface_classification)
# classify from the taxonomy instead of re-listing names. The flat
# MACOS_DANGEROUS_SUBSTRINGS set is the DERIVED union — add a new
# symbol to exactly one group; a drift guard asserts the union stays
# complete and the groups disjoint.

# Structured-data parse surfaces (plist / JSON / XML deserialization).
MACOS_PARSER_SUBSTRINGS: frozenset[str] = frozenset({
    "CFPropertyListCreateWithData", "CFPropertyListCreateFromXMLData",
    "CFXMLParserCreate", "CFXMLTreeCreateFromData",
    "Foundation.JSONSerialization",
    "Foundation.PropertyListSerialization",
    "Foundation.PropertyListDecoder",
    "Foundation.JSONDecoder",
    "Foundation.Data.base64Encoded",
})

# Filesystem / URL handling surfaces.
MACOS_FILESYSTEM_URL_SUBSTRINGS: frozenset[str] = frozenset({
    "CFURLCreateWithBytes",
    "Foundation.Data.contentsOf",
    "Foundation.URL.fileURLWithPath",
    "Foundation.URL.absoluteString",
})

# Apple security framework / keychain boundary APIs. The prefix tuple
# is what consumers match with (SecTrust* covers the wider family);
# the named entries are the catalogued exemplars.
MACOS_SECURITY_BOUNDARY_PREFIXES: tuple = (
    "SecTrust", "SecPolicy", "SecItem", "SecKeychain",
)
MACOS_SECURITY_BOUNDARY_SUBSTRINGS: frozenset[str] = frozenset({
    "SecPolicyCreateSSL",
    "SecTrustEvaluate",
    "SecItemCopyMatching",
    "SecKeychainItem",
})

# NSData / NSString / CF byte-buffer interop — option/byte-buffer
# parameters often carry tainted input (base64 decode flags, byte
# ranges). Catalogued for import-surface weighting; not yet mapped to
# a classification category by surface_classification.
MACOS_BYTE_BUFFER_SUBSTRINGS: frozenset[str] = frozenset({
    "CFReadStreamRead", "CFDataGetBytes", "CFStringCreateWithBytes",
    "Foundation.Data.write",
    "Foundation.Data.Iterator",
    "NSDataReadingOptions",
    "NSDataBase64DecodingOptions",
    "NSStringFromBytes",
})

# Process execution via Foundation (NSTask / Swift Process).
MACOS_PROCESS_EXEC_SUBSTRINGS: frozenset[str] = frozenset({
    "NSTask",
    "Foundation.Process",
})

MACOS_DANGEROUS_SUBSTRINGS: frozenset[str] = (
    MACOS_PARSER_SUBSTRINGS
    | MACOS_FILESYSTEM_URL_SUBSTRINGS
    | MACOS_SECURITY_BOUNDARY_SUBSTRINGS
    | MACOS_BYTE_BUFFER_SUBSTRINGS
    | MACOS_PROCESS_EXEC_SUBSTRINGS
)


# === Entry-point name exact matches ===
# Function-name EXACT matches that suggest the function is an entry
# point worth exploring. Used by radare2_understand for membership
# check; the consumer separately applies a suffix-pattern check for
# `*main`/`*init`/`*Main`/`*Init`/`*Entry` patterns (those don't
# belong here — they're patterns, not names).
ENTRY_POINT_HINTS: frozenset[str] = frozenset({
    "main", "_start", "wmain",
    "WinMain", "DllMain", "DriverEntry",
    "LLVMFuzzerTestOneInput",   # libFuzzer harness convention
    "do_main",                   # common alias seen in real codebases
})


# === Helpers ===

def fortified(base: frozenset[str]) -> frozenset[str]:
    """Return the FORTIFY_SOURCE __*_chk variants of every function in
    `base`. Exact-match set — useful for consumers that need to
    recognise `__strcpy_chk` as the bounded variant of `strcpy`
    (e.g. distinguishing fortified-build vs non-fortified-build
    behaviour during exploit primitive selection).

    No current consumer uses this; substring-matching `__chk` against
    objdump output covers the most common case (packages/exploit_
    feasibility/analyzer.py). Kept here for future consumers that need
    exact-match semantics — if a downstream wants to map a
    `__strcpy_chk` symbol back to the unfortified `strcpy`, doing
    `name in fortified(STRING_OVERFLOW_FUNCS)` is the right shape.
    """
    return frozenset(f"__{name}_chk" for name in base)


__all__ = [
    "ALLOC_FUNCS",
    "DEVICE_CONTROL_FUNCS",
    "ENTRY_POINT_HINTS",
    "EXEC_FUNCS",
    "FORMAT_STRING_FUNCS",
    "INTEGER_PARSE_FUNCS",
    "IPC_FUNCS",
    "KERNEL_TRACE_FUNCS",
    "KERNEL_USERSPACE_FUNCS",
    "MACOS_BYTE_BUFFER_SUBSTRINGS",
    "MACOS_DANGEROUS_SUBSTRINGS",
    "MACOS_FILESYSTEM_URL_SUBSTRINGS",
    "MACOS_PARSER_SUBSTRINGS",
    "MACOS_PROCESS_EXEC_SUBSTRINGS",
    "MACOS_SECURITY_BOUNDARY_PREFIXES",
    "MACOS_SECURITY_BOUNDARY_SUBSTRINGS",
    "MEMORY_COPY_FUNCS",
    "NETWORK_INGEST_FUNCS",
    "PARSER_FUNCS",
    "PARSER_SEED_FUNCS",
    "PROCESS_BOUNDARY_FUNCS",
    "PROCESS_BOUNDARY_MARKERS",
    "RUNTIME_PRIVILEGE_FUNCS",
    "SCAN_FAMILY_FUNCS",
    "STREAM_INPUT_FUNCS",
    "STRING_OVERFLOW_FUNCS",
    "TOCTOU_FUNCS",
    "fortified",
]
