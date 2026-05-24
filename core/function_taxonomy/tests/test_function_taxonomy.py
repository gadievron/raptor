"""Tests for core.function_taxonomy.

These tests enforce the curation policy stated in the module docstring:
ubiquitous functions stay OUT of fuzz-priority categories; safe variants
stay OUT of dangerous categories; banned-by-design APIs stay IN;
category-membership invariants hold (no accidental cross-category dupes
that would inflate consumer composition counts).
"""

from __future__ import annotations

import unittest

from core.function_taxonomy import (
    ALLOC_FUNCS,
    DEVICE_CONTROL_FUNCS,
    ENTRY_POINT_HINTS,
    EXEC_FUNCS,
    FORMAT_STRING_FUNCS,
    INTEGER_PARSE_FUNCS,
    IPC_FUNCS,
    KERNEL_USERSPACE_FUNCS,
    MACOS_DANGEROUS_SUBSTRINGS,
    MEMORY_COPY_FUNCS,
    NETWORK_INGEST_FUNCS,
    PARSER_FUNCS,
    PROCESS_BOUNDARY_FUNCS,
    PROCESS_BOUNDARY_MARKERS,
    SCAN_FAMILY_FUNCS,
    STREAM_INPUT_FUNCS,
    STRING_OVERFLOW_FUNCS,
    TOCTOU_FUNCS,
    fortified,
)


ALL_DANGEROUS_CATEGORIES = [
    STRING_OVERFLOW_FUNCS, SCAN_FAMILY_FUNCS, MEMORY_COPY_FUNCS,
    FORMAT_STRING_FUNCS, EXEC_FUNCS, ALLOC_FUNCS,
    NETWORK_INGEST_FUNCS, PARSER_FUNCS, INTEGER_PARSE_FUNCS,
    TOCTOU_FUNCS,
    STREAM_INPUT_FUNCS, PROCESS_BOUNDARY_FUNCS, IPC_FUNCS,
    KERNEL_USERSPACE_FUNCS, DEVICE_CONTROL_FUNCS,
]


# === Ubiquity exclusion (the central curation rule) ===

UBIQUITOUS_EXCLUSIONS = {
    "malloc", "realloc", "free",
    "open", "fopen", "fclose",
    "read", "write", "fread", "fwrite",
    "printf", "fprintf", "vprintf",
    "memset",  # not malicious-side, not in our dangerous set either
}


class TestUbiquityExclusion(unittest.TestCase):
    """Ubiquitous functions deliberately excluded from every dangerous
    category — every binary imports them, so their presence carries
    zero fuzz-priority signal."""

    def test_ubiquitous_functions_not_in_any_dangerous_category(self):
        for name in UBIQUITOUS_EXCLUSIONS:
            for cat in ALL_DANGEROUS_CATEGORIES:
                self.assertNotIn(
                    name, cat,
                    msg=(f"{name!r} is ubiquitous and should not be in "
                         f"any dangerous category (found in "
                         f"{cat.__class__.__name__} composition). See "
                         f"core/function_taxonomy.py docstring for the "
                         f"curation policy.")
                )


class TestSafeVariantsExcluded(unittest.TestCase):
    """Functions that are SAFE when used correctly (size param explicit,
    auto-cleaned tempfile, etc.) must not appear in dangerous lists —
    inclusion would generate false-positive fuzz-priority signal."""

    def test_microsoft_safe_string_variants_excluded(self):
        """Microsoft's `_s` suffix means explicit-size — these are the
        SAFE variants of strcpy/strncpy."""
        safe_ms_variants = {"strcpy_s", "strncpy_s", "wcscpy_s",
                            "wcsncpy_s", "strcat_s", "strncat_s"}
        for name in safe_ms_variants:
            self.assertNotIn(name, STRING_OVERFLOW_FUNCS,
                             f"{name!r} is the SAFE Microsoft variant")

    def test_safe_tempfile_apis_excluded(self):
        """tmpfile() and mkstemp() are race-free when used correctly.
        Only the banned-by-design mktemp / tempnam are TOCTOU sinks."""
        self.assertNotIn("tmpfile", TOCTOU_FUNCS)
        self.assertNotIn("mkstemp", TOCTOU_FUNCS)
        # And the banned ones ARE in.
        self.assertIn("mktemp", TOCTOU_FUNCS)
        self.assertIn("tempnam", TOCTOU_FUNCS)

    def test_atof_float_strto_excluded_from_integer_parse(self):
        """Float-parsing CVEs are fundamentally different from integer
        overflow (no map to memory corruption). Float APIs out."""
        for name in {"atof", "strtod", "strtof", "strtold"}:
            self.assertNotIn(name, INTEGER_PARSE_FUNCS,
                             f"{name!r} is float-parsing, not integer")


# === Banned APIs MUST be in ===

class TestBannedApisIncluded(unittest.TestCase):
    """C11 / glibc / POSIX banned-by-design APIs must be present —
    they have no legitimate safe usage."""

    def test_gets_in_string_overflow(self):
        """gets() has been banned since C11 Annex K — its API cannot
        be used safely."""
        self.assertIn("gets", STRING_OVERFLOW_FUNCS)

    def test_mktemp_tempnam_in_toctou(self):
        self.assertIn("mktemp", TOCTOU_FUNCS)
        self.assertIn("tempnam", TOCTOU_FUNCS)


# === High-CVE-density parsers present ===

class TestKeyParsersPresent(unittest.TestCase):
    """Spot-check the most-fuzzed parser families. Adding categories
    of parser tests catches regressions where a category gets accidentally
    pruned."""

    def test_openssl_asn1_x509_present(self):
        self.assertIn("d2i_X509", PARSER_FUNCS)

    def test_expat_xml_parse_present(self):
        self.assertIn("XML_Parse", PARSER_FUNCS)

    def test_libxml2_xmlReadMemory_present(self):
        self.assertIn("xmlReadMemory", PARSER_FUNCS)

    def test_libpng_jpeg_libtiff_present(self):
        self.assertIn("png_read_info", PARSER_FUNCS)
        self.assertIn("jpeg_read_header", PARSER_FUNCS)
        self.assertIn("TIFFOpen", PARSER_FUNCS)

    def test_compression_zlib_zstd_brotli_present(self):
        self.assertIn("inflate", PARSER_FUNCS)
        self.assertIn("ZSTD_decompress", PARSER_FUNCS)
        self.assertIn("BrotliDecoderDecompress", PARSER_FUNCS)

    def test_lua_python_embedded_scripting_present(self):
        self.assertIn("luaL_loadstring", PARSER_FUNCS)
        self.assertIn("Py_CompileString", PARSER_FUNCS)


# === Source-side categories (data-flow classification) ===

class TestStreamInputFuncs(unittest.TestCase):
    """STREAM_INPUT_FUNCS = bounded line / delimiter / fd-level
    input that isn't ubiquitous. fgets/getline are the signature
    parse-attacker-line patterns; pread/readv signal positional or
    scatter-gather I/O."""

    def test_fgets_and_getline_present(self):
        self.assertIn("fgets", STREAM_INPUT_FUNCS)
        self.assertIn("getline", STREAM_INPUT_FUNCS)
        self.assertIn("getdelim", STREAM_INPUT_FUNCS)

    def test_pread_readv_present(self):
        self.assertIn("pread", STREAM_INPUT_FUNCS)
        self.assertIn("readv", STREAM_INPUT_FUNCS)

    def test_ubiquitous_read_fread_excluded(self):
        """read/fread are ubiquitous per module policy — must not
        be in STREAM_INPUT_FUNCS (their presence carries zero
        fuzz-priority signal). Consumers that want them add them
        explicitly (see exploit_feasibility.constants.INPUT_FUNCTIONS)."""
        self.assertNotIn("read", STREAM_INPUT_FUNCS)
        self.assertNotIn("fread", STREAM_INPUT_FUNCS)

    def test_gets_not_duplicated_here(self):
        """gets() is banned by C11 Annex K and lives in
        STRING_OVERFLOW_FUNCS — must not be duplicated here."""
        self.assertNotIn("gets", STREAM_INPUT_FUNCS)
        self.assertIn("gets", STRING_OVERFLOW_FUNCS)


class TestProcessBoundaryFuncs(unittest.TestCase):
    """PROCESS_BOUNDARY_FUNCS = direct attacker-controlled env
    sources. Currently only `getenv`. argv/envp are main()
    parameters, not function calls, so out of scope (this module
    is a function-name catalog). secure_getenv and getauxval are
    NOT here — they're markers (see PROCESS_BOUNDARY_MARKERS)."""

    def test_getenv_present(self):
        self.assertIn("getenv", PROCESS_BOUNDARY_FUNCS)

    def test_markers_not_in_funcs(self):
        """secure_getenv returns NULL in suid context (sanitiser,
        not source); getauxval is kernel-supplied. Both live in
        PROCESS_BOUNDARY_MARKERS and must NOT contaminate the
        attacker-source set that downstream consumers treat as
        taint origins."""
        self.assertNotIn("secure_getenv", PROCESS_BOUNDARY_FUNCS)
        self.assertNotIn("getauxval", PROCESS_BOUNDARY_FUNCS)

    def test_setenv_excluded(self):
        """setenv/putenv are sinks (writing env), not sources of
        attacker-controlled data."""
        self.assertNotIn("setenv", PROCESS_BOUNDARY_FUNCS)
        self.assertNotIn("putenv", PROCESS_BOUNDARY_FUNCS)


class TestProcessBoundaryMarkers(unittest.TestCase):
    """PROCESS_BOUNDARY_MARKERS = suid-context signal functions.
    Separate from PROCESS_BOUNDARY_FUNCS because their returns are
    NOT attacker-controlled (NULL in suid, or kernel-supplied),
    so they're not taint sources. Their presence at a call site
    weights the suspicion of co-located plain getenv calls."""

    def test_secure_getenv_present(self):
        self.assertIn("secure_getenv", PROCESS_BOUNDARY_MARKERS)

    def test_getauxval_present(self):
        self.assertIn("getauxval", PROCESS_BOUNDARY_MARKERS)


class TestIpcFuncs(unittest.TestCase):
    """IPC_FUNCS = inter-process communication source primitives.
    Several explicit exclusions per the CVE-shape policy — see
    docstring on the set."""

    def test_sysv_shm_present(self):
        self.assertIn("shmat", IPC_FUNCS)
        self.assertIn("shmget", IPC_FUNCS)

    def test_message_queues_present(self):
        self.assertIn("mq_receive", IPC_FUNCS)
        self.assertIn("msgrcv", IPC_FUNCS)

    def test_mmap_excluded(self):
        """mmap usage is dominantly file-backed read-only; the
        attacker-controlled MAP_SHARED case is not distinguishable
        from the call site, so the category excludes it per the
        CVE-shape policy."""
        self.assertNotIn("mmap", IPC_FUNCS)

    def test_shm_open_excluded(self):
        """shm_open returns an fd; the actual read goes through
        mmap (excluded above) or read (ubiquitous). Flagging
        shm_open alone gives a category with no live read
        primitive — drop per the CVE-shape policy."""
        self.assertNotIn("shm_open", IPC_FUNCS)

    def test_pipe_excluded(self):
        """pipe/mkfifo are setup primitives — the actual attacker
        data read happens via read() on the resulting fd (which
        is ubiquitous and excluded everywhere)."""
        self.assertNotIn("pipe", IPC_FUNCS)
        self.assertNotIn("mkfifo", IPC_FUNCS)


class TestKernelUserspaceFuncs(unittest.TestCase):
    """KERNEL_USERSPACE_FUNCS = kernel-side functions reading
    userspace data. These do not appear in user-space binary
    import tables — value is for source-code analysis of kernel
    modules / drivers where userspace pointers are the canonical
    L1 source. Covers bare copies, allocator wrappers, and
    iovec/pages interfaces."""

    def test_bare_copy_primitives_present(self):
        self.assertIn("copy_from_user", KERNEL_USERSPACE_FUNCS)
        self.assertIn("_copy_from_user", KERNEL_USERSPACE_FUNCS)
        self.assertIn("raw_copy_from_user", KERNEL_USERSPACE_FUNCS)
        self.assertIn("__copy_from_user_inatomic",
                      KERNEL_USERSPACE_FUNCS)

    def test_get_user_present(self):
        self.assertIn("get_user", KERNEL_USERSPACE_FUNCS)
        self.assertIn("__get_user", KERNEL_USERSPACE_FUNCS)

    def test_string_variants_present(self):
        self.assertIn("strncpy_from_user", KERNEL_USERSPACE_FUNCS)
        self.assertIn("strnlen_user", KERNEL_USERSPACE_FUNCS)
        self.assertIn("strndup_user", KERNEL_USERSPACE_FUNCS)

    def test_allocator_wrappers_present(self):
        """memdup_user-family is more common at call sites in
        modern kernel code than bare copy_from_user."""
        self.assertIn("memdup_user", KERNEL_USERSPACE_FUNCS)
        self.assertIn("memdup_user_nul", KERNEL_USERSPACE_FUNCS)
        self.assertIn("vmemdup_user", KERNEL_USERSPACE_FUNCS)

    def test_iovec_pages_interfaces_present(self):
        """iovec + get_user_pages cover scatter-gather + DMA paths."""
        self.assertIn("import_iovec", KERNEL_USERSPACE_FUNCS)
        self.assertIn("import_single_range", KERNEL_USERSPACE_FUNCS)
        self.assertIn("_copy_from_iter", KERNEL_USERSPACE_FUNCS)
        self.assertIn("copy_from_iter_full", KERNEL_USERSPACE_FUNCS)
        self.assertIn("get_user_pages", KERNEL_USERSPACE_FUNCS)
        self.assertIn("get_user_pages_fast", KERNEL_USERSPACE_FUNCS)

    def test_copy_to_user_excluded(self):
        """copy_to_user is a sink (kernel writes to user), not a
        source — must not be in this set."""
        self.assertNotIn("copy_to_user", KERNEL_USERSPACE_FUNCS)
        self.assertNotIn("put_user", KERNEL_USERSPACE_FUNCS)


class TestDeviceControlFuncs(unittest.TestCase):
    """DEVICE_CONTROL_FUNCS = ioctl-style driver command entry points.

    These are function-name shaped and therefore live in the shared
    function taxonomy; source-intel can classify them as L1 context
    without needing a parallel catalog.
    """

    def test_ioctl_family_present(self):
        self.assertIn("ioctl", DEVICE_CONTROL_FUNCS)
        self.assertIn("unlocked_ioctl", DEVICE_CONTROL_FUNCS)
        self.assertIn("compat_ioctl", DEVICE_CONTROL_FUNCS)


# === Cross-category invariants ===

class TestCrossCategory(unittest.TestCase):
    """Internal taxonomy consistency."""

    def test_snprintf_only_in_format_string_not_overflow(self):
        """snprintf's dominant CVE shape is format-string, not overflow
        (the bounded-size param prevents the overflow). It must be in
        FORMAT_STRING_FUNCS, NOT STRING_OVERFLOW_FUNCS."""
        self.assertIn("snprintf", FORMAT_STRING_FUNCS)
        self.assertNotIn("snprintf", STRING_OVERFLOW_FUNCS)
        self.assertIn("vsnprintf", FORMAT_STRING_FUNCS)
        self.assertNotIn("vsnprintf", STRING_OVERFLOW_FUNCS)

    def test_categories_are_disjoint(self):
        """No function should appear in more than one of the 10
        dangerous categories — duplicates inflate consumer composition
        counts and obscure category semantics. Cross-category placement
        decisions should be explicit (and tested above) not accidental."""
        from collections import Counter
        all_members = []
        for cat in ALL_DANGEROUS_CATEGORIES:
            all_members.extend(cat)
        counts = Counter(all_members)
        dupes = {name: n for name, n in counts.items() if n > 1}
        self.assertEqual(
            dupes, {},
            msg=("Duplicate entries across dangerous categories — pick "
                 "the dominant category and remove from the others. "
                 f"Duplicates: {dupes}"),
        )

    def test_all_categories_nonempty(self):
        """Empty category = either bad curation or dead concept. Both
        warrant explicit removal of the category, not silent emptiness."""
        for cat in ALL_DANGEROUS_CATEGORIES:
            self.assertGreater(len(cat), 0)
        self.assertGreater(len(MACOS_DANGEROUS_SUBSTRINGS), 0)
        self.assertGreater(len(ENTRY_POINT_HINTS), 0)

    def test_all_members_are_strings(self):
        """No accidental non-string members (would crash consumer
        composition / substring matching)."""
        for cat in ALL_DANGEROUS_CATEGORIES + [
            MACOS_DANGEROUS_SUBSTRINGS, ENTRY_POINT_HINTS,
        ]:
            for member in cat:
                self.assertIsInstance(member, str,
                                      f"non-string member: {member!r}")
                self.assertGreater(len(member), 0,
                                   "empty-string member in category")


# === fortified() helper ===

class TestFortified(unittest.TestCase):
    """The fortified() helper auto-derives FORTIFY_SOURCE __*_chk
    variants of any base set."""

    def test_fortified_prepends_double_underscore_appends_chk(self):
        result = fortified(frozenset({"strcpy", "memcpy"}))
        self.assertEqual(result, frozenset({"__strcpy_chk", "__memcpy_chk"}))

    def test_fortified_string_overflow_includes_strcpy_chk(self):
        """The whole point — fortified(STRING_OVERFLOW_FUNCS) gives the
        right set without anyone needing to hardcode __strcpy_chk."""
        fortified_strings = fortified(STRING_OVERFLOW_FUNCS)
        self.assertIn("__strcpy_chk", fortified_strings)
        self.assertIn("__strncpy_chk", fortified_strings)
        self.assertIn("__gets_chk", fortified_strings)

    def test_fortified_returns_frozenset(self):
        result = fortified(frozenset({"foo"}))
        self.assertIsInstance(result, frozenset)

    def test_fortified_empty_in_empty_out(self):
        self.assertEqual(fortified(frozenset()), frozenset())


# === Sanity counts (catches gross drift over time) ===

class TestSizeBounds(unittest.TestCase):
    """Coarse sanity bounds on category sizes. A future contributor who
    accidentally clears or 10x's a category triggers this rather than
    silently shipping degraded curation."""

    def test_string_overflow_size_reasonable(self):
        n = len(STRING_OVERFLOW_FUNCS)
        self.assertGreater(n, 8, f"only {n} entries — pruned too far?")
        self.assertLess(n, 50, f"{n} entries — likely false-positive bloat")

    def test_parser_funcs_is_the_biggest_category(self):
        """PARSER_FUNCS should be the largest dangerous category — it
        covers the highest CVE-density attack surface."""
        for cat in ALL_DANGEROUS_CATEGORIES:
            if cat is PARSER_FUNCS:
                continue
            self.assertGreater(
                len(PARSER_FUNCS), len(cat),
                msg=("PARSER_FUNCS should be the largest dangerous "
                     "category — covers most CVE-density attack "
                     "surface"),
            )

    def test_macos_substrings_nontrivial(self):
        self.assertGreater(len(MACOS_DANGEROUS_SUBSTRINGS), 10)

    def test_stream_input_size_reasonable(self):
        n = len(STREAM_INPUT_FUNCS)
        self.assertGreater(n, 4, f"only {n} entries — pruned too far?")
        self.assertLess(n, 20, f"{n} entries — likely bloat")

    def test_process_boundary_size_reasonable(self):
        n = len(PROCESS_BOUNDARY_FUNCS)
        self.assertGreaterEqual(n, 1,
                                f"only {n} entries — pruned too far?")
        self.assertLess(n, 10, f"{n} entries — likely bloat")

    def test_process_boundary_markers_size_reasonable(self):
        n = len(PROCESS_BOUNDARY_MARKERS)
        self.assertGreaterEqual(n, 1)
        self.assertLess(n, 10)

    def test_ipc_size_reasonable(self):
        n = len(IPC_FUNCS)
        self.assertGreater(n, 2, f"only {n} entries — pruned too far?")
        self.assertLess(n, 15, f"{n} entries — likely bloat")

    def test_kernel_userspace_size_reasonable(self):
        """Linux kernel uaccess + memdup_user + iovec/pages
        interfaces — meaningful range is 10-40."""
        n = len(KERNEL_USERSPACE_FUNCS)
        self.assertGreater(n, 10, f"only {n} entries — pruned too far?")
        self.assertLess(n, 40, f"{n} entries — likely bloat")

    def test_device_control_size_reasonable(self):
        n = len(DEVICE_CONTROL_FUNCS)
        self.assertGreaterEqual(n, 3)
        self.assertLess(n, 10)


if __name__ == "__main__":
    unittest.main()
