"""Direct unit tests for surface_classification.classify_security_api."""

from packages.binary_analysis.surface_classification import classify_security_api


def test_memory_write_sinks_from_import_prefixed_names():
    for name in ("sym.imp.strcpy", "imp.memcpy", "__imp_strncpy"):
        result = classify_security_api(name)
        assert result is not None, f"{name} should classify"
        assert result.is_sink is True
        assert result.category == "memory_write"


def test_format_string_sinks():
    result = classify_security_api("sym.imp.syslog")
    assert result is not None
    assert result.is_sink is True
    assert result.category == "format_string"


def test_exec_sinks():
    result = classify_security_api("sym.imp.execve")
    assert result is not None
    assert result.is_sink is True
    assert result.category == "process_execution"


def test_nstask_is_process_execution_sink():
    result = classify_security_api("Foundation.NSTask.launch")
    assert result is not None
    assert result.is_sink is True
    assert result.category == "process_execution"


def test_logging_apis_are_surfaces_not_sinks():
    for name in ("sym.imp.NSLog", "CFLog", "os_log_impl"):
        result = classify_security_api(name)
        assert result is not None, f"{name} should classify"
        assert result.is_sink is False
        assert result.category == "logging"


def test_parser_apis_are_surfaces_not_sinks():
    result = classify_security_api("Foundation.JSONDecoder.decode")
    assert result is not None
    assert result.is_sink is False
    assert result.category == "parser"


def test_filesystem_race_primitives():
    result = classify_security_api("sym.imp.mktemp")
    assert result is not None
    assert result.is_sink is True
    assert result.category == "filesystem_race"


def test_security_boundary_apis():
    result = classify_security_api("Security.SecTrustEvaluate")
    assert result is not None
    assert result.is_sink is False
    assert result.category == "security_boundary"


def test_unknown_symbol_returns_none():
    assert classify_security_api("sym.imp.my_custom_function") is None


def test_empty_and_none_return_none():
    assert classify_security_api("") is None
    assert classify_security_api(None) is None


def test_to_dict_round_trips():
    result = classify_security_api("sym.imp.system")
    assert result is not None
    d = result.to_dict()
    assert d["name"] == "sym.imp.system"
    assert d["role"] == "sink"
    assert d["is_sink"] is True
    assert isinstance(d["rationale"], str)


def test_macos_categories_come_from_taxonomy_groups():
    """The macOS branches classify from the taxonomy's grouped sets."""
    assert classify_security_api("NSTask").category == "process_execution"
    assert classify_security_api(
        "Foundation.Process.run",
    ).category == "process_execution"
    assert classify_security_api(
        "Foundation.JSONDecoder.decode",
    ).category == "parser"
    # CF plist/XML parse surfaces were in the taxonomy set but missing
    # from the consumer's re-listed copy before consolidation.
    assert classify_security_api(
        "CFPropertyListCreateWithData",
    ).category == "parser"
    assert classify_security_api(
        "CFXMLParserCreate",
    ).category == "parser"
    assert classify_security_api(
        "CFURLCreateWithBytes",
    ).category == "filesystem_or_url"
    assert classify_security_api(
        "SecTrustEvaluateWithError",
    ).category == "security_boundary"


# --- Win32 arms -------------------------------------------------------------


def test_win32_device_control_callers_are_sinks():
    for name in ("sym.imp.DeviceIoControl", "NtDeviceIoControlFile"):
        result = classify_security_api(name)
        assert result is not None, name
        assert result.is_sink is True
        assert result.category == "device_control"


def test_win32_device_control_subset_tracks_taxonomy():
    """The consumer's composed subset stays anchored to the taxonomy
    group: exactly DEVICE_CONTROL_FUNCS minus the POSIX/kernel-side
    names it documents excluding. A new caller-side name added to the
    taxonomy fails here, forcing an explicit include/exclude call."""
    from core.function_taxonomy import DEVICE_CONTROL_FUNCS
    from packages.binary_analysis.surface_classification import (
        _WIN32_DEVICE_CONTROL,
    )
    assert _WIN32_DEVICE_CONTROL == DEVICE_CONTROL_FUNCS - {
        "ioctl", "unlocked_ioctl", "compat_ioctl",
    }


def test_posix_ioctl_stays_unclassified():
    """The taxonomy group carries ioctl for other consumers, but the
    classifier's composition deliberately excludes it (ubiquity —
    every TTY-touching binary imports it)."""
    assert classify_security_api("sym.imp.ioctl") is None


def test_registry_reads_are_surfaces():
    for name in ("RegQueryValueExW", "sym.imp.RegGetValueA"):
        result = classify_security_api(name)
        assert result is not None, name
        assert result.is_sink is False
        assert result.category == "registry_input"


def test_dynamic_load_is_surface_not_sink():
    result = classify_security_api("sym.imp.LoadLibraryW")
    assert result is not None
    assert result.is_sink is False
    assert result.category == "dynamic_load"
    # GetProcAddress stays out entirely (pure lookup, ubiquitous).
    assert classify_security_api("sym.imp.GetProcAddress") is None


def test_seh_machinery_is_surface():
    result = classify_security_api("SetUnhandledExceptionFilter")
    assert result is not None
    assert result.is_sink is False
    assert result.category == "exception_handling"


def test_underscored_seh_personalities_survive_normalisation():
    """The SEH personality routines only exist in underscored form —
    the leading underscore is identity, not decoration, so the symbol
    normaliser must NOT strip it (a stripped `except_handler4` matches
    nothing in any catalog). Pinned for the bare, sym.imp.-prefixed
    and once-stripped spellings."""
    for name in ("_except_handler3", "_except_handler4",
                 "sym.imp._except_handler3",
                 "sym.imp._except_handler4",
                 "__C_specific_handler", "_C_specific_handler",
                 "sym.imp.__C_specific_handler"):
        result = classify_security_api(name)
        assert result is not None, name
        assert result.is_sink is False, name
        assert result.category == "exception_handling", name


def test_underscored_mbcs_copies_survive_normalisation():
    """_mbscpy/_mbscat are the real msvcrt export names (underscore
    included) — normalisation must keep them matchable as
    memory_write sinks in every import spelling."""
    for name in ("_mbscpy", "_mbscat",
                 "sym.imp._mbscpy", "sym.imp._mbscat",
                 "imp._mbscpy"):
        result = classify_security_api(name)
        assert result is not None, name
        assert result.is_sink is True, name
        assert result.category == "memory_write", name


def test_win32_crt_sinks_via_existing_categories():
    """The Win32 category ADDITIONS flow through the pre-existing
    arms — no new arm needed for the memcpy/strcpy families; the
    Winsock ingest names stay channel vocabulary, not sinks."""
    assert classify_security_api(
        "sym.imp.RtlMoveMemory").category == "memory_write"
    assert classify_security_api("StrCpyW").category == "memory_write"
    assert classify_security_api("sym.imp.WSARecv") is None


# --- darwin arms ------------------------------------------------------------


def test_ioconnect_calls_are_device_control_sinks():
    result = classify_security_api("sym.imp.IOConnectCallStructMethod")
    assert result is not None
    assert result.is_sink is True
    assert result.category == "device_control"


def test_ioconnect_async_variants_are_device_control_sinks():
    """The async IOConnectCall* variants push the same
    attacker-shaped selectors/buffers across the kext boundary —
    the closed dispatch family classifies uniformly."""
    for name in ("IOConnectCallAsyncScalarMethod",
                 "sym.imp.IOConnectCallAsyncStructMethod",
                 "IOConnectCallAsyncMethod"):
        result = classify_security_api(name)
        assert result is not None, name
        assert result.is_sink is True, name
        assert result.category == "device_control", name


def test_iokit_discovery_is_surface():
    result = classify_security_api("IOServiceOpen")
    assert result is not None
    assert result.is_sink is False
    assert result.category == "iokit_boundary"


def test_xpc_ingress_is_surface():
    for name in ("xpc_connection_set_event_handler",
                 "sym.imp.xpc_dictionary_get_data"):
        result = classify_security_api(name)
        assert result is not None, name
        assert result.is_sink is False
        assert result.category == "ipc_ingress"


def test_byte_buffer_bridges_now_classified():
    """The taxonomy's byte-buffer group was catalogued but unmapped
    by this consumer (a documented gap) — now a surface."""
    result = classify_security_api("CFDataGetBytes")
    assert result is not None
    assert result.is_sink is False
    assert result.category == "byte_buffer_bridge"


# --- no-ELF-regression pin --------------------------------------------------


def test_elf_libc_classifications_unchanged():
    """The Win32/darwin catalogs must change NOTHING for the
    ELF/libc vocabulary: exact (role, category, is_sink) pins for a
    representative battery, plus the None-answers that keep
    ubiquitous names unranked."""
    pins = {
        "memcpy": ("sink", "memory_write", True),
        "strcpy": ("sink", "memory_write", True),
        "sprintf": ("sink", "memory_write", True),
        "syslog": ("sink", "format_string", True),
        "system": ("sink", "process_execution", True),
        "execve": ("sink", "process_execution", True),
        "mktemp": ("sink", "filesystem_race", True),
        "access": ("surface", "filesystem_path", False),
        "readlink": ("surface", "filesystem_path", False),
        "inflate": ("surface", "parser", False),
        "sscanf": ("surface", "parser", False),
        "NSLog": ("surface", "logging", False),
    }
    for name, (role, category, is_sink) in pins.items():
        result = classify_security_api(name)
        assert result is not None, name
        assert (result.role, result.category,
                result.is_sink) == (role, category, is_sink), name
    for unranked in ("read", "open", "malloc", "getenv", "printf",
                     "ioctl", "my_project_helper"):
        assert classify_security_api(unranked) is None, unranked
