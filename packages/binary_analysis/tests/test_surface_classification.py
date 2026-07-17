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
