"""Summary lineage cannot erase unresolved catalogue source contracts."""
from core.analysis.sanitizer_cut import VERDICT_CANDIDATE_ONLY, VERDICT_SUPPRESS
from core.analysis.tests.test_interproc import _bindings_for, _evaluate


_REQUIRED = frozenset({"exact_builtin_str_default_call"})


def test_helper_name_retains_underlying_primitive_requirement():
    source = (
        "import html\n"
        "def clean(value):\n    return html.escape(value)\n"
        "def handle(raw):\n    safe = clean(raw)\n    render(safe)\n"
    )
    _, bindings = _bindings_for(source, "handle")
    binding, = bindings
    assert binding.callable == "clean"  # not the catalogue name
    assert binding.input_symbols == frozenset({"raw"})
    assert binding.output_symbols == frozenset({"safe"})
    assert binding.unverified_source_contracts == _REQUIRED
    result = _evaluate(source, "handle", {"raw"}, "safe", 6)
    assert result.verdict == VERDICT_CANDIDATE_ONLY and result.suppress is False
    assert result.value_bound_bindings
    assert {b.callable for b in result.value_bound_bindings} == {"clean"}
    assert all(b.unverified_source_contracts == _REQUIRED for b in result.value_bound_bindings)


def test_transitive_summary_retains_original_library_contract():
    source = (
        "import html\n"
        "def first(value):\n    return html.escape(value)\n"
        "def second(value):\n    return first(value)\n"
        "def handle(raw):\n    safe = second(raw)\n    render(safe)\n"
    )
    _, bindings = _bindings_for(source, "handle")
    binding, = bindings
    assert binding.callable == "second"
    assert binding.unverified_source_contracts == _REQUIRED
    result = _evaluate(source, "handle", {"raw"}, "safe", 8)
    assert result.verdict == VERDICT_CANDIDATE_ONLY
    assert result.value_bound_bindings and result.suppress is False


def test_repeated_source_at_conditional_and_unconditional_positions_unions_requirements():
    source = (
        "import werkzeug.security\nimport werkzeug.utils\n"
        "def clean(left, right):\n    return werkzeug.security.safe_join(left) + werkzeug.utils.secure_filename(right)\n"
        "def handle(raw):\n    safe = clean(raw, raw)\n    open(safe)\n"
    )
    _, bindings = _bindings_for(source, "handle", "CWE-22")
    binding, = bindings
    assert binding.input_symbols == frozenset({"raw"})
    assert binding.unverified_source_contracts == frozenset({"trusted_path_base_components_and_containment"})
    result = _evaluate(source, "handle", {"raw"}, "safe", 7, "CWE-22")
    assert result.verdict == VERDICT_CANDIDATE_ONLY
    assert result.value_bound_bindings and result.suppress is False


def test_constant_position_does_not_discharge_return_effect_requirement():
    source = (
        "import html\nimport bleach\n"
        "def clean(left, right):\n    return html.escape(left) + bleach.clean(right)\n"
        "def handle(raw):\n    safe = clean(123, raw)\n    render(safe)\n"
    )
    _, bindings = _bindings_for(source, "handle")
    binding, = bindings
    assert binding.input_symbols == frozenset({"raw"})
    assert binding.unverified_source_contracts == _REQUIRED | frozenset({"single_positional_default_call"})
    # The summary cannot prove the first input is an exact string, even
    # when only the second position contributes a bare tainted symbol.
    result = _evaluate(source, "handle", {"raw"}, "safe", 7)
    assert result.verdict == VERDICT_CANDIDATE_ONLY
    assert result.suppress is False and result.value_bound_bindings


def test_unconditional_summary_keeps_real_suppression_control():
    source = (
        "import werkzeug\n"
        "def clean(value):\n    return werkzeug.utils.secure_filename(value)\n"
        "def handle(raw):\n    safe = clean(raw)\n    open(safe)\n"
    )
    _, bindings = _bindings_for(source, "handle", "CWE-22")
    binding, = bindings
    assert binding.unverified_source_contracts == frozenset()
    assert binding.input_symbols == frozenset({"raw"})
    result = _evaluate(source, "handle", {"raw"}, "safe", 6, "CWE-22")
    assert result.verdict == VERDICT_SUPPRESS and result.suppress is True
    assert result.value_bound_bindings
