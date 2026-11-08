"""Cold error paths must not initialise provider SDKs."""

from pathlib import Path
import sys

import pytest

from core.testing.standalone_cli import run_standalone_cli


_PROBES = {
    "structured-errors": '''
from core.llm.structured_call import is_content_filter_error, is_refusal_error
error = RuntimeError("wrapper")
error.__cause__ = RuntimeError("request blocked by content filter")
assert is_content_filter_error(error)
assert not is_refusal_error(error)
error.__cause__ = RuntimeError("Anthropic model refused request (stop_reason=refusal)")
assert is_refusal_error(error)
error.__cause__ = ConnectionRefusedError(111, "Connection refused")
assert not is_refusal_error(error)
''',
    "study-truncation": '''
from core.concepts.study import _is_truncation_error
from core.llm.response_validation import _llm_truncation_error
assert _is_truncation_error(_llm_truncation_error("anything at all"))
inner = RuntimeError("provider stopped")
inner.llm_truncation = True
error = RuntimeError("wrapper")
error.__cause__ = inner
assert _is_truncation_error(error)
assert not _is_truncation_error(RuntimeError("ordinary failure"))
''',
    "study-output-budget": '''
from core.concepts.study import _study_max_output_tokens, _study_text_output_tokens
from core.llm.model_capabilities import supports_temperature, thinking_shares_output_budget
text = _study_text_output_tokens()
assert _study_max_output_tokens("claude-fable-5") == 2 * text
assert _study_max_output_tokens("claude-sonnet-4-6") == text
assert _study_max_output_tokens("unknown-model") == text
assert not supports_temperature("claude-fable-5")
assert thinking_shares_output_budget("claude-fable-5")
assert supports_temperature("claude-opus-4-20250514")
assert not thinking_shares_output_budget("claude-opus-4-20250514")
''',
    "invariant-cli": '''
from core.concepts.tests.test_compile_invariants_cli import cli, _run_main, _invariant, _result
fixture = cli.__wrapped__()
try:
    script = next(fixture)
    with pytest.MonkeyPatch.context() as scope:
        assert _run_main(script, scope, target, [_invariant("i1")], [_result("i1", False)]) == 1
finally:
    fixture.close()
''',
    "study-spend-failure": '''
from core.concepts.tests.test_study_budget import TestStudyRunMaxCost
with pytest.MonkeyPatch.context() as scope:
    TestStudyRunMaxCost().test_spend_record_written_when_run_study_raises(target, scope)
''',

}


@pytest.mark.parametrize("probe", _PROBES)
def test_error_paths_stay_sdk_free(probe, tmp_path):
    root = Path(__file__).resolve().parents[3]
    program = '''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import pytest
assert "core.llm.client" not in sys.modules
target = Path(sys.argv[2])
''' + _PROBES[probe] + '''
for name in ("core.llm.client", "core.llm.providers", "openai", "anthropic", "google.genai"):
    assert name not in sys.modules, f"unexpected SDK startup: {name}"
'''
    result = run_standalone_cli(
        [sys.executable, "-I", "-c", program, str(root), str(tmp_path)],
        cwd=tmp_path, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
