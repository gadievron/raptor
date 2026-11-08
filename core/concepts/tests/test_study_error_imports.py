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
inner = RuntimeError("provider stopped")
inner.llm_truncation = True
error = RuntimeError("wrapper")
error.__cause__ = inner
assert _is_truncation_error(error)
assert not _is_truncation_error(RuntimeError("ordinary failure"))
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
