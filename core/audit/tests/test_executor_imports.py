"""Budget-stop checks must not initialize provider SDKs."""

from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

from core.audit import executor
from core.llm import budget_errors


@pytest.mark.parametrize("module", [budget_errors.__name__, executor.__name__])
def test_budget_checks_import_without_client_or_sdks(module):
    root = Path(__file__).resolve().parents[3]
    code = f"import sys\nsys.path.insert(0, {str(root)!r})\n"
    code += textwrap.dedent("""\
        class RejectSDKImports:
            def find_spec(self, fullname, path=None, target=None):
                if fullname == 'core.llm.client' or fullname.split('.')[0] in {
                    'openai', 'anthropic', 'google', 'botocore', 'instructor',
                }:
                    raise AssertionError('unexpected SDK import: ' + fullname)
        sys.meta_path.insert(0, RejectSDKImports())
    """)
    code += f"import {module}\n"
    code += textwrap.dedent("""\
        from core.llm.budget_errors import (
            LLMBudgetExceededError, is_budget_exceeded_error,
        )
        assert is_budget_exceeded_error(LLMBudgetExceededError('cap'))
        assert is_budget_exceeded_error(RuntimeError('budget exceeded'))
        assert not is_budget_exceeded_error(RuntimeError('ordinary failure'))
        assert 'core.llm.client' not in sys.modules
    """)
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=root,
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
