"""Slice-model results remain conditional and cannot suppress source findings."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re

import pytest

from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available

pytestmark = pytest.mark.skipif(not z3_available(), reason="z3-solver not installed")


def _adjudicate(tmp_path: Path, *, operation="[:-1]", bound="8", prefix="", quantifier="+"):
    line = f'    if not re.match(r"^[a-z]{quantifier}$", name):'
    source = (
        "import re\n" + prefix + "def handle(name):\n"
        f"    if len(name) > {bound}: return\n" + line + "\n"
        "        return\n"
        f"    trimmed = name{operation}\n"
        "    return os.system(trimmed)\n"
    )
    (tmp_path / "app.py").write_text(source)
    result = sb.try_tier0(
        fix_diff="+" + line + "\n", repo_root=tmp_path,
        sink_uri="app.py", sink_line=len(source.splitlines()), sink_class="cmdi",
    )
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.counterexample is None
    return result, source


def test_slice_exclusion_is_a_real_model_diagnostic_not_source_refutation(tmp_path: Path):
    result, source = _adjudicate(tmp_path)
    diagnostic = result.extras["smt_slice_model"]
    assert diagnostic["status"] == "excluded"
    assert diagnostic["source_bound"] is False
    assert diagnostic["scope"] == "conditional-untyped-string-model"
    assert diagnostic["source_digest"] == sha256(source.encode()).hexdigest()
    assert diagnostic["source_max_length"] == 8
    assert diagnostic["validator_line"] == 4
    assert diagnostic["bound_line"] == 3
    assert diagnostic["slice_span"][0] == 6
    assert diagnostic["unverified_source_premises"]
    assert "not source-bound" in result.reasoning


def test_slice_counterexample_replays_only_the_conditional_property(tmp_path: Path):
    result, _ = _adjudicate(tmp_path, operation="[1:]")
    diagnostic = result.extras["smt_slice_model"]
    assert diagnostic["status"] == "counterexample"
    value, output = diagnostic["input_value"], diagnostic["output_value"]
    assert type(value) is str and type(output) is str
    assert len(value) <= 8 and re.match(r"^[a-z]+$", value)
    assert output == value[1:]
    assert "\n" in output
    assert diagnostic["source_bound"] is False


def test_actual_observed_bound_is_not_silently_truncated(tmp_path: Path):
    result, _ = _adjudicate(tmp_path, bound="129")
    diagnostic = result.extras["smt_slice_model"]
    assert diagnostic["status"] == "unsupported"
    assert diagnostic["source_max_length"] == 129
    assert diagnostic["input_value"] is None


@pytest.mark.parametrize("operation,bound", [
    ("[:-1]", "limit"), ("[:-1]", "True"),
    ("[::-1]", "8"), ("[-1:]", "8"), ("[:2]", "8"),
])
def test_unsupported_source_observations_do_not_invent_model_premises(tmp_path: Path, operation, bound):
    result, _ = _adjudicate(tmp_path, operation=operation, bound=bound)
    assert "smt_slice_model" not in result.extras


def test_overridden_length_observation_never_becomes_source_authority(tmp_path: Path):
    result, _ = _adjudicate(tmp_path, prefix="len = lambda value: 0\n")
    diagnostic = result.extras["smt_slice_model"]
    assert diagnostic["status"] == "excluded"
    assert diagnostic["source_bound"] is False
    assert any("length callable" in assumption for assumption in diagnostic["unverified_source_premises"])


def test_expired_budget_has_no_positive_slice_model_result(tmp_path: Path):
    from core.smt_solver.session import query_budget

    with query_budget(0):
        result, _ = _adjudicate(tmp_path)
    diagnostic = result.extras["smt_slice_model"]
    assert diagnostic["status"] == "unknown"
    assert diagnostic["input_value"] is None
    assert diagnostic["output_value"] is None


@pytest.mark.parametrize("quantifier,expected", [("+", "unsupported"), ("*", "excluded")])
def test_empty_source_domain_cannot_mint_vacuous_exclusion(tmp_path: Path, quantifier, expected):
    result, _ = _adjudicate(tmp_path, bound="0", quantifier=quantifier)
    assert result.extras["smt_slice_model"]["status"] == expected
