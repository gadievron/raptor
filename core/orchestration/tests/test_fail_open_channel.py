"""Fail-open channel beyond /audit — the /agentic adapter.

Mirrors the guard-dominance (P23) adapter contract: claim-shape
binding gates dispatch, refuted/confirmed return receipt dicts,
inconclusive returns nothing. Hermetic — Python fixtures (stdlib ast
leg, no grammar wheels needed), no LLM, no subprocesses.
"""

from __future__ import annotations

from core.orchestration.fail_open_channel import (
    FAIL_OPEN_CHANNEL_CAP,
    adjudicate_finding,
    check_finding,
    fail_open_binding,
)

SWALLOW_PY = '''
def check_token(tok):
    if not tok:
        raise ValueError("no token")
    return True


def verify_session(request):
    try:
        check_token(request.token)
    except Exception:
        pass
    return True
'''

FAIL_CLOSED_PY = SWALLOW_PY.replace(
    "    except Exception:\n        pass\n    return True",
    "    except Exception:\n        raise\n    return True",
)


def _finding(reasoning, *, file="auth.py", function="verify_session"):
    return {
        "finding_id": "FIND-0001",
        "rule_id": "swallowed-exception",
        "file": file,
        "function": function,
        "line": 9,
        "message": reasoning,
        "candidate_reasoning": reasoning,
    }


FAIL_OPEN_CLAIM = (
    "the broad except swallows the check_token exception and "
    "verify_session fails open"
)


class TestBinding:
    def test_fail_open_claim_binds(self):
        assert fail_open_binding(_finding(FAIL_OPEN_CLAIM))

    def test_unrelated_claim_does_not_bind(self):
        assert fail_open_binding(
            _finding("integer overflow in size calculation"),
        ) is None

    def test_empty_claim_does_not_bind(self):
        assert fail_open_binding({"file": "a.py"}) is None

    def test_missing_coords_returns_none(self, tmp_path):
        finding = _finding(FAIL_OPEN_CLAIM)
        del finding["function"]
        assert check_finding(finding, tmp_path) is None


class TestAdjudication:
    def test_confirmed_swallow_returns_receipt(self, tmp_path):
        (tmp_path / "auth.py").write_text(SWALLOW_PY)
        receipt = adjudicate_finding(
            _finding(FAIL_OPEN_CLAIM), tmp_path,
        )
        assert receipt is not None
        assert receipt["outcome"] == "confirmed"
        assert receipt["rule_id"].startswith("fail_open:")
        assert receipt["language"] == "python"
        assert receipt["handler"]["idiom"] == "except_pass"
        assert receipt["fallible"]["callee"] == "check_token"

    def test_fail_closed_handler_refutes(self, tmp_path):
        (tmp_path / "auth.py").write_text(FAIL_CLOSED_PY)
        receipt = adjudicate_finding(
            _finding(FAIL_OPEN_CLAIM), tmp_path,
        )
        assert receipt is not None
        assert receipt["outcome"] == "refuted"
        assert "re-raises" in receipt["reason"]

    def test_inconclusive_returns_none(self, tmp_path):
        # No handler in the named function: hypothesis-unbindable.
        (tmp_path / "auth.py").write_text(
            "def verify_session(request):\n"
            "    return check_token(request.token)\n",
        )
        assert adjudicate_finding(
            _finding(FAIL_OPEN_CLAIM), tmp_path,
        ) is None

    def test_unbound_claim_returns_none(self, tmp_path):
        (tmp_path / "auth.py").write_text(SWALLOW_PY)
        assert adjudicate_finding(
            _finding("buffer overflow via memcpy"), tmp_path,
        ) is None

    def test_missing_file_returns_none(self, tmp_path):
        assert adjudicate_finding(
            _finding(FAIL_OPEN_CLAIM, file="gone.py"), tmp_path,
        ) is None

    def test_learned_vocab_out_dir_participates(self, tmp_path):
        # An operator annotation in the run dir binds registry-grade:
        # the receipt's rule id loses the -naming detection suffix.
        import json
        src = SWALLOW_PY.replace("check_token", "step_two")
        src = src.replace("verify_session", "run_pipeline")
        (tmp_path / "auth.py").write_text(src)
        out = tmp_path / "out"
        ann = out / "annotations"
        ann.mkdir(parents=True)
        (ann / "auth.py.md").write_text(
            "## step_two\n"
            "<!-- meta: status=trust_boundary -->\n"
            "Gate for the pipeline.\n",
        )
        claim = (
            "the broad except swallows the step_two exception and "
            "run_pipeline fails open"
        )
        receipt = adjudicate_finding(
            _finding(claim, function="run_pipeline"), tmp_path,
            out_dir=out,
        )
        assert receipt is not None, receipt
        assert receipt["outcome"] == "confirmed"
        assert receipt["role"]["source"] == "annotation"
        assert not receipt["rule_id"].endswith("-naming")
        assert json.dumps(receipt)  # receipt is JSON-serialisable

    def test_cap_constant_sane(self):
        assert FAIL_OPEN_CHANNEL_CAP > 0
