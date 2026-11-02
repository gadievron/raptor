"""PyJWT verification switches have different semantics across APIs and releases."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

_RULE = Path(__file__).resolve().parents[1] / "rules/auth/jwt-no-verify.yaml"
_MODERN = "raptor.auth.jwt-no-verify.python"
_LEGACY = "raptor.auth.jwt-legacy-verify.python"


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_pyjwt_verification_contract(tmp_path):
    source = '''import jwt
import jwt as pyjwt
from jwt import decode_complete as complete_alias

def disabled_decode(token):
    return jwt.decode(token, options={"verify_signature": False})  # modern

def disabled_complete(token):
    return jwt.decode_complete(token, options={"verify_signature": False})  # modern

def keyword_decode(token):
    return jwt.decode(jwt=token, options={"verify_signature": False})  # modern

def keyword_complete(token):
    return jwt.decode_complete(jwt=token, options={"verify_signature": False})  # modern

def aliased_module(token):
    return pyjwt.decode_complete(token, options={"verify_signature": False})  # modern

def imported_alias(token):
    return complete_alias(token, options={"verify_signature": False})  # modern

def extra_options(token):
    return jwt.decode_complete(token, options={"verify_exp": True, "verify_signature": False})  # unmodeled

def explicit_false_wins(token):
    return jwt.decode(token, verify=True, options={"verify_signature": False})  # modern

def legacy_and_explicit(token):
    return jwt.decode(token, verify=False, options={"verify_signature": False})  # modern

def legacy_keyword(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], verify=False)  # legacy

def legacy_keyword_token(token, key):
    return jwt.decode(jwt=token, key=key, verify=False)  # legacy

def unsigned_allowlist(token):
    return jwt.decode(token, algorithms=["none"])

def complete_unsigned_allowlist(token):
    return jwt.decode_complete(token, algorithms=["none"])

def verified_decode(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])

def verified_complete(token, key):
    return jwt.decode_complete(token, key, algorithms=["HS256"])

def explicit_signature_check(token, key):
    return jwt.decode_complete(token, key, algorithms=["HS256"], options={"verify_signature": True})

def expiration_only(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_exp": False})

def complete_expiration_only(token, key):
    return jwt.decode_complete(token, key, algorithms=["HS256"], options={"verify_exp": False})

def header_only(token):
    return jwt.get_unverified_header(token)

def legacy_true(token, key):
    return jwt.decode(token, key, verify=True)

def complete_ignored_legacy_flag(token, key):
    return jwt.decode_complete(token, key, algorithms=["HS256"], verify=False)

def restored_by_duplicate(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": False, "verify_signature": True})

def disabled_by_duplicate(token):
    return jwt.decode(token, options={"verify_signature": True, "verify_signature": False})  # unmodeled

def dynamic_override(token, overrides):
    return jwt.decode(token, options={"verify_signature": False, **overrides})

def final_explicit_disable(token, overrides):
    return jwt.decode(token, options={**overrides, "verify_signature": False})  # unmodeled

def restored_options_variable(token, key):
    opts = {"verify_signature": False}
    opts["verify_signature"] = True
    return jwt.decode_complete(token, key, algorithms=["HS256"], options=opts)

def replaced_options_variable(token, key):
    opts = {"verify_signature": False}
    opts = {"verify_signature": True}
    return jwt.decode(token, key, algorithms=["HS256"], options=opts)

def unrelated_method(token, decoder):
    return decoder.decode_complete(token, options={"verify_signature": False})
'''
    target = tmp_path / "cases.py"
    target.write_text(source)
    process = subprocess.run(
        ["semgrep", "scan", "--config", str(_RULE), "--metrics=off",
         "--disable-version-check", "--jobs=1", "--json", str(target)],
        env={**os.environ, "SEMGREP_SETTINGS_FILE": str(tmp_path / "settings.yml"),
             "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log")},
        capture_output=True, text=True, timeout=180,
    )
    assert process.returncode == 0, process.stderr
    data = json.loads(process.stdout)
    assert not data.get("errors"), data.get("errors")
    functions = [node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)]
    expected = {"modern": set(), "legacy": set()}
    for function in functions:
        for kind in expected:
            if f"# {kind}" in "\n".join(source.splitlines()[function.lineno - 1:function.end_lineno]):
                expected[kind].add(function.name)
    actual = {"modern": set(), "legacy": set()}
    for result in data["results"]:
        owners = [function.name for function in functions
                  if function.lineno <= result["start"]["line"] <= function.end_lineno]
        assert len(owners) == 1, result
        if result["check_id"].endswith(_MODERN):
            assert result["extra"]["severity"] == "CRITICAL"
            actual["modern"].add(owners[0])
        else:
            assert result["check_id"].endswith(_LEGACY), result
            assert result["extra"]["severity"] == "MEDIUM"
            actual["legacy"].add(owners[0])
    assert actual == expected, {
        "version": data.get("version"),
        "missing": {kind: expected[kind] - actual[kind] for kind in expected},
        "extra": {kind: actual[kind] - expected[kind] for kind in expected},
    }
