"""Native import-identity controls; source strings are never executed."""
from pathlib import Path
import json
from core.audit.tests._live_transport import run_pinned_subprocess
from core.config import RaptorConfig
import shutil
import pytest

pytestmark = [pytest.mark.slow, pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")]


def test_jwt_javascript_typescript_import_identity(tmp_path):
    target = tmp_path / "owned"
    target.mkdir(exist_ok=True)
    cases = {
        "canonical": ('import jwt from "jsonwebtoken";\njwt.decode("owned-inert-input");\n', True),
        "namespace": ('import * as jose from "jose";\njose.decodeJwt("owned-inert-input");\n', True),
        "named": ('import {decodeJwt} from "jose";\ndecodeJwt("owned-inert-input");\n', True),
        "required_jwt": ('const tokenApi = require("jsonwebtoken");\ntokenApi.decode("owned-inert-input");\n', True),
        "aliased_jose": ('import {decodeJwt as unpack} from "jose";\nunpack("owned-inert-input");\n', True),
        "required_jose": ('const tokenApi = require("jose");\ntokenApi.decodeJwt("owned-inert-input");\n', True),
        "verify_empty": ('import tokenApi from "jsonwebtoken";\ntokenApi.verify("owned-inert-input", "");\n', True),
        "verify_key": ('import tokenApi from "jsonwebtoken";\ntokenApi.verify("owned-inert-input", key);\n', False),
        "other_verify": ('import jwt from "owned-unrelated-module";\njwt.verify("owned-inert-input", "");\n', False),
        "other_named": ('import {decodeJwt} from "owned-unrelated-module";\ndecodeJwt("owned-inert-input");\n', False),
        "other_jwt": ('import jwt from "owned-unrelated-module";\njwt.decode("owned-inert-input");\n', False),
        "other_jose": ('import * as jose from "owned-unrelated-module";\njose.decodeJwt("owned-inert-input");\n', False),
    }
    expected = set()
    for extension in ("js", "ts"):
        for name, (source, reports) in cases.items():
            filename = f"{name}.{extension}"
            (target / filename).write_text(source)
            if reports:
                expected.add(filename)
    rule = Path(__file__).resolve().parents[1] / "rules/auth/jwt-no-verify.yaml"
    result = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(rule), "--metrics", "off", "--disable-version-check", "--jobs", "1", "--json", *map(str, sorted(target.iterdir()))],
        timeout=60, context="Owned inert JWT JavaScript import identity review",
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(p).name for p in data["paths"]["scanned"]} == {p.name for p in target.iterdir()}
    actual = {Path(row["path"]).name for row in data["results"] if row["check_id"].endswith("raptor.auth.jwt-no-verify.javascript")}
    assert actual == expected
