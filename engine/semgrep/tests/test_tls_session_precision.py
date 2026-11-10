"""Native Requests session context/factory coverage without network execution."""
from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from core.audit.tests._live_transport import run_pinned_subprocess
from core.config import RaptorConfig

_RULE = Path(__file__).resolve().parents[1] / "rules/auth/tls-skip-verify.yaml"
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed")]


def test_requests_session_context_and_factory_forms(tmp_path):
    # These bodies are scanned as inert source, never imported or called.
    lines = ["import requests", "import requests as r", "from requests import Session",
             "import other", "import httpx", "import aiohttp"]
    cases = [
        ('requests.get("https://owned.invalid/", verify=False)', True),
        ('s = requests.Session()\ns.get("https://owned.invalid/", verify=False)', True),
        ('s = requests.session()\ns.get("https://owned.invalid/", verify=False)', True),
        ('with requests.Session() as s:\n    s.get("https://owned.invalid/", verify=False)', True),
        ('with requests.session() as s:\n    s.get("https://owned.invalid/", verify=False)', True),
        ('with Session() as s:\n    s.post("https://owned.invalid/", verify=False)', True),
        ('with r.Session() as s:\n    s.get("https://owned.invalid/", verify=False)', True),
        ('with requests.Session() as s:\n    s.verify = False', True),
        ('with requests.session() as s:\n    s.verify = False', True),
        ('httpx.get("https://owned.invalid/", verify=False)', True),
        ('aiohttp.TCPConnector(ssl=False)', True),
        ('with requests.Session() as s:\n    s.get("https://owned.invalid/", verify=True)', False),
        ('with requests.Session() as s:\n    s.verify = True', False),
        ('with other.Session() as s:\n    s.get("https://owned.invalid/", verify=False)', False),
        ('s = requests.session()\ns.get("https://owned.invalid/", verify=True)', False),
        ('requests.get("https://owned.invalid/", verify=True)', False),
        ('httpx.get("https://owned.invalid/", verify=True)', False),
    ]
    expected = set()
    for number, (body, reports) in enumerate(cases):
        lines.append(f"def case_{number}():")
        lines.extend("    " + line for line in body.splitlines())
        if reports:
            expected.add(len(lines))
    target = tmp_path / "owned_tls.py"
    target.write_text("\n".join(lines) + "\n")
    proc = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(_RULE), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", str(target)],
        timeout=60, context="Requests session TLS context/factory coverage",
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(path).name for path in data["paths"]["scanned"]} == {target.name}
    actual = {row["start"]["line"] for row in data["results"]
              if row["check_id"].endswith("raptor.tls.skip-verify.python")}
    assert actual == expected
