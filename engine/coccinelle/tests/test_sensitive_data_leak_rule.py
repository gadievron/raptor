"""Fixture tests for the sensitive_data_leak rule.

The negatives pin the substring-match regression: the identifier
pattern matched 'priv' (and 'pass'/'key'/... ) anywhere in the name,
so freeing a driver private-data pointer (`kfree(priv);` — the
standard driver teardown idiom) or any benign carrier of an embedded
word (bypass, monkey, keyboard) minted a CWE-244 secret-leak finding.
Components are now anchored to the start of the name or of an
underscore-separated part, bare `priv` no longer matches, and a small
deny-set drops full English words like keyboard/passthrough.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "sensitive_data_leak.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(_RULE), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


class TestPositives:
    def test_secret_names_freed_uncleared_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bad(char *password, char *session_token, char *aes_key,
                     char *privkey, char *user_pass)
            {
                free(password);
                free(session_token);
                free(aes_key);
                free(privkey);
                free(user_pass);
            }
        """)
        assert len(results) == 5
        assert all(r["rule"] == "sensitive_data_leak" for r in results)

    def test_kfree_of_secret_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bad(char *master_secret)
            {
                kfree(master_secret);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_driver_priv_pointer_does_not_fire(self, tmp_path):
        # 'priv' is the standard private-context pointer name across
        # driver code — private DATA, not private KEY.
        results = _run_rule(tmp_path, """\
            void teardown(struct net_device *dev)
            {
                struct drv_priv *priv = netdev_priv(dev);
                kfree(priv);
            }
        """)
        assert results == []

    def test_embedded_word_carriers_do_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void other(char *bypass_flag, char *monkey, char *keyboard,
                       char *passthrough)
            {
                free(bypass_flag);
                free(monkey);
                free(keyboard);
                free(passthrough);
            }
        """)
        assert results == []

    def test_cleared_before_free_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void good(char *password)
            {
                memset(password, 0, 32);
                free(password);
            }
        """)
        assert results == []
