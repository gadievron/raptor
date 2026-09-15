"""End-to-end closure tests for the IRIS→CodeQL confirmation lane.

These run the REAL CodeQL CLI: the generated query text is compiled
against the locally cached stock packs for every supported language,
and one full lane pass (database create → generated-pack analyze →
SARIF token join → spec-key confirmation) runs on a real python
database. Text-shape unit tests cannot catch a query that references
classes absent from a language's QL library — that exact gap kept
this lane dead through two prior construction-level fixes — so the
closure test is the CLI itself.

Hermetic-skip: everything skips when no CodeQL CLI is resolvable, and
the per-language compiles skip for languages whose stdlib pack is not
cached locally. Slow-tier: query compilation alone exceeds the
default-tier time budget.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from core.iris.specs import (
    CODEQL_QUERY_LANGUAGES,
    TaintSpec,
    compile_codeql_config,
    spec_message_token,
)

pytestmark = pytest.mark.slow


def _resolve_cli() -> str | None:
    from packages.codeql import _resolve_cli as resolve
    return resolve()


requires_codeql = pytest.mark.skipif(
    _resolve_cli() is None,
    reason="CodeQL CLI not installed (PATH or CODEQL_CLI)",
)


def _offline_env() -> dict[str, str]:
    """Environment with every proxy/egress hint scrubbed — the compile
    and analyze must succeed with NO path to the pack registry, which
    is exactly the block_network condition the production analyze runs
    under."""
    env = dict(os.environ)
    for var in list(env):
        if var.lower() in (
            "http_proxy", "https_proxy", "ftp_proxy", "all_proxy",
        ):
            env.pop(var)
    return env


def _vendored_roots(language: str) -> list[Path]:
    from packages.codeql.query_runner import vendored_stdlib_roots
    return vendored_stdlib_roots(language)


def _specs(src: str, snk: str, cln: str, prp: str) -> list[TaintSpec]:
    return [
        TaintSpec(function=src, file="app", role="source"),
        TaintSpec(function=snk, file="app", role="sink"),
        TaintSpec(function=cln, file="app", role="sanitiser"),
        TaintSpec(function=prp, file="app", role="propagator"),
    ]


#: Identifier styles per language keep the fixtures idiomatic; the
#: query shape under test is identical.
_NAMES = {
    "cpp": ("read_input", "my_sink", "my_clean", "my_pass"),
    "java": ("readInput", "mySink", "myClean", "myPass"),
    "csharp": ("ReadInput", "MySink", "MyClean", "MyPass"),
    "python": ("read_input", "my_sink", "my_clean", "my_pass"),
    "javascript": ("readInput", "mySink", "myClean", "myPass"),
    "go": ("readInput", "mySink", "myClean", "myPass"),
    "ruby": ("read_input", "my_sink", "my_clean", "my_pass"),
}


@requires_codeql
@pytest.mark.parametrize("language", sorted(CODEQL_QUERY_LANGUAGES))
def test_generated_query_compiles(language: str, tmp_path: Path) -> None:
    """Every language row's generated query must compile against the
    real stock pack — both the path-problem and sink-only shapes."""
    roots = _vendored_roots(language)
    if not roots:
        pytest.skip(f"no cached codeql/{language}-queries pack")

    from core.iris.codeql_runner import _write_temp_pack

    cli = _resolve_cli()
    src, snk, cln, prp = _NAMES[language]
    for name, specs in (
        ("path", _specs(src, snk, cln, prp)),
        ("sinkonly", [TaintSpec(function=snk, file="app", role="sink")]),
    ):
        query = compile_codeql_config(specs, language=language)
        pack = _write_temp_pack(query, language, tmp_path / name)
        proc = subprocess.run(
            [
                cli, "query", "compile", str(pack / "IrisSpecs.ql"),
                *(f"--additional-packs={r}" for r in roots),
            ],
            capture_output=True, text=True, timeout=600,
            env=_offline_env(), check=False,
        )
        assert proc.returncode == 0, (
            f"{language}/{name} query failed to compile:\n{proc.stderr}"
        )


@requires_codeql
def test_full_lane_confirms_specs_on_real_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Whole lane on a real database: probe the DB's language, generate
    the query, resolve the temp pack offline via the vendored stdlib
    root, analyze, join the SARIF messages back to spec keys.

    The sandbox wrapper is replaced with a plain subprocess run on a
    proxy-scrubbed environment — sandbox engagement has its own suite;
    what must be real here is the CLI, the pack resolution, and the
    token join.
    """
    if not _vendored_roots("python"):
        pytest.skip("no cached codeql/python-queries pack")

    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text(
        "def read_input():\n"
        "    return input()\n"
        "\n"
        "def my_sink(s):\n"
        "    print(s)\n"
        "\n"
        "def my_clean(s):\n"
        "    return s\n"
        "\n"
        "def my_pass(s):\n"
        "    return s\n"
        "\n"
        "def main():\n"
        "    a = read_input()\n"
        "    my_sink(a)\n"
        "    my_sink(my_clean(a))\n"
        "    my_sink(my_pass(a))\n",
    )

    cli = _resolve_cli()
    db = tmp_path / "db"
    create = subprocess.run(
        [
            cli, "database", "create", str(db), "--language=python",
            f"--source-root={target}",
        ],
        capture_output=True, text=True, timeout=600,
        env=_offline_env(), check=False,
    )
    assert create.returncode == 0, f"db create failed:\n{create.stderr}"

    def _fake_sandbox_run(cmd, **kwargs):
        return subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=kwargs.get("timeout", 600),
            env=_offline_env(), check=False,
        )

    monkeypatch.setattr("core.sandbox.run", _fake_sandbox_run)

    from core.iris.codeql_runner import make_codeql_tool_runner
    from core.iris.store import _spec_key

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    # No language argument: the DB's own metadata must drive it.
    runner = make_codeql_tool_runner(db, out_dir)
    assert runner is not None

    specs = _specs("read_input", "my_sink", "my_clean", "my_pass")
    feedback = runner(specs)

    assert feedback.tool_errors == []
    assert feedback.n_successes == 1
    # The direct and propagated flows confirm source + sink; the
    # sanitised call must NOT create extra confirmations (the barrier
    # is live), and the sanitiser/propagator specs are not endpoints.
    assert set(feedback.confirmed_keys) == {
        _spec_key(specs[0]), _spec_key(specs[1]),
    }
    sarif = out_dir / "codeql_python_iris_refine.sarif"
    assert sarif.is_file()
    text = sarif.read_text()
    assert spec_message_token(specs[0]) in text
    assert spec_message_token(specs[1]) in text
