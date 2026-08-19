"""Tests for ``libexec/raptor-siftrank`` deterministic paths."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SHIM = REPO_ROOT / "libexec" / "raptor-siftrank"


def _run(*args: str, env_extra: dict[str, str] | None = None):
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(SHIM), *args],
        env=env,
        capture_output=True,
        text=True,
    )


def test_empty_input_produces_empty_array(tmp_path):
    candidates = tmp_path / "candidates.json"
    output = tmp_path / "ranked.json"
    candidates.write_text("[]\n", encoding="utf-8")

    result = _run("--input", str(candidates), "--output", str(output))

    assert result.returncode == 0, result.stderr
    assert json.loads(output.read_text(encoding="utf-8")) == []


def test_single_item_avoids_siftrank_and_returns_rank_one(tmp_path):
    candidates = tmp_path / "candidates.json"
    output = tmp_path / "ranked.json"
    item = {"title": "Potential SQL injection"}
    candidates.write_text(json.dumps([item]), encoding="utf-8")

    result = _run(
        "--input", str(candidates),
        "--output", str(output),
        env_extra={"PATH": str(tmp_path / "empty-bin")},
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(output.read_text(encoding="utf-8")) == [{
        "rank": 1,
        "score": 0.0,
        "id": "item-1",
        "item": item,
    }]


def test_model_selection_prefers_openai_compatible_analysis_model(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    capture = tmp_path / "capture.json"
    go_called = tmp_path / "go-called"
    fake = bin_dir / "siftrank"
    fake.write_text(
        f"""#!{sys.executable}
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
input_path = args[args.index("--file") + 1]
output_path = args[args.index("--output") + 1]
records = json.loads(Path(input_path).read_text())
Path({str(capture)!r}).write_text(json.dumps({{
    "argv": args,
    "api_key": os.environ.get("OPENAI_API_KEY"),
}}))
results = []
for rank, record in enumerate(reversed(records), start=1):
    results.append({{
        "rank": rank,
        "score": rank + 0.5,
        "exposure": rank,
        "rounds": 2,
        "input_index": record["_raptor_index"],
        "key": "key-" + record["_raptor_id"],
        "document": record,
    }})
Path(output_path).write_text(json.dumps(results))
""",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    fake_go = bin_dir / "go"
    fake_go.write_text(
        f"""#!{sys.executable}
from pathlib import Path
Path({str(go_called)!r}).write_text("called")
raise SystemExit(1)
""",
        encoding="utf-8",
    )
    fake_go.chmod(0o755)

    config = tmp_path / "models.json"
    config.write_text(json.dumps({
        "models": [
            {
                "provider": "openai",
                "model": "fallback-model",
                "api_key": "fallback-key",
            },
            {
                "provider": "local-openai-compatible",
                "model": "analysis-model",
                "role": "analysis",
                "api_key": "analysis-key",
                "base_url": "http://example.test/v1",
            },
        ],
    }), encoding="utf-8")

    candidates = tmp_path / "candidates.json"
    output = tmp_path / "ranked.json"
    candidates.write_text(json.dumps([
        {"id": "one", "title": "First"},
        {"id": "two", "title": "Second"},
    ]), encoding="utf-8")

    result = _run(
        "--input", str(candidates),
        "--output", str(output),
        env_extra={
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "RAPTOR_CONFIG": str(config),
        },
    )

    assert result.returncode == 0, result.stderr
    assert not go_called.exists()
    seen = json.loads(capture.read_text(encoding="utf-8"))
    assert seen["api_key"] == "analysis-key"
    assert seen["argv"][seen["argv"].index("--model") + 1] == "analysis-model"
    assert seen["argv"][seen["argv"].index("--base-url") + 1] == "http://example.test/v1"
    assert json.loads(output.read_text(encoding="utf-8")) == [
        {
            "rank": 1,
            "score": 1.5,
            "id": "two",
            "item": {"id": "two", "title": "Second"},
            "siftrank_key": "key-two",
            "exposure": 1,
            "rounds": 2,
            "input_index": 1,
        },
        {
            "rank": 2,
            "score": 2.5,
            "id": "one",
            "item": {"id": "one", "title": "First"},
            "siftrank_key": "key-one",
            "exposure": 2,
            "rounds": 2,
            "input_index": 0,
        },
    ]


def test_missing_siftrank_and_go_errors_clearly(tmp_path):
    candidates = tmp_path / "candidates.json"
    output = tmp_path / "ranked.json"
    candidates.write_text(json.dumps([
        {"id": "one", "title": "First"},
        {"id": "two", "title": "Second"},
    ]), encoding="utf-8")

    result = _run(
        "--input", str(candidates),
        "--output", str(output),
        env_extra={"PATH": str(tmp_path / "empty-bin")},
    )

    assert result.returncode == 1
    assert "siftrank is not installed and Go is not available." in result.stderr
    assert "go install github.com/noperator/siftrank/cmd/siftrank@latest" in result.stderr


def test_go_install_success_uses_siftrank_from_gobin(tmp_path):
    bin_dir = tmp_path / "bin"
    gobin = tmp_path / "gobin"
    bin_dir.mkdir()
    gobin.mkdir()
    capture = tmp_path / "capture.json"
    fake_go = bin_dir / "go"
    fake_go.write_text(
        f"""#!{sys.executable}
import os
import stat
import sys
from pathlib import Path

if sys.argv[1:] == ["install", "github.com/noperator/siftrank/cmd/siftrank@latest"]:
    target = Path(os.environ["GOBIN"]) / "siftrank"
    target.write_text({f'''#!{sys.executable}
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
input_path = args[args.index("--file") + 1]
output_path = args[args.index("--output") + 1]
records = json.loads(Path(input_path).read_text())
Path({str(capture)!r}).write_text(json.dumps({{"argv": args, "api_key": os.environ.get("OPENAI_API_KEY")}}))
results = []
for rank, record in enumerate(records, start=1):
    results.append({{
        "rank": rank,
        "score": rank,
        "document": record,
        "input_index": record["_raptor_index"],
    }})
Path(output_path).write_text(json.dumps(results))
'''!r})
    target.chmod(target.stat().st_mode | stat.S_IXUSR)
    raise SystemExit(0)

raise SystemExit(1)
""",
        encoding="utf-8",
    )
    fake_go.chmod(0o755)

    config = tmp_path / "models.json"
    config.write_text(json.dumps({
        "models": [{
            "provider": "openai",
            "model": "analysis-model",
            "role": "analysis",
            "api_key": "analysis-key",
        }],
    }), encoding="utf-8")

    candidates = tmp_path / "candidates.json"
    output = tmp_path / "ranked.json"
    candidates.write_text(json.dumps([
        {"id": "one", "title": "First"},
        {"id": "two", "title": "Second"},
    ]), encoding="utf-8")

    result = _run(
        "--input", str(candidates),
        "--output", str(output),
        env_extra={
            "GOBIN": str(gobin),
            "PATH": str(bin_dir),
            "RAPTOR_CONFIG": str(config),
        },
    )

    assert result.returncode == 0, result.stderr
    seen = json.loads(capture.read_text(encoding="utf-8"))
    assert seen["api_key"] == "analysis-key"
    assert seen["argv"][seen["argv"].index("--model") + 1] == "analysis-model"
    assert [item["id"] for item in json.loads(output.read_text(encoding="utf-8"))] == [
        "one", "two",
    ]


def test_go_install_failure_errors_clearly(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_go = bin_dir / "go"
    fake_go.write_text(
        f"""#!{sys.executable}
import sys
sys.stderr.write("module download failed\\n")
raise SystemExit(42)
""",
        encoding="utf-8",
    )
    fake_go.chmod(0o755)

    candidates = tmp_path / "candidates.json"
    output = tmp_path / "ranked.json"
    candidates.write_text(json.dumps([
        {"id": "one", "title": "First"},
        {"id": "two", "title": "Second"},
    ]), encoding="utf-8")

    result = _run(
        "--input", str(candidates),
        "--output", str(output),
        env_extra={"PATH": str(bin_dir)},
    )

    assert result.returncode == 1
    assert "module download failed" in result.stderr
    assert "Failed to install siftrank with:" in result.stderr
    assert "go install github.com/noperator/siftrank/cmd/siftrank@latest" in result.stderr
