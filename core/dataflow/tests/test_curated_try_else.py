"""A caught body error skips a transform in try/else."""
import json

from core.dataflow import tier1_llm as t1


def test_curated_try_else_requires_execution_before_sink(tmp_path):
    line = "        safe = werkzeug.utils.secure_filename(raw)"
    source = (
        "import werkzeug.utils\n"
        "def handle(raw):\n"
        "    safe = raw\n"
        "    try:\n"
        "        prepare()\n"
        "    except Exception:\n"
        "        pass\n"
        "    else:\n" + line + "\n"
        "    return open(safe)\n"
    )
    (tmp_path / "app.py").write_text(source)
    reply = json.dumps({
        "kind": "known_safe_call", "validator_source_line": line,
        "variable_name": "raw", "charset": "", "forbidden": "",
        "library_call": "werkzeug.utils.secure_filename",
    })
    result = t1.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path,
        sink_uri="app.py", sink_line=10, sink_class="pathtrav",
        language="python", complete=lambda _system, _user: reply,
    )
    assert result.status is not t1.Tier0Status.SOUND, result
    assert result.artifact is None
    assert "conditional branch" in result.reasoning

    # Both calls are skipped together on the exception edge.
    (tmp_path / "app.py").write_text(source.replace(
        "    return open(safe)", "        return open(safe)",
    ))
    control = t1.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path,
        sink_uri="app.py", sink_line=10, sink_class="pathtrav",
        language="python", complete=lambda _system, _user: reply,
    )
    assert control.status is t1.Tier0Status.SOUND, control
