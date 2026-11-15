"""A finally sink can run when a curated transform raises."""
import json

from core.dataflow import tier1_llm as t1


def test_curated_transform_error_reaches_finally_sink(tmp_path):
    line = "        safe = werkzeug.utils.secure_filename(raw)"
    source = (
        "import werkzeug.utils\n"
        "def handle(raw):\n"
        "    safe = raw\n"
        "    try:\n" + line + "\n"
        "    finally:\n"
        "        return open(safe)\n"
    )
    (tmp_path / "app.py").write_text(source)
    reply = json.dumps({
        "kind": "known_safe_call", "validator_source_line": line,
        "variable_name": "raw", "charset": "", "forbidden": "",
        "library_call": "werkzeug.utils.secure_filename",
    })
    result = t1.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path,
        sink_uri="app.py", sink_line=7, sink_class="pathtrav",
        language="python", complete=lambda _system, _user: reply,
    )
    assert result.status is not t1.Tier0Status.SOUND, result
    assert result.artifact is None

    # A sink in the same protected body is skipped if the call fails.
    control = source.replace(
        "    finally:\n        return open(safe)\n",
        "        return open(safe)\n    finally:\n        pass\n",
    )
    (tmp_path / "app.py").write_text(control)
    result = t1.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path,
        sink_uri="app.py", sink_line=6, sink_class="pathtrav",
        language="python", complete=lambda _system, _user: reply,
    )
    assert result.status is t1.Tier0Status.SOUND, result

    # Errors in else and handler sections also execute finally.
    for section in (
        "    try:\n        pass\n    except Exception:\n        return\n    else:\n",
        "    try:\n        raise ValueError\n    except Exception:\n",
    ):
        changed = source.replace("    try:\n", section)
        (tmp_path / "app.py").write_text(changed)
        result = t1.try_tier1b(
            fix_diff="+" + line + "\n", repo_root=tmp_path,
            sink_uri="app.py", sink_line=len(changed.splitlines()), sink_class="pathtrav",
            language="python", complete=lambda _system, _user: reply,
        )
        assert result.status is not t1.Tier0Status.SOUND, result
