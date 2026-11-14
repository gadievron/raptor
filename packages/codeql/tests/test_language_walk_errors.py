"""Directory enumeration failures must remain visible in partial censuses."""

import os
from pathlib import Path
from unittest.mock import Mock

from packages.codeql import language_detector as detection


def test_walk_warns_for_unreadable_directory_and_keeps_readable_files(
    tmp_path, monkeypatch,
):
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "hidden.py").write_text("# inert fixture\n")
    visible = tmp_path / "visible.py"
    visible.write_text("# inert fixture\n")
    real_scandir = os.scandir
    denied = []

    def scandir(path):
        if Path(path) == blocked:
            denied.append(path)
            raise PermissionError(13, "owned directory read refused", str(path))
        return real_scandir(path)

    log = Mock()
    monkeypatch.setattr(detection.logger, "warning", log)
    monkeypatch.setattr(os, "scandir", scandir)
    # Call the fallback directly: no Git census or extractor probes.
    files = list(detection.LanguageDetector(tmp_path)._walk_all_files())

    assert denied
    assert files == [visible]
    messages = [call.args[0] % call.args[1:] for call in log.call_args_list]
    assert any(str(blocked) in message and "partial" in message.lower()
               for message in messages)
