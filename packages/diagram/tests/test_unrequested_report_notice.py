"""Native-only diagram completion identifies retained portable receipts."""
import pytest

from core.testing.state_isolation import pin_user_state_dirs
from packages.diagram import cli, cli_reporting, renderer


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path)


def _captured_renderer(monkeypatch):
    calls = []

    def render(out_dir, *, target=None, source_observer=None, rendered_observer=None):
        content = f"# Captured diagrams\nRecorded render {len(calls)}.\n"
        calls.append(content)
        path = out_dir / "diagrams.md"
        path.write_text(content, encoding="utf-8")
        if rendered_observer is not None:
            rendered_observer(content)
        return path

    monkeypatch.setattr(renderer, "render_and_write", render)
    return calls


@pytest.mark.parametrize("disabled", [False, True])
def test_native_only_render_preserves_receipt_and_warns_once(tmp_path, monkeypatch, capsys, disabled):
    calls = _captured_renderer(monkeypatch)
    assert cli.main([str(tmp_path), "--report-format", "json"]) == 0
    assert (tmp_path / "reporting-manifest.json").is_file()
    portable = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*")
                if p.is_file() and p.name != "diagrams.md"}

    def forbidden(*args, **kwargs):
        pytest.fail("native-only render must not build another portable result")

    monkeypatch.setattr(cli_reporting, "NativeResult", forbidden)
    capsys.readouterr()
    flags = ["--no-report"] if disabled else []
    assert cli.main([str(tmp_path), "--force", *flags]) == 0
    streams = capsys.readouterr()
    assert streams.err.count("prior report artifacts were not refreshed") == 1
    assert "Diagrams rendered: 0" in streams.err and "Summary" not in streams.err
    assert len(calls) == 2 and calls[0] != calls[1]
    assert (tmp_path / "diagrams.md").read_text(encoding="utf-8") == calls[1]
    for name, contents in portable.items():
        assert (tmp_path / name).read_bytes() == contents


def test_fresh_native_only_render_has_no_retained_report_notice(tmp_path, monkeypatch, capsys):
    calls = _captured_renderer(monkeypatch)
    assert cli.main([str(tmp_path)]) == 0
    streams = capsys.readouterr()
    assert "prior report artifacts" not in streams.err and "Summary" not in streams.err
    assert "Diagrams rendered: 0" in streams.err and len(calls) == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == ["diagrams.md"]
