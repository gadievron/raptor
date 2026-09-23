"""Destination confinement for ``libexec/raptor-fetch-attachment``.

The URL is allowlisted against the bug report, but the destination
used to be written wherever argv[3] pointed — and the agent composes
that path from the UNTRUSTED tracker's attachment file name, so a
name like ``../../.ssh/authorized_keys`` wrote attacker bytes to any
writable path. The script must confine the write to the
``attachments/`` directory beside the bug report.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-fetch-attachment"

_URL = "https://tracker.example.test/attachment/1/crash.bin"


@pytest.fixture(scope="module")
def cli():
    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        loader = importlib.machinery.SourceFileLoader(
            "raptor_fetch_attachment", str(SCRIPT),
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec is not None
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        yield mod
    finally:
        if prior is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = prior


@pytest.fixture()
def workdir(tmp_path: Path) -> Path:
    report = {"attachments": [{"url": _URL, "filename": "crash.bin"}]}
    (tmp_path / "bug-report.json").write_text(
        json.dumps(report), encoding="utf-8",
    )
    return tmp_path


def _main(cli, monkeypatch, workdir: Path, dest: str) -> int:
    monkeypatch.setattr(
        "sys.argv",
        ["raptor-fetch-attachment", str(workdir / "bug-report.json"),
         _URL, dest],
    )
    return cli.main()


class TestConfineDest:
    def test_documented_shape_lands_in_attachments(self, cli, tmp_path):
        report = tmp_path / "bug-report.json"
        dest = cli._confine_dest(str(tmp_path / "attachments" / "crash.bin"),
                                 report)
        assert dest == tmp_path.resolve() / "attachments" / "crash.bin"

    @pytest.mark.parametrize(
        "shape",
        [
            "attachments/../../etc/cron.d/x",
            "../outside",
            "..",
            "attachments/..",
            "",
            ".",
        ],
    )
    def test_parent_components_and_nameless_refused(
        self, cli, tmp_path, shape,
    ):
        assert cli._confine_dest(shape, tmp_path / "bug-report.json") is None

    def test_absolute_escape_reduced_to_basename(self, cli, tmp_path):
        # No '..' components, but pointing outside the workdir: only
        # the file name survives, confined under attachments/.
        dest = cli._confine_dest("/etc/cron.d/evil", tmp_path / "r.json")
        assert dest == tmp_path.resolve() / "attachments" / "evil"

    def test_charset_sanitised_and_option_shape_defused(self, cli, tmp_path):
        report = tmp_path / "r.json"
        dest = cli._confine_dest("a b;c$(x).bin", report)
        assert dest is not None
        assert dest.name == "a_b_c__x_.bin"
        dest = cli._confine_dest("--output.bin", report)
        assert dest is not None
        assert dest.name == "output.bin"
        dest = cli._confine_dest(".hidden", report)
        assert dest is not None
        assert dest.name == "hidden"


class TestMainConfinement:
    def test_traversal_dest_refused_before_download(
        self, cli, monkeypatch, workdir,
    ):
        """Traversal-shaped destinations exit 1 without any network
        attempt (EgressClient would refuse the fake host anyway — the
        point is the refusal happens first and nothing is written)."""
        victim = workdir / "outside"
        rc = _main(
            cli, monkeypatch, workdir,
            str(workdir / "attachments" / ".." / ".." / "outside"),
        )
        assert rc == 1
        assert not victim.exists()
        assert not (workdir / "attachments").exists()

    def test_download_written_only_under_attachments(
        self, cli, monkeypatch, workdir,
    ):
        import core.http.egress_backend as egress_backend

        class _FakeClient:
            def __init__(self, allowed_hosts):
                assert allowed_hosts == ["tracker.example.test"]

            def get_bytes(self, url: str) -> bytes:
                assert url == _URL
                return b"crashdata"

        monkeypatch.setattr(egress_backend, "EgressClient", _FakeClient)

        rc = _main(
            cli, monkeypatch, workdir,
            str(workdir / "attachments" / "crash.bin"),
        )
        assert rc == 0
        written = workdir / "attachments" / "crash.bin"
        assert written.read_bytes() == b"crashdata"

    def test_symlinked_attachments_dir_refused(
        self, cli, monkeypatch, workdir, tmp_path_factory,
    ):
        elsewhere = tmp_path_factory.mktemp("elsewhere")
        (workdir / "attachments").symlink_to(elsewhere)
        rc = _main(
            cli, monkeypatch, workdir,
            str(workdir / "attachments" / "crash.bin"),
        )
        assert rc == 1
        assert not (elsewhere / "crash.bin").exists()


class TestTerminalEscapeScrub:
    """The tracker URL comes verbatim from the untrusted bug report —
    scheme/host validation constrains neither path bytes nor the
    not-in-attachments refusal path. Prints must escape."""

    def test_unlisted_hostile_url_refusal_is_escaped(
        self, cli, monkeypatch, workdir, capsys,
    ):
        hostile = "https://tracker.example.test/a/\x1b[2J\x9bpwn"
        monkeypatch.setattr(
            "sys.argv",
            ["raptor-fetch-attachment", str(workdir / "bug-report.json"),
             hostile, str(workdir / "attachments" / "crash.bin")],
        )
        rc = cli.main()
        assert rc == 1
        err = capsys.readouterr().err
        assert "refusing download" in err
        assert "\x1b" not in err
        assert "\x9b" not in err

    def test_listed_hostile_url_success_line_is_escaped(
        self, cli, monkeypatch, tmp_path, capsys,
    ):
        hostile = "https://tracker.example.test/a/\x1b]0;evil\x07crash.bin"
        report = {"attachments": [{"url": hostile,
                                   "filename": "crash.bin"}]}
        (tmp_path / "bug-report.json").write_text(
            json.dumps(report), encoding="utf-8",
        )

        class _FakeClient:
            def __init__(self, *a, **kw):
                pass

            def get_bytes(self, url):
                return b"data"

        import core.http.egress_backend as egress
        monkeypatch.setattr(egress, "EgressClient", _FakeClient)
        monkeypatch.setattr(
            "sys.argv",
            ["raptor-fetch-attachment", str(tmp_path / "bug-report.json"),
             hostile, str(tmp_path / "attachments" / "crash.bin")],
        )
        rc = cli.main()
        assert rc == 0
        out = capsys.readouterr().out
        assert out.startswith("OK: ")
        assert "\x1b" not in out
        assert "\x07" not in out


class TestDestSymlinkRace:
    """The final-component write uses O_NOFOLLOW: an is_symlink()
    probe followed by write_bytes left a check-then-use window a
    run-dir-writing racer could win. The open itself must refuse."""

    def test_symlinked_dest_refused_at_open(
        self, cli, monkeypatch, workdir, tmp_path_factory,
    ):
        import core.http.egress_backend as egress_backend

        class _FakeClient:
            def __init__(self, allowed_hosts):
                pass

            def get_bytes(self, url: str) -> bytes:
                return b"crashdata"

        monkeypatch.setattr(egress_backend, "EgressClient", _FakeClient)
        victim = tmp_path_factory.mktemp("victim") / "target-file"
        (workdir / "attachments").mkdir()
        (workdir / "attachments" / "crash.bin").symlink_to(victim)

        rc = _main(
            cli, monkeypatch, workdir,
            str(workdir / "attachments" / "crash.bin"),
        )
        assert rc == 1
        assert not victim.exists()

    def test_probe_then_write_window_is_closed(
        self, cli, monkeypatch, workdir, tmp_path_factory,
    ):
        """Deterministically play the racer winning the old
        is_symlink()-then-write_bytes window: every probe reports
        clean while the symlink is already in place. Only an
        atomic-refusal open (O_NOFOLLOW) protects the victim."""
        import core.http.egress_backend as egress_backend

        class _FakeClient:
            def __init__(self, allowed_hosts):
                pass

            def get_bytes(self, url: str) -> bytes:
                return b"crashdata"

        monkeypatch.setattr(egress_backend, "EgressClient", _FakeClient)
        victim = tmp_path_factory.mktemp("victim") / "target-file"
        (workdir / "attachments").mkdir()
        (workdir / "attachments" / "crash.bin").symlink_to(victim)
        monkeypatch.setattr(Path, "is_symlink", lambda self: False)

        rc = _main(
            cli, monkeypatch, workdir,
            str(workdir / "attachments" / "crash.bin"),
        )
        assert rc == 1
        assert not victim.exists()


class TestParentDirSymlinkRace:
    """The attachments/ PARENT component: probing it by name and then
    re-resolving the path for mkdir/write AFTER the network fetch left
    a window spanning the whole download in which a racer could swap
    attachments/ for a symlink and redirect the write. The directory
    is anchored to an fd before the fetch; the write never re-resolves
    the path."""

    def test_racer_winning_every_probe_is_refused(
        self, cli, monkeypatch, workdir, tmp_path_factory,
    ):
        """attachments/ is already a symlink and the racer wins every
        by-name probe (is_symlink reports clean). Only the anchored
        O_NOFOLLOW directory open refuses — O_NOFOLLOW on the final
        write component does not cover intermediate directories."""
        import core.http.egress_backend as egress_backend

        class _FakeClient:
            def __init__(self, allowed_hosts):
                pass

            def get_bytes(self, url: str) -> bytes:
                return b"crashdata"

        monkeypatch.setattr(egress_backend, "EgressClient", _FakeClient)
        victim_dir = tmp_path_factory.mktemp("victim")
        (workdir / "attachments").symlink_to(victim_dir)
        monkeypatch.setattr(Path, "is_symlink", lambda self: False)

        rc = _main(
            cli, monkeypatch, workdir,
            str(workdir / "attachments" / "crash.bin"),
        )
        assert rc == 1
        assert not (victim_dir / "crash.bin").exists()

    def test_swap_during_fetch_cannot_redirect_the_write(
        self, cli, monkeypatch, workdir, tmp_path_factory,
    ):
        """Deterministically play the racer swapping attachments/ for
        a symlink WHILE the download is in flight: the stubbed fetch
        performs the swap before returning the body. The write must
        land in the directory anchored before the fetch, never in the
        victim directory the symlink points at."""
        import core.http.egress_backend as egress_backend

        victim_dir = tmp_path_factory.mktemp("victim")
        attachments = workdir / "attachments"
        aside = workdir / "attachments.aside"

        class _SwappingClient:
            def __init__(self, allowed_hosts):
                pass

            def get_bytes(self, url: str) -> bytes:
                # The racer wins during the network round-trip.
                attachments.rename(aside)
                attachments.symlink_to(victim_dir)
                return b"crashdata"

        monkeypatch.setattr(egress_backend, "EgressClient", _SwappingClient)
        rc = _main(
            cli, monkeypatch, workdir,
            str(workdir / "attachments" / "crash.bin"),
        )
        assert not (victim_dir / "crash.bin").exists(), (
            "swap during fetch redirected the write"
        )
        # The anchored fd still names the pre-fetch directory: the
        # download lands there (at its post-rename location) — inode
        # identity, not path identity, and it confers nothing on the
        # racer.
        assert rc == 0
        assert (aside / "crash.bin").read_bytes() == b"crashdata"
