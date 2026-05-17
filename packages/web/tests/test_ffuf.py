"""Tests for the narrow ffuf integration."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.web.ffuf import FfufConfig, FfufRunner


def test_build_command_anchors_relative_template_to_base_url(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    output = tmp_path / "ffuf_results.json"

    runner = FfufRunner("https://example.test/app", tmp_path)
    cmd = runner.build_command(
        FfufConfig(wordlist=wordlist, path_template="admin/FUZZ", threads=3, rate=5),
        output,
    )

    assert cmd[:6] == [
        "ffuf",
        "-u",
        "https://example.test/app/admin/FUZZ",
        "-w",
        str(wordlist),
        "-of",
    ]
    assert "-noninteractive" in cmd
    assert cmd[cmd.index("-t") + 1] == "3"
    assert cmd[cmd.index("-rate") + 1] == "5"


def test_build_command_allows_same_origin_absolute_template(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("health\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    url = runner.build_url_template("https://example.test/api/FUZZ")

    assert url == "https://example.test/api/FUZZ"


@pytest.mark.parametrize(
    "template",
    [
        "https://evil.test/FUZZ",
        "//evil.test/FUZZ",
        "https://example.test.evil/FUZZ",
    ],
)
def test_build_url_template_rejects_out_of_scope_templates(tmp_path: Path, template: str):
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="outside configured target scope"):
        runner.build_url_template(template)


def test_build_url_template_requires_fuzz_marker(tmp_path: Path):
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="must include FUZZ"):
        runner.build_url_template("admin")


@pytest.mark.parametrize(
    ("config_kwargs", "message"),
    [
        ({"threads": 0}, "threads must be >= 1"),
        ({"rate": 0}, "rate must be >= 1"),
        ({"timeout": 0}, "timeout must be >= 1"),
        ({"max_runtime": 0}, "max runtime must be >= 1"),
        ({"report_limit": -1}, "report limit must be >= 0"),
        ({"filter_size": -1}, "filter size must be >= 0"),
    ],
)
def test_build_command_rejects_invalid_numeric_options(
    tmp_path: Path,
    config_kwargs: dict[str, int],
    message: str,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match=message):
        runner.build_command(FfufConfig(wordlist=wordlist, **config_kwargs), tmp_path / "out.json")


def test_run_requires_explicit_ffuf_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: None)

    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(FileNotFoundError, match="ffuf binary not found"):
        runner.run(FfufConfig(wordlist=wordlist))


def test_run_uses_subprocess_argv_and_summarizes_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "url": "https://example.test/admin?" + "tok" + "en=abc123",
                            "status": 200,
                            "length": 42,
                            "words": 3,
                            "lines": 1,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr=None)

    monkeypatch.setattr("packages.web.ffuf.run_untrusted", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist, path_template="FUZZ"))

    assert captured["cmd"][0] == "ffuf"
    assert captured["kwargs"]["capture_output"] is True
    assert captured["kwargs"]["text"] is True
    assert captured["kwargs"]["use_egress_proxy"] is True
    assert captured["kwargs"]["proxy_hosts"] == ["example.test"]
    assert captured["kwargs"]["caller_label"] == "web-ffuf"
    assert result["returncode"] == 0
    assert result["stderr"] == ""
    assert result["result_count"] == 1
    assert result["reported_result_count"] == 1
    assert result["omitted_result_count"] == 0
    assert result["results"] == [
        {
            "url": "https://example.test/admin?" + "tok" + "en=[REDACTED]",
            "status": 200,
            "length": 42,
            "words": 3,
            "lines": 1,
        }
    ]


def test_run_limits_embedded_report_results_but_keeps_raw_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "results": [
                        {"url": f"https://example.test/{idx}", "status": 200}
                        for idx in range(3)
                    ]
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist, report_limit=2))

    assert result["result_count"] == 3
    assert result["reported_result_count"] == 2
    assert result["omitted_result_count"] == 1
    assert [entry["url"] for entry in result["results"]] == [
        "https://example.test/0",
        "https://example.test/1",
    ]


def test_scanner_cli_wires_all_ffuf_options(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-path",
            "admin/FUZZ",
            "--ffuf-bin",
            "custom-ffuf",
            "--ffuf-threads",
            "7",
            "--ffuf-rate",
            "11",
            "--ffuf-timeout",
            "12",
            "--ffuf-report-limit",
            "13",
            "--ffuf-max-runtime",
            "14",
            "--ffuf-no-auto-calibration",
            "--ffuf-match-status",
            "200,401",
            "--ffuf-filter-status",
            "403,404",
            "--ffuf-filter-size",
            "1234",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.wordlist == wordlist
    assert config.path_template == "admin/FUZZ"
    assert config.binary == "custom-ffuf"
    assert config.threads == 7
    assert config.rate == 11
    assert config.timeout == 12
    assert config.report_limit == 13
    assert config.max_runtime == 14
    assert config.auto_calibration is False
    assert config.match_status == "200,401"
    assert config.filter_status == "403,404"
    assert config.filter_size == 1234


def test_scanner_cli_can_omit_optional_ffuf_match_and_filter_status(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-match-status",
            "",
            "--ffuf-filter-status",
            "",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.match_status is None
    assert config.filter_status is None
