"""Tests for C/C++ L1 source observations.

These sources feed /understand and /validate with process, fd, stream,
and socket input context without changing the source_intel verdict policy.
"""

from __future__ import annotations

from core.input_taxonomy import C_L1_SOURCE_CALLS, TRUST_L1_ATTACKER_CONTROLLED
from packages.source_intel.analyze import (
    CLevelSourceEvidence,
    SourceIntelResult,
    _scan_c_level_source_inputs,
)
from packages.source_intel.render import derive_evidence_strings


def test_input_taxonomy_covers_issue_comment_l1_sources():
    assert TRUST_L1_ATTACKER_CONTROLLED == "L1"
    assert C_L1_SOURCE_CALLS["read"] == "fd"
    assert C_L1_SOURCE_CALLS["recv"] == "socket"
    assert C_L1_SOURCE_CALLS["fgets"] == "stream"
    assert C_L1_SOURCE_CALLS["getenv"] == "env"
    assert C_L1_SOURCE_CALLS["ioctl"] == "device_control"
    assert C_L1_SOURCE_CALLS["copy_from_user"] == "kernel_user"


def test_c_level_source_scan_captures_read_recv_fgets_argv_env(tmp_path):
    src = tmp_path / "input.c"
    src.write_text(
        "extern long read(int, void *, unsigned long);\n"
        "extern int recv(int, void *, unsigned long, int);\n"
        "extern char *fgets(char *, int, void *);\n"
        "extern char *getenv(const char *);\n"
        "int main(int argc, char **argv, char **envp) {\n"
        "    char buf[128];\n"
        "    read(0, buf, sizeof(buf));\n"
        "    recv(3, buf, sizeof(buf), 0);\n"
        "    fgets(buf, sizeof(buf), 0);\n"
        "    getenv(\"HOME\");\n"
        "    ioctl(3, 0x1234, buf);\n"
        "    copy_from_user(buf, (void *)argv[1], sizeof(buf));\n"
        "    return argv[1][0] + envp[0][0] + argc;\n"
        "}\n"
    )

    observations = _scan_c_level_source_inputs(tmp_path)

    seen = {(ev.source_kind, ev.source_name) for ev in observations}
    assert ("fd", "read") in seen
    assert ("socket", "recv") in seen
    assert ("stream", "fgets") in seen
    assert ("env", "getenv") in seen
    assert ("device_control", "ioctl") in seen
    assert ("kernel_user", "copy_from_user") in seen
    assert ("argv", "argv") in seen
    assert ("env", "envp") in seen


def test_c_level_source_scan_ignores_comments_strings_and_prototypes(tmp_path):
    src = tmp_path / "noise.c"
    src.write_text(
        "extern long read(int, void *, unsigned long);\n"
        "static int recv(int fd, void *buf, unsigned long len, int flags);\n"
        "/* recv(3, buf, len, 0); */\n"
        "/* block comment starts with read(0, buf, len)\n"
        "   and keeps getenv(\"SECRET\") hidden */\n"
        "int main(int argc, char **argv, char **envp) {\n"
        "    char *example = \"fgets(buf, sizeof(buf), stdin)\";\n"
        "    // getenv(\"HOME\") and read(0, buf, 8) are examples only\n"
        "    return argv[0][0] + envp[0][0] + argc;\n"
        "}\n"
    )

    observations = _scan_c_level_source_inputs(tmp_path)

    seen = {(ev.source_kind, ev.source_name) for ev in observations}
    assert ("argv", "argv") in seen
    assert ("env", "envp") in seen
    assert ("fd", "read") not in seen
    assert ("socket", "recv") not in seen
    assert ("stream", "fgets") not in seen
    assert ("env", "getenv") not in seen


def test_c_level_sources_render_into_prompt_lines():
    result = SourceIntelResult(
        c_level_sources=(
            CLevelSourceEvidence(
                source_kind="socket",
                source_name="recv",
                location=("server.c", 42),
                enclosing_function="handle_client",
            ),
        ),
    )

    lines = derive_evidence_strings(result, finding_function="handle_client")

    assert any("C/C++ L1 source" in line for line in lines)
    assert any("recv" in line and "attacker-controlled" in line for line in lines)


def test_c_level_sources_filter_by_finding_function():
    result = SourceIntelResult(
        c_level_sources=(
            CLevelSourceEvidence(
                source_kind="socket",
                source_name="recv",
                location=("server.c", 42),
                enclosing_function="handle_client",
            ),
            CLevelSourceEvidence(
                source_kind="argv",
                source_name="argv",
                location=("cli.c", 8),
                enclosing_function="main",
            ),
        ),
    )

    lines = derive_evidence_strings(result, finding_function="main")

    joined = "\n".join(lines)
    assert "argv" in joined
    assert "recv" not in joined
