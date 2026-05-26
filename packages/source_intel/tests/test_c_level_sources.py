"""Tests for C/C++ L1 source observations.

These sources feed /understand and /validate with process, fd, stream,
and socket input context without changing the source_intel verdict policy.
"""

from __future__ import annotations

from packages.source_intel.analyze import (
    _C_L1_SOURCE_CALLS,
    CLevelSourceEvidence,
    SourceIntelResult,
    _scan_c_level_source_inputs,
)
from packages.source_intel.render import derive_evidence_strings


def test_source_scanner_composes_shared_catalog_with_source_local_reads():
    assert _C_L1_SOURCE_CALLS["read"] == "fd"
    assert _C_L1_SOURCE_CALLS["fread"] == "fd"
    assert _C_L1_SOURCE_CALLS["recv"] == "socket"
    assert _C_L1_SOURCE_CALLS["fgets"] == "stream"
    assert _C_L1_SOURCE_CALLS["scanf"] == "stream"
    assert _C_L1_SOURCE_CALLS["wscanf"] == "stream"
    assert "accept" not in _C_L1_SOURCE_CALLS
    assert "bind" not in _C_L1_SOURCE_CALLS
    assert "listen" not in _C_L1_SOURCE_CALLS
    assert "sscanf" not in _C_L1_SOURCE_CALLS
    assert "vsscanf" not in _C_L1_SOURCE_CALLS
    assert "swscanf" not in _C_L1_SOURCE_CALLS
    assert _C_L1_SOURCE_CALLS["getenv"] == "env"
    assert _C_L1_SOURCE_CALLS["ioctl"] == "device_control"
    assert _C_L1_SOURCE_CALLS["copy_from_user"] == "kernel_user"
    assert _C_L1_SOURCE_CALLS["import_iovec"] == "kernel_user"
    assert _C_L1_SOURCE_CALLS["mq_receive"] == "ipc"


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


def test_c_level_source_scan_excludes_setup_and_in_memory_parse_calls(tmp_path):
    src = tmp_path / "setup_only.c"
    src.write_text(
        "extern int accept(int, void *, void *);\n"
        "extern int bind(int, const void *, unsigned int);\n"
        "extern int listen(int, int);\n"
        "extern int recv(int, void *, unsigned long, int);\n"
        "extern int sscanf(const char *, const char *, ...);\n"
        "extern int swscanf(const wchar_t *, const wchar_t *, ...);\n"
        "extern int wscanf(const wchar_t *, ...);\n"
        "int main(void) {\n"
        "    char buf[128];\n"
        "    wchar_t wbuf[128];\n"
        "    accept(3, 0, 0);\n"
        "    bind(3, 0, 0);\n"
        "    listen(3, 16);\n"
        "    sscanf(buf, \"%d\", 0);\n"
        "    swscanf(wbuf, L\"%d\", 0);\n"
        "    recv(3, buf, sizeof(buf), 0);\n"
        "    wscanf(L\"%d\", 0);\n"
        "    return 0;\n"
        "}\n"
    )

    observations = _scan_c_level_source_inputs(tmp_path)

    seen = {(ev.source_kind, ev.source_name) for ev in observations}
    assert ("socket", "recv") in seen
    assert ("stream", "wscanf") in seen
    assert ("socket", "accept") not in seen
    assert ("socket", "bind") not in seen
    assert ("socket", "listen") not in seen
    assert ("stream", "sscanf") not in seen
    assert ("stream", "swscanf") not in seen


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
