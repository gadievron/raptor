"""Actual token-read statements release descriptors on read/decode failure."""

import ast
import copy
import errno
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.testing import fds as support
from core.testing.pipes import pipes_for_setup

CASES = [
    ("core/llm/tests/test_consumed_attempt_e2e.py", ["_wire"], "token"),
    (
        "core/llm/dispatcher/tests/test_usage_scan_seam.py",
        ["TestAdmissionGate", "test_worker_token_relays_when_jail_unavailable"],
        "token",
    ),
    ("core/llm/dispatcher/tests/test_upstream_pooling.py", ["_issue_token"], "token"),
    (
        "core/llm/dispatcher/tests/test_dispatcher.py",
        ["TestLayer3TokenAuth", "test_request_with_valid_token_passes_token_check"],
        "token",
    ),
    (
        "core/llm/dispatcher/tests/test_dispatcher.py",
        ["TestLayer4TokenLifecycle", "test_token_budget_exhaustion"],
        "token",
    ),
    (
        "core/llm/dispatcher/tests/test_dispatcher.py",
        ["TestLayer4TokenLifecycle", "test_token_expiry"],
        "token",
    ),
    (
        "core/llm/dispatcher/tests/test_dispatcher.py",
        ["TestLayer4TokenLifecycle", "test_revoked_token_is_rejected"],
        "token",
    ),
    (
        "core/llm/dispatcher/tests/test_dispatcher.py",
        ["TestLayer4TokenLifecycle", "_mint_worker_token"],
        "token",
    ),
    (
        "core/llm/dispatcher/tests/test_dispatcher.py",
        ["TestLayer5AuditLog", "test_audit_does_not_log_token_value"],
        "token",
    ),
    (
        "core/llm/dispatcher/tests/test_dispatcher.py",
        ["TestE2ECredentialIsolation", "test_e2e_credentials_injected_dummy_stripped"],
        "token",
    ),
    (
        "core/llm/dispatcher/tests/test_dispatcher.py",
        ["TestE2ECredentialIsolation", "test_e2e_audit_records_dispatch_without_body"],
        "token",
    ),
    (
        "core/llm/dispatcher/tests/test_dispatcher.py",
        [
            "TestRealAnthropicSDKThroughDispatcher",
            "test_real_anthropic_sdk_call_succeeds",
        ],
        "token",
    ),
    (
        "core/llm/dispatcher/tests/test_dispatcher.py",
        ["TestChildPlaneSocket", "_worker_token"],
        "token",
    ),
    (
        "core/llm/dispatcher/tests/test_dispatcher.py",
        [
            "TestE2EResponseEncodingPreserved",
            "test_gzipped_upstream_body_decompresses_at_worker",
        ],
        "token",
    ),
    (
        "core/llm/dispatcher/tests/test_child_path_allowlist.py",
        ["TestChildPathAllowlist", "test_worker_tokens_unaffected"],
        "worker_token",
    ),
    ("core/llm/dispatcher/tests/test_bedrock_signing.py", ["_post_bedrock"], "token"),
    (
        "core/llm/dispatcher/tests/test_bedrock_signing.py",
        ["test_anthropic_sdk_roundtrip"],
        "token",
    ),
]
ROOT = Path(__file__).resolve().parents[3]


def _owned(fd, identity):
    try:
        stat = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return False
        raise
    return (stat.st_dev, stat.st_ino) == identity


def _statements(case):
    path, target_scope, variable = case
    found = []

    def visit(node, scope=()):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope = (*scope, node.name)
        for _, value in ast.iter_fields(node):
            if isinstance(value, list) and list(scope) == target_scope:
                for index, statement in enumerate(value):
                    if (
                        not isinstance(statement, ast.Assign)
                        or len(statement.targets) != 1
                    ):
                        continue
                    if (
                        not isinstance(statement.targets[0], ast.Name)
                        or statement.targets[0].id != variable
                    ):
                        continue
                    reads = [
                        call
                        for call in ast.walk(statement.value)
                        if isinstance(call, ast.Call)
                        and (
                            isinstance(call.func, ast.Name)
                            and call.func.id == "read_and_close"
                            or isinstance(call.func, ast.Attribute)
                            and call.func.attr == "read"
                        )
                    ]
                    if len(reads) != 1:
                        continue
                    read = reads[0]
                    assert len(read.args) == 2 and isinstance(read.args[0], ast.Name)
                    # Execute only this bounded read/decode/strip chain, never
                    # the surrounding authentication test or worker workflow.
                    for call in [
                        n for n in ast.walk(statement.value) if isinstance(n, ast.Call)
                    ]:
                        assert (
                            call is read
                            or isinstance(call.func, ast.Attribute)
                            and call.func.attr in ("decode", "strip")
                        )
                    selected = [copy.deepcopy(statement)]
                    if index + 1 < len(value):
                        following = value[index + 1]
                        if (
                            isinstance(following, ast.Expr)
                            and isinstance(following.value, ast.Call)
                            and isinstance(following.value.func, ast.Attribute)
                            and following.value.func.attr == "close"
                        ):
                            assert ast.dump(following.value.args[0]) == ast.dump(
                                read.args[0]
                            )
                            selected.append(copy.deepcopy(following))
                    found.append((selected, read.args[0].id))
            if isinstance(value, ast.AST):
                visit(value, scope)
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, ast.AST):
                        visit(child, scope)

    visit(ast.parse((ROOT / path).read_text()))
    assert len(found) == 1, case
    return found[0]


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("fault", ["read_error", "interrupt", "decode", "none"])
def test_token_read_releases_its_owned_descriptor(case, fault, monkeypatch):
    with pipes_for_setup(1) as pairs:
        read_fd, write_fd = pairs[0]
        stat = os.fstat(read_fd)
        identity = (stat.st_dev, stat.st_ino)
        os.write(write_fd, b"\xff" if fault == "decode" else b"owned-token")
    try:
        os.close(write_fd)
        real_read = os.read
        def read(fd, size):
            assert fd == read_fd and size in (64, 256)
            if fault in ("read_error", "interrupt"):
                raise (OSError if fault == "read_error" else KeyboardInterrupt)(
                    "injected token read failure"
                )
            return real_read(fd, size)
        proxy = SimpleNamespace(**vars(os))
        proxy.read = read
        statements, name = _statements(case)
        namespace = {
            "os": proxy,
            "_os": proxy,
            name: read_fd,
            "read_and_close": getattr(support, "read_and_close", None),
        }
        code = compile(ast.Module(body=statements, type_ignores=[]), case[0], "exec")
        with monkeypatch.context() as patcher:
            patcher.setattr(support, "os", proxy)
            if fault == "none":
                exec(code, namespace)
                assert namespace[case[2]] == "owned-token"
            else:
                expected = {
                    "read_error": OSError,
                    "interrupt": KeyboardInterrupt,
                    "decode": UnicodeDecodeError,
                }[fault]
                with pytest.raises(expected):
                    exec(code, namespace)
        assert not _owned(read_fd, identity), (
            "read/decode failure left token descriptor open"
        )
    finally:
        if _owned(read_fd, identity):
            os.close(read_fd)
