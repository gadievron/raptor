"""Owned host metadata for report-composition tests."""

import pytest

from core.run.toolprobe import ToolInfo


@pytest.fixture
def describe_tool_probes(monkeypatch):
    """Keep version startup out of tests of target facts and report rendering.

    Readiness decisions remain real. Dedicated readiness and toolprobe tests
    cover version discovery; these report tests do not require installed tools.
    """
    from packages.describe import tool_readiness

    def probe(binary, *, args, timeout):
        assert binary in {"codeql", "spatch"}, binary
        return ToolInfo(name=binary, path=f"/fixture/bin/{binary}", args=args,
                        returncode=0, stdout=f"{binary} 1.2.3\n")

    monkeypatch.setattr(tool_readiness, "probe", probe)
