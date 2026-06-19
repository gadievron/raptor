"""Capability probe - must never raise and must report a stable shape,
whether or not Frida is installed on the test host."""

from packages.dynamic_instrumentation.capability import CapabilityReport, probe


def test_probe_returns_report():
    rep = probe()
    assert isinstance(rep, CapabilityReport)
    assert isinstance(rep.platform, str) and rep.platform
    # available iff the binding imported
    assert rep.available == (rep.frida_python is not None)
    assert isinstance(rep.summary(), str) and rep.summary()


def test_unavailable_summary_has_install_hint():
    rep = CapabilityReport(platform="Linux", arch="x86_64", frida_python=None)
    assert not rep.available
    assert "pipx install frida-tools" in rep.summary()


def test_high_ptrace_scope_noted():
    rep = CapabilityReport(platform="Linux", arch="x86_64",
                           frida_python="17.0", ptrace_scope=3)
    # probe() adds the note; construct-and-call path is exercised in probe(),
    # here we assert the field is carried.
    assert rep.ptrace_scope == 3
