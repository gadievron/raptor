"""Trust gate on the repo-shipped ``.raptor-sca-bump.yml``.

The policy file lives inside the scanned repo — on an untrusted run
its ``skip:`` rules and loosened thresholds are attacker-writable and
can hide the repo's own outdated-pin findings. The whole file must be
honoured only with repo trust, matching the scan-side suppression
overlay's gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from packages.sca.bump.policy import BumpPolicy, load_policy  # noqa: E402

_POLICY = """\
skip:
  - locator: actions/checkout
    reason: "hide me"
thresholds:
  rapid_release_days: 1
binary_capability_delta: true
"""


def _write_policy(target: Path) -> None:
    (target / ".raptor-sca-bump.yml").write_text(_POLICY, encoding="utf-8")


def test_untrusted_run_ignores_repo_policy(tmp_path, caplog):
    _write_policy(tmp_path)
    with caplog.at_level("WARNING", logger="packages.sca.bump.policy"):
        policy = load_policy(tmp_path, trust_repo=False)
    # Whole file ignored: default policy.
    assert policy == BumpPolicy()
    assert not policy.skip
    assert policy.thresholds == BumpPolicy().thresholds
    assert policy.binary_capability_delta_enabled is False
    # Loud, with the opt-in named.
    warnings = [r.getMessage() for r in caplog.records]
    assert any("not repo-trusted" in w and "--trust-repo" in w
               for w in warnings)


def test_trusted_run_honours_repo_policy(tmp_path):
    _write_policy(tmp_path)
    policy = load_policy(tmp_path, trust_repo=True)
    assert len(policy.skip) == 1
    assert policy.skip[0].locator == "actions/checkout"
    assert policy.thresholds.rapid_release_days == 1
    assert policy.binary_capability_delta_enabled is True


def test_no_policy_file_default_without_warning(tmp_path, caplog):
    with caplog.at_level("WARNING", logger="packages.sca.bump.policy"):
        policy = load_policy(tmp_path, trust_repo=False)
    assert policy == BumpPolicy()
    assert not caplog.records
