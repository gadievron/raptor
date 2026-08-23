"""Safety pins for the sca YAML loaders (S506 triage).

All sca YAML parsing runs over scanned-repo content — action.yml
bodies, k8s manifests, compose files, the repo-shipped bump policy —
i.e. attacker-writable input inside a security scanner. Each loader is
safe by construction today (``CSafeLoader``/``SafeLoader`` only, never
the full ``Loader``/``UnsafeLoader``), which makes ``yaml.load`` unable
to instantiate arbitrary Python objects. These tests pin that property
so a future edit cannot silently downgrade any of the three loaders to
an unsafe one.

Outcome-equivalence is NOT enough to detect a downgrade: an unsafe
loader EXECUTES ``!!python/object/apply:os.system [...]`` and the
document then constructs to ``0`` (an int), which fails the callers'
downstream ``isinstance(..., dict)`` shape checks — the function still
returns None / the default AFTER the code ran. So the gha/policy tests
assert the refusal MECHANISM instead: an execution sentinel that must
NOT be created, plus the parse-refusal log line that only the
safe-loader ConstructorError path emits. Under a loader downgrade both
assertions fail; under the safe loaders both hold.
"""

from __future__ import annotations

import pytest

yaml = pytest.importorskip("yaml")

from packages.sca import _yaml_fast  # noqa: E402
from packages.sca.bump.gha_action_image import _parse_docker_action_image  # noqa: E402
from packages.sca.bump.policy import BumpPolicy, load_policy  # noqa: E402

# Classic arbitrary-code payload: full/unsafe loaders would call
# os.system("true") during construction; safe loaders raise
# ConstructorError ("could not determine a constructor for the tag").
_EXPLOIT_DOC = '!!python/object/apply:os.system ["true"]\n'


class TestYamlFastShim:
    """packages/sca/_yaml_fast — the shared safe_load shim."""

    def test_loader_is_a_safe_loader(self):
        safe_bases = (yaml.SafeLoader,) + (
            (yaml.CSafeLoader,) if hasattr(yaml, "CSafeLoader") else ()
        )
        assert issubclass(_yaml_fast._Loader, safe_bases)

    def test_safe_load_refuses_python_object_tags(self):
        with pytest.raises(yaml.YAMLError):
            _yaml_fast.safe_load(_EXPLOIT_DOC)

    def test_safe_load_all_refuses_python_object_tags(self):
        with pytest.raises(yaml.YAMLError):
            list(_yaml_fast.safe_load_all(_EXPLOIT_DOC))

    def test_safe_load_plain_shapes_still_work(self):
        assert _yaml_fast.safe_load("a: [1, 2]\n") == {"a": [1, 2]}


def _sentinel_payload(tmp_path):
    """(payload_doc, sentinel_path): the payload creates the sentinel
    if — and only if — a loader actually constructs the python/object
    tag. Safe loaders refuse at construction; the sentinel existing
    means arbitrary code ran."""
    sentinel = tmp_path / "executed-sentinel"
    doc = f'!!python/object/apply:os.system ["touch {sentinel}"]\n'
    return doc, sentinel


class TestGhaActionImageLoader:
    """action.yml bodies come straight from third-party action repos.

    These tests assert the refusal MECHANISM, not just the outcome:
    under an unsafe-loader downgrade the function still returns None
    (the constructed int fails the shape checks) but only after the
    payload executed — so outcome-only assertions would pass. The
    sentinel and the parse-refusal log line both fail on a downgrade.
    """

    def test_python_object_payload_refused_not_executed(self, tmp_path, caplog):
        doc, sentinel = _sentinel_payload(tmp_path)
        with caplog.at_level(
            "DEBUG", logger="packages.sca.bump.gha_action_image",
        ):
            assert _parse_docker_action_image(doc) is None
        # Mechanism 1: the payload must never run.
        assert not sentinel.exists(), (
            "python/object payload EXECUTED — loader downgraded?"
        )
        # Mechanism 2: refusal happens at parse time (ConstructorError
        # → the parse-failed debug line). An unsafe loader parses fine
        # and returns None later, without this line.
        assert any(
            "parse failed" in r.getMessage() for r in caplog.records
        )

    def test_python_object_inside_runs_refused_not_executed(self, tmp_path, caplog):
        sentinel = tmp_path / "executed-sentinel"
        doc = (
            "runs:\n"
            "  using: docker\n"
            f'  image: !!python/object/apply:os.system ["touch {sentinel}"]\n'
        )
        with caplog.at_level(
            "DEBUG", logger="packages.sca.bump.gha_action_image",
        ):
            assert _parse_docker_action_image(doc) is None
        assert not sentinel.exists(), (
            "python/object payload EXECUTED — loader downgraded?"
        )
        assert any(
            "parse failed" in r.getMessage() for r in caplog.records
        )

    def test_plain_docker_action_still_parses(self):
        doc = (
            "runs:\n"
            "  using: docker\n"
            "  image: docker://ghcr.io/acme/tool:1.2.3\n"
        )
        assert _parse_docker_action_image(doc) == "ghcr.io/acme/tool:1.2.3"


class TestBumpPolicyLoader:
    """.raptor-sca-bump.yml is attacker-writable on untrusted repos.

    Mechanism-asserting for the same reason as the gha tests: an unsafe
    loader also yields the default policy (the constructed int fails
    the top-level-mapping check) — after executing the payload and via
    the "not a mapping" warning instead of the parse-refusal one.
    """

    def test_python_object_payload_refused_not_executed(self, tmp_path, caplog):
        doc, sentinel = _sentinel_payload(tmp_path)
        (tmp_path / ".raptor-sca-bump.yml").write_text(doc, encoding="utf-8")
        with caplog.at_level("WARNING", logger="packages.sca.bump.policy"):
            policy = load_policy(tmp_path, trust_repo=True)
        # Refused at parse time even on a trusted run: default policy.
        assert policy == BumpPolicy()
        # Mechanism 1: the payload must never run.
        assert not sentinel.exists(), (
            "python/object payload EXECUTED — loader downgraded?"
        )
        # Mechanism 2: the SAFE loader refuses at parse ("malformed
        # YAML", the yaml.YAMLError branch). An unsafe loader instead
        # constructs an int and warns "top-level is not a mapping".
        messages = [r.getMessage() for r in caplog.records]
        assert any("malformed YAML" in m for m in messages)
        assert not any("not a mapping" in m for m in messages)
