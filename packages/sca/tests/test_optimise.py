"""Tests for ``packages.sca.optimise`` (the ``raptor-sca fix`` subcommand)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from packages.sca import optimise
from packages.sca.update import _PlanEntry, UpgradeChange
from packages.sca.versions import VersionError


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _vuln_row(
    *,
    ecosystem: str = "PyPI",
    name: str = "requests",
    version: str = "2.25.0",
    fixed_version: str = "2.28.0",
    manifest: str = "/project/requirements.txt",
    advisory_id: str = "GHSA-x",
    pin_style: str = "exact",
) -> dict:
    return {
        "vuln_type": "sca:vulnerable_dependency",
        "tool": "sca",
        "file": manifest,
        "function": name,
        "severity": "high",
        "sca": {
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "pin_style": pin_style,
            "is_lockfile": False,
            "fixed_version": fixed_version,
            "advisory": {
                "id": advisory_id,
                "aliases": [],
                "fixed_versions": [fixed_version],
            },
        },
    }


def _hygiene_row(
    *,
    kind: str = "unpinned_dependency",
    ecosystem: str = "PyPI",
    name: str = "flask",
    version: str = "2.3.0",
    manifest: str = "/project/requirements.txt",
    pin_style: str = "unknown",
    is_lockfile: bool = False,
) -> dict:
    return {
        "vuln_type": f"sca:hygiene:{kind}",
        "tool": "sca",
        "file": manifest,
        "function": name,
        "severity": "info",
        "sca": {
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "pin_style": pin_style,
            "is_lockfile": is_lockfile,
            "kind": kind,
        },
    }


# ---------------------------------------------------------------------------
# _plan_hygiene_pins
# ---------------------------------------------------------------------------

class TestPlanHygienePins:
    def test_basic_unpinned(self):
        rows = [_hygiene_row()]
        plans = optimise._plan_hygiene_pins(rows, vuln_plans={})
        assert len(plans) == 1
        key = ("PyPI", "flask", "/project/requirements.txt")
        assert key in plans
        assert plans[key].target == "2.3.0"
        assert plans[key].advisory_ids == []

    def test_loose_pin(self):
        rows = [_hygiene_row(kind="loose_pin", pin_style="tilde")]
        plans = optimise._plan_hygiene_pins(rows, vuln_plans={})
        assert len(plans) == 1

    def test_skips_lockfile(self):
        rows = [_hygiene_row(is_lockfile=True)]
        plans = optimise._plan_hygiene_pins(rows, vuln_plans={})
        assert len(plans) == 0

    def test_skips_deps_with_vuln_plan(self):
        rows = [_hygiene_row()]
        vuln_plans = {
            ("PyPI", "flask", "/project/requirements.txt"): _PlanEntry(
                ecosystem="PyPI", name="flask",
                installed="2.3.0", target="2.3.1",
                manifest=Path("/project/requirements.txt"),
                advisory_ids=["GHSA-y"],
            ),
        }
        plans = optimise._plan_hygiene_pins(rows, vuln_plans)
        assert len(plans) == 0

    def test_skips_non_hygiene_findings(self):
        rows = [_vuln_row()]
        plans = optimise._plan_hygiene_pins(rows, vuln_plans={})
        assert len(plans) == 0

    def test_skips_irrelevant_hygiene_kinds(self):
        rows = [_hygiene_row(kind="lockfile_missing")]
        plans = optimise._plan_hygiene_pins(rows, vuln_plans={})
        assert len(plans) == 0

    def test_deduplicates(self):
        rows = [
            _hygiene_row(kind="unpinned_dependency"),
            _hygiene_row(kind="loose_pin"),
        ]
        plans = optimise._plan_hygiene_pins(rows, vuln_plans={})
        assert len(plans) == 1

    def test_multiple_manifests(self):
        rows = [
            _hygiene_row(manifest="/a/requirements.txt"),
            _hygiene_row(manifest="/b/requirements.txt"),
        ]
        plans = optimise._plan_hygiene_pins(rows, vuln_plans={})
        assert len(plans) == 2

    def test_cross_manifest_cve_propagation(self):
        """If pytest@7.0.0 has a CVE fix in manifest A, a hygiene-only
        pin in manifest B should adopt the fix version, not pin to 7.0.0."""
        rows = [
            _hygiene_row(
                name="pytest", version="7.0.0",
                manifest="/b/requirements-dev.txt",
                kind="loose_pin", pin_style="range",
            ),
        ]
        vuln_plans = {
            ("PyPI", "pytest", "/a/requirements.txt"): _PlanEntry(
                ecosystem="PyPI", name="pytest",
                installed="7.0.0", target="9.0.3",
                manifest=Path("/a/requirements.txt"),
                advisory_ids=["GHSA-x"],
            ),
        }
        plans = optimise._plan_hygiene_pins(rows, vuln_plans)
        assert len(plans) == 1
        key = ("PyPI", "pytest", "/b/requirements-dev.txt")
        assert plans[key].target == "9.0.3"
        assert plans[key].advisory_ids == ["GHSA-x"]

    def test_cross_manifest_inconsistency_pins_all_to_highest(self):
        """``cross_manifest_inconsistency`` finding triggers a sweep:
        every manifest pinning that ``(ecosystem, name)`` gets a
        rewrite plan to the highest version found across all of them.
        """
        # Three manifests pin requests at different versions. SCA
        # surfaces the conflict on one of them (the "primary" file).
        rows = [
            # The cross-manifest finding itself, anchored to the
            # primary manifest with version 2.31.0.
            {
                "vuln_type": "sca:hygiene:cross_manifest_inconsistency",
                "file": "/project/requirements.txt",
                "function": "requests",
                "severity": "medium",
                "sca": {
                    "ecosystem": "PyPI", "name": "requests",
                    "version": "2.31.0", "pin_style": "exact",
                    "is_lockfile": False,
                    "kind": "cross_manifest_inconsistency",
                },
            },
            # Sibling rows that establish the per-manifest versions
            # (these rows might be vuln findings, hygiene findings, or
            # plain dep-presence findings — the planner sees them all).
            _hygiene_row(name="requests", version="2.31.0",
                          manifest="/project/requirements.txt",
                          kind="loose_pin"),
            _hygiene_row(name="requests", version="2.31",
                          manifest="/project/packages/web/requirements.txt",
                          kind="loose_pin"),
            _hygiene_row(name="requests", version="2.33.1",
                          manifest="/project/requirements-dev.txt",
                          kind="loose_pin"),
        ]
        plans = optimise._plan_hygiene_pins(rows, vuln_plans={})
        # Expect 3 plans (one per manifest), all targeting 2.33.1.
        request_plans = [p for k, p in plans.items() if k[1] == "requests"]
        assert len(request_plans) == 3, (
            f"expected 3 requests plans, got {len(request_plans)}: "
            f"{[(p.manifest.name, p.target) for p in request_plans]}"
        )
        for p in request_plans:
            assert p.target == "2.33.1", \
                f"plan for {p.manifest} targets {p.target}, not 2.33.1"

    def test_cross_manifest_inconsistency_skipped_when_only_one_location(self):
        """Defensive: if the finding fires but only one manifest is
        actually visible in the findings list, don't synthesise a
        single-manifest fake conflict."""
        rows = [
            {
                "vuln_type": "sca:hygiene:cross_manifest_inconsistency",
                "file": "/project/requirements.txt",
                "function": "requests",
                "severity": "medium",
                "sca": {
                    "ecosystem": "PyPI", "name": "requests",
                    "version": "2.31.0", "pin_style": "exact",
                    "is_lockfile": False,
                    "kind": "cross_manifest_inconsistency",
                },
            },
        ]
        plans = optimise._plan_hygiene_pins(rows, vuln_plans={})
        assert plans == {}

    def test_cross_manifest_no_propagation_different_version(self):
        """CVE propagation only applies when installed versions match."""
        rows = [
            _hygiene_row(
                name="pytest", version="8.0.0",
                manifest="/b/requirements.txt",
                kind="loose_pin",
            ),
        ]
        vuln_plans = {
            ("PyPI", "pytest", "/a/requirements.txt"): _PlanEntry(
                ecosystem="PyPI", name="pytest",
                installed="7.0.0", target="9.0.3",
                manifest=Path("/a/requirements.txt"),
                advisory_ids=["GHSA-x"],
            ),
        }
        plans = optimise._plan_hygiene_pins(rows, vuln_plans)
        assert len(plans) == 1
        key = ("PyPI", "pytest", "/b/requirements.txt")
        assert plans[key].target == "8.0.0"
        assert plans[key].advisory_ids == []


# ---------------------------------------------------------------------------
# _pin_bare_requirements
# ---------------------------------------------------------------------------

class TestPinBareRequirements:
    def _plan(self, name="flask", version="2.3.0"):
        return _PlanEntry(
            ecosystem="PyPI", name=name,
            installed=version, target=version,
            manifest=Path("/project/requirements.txt"),
            advisory_ids=[],
        )

    def test_bare_name(self):
        text = "flask\nrequests==2.28.0\n"
        new, applied, reason = optimise._pin_bare_requirements(
            text, self._plan(),
        )
        assert applied
        assert "flask==2.3.0" in new
        assert "requests==2.28.0" in new

    def test_bare_name_case_insensitive(self):
        text = "Flask\n"
        new, applied, _ = optimise._pin_bare_requirements(
            text, self._plan(),
        )
        assert applied
        assert "Flask==2.3.0" in new

    def test_bare_name_with_comment(self):
        text = "flask  # web framework\n"
        new, applied, _ = optimise._pin_bare_requirements(
            text, self._plan(),
        )
        assert applied
        assert "flask==2.3.0" in new
        assert "# web framework" in new

    def test_already_pinned_not_matched(self):
        text = "flask==2.3.0\n"
        new, applied, _ = optimise._pin_bare_requirements(
            text, self._plan(),
        )
        assert not applied

    def test_normalised_name(self):
        text = "my-package\n"
        new, applied, _ = optimise._pin_bare_requirements(
            text, self._plan(name="my_package", version="1.0.0"),
        )
        assert applied
        assert "my-package==1.0.0" in new

    def test_preserves_other_lines(self):
        text = "# comment\nflask\nrequests==2.28.0\n-r other.txt\n"
        new, applied, _ = optimise._pin_bare_requirements(
            text, self._plan(),
        )
        assert applied
        assert "# comment" in new
        assert "requests==2.28.0" in new
        assert "-r other.txt" in new


# ---------------------------------------------------------------------------
# _pin_bare_package_json
# ---------------------------------------------------------------------------

class TestPinBarePackageJson:
    def _plan(self, name="lodash", version="4.17.21"):
        return _PlanEntry(
            ecosystem="npm", name=name,
            installed=version, target=version,
            manifest=Path("/project/package.json"),
            advisory_ids=[],
        )

    def test_wildcard(self):
        text = '{\n  "dependencies": {\n    "lodash": "*"\n  }\n}'
        new, applied, _ = optimise._pin_bare_package_json(
            text, self._plan(),
        )
        assert applied
        assert '"lodash": "4.17.21"' in new

    def test_latest(self):
        text = '{"dependencies": {"lodash": "latest"}}'
        new, applied, _ = optimise._pin_bare_package_json(
            text, self._plan(),
        )
        assert applied
        assert '"lodash": "4.17.21"' in new

    def test_empty_string(self):
        text = '{"dependencies": {"lodash": ""}}'
        new, applied, _ = optimise._pin_bare_package_json(
            text, self._plan(),
        )
        assert applied
        assert '"lodash": "4.17.21"' in new

    def test_semver_not_matched(self):
        text = '{"dependencies": {"lodash": "^4.17.0"}}'
        new, applied, _ = optimise._pin_bare_package_json(
            text, self._plan(),
        )
        assert not applied


# ---------------------------------------------------------------------------
# _pin_bare_pyproject
# ---------------------------------------------------------------------------

class TestPinBarePyproject:
    def _plan(self, name="flask", version="2.3.0"):
        return _PlanEntry(
            ecosystem="PyPI", name=name,
            installed=version, target=version,
            manifest=Path("/project/pyproject.toml"),
            advisory_ids=[],
        )

    def test_pep621_bare(self):
        text = '[project]\ndependencies = [\n    "flask",\n    "requests>=2.28",\n]\n'
        new, applied, _ = optimise._pin_bare_pyproject(
            text, self._plan(),
        )
        assert applied
        assert '"flask==2.3.0"' in new
        assert '"requests>=2.28"' in new

    def test_single_quote(self):
        text = "[project]\ndependencies = [\n    'flask',\n]\n"
        new, applied, _ = optimise._pin_bare_pyproject(
            text, self._plan(),
        )
        assert applied
        assert "'flask==2.3.0'" in new

    def test_already_versioned_not_matched(self):
        text = '[project]\ndependencies = [\n    "flask>=2.0",\n]\n'
        new, applied, _ = optimise._pin_bare_pyproject(
            text, self._plan(),
        )
        assert not applied


# ---------------------------------------------------------------------------
# _materialise_pin_changes
# ---------------------------------------------------------------------------

class TestMaterialisePinChanges:
    def test_requirements_loose_pin(self, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("flask~=2.3.0\nrequests==2.28.0\n")

        plans = {
            ("PyPI", "flask", str(manifest)): _PlanEntry(
                ecosystem="PyPI", name="flask",
                installed="2.3.0", target="2.3.0",
                manifest=manifest,
                advisory_ids=[],
            ),
        }
        proposed = tmp_path / "proposed"
        changes = optimise._materialise_pin_changes(plans, proposed)
        assert len(changes) == 1
        assert changes[0].skipped_reason is None

        # Out-of-cwd manifests stage under the shared disambiguated
        # anchor (same scheme as the CVE-fix phase).
        from packages.sca.update import _proposed_rel_path
        result = (proposed / _proposed_rel_path(manifest)).read_text()
        assert "flask==2.3.0" in result
        assert "requests==2.28.0" in result

    def test_requirements_bare_name(self, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("flask\n")

        plans = {
            ("PyPI", "flask", str(manifest)): _PlanEntry(
                ecosystem="PyPI", name="flask",
                installed="2.3.0", target="2.3.0",
                manifest=manifest,
                advisory_ids=[],
            ),
        }
        proposed = tmp_path / "proposed"
        changes = optimise._materialise_pin_changes(plans, proposed)
        assert len(changes) == 1
        assert changes[0].skipped_reason is None

        # Out-of-cwd manifests stage under the shared disambiguated
        # anchor (same scheme as the CVE-fix phase).
        from packages.sca.update import _proposed_rel_path
        result = (proposed / _proposed_rel_path(manifest)).read_text()
        assert "flask==2.3.0" in result

    def test_package_json_caret(self, tmp_path):
        manifest = tmp_path / "package.json"
        manifest.write_text(json.dumps({
            "dependencies": {"lodash": "^4.17.0"},
        }, indent=2))

        plans = {
            ("npm", "lodash", str(manifest)): _PlanEntry(
                ecosystem="npm", name="lodash",
                installed="4.17.0", target="4.17.0",
                manifest=manifest,
                advisory_ids=[],
            ),
        }
        proposed = tmp_path / "proposed"
        changes = optimise._materialise_pin_changes(plans, proposed)
        # The standard rewriter replaces ^4.17.0 with ^4.17.0 (same ver)
        # which is a no-op text change. Falls through to bare-name
        # pinner which also won't match. Expected: skipped.
        assert len(changes) == 1


# ---------------------------------------------------------------------------
# _render_optimise_markdown
# ---------------------------------------------------------------------------

class TestRenderOptimiseMarkdown:
    def test_mixed_changes(self):
        changes = [
            UpgradeChange("PyPI", "requests", "2.25.0", "2.28.0",
                          Path("/r.txt"), ("GHSA-x",)),
            UpgradeChange("PyPI", "flask", "2.3.0", "2.3.0",
                          Path("/r.txt"), ()),
            UpgradeChange("npm", "lodash", "4.17.0", "4.17.0",
                          Path("/p.json"), (),
                          skipped_reason="no match"),
        ]
        md = optimise._render_optimise_markdown(changes)
        assert "CVE Fixes" in md
        assert "Pins Tightened" in md
        assert "Skipped" in md
        assert "CVE fixes: **1**" in md
        assert "Pins tightened: **1**" in md
        assert "Skipped: **1**" in md

    def test_only_vuln(self):
        changes = [
            UpgradeChange("PyPI", "requests", "2.25.0", "2.28.0",
                          Path("/r.txt"), ("GHSA-x",)),
        ]
        md = optimise._render_optimise_markdown(changes)
        assert "CVE Fixes" in md
        assert "Pins Tightened" not in md


# ---------------------------------------------------------------------------
# CLI dispatch
# ---------------------------------------------------------------------------

class TestCliDispatch:
    def test_fix_in_subcommands(self):
        from packages.sca.cli import _SUBCOMMANDS
        assert "fix" in _SUBCOMMANDS

    def test_dispatch_routes(self):
        from packages.sca.cli import _split_subcommand
        sub, rest = _split_subcommand(["fix", "/path"])
        assert sub == "fix"
        assert rest == ["/path"]

    def test_fix_default_routes_to_optimise(self):
        from packages.sca.cli import _dispatch_fix
        from unittest.mock import patch
        with patch("packages.sca.optimise.main", return_value=0) as m:
            _dispatch_fix(["/path"])
            m.assert_called_once_with(["/path"])

    def test_fix_cve_only_routes_to_update(self):
        from packages.sca.cli import _dispatch_fix
        from unittest.mock import patch
        with patch("packages.sca.update.main", return_value=0) as m:
            _dispatch_fix(["--cve-only", "--findings", "/f.json"])
            m.assert_called_once_with(["--findings", "/f.json"])

    def test_fix_cve_only_positional_target(self):
        """Positional target is translated to --target for update.py."""
        from packages.sca.cli import _dispatch_fix
        from unittest.mock import patch
        with patch("packages.sca.update.main", return_value=0) as m:
            _dispatch_fix(["/path/to/project", "--cve-only"])
            m.assert_called_once_with(["--target", "/path/to/project"])

    def test_fix_findings_implies_cve_only(self):
        """--findings without --cve-only routes to update.py."""
        from packages.sca.cli import _dispatch_fix
        from unittest.mock import patch
        with patch("packages.sca.update.main", return_value=0) as m:
            _dispatch_fix(["--findings", "/f.json"])
            m.assert_called_once_with(["--findings", "/f.json"])

    def test_fix_cve_only_harden_mutual_exclusion(self):
        from packages.sca.cli import _dispatch_fix
        rc = _dispatch_fix(["--cve-only", "--harden", "/path"])
        assert rc == 2

    def test_fix_cve_only_preserves_other_flags(self):
        """--allow-major and --out survive positional translation."""
        from packages.sca.cli import _dispatch_fix
        from unittest.mock import patch
        with patch("packages.sca.update.main", return_value=0) as m:
            _dispatch_fix(["/path", "--cve-only", "--allow-major", "--out", "./out"])
            args = m.call_args[0][0]
            assert "--target" in args
            assert "/path" in args
            assert "--allow-major" in args
            assert "--out" in args
            assert "./out" in args

    def test_fix_findings_with_positional_drops_positional(self):
        """fix /path --findings /f.json drops the positional (--findings wins)."""
        from packages.sca.cli import _dispatch_fix
        from unittest.mock import patch
        with patch("packages.sca.update.main", return_value=0) as m:
            _dispatch_fix(["/path", "--findings", "/f.json"])
            args = m.call_args[0][0]
            assert "--findings" in args
            assert "/path" not in args

    def test_positional_to_target_flag_empty(self):
        from packages.sca.cli import _positional_to_target_flag
        assert _positional_to_target_flag([]) == []

    def test_positional_to_target_flag_only_flags(self):
        from packages.sca.cli import _positional_to_target_flag
        result = _positional_to_target_flag(["--allow-major", "--out", "."])
        assert "--target" not in result

    def test_positional_to_target_flag_format_value_not_target(self):
        """``--format``'s value must not be mistaken for the positional
        target."""
        from packages.sca.cli import _positional_to_target_flag
        result = _positional_to_target_flag(
            ["--format", "pr-comment", "/path"])
        assert result == ["--format", "pr-comment", "--target", "/path"]

    def test_positional_to_target_flag_validate_against_value_not_target(self):
        from packages.sca.cli import _positional_to_target_flag
        result = _positional_to_target_flag(
            ["--validate-against", "pkg.json", "/path"])
        assert result == ["--validate-against", "pkg.json",
                          "--target", "/path"]

    def test_fix_harden_routes_to_harden(self):
        from packages.sca.cli import _dispatch_fix
        from unittest.mock import patch
        with patch("packages.sca.harden.main", return_value=0) as m:
            _dispatch_fix(["/path", "--harden"])
            m.assert_called_once_with(["/path"])


# ---------------------------------------------------------------------------
# _parse_args
# ---------------------------------------------------------------------------

class TestParseArgs:
    def test_basic(self):
        args = optimise._parse_args(["/path/to/project"])
        assert args.target == "/path/to/project"
        assert not args.allow_major
        assert not args.git_patch
        assert not args.apply
        assert not args.no_llm
        assert args.out is None

    def test_no_llm_flag(self):
        args = optimise._parse_args(["/path", "--no-llm"])
        assert args.no_llm

    def test_apply_flag(self):
        args = optimise._parse_args(["/path", "--apply"])
        assert args.apply

    def test_out_flag(self):
        args = optimise._parse_args(["/path", "--out", "./out"])
        assert args.out == "./out"

    def test_all_flags(self):
        args = optimise._parse_args([
            "/path", "--apply", "--allow-major", "--git-patch",
            "--offline", "--no-cache", "--cache-root", "./cache",
            "-vv",
        ])
        assert args.allow_major
        assert args.git_patch
        assert args.apply
        assert args.offline
        assert args.no_cache
        assert args.cache_root == "./cache"
        assert args.verbose == 2

    def test_no_hash_pin_flag_default_off(self):
        """Default behaviour is to hash-pin GHA refs when drift findings
        are present; ``--no-hash-pin`` opts out."""
        args = optimise._parse_args(["/path"])
        assert args.no_hash_pin is False

    def test_no_hash_pin_flag_set(self):
        args = optimise._parse_args(["/path", "--no-hash-pin"])
        assert args.no_hash_pin is True


class TestHashPinAutoTrigger:
    """``fix`` runs hash_pin_workflows automatically when drift findings
    are present, unless ``--no-hash-pin`` is set."""

    def test_invokes_hash_pin_when_drift_findings_present(
        self, tmp_path, monkeypatch,
    ):
        """When findings.json has a gha_action_ref_drift row,
        ``hash_pin_workflows`` is called against the target."""
        from packages.sca import optimise as opt
        from packages.sca.hash_pin import HashPinResult

        captured = {}
        def fake_hash_pin(target, *, write):
            captured["target"] = target
            captured["write"] = write
            return HashPinResult(changed_files=[], changes=[], skipped=[])

        monkeypatch.setattr(
            "packages.sca.hash_pin.hash_pin_workflows", fake_hash_pin,
        )

        # Stub the rest of the pipeline to focus on the hash-pin trigger.
        target = tmp_path / "repo"
        target.mkdir()
        (target / "package.json").write_text(
            '{"dependencies": {}}', encoding="utf-8",
        )
        out = tmp_path / "out"
        out.mkdir()

        # Synthesise findings with one gha_action_ref_drift row.
        findings = [
            {
                "vuln_type": "sca:supply_chain:gha_action_ref_drift",
                "file": str(target / ".github/workflows/test.yml"),
                "function": "actions/checkout",
                "severity": "low",
                "sca": {
                    "ecosystem": "Inline", "name": "<github-actions>",
                    "version": "v6", "is_lockfile": False,
                },
            },
        ]

        from packages.sca.pipeline import RunResult
        def fake_run_sca(**kw):
            kw["output_dir"].mkdir(parents=True, exist_ok=True)
            (kw["output_dir"] / "findings.json").write_text(
                __import__("json").dumps(findings), encoding="utf-8",
            )
            return RunResult(
                target=kw["target"], output_dir=kw["output_dir"],
                deps_analysed=0, vuln_findings=0, in_kev=0,
                supply_chain_findings=1, hygiene_findings=0,
                suppressed_findings=0,
                cache_hits=0, cache_misses=0,
                llm_reviews_run=0, llm_reviews_failed=0,
                triage_run=False, llm_cost=0.0,
                findings_path=kw["output_dir"] / "findings.json",
                report_path=kw["output_dir"] / "report.md",
                sbom_path=kw["output_dir"] / "sbom.cdx.json",
                sarif_path=kw["output_dir"] / "findings.sarif",
                transitive_added=0, transitive_statuses=[],
            )
        monkeypatch.setattr(
            "packages.sca.pipeline.run_sca", fake_run_sca,
        )

        opt.main([str(target), "--out", str(out)])
        assert captured.get("target") == target
        assert captured.get("write") is False, "plan-only mode → write=False"

    def test_no_hash_pin_flag_skips_invocation(
        self, tmp_path, monkeypatch,
    ):
        """``--no-hash-pin`` prevents the auto-trigger even with drift."""
        from packages.sca import optimise as opt
        from packages.sca.hash_pin import HashPinResult

        called = []
        def fake_hash_pin(target, *, write):
            called.append(target)
            return HashPinResult(changed_files=[], changes=[], skipped=[])
        monkeypatch.setattr(
            "packages.sca.hash_pin.hash_pin_workflows", fake_hash_pin,
        )

        target = tmp_path / "repo"
        target.mkdir()
        (target / "package.json").write_text(
            '{"dependencies": {}}', encoding="utf-8",
        )
        out = tmp_path / "out"
        out.mkdir()

        findings = [{
            "vuln_type": "sca:supply_chain:gha_action_ref_drift",
            "file": str(target), "function": "x", "severity": "low",
            "sca": {"ecosystem": "Inline", "name": "x",
                     "version": "v1", "is_lockfile": False},
        }]
        from packages.sca.pipeline import RunResult
        def fake_run_sca(**kw):
            kw["output_dir"].mkdir(parents=True, exist_ok=True)
            (kw["output_dir"] / "findings.json").write_text(
                __import__("json").dumps(findings), encoding="utf-8",
            )
            return RunResult(
                target=kw["target"], output_dir=kw["output_dir"],
                deps_analysed=0, vuln_findings=0, in_kev=0,
                supply_chain_findings=1, hygiene_findings=0,
                suppressed_findings=0,
                cache_hits=0, cache_misses=0,
                llm_reviews_run=0, llm_reviews_failed=0,
                triage_run=False, llm_cost=0.0,
                findings_path=kw["output_dir"] / "findings.json",
                report_path=kw["output_dir"] / "report.md",
                sbom_path=kw["output_dir"] / "sbom.cdx.json",
                sarif_path=kw["output_dir"] / "findings.sarif",
                transitive_added=0, transitive_statuses=[],
            )
        monkeypatch.setattr(
            "packages.sca.pipeline.run_sca", fake_run_sca,
        )

        opt.main([str(target), "--out", str(out), "--no-hash-pin"])
        assert called == [], "hash_pin should not be called when --no-hash-pin"


class TestPlanOutput:
    def test_prints_plan(self, capsys):
        vuln_plans = {
            ("PyPI", "requests", "/r.txt"): _PlanEntry(
                ecosystem="PyPI", name="requests",
                installed="2.25.0", target="2.28.0",
                manifest=Path("/r.txt"),
                advisory_ids=["GHSA-x"],
            ),
        }
        hygiene_plans = {
            ("PyPI", "flask", "/r.txt"): _PlanEntry(
                ecosystem="PyPI", name="flask",
                installed="2.3.0", target="2.3.0",
                manifest=Path("/r.txt"),
                advisory_ids=[],
            ),
        }
        optimise._print_dry_run(vuln_plans, hygiene_plans)
        out = capsys.readouterr().out
        assert "2 change(s) planned" in out
        assert "1 CVE" in out
        assert "1 pin" in out
        assert "requests" in out
        assert "GHSA-x" in out
        assert "flask" in out
        assert "r.txt" in out
        assert "--apply" in out

    def test_groups_by_manifest(self, capsys):
        vuln_plans = {}
        hygiene_plans = {
            ("PyPI", "flask", "/a/requirements.txt"): _PlanEntry(
                ecosystem="PyPI", name="flask",
                installed="2.3.0", target="2.3.0",
                manifest=Path("/a/requirements.txt"),
                advisory_ids=[],
            ),
            ("PyPI", "django", "/b/requirements.txt"): _PlanEntry(
                ecosystem="PyPI", name="django",
                installed="4.2.0", target="4.2.0",
                manifest=Path("/b/requirements.txt"),
                advisory_ids=[],
            ),
        }
        optimise._print_dry_run(vuln_plans, hygiene_plans)
        out = capsys.readouterr().out
        lines = out.splitlines()
        manifest_lines = [line for line in lines
                          if "requirements.txt" in line
                          and "==" not in line]
        assert len(manifest_lines) == 2

    def test_major_blocked_warning(self, capsys):
        vuln_plans = {}
        hygiene_plans = {}
        major_blocked = {
            ("PyPI", "pytest", "/r.txt"): _PlanEntry(
                ecosystem="PyPI", name="pytest",
                installed="7.0.0", target="9.0.3",
                manifest=Path("/r.txt"),
                advisory_ids=["GHSA-y"],
            ),
        }
        optimise._print_dry_run(vuln_plans, hygiene_plans, major_blocked)
        out = capsys.readouterr().out
        assert "blocked" in out
        assert "major version" in out
        assert "pytest" in out
        assert "7.0.0" in out
        assert "9.0.3" in out
        assert "--allow-major" in out

    def test_llm_approved_annotation(self, capsys):
        key = ("PyPI", "pytest", "/r.txt")
        vuln_plans = {
            key: _PlanEntry(
                ecosystem="PyPI", name="pytest",
                installed="7.0.0", target="9.0.3",
                manifest=Path("/r.txt"),
                advisory_ids=["GHSA-y"],
            ),
        }
        optimise._print_dry_run(
            vuln_plans, {}, {},
            llm_approved={key}, llm_verdicts={},
        )
        out = capsys.readouterr().out
        assert "LLM: safe to bump" in out
        assert "pytest" in out
        assert "GHSA-y" in out

    def test_llm_verdict_display(self, capsys):
        from pydantic import BaseModel

        class _FakeVerdict(BaseModel):
            verdict: str = "major_migration"
            confidence: str = "high"
            summary: str = "API removed in v9"
            breaking_changes: list = []

        key = ("PyPI", "pytest", "/r.txt")
        major_blocked = {
            key: _PlanEntry(
                ecosystem="PyPI", name="pytest",
                installed="7.0.0", target="9.0.3",
                manifest=Path("/r.txt"),
                advisory_ids=["GHSA-y"],
            ),
        }
        optimise._print_dry_run(
            {}, {}, major_blocked,
            llm_verdicts={key: _FakeVerdict()},
        )
        out = capsys.readouterr().out
        assert "LLM: major migration" in out
        assert "API removed in v9" in out
        assert "blocked" in out


# ---------------------------------------------------------------------------
# _analyze_major_bumps
# ---------------------------------------------------------------------------

class TestAnalyzeMajorBumps:
    def test_no_client_returns_empty(self):
        major_blocked = {
            ("PyPI", "pytest", "/r.txt"): _PlanEntry(
                ecosystem="PyPI", name="pytest",
                installed="7.0.0", target="9.0.3",
                manifest=Path("/r.txt"),
                advisory_ids=["GHSA-y"],
            ),
        }
        vuln_plans = {}
        with patch("packages.sca.llm.get_llm_client", return_value=None):
            approved, verdicts = optimise._analyze_major_bumps(
                major_blocked, vuln_plans, Path("/project"),
            )
        assert approved == set()
        assert verdicts == {}
        assert len(major_blocked) == 1

    @pytest.mark.slow
    def test_safe_verdict_moves_to_vuln_plans(self):
        from pydantic import BaseModel

        class _SafeVerdict(BaseModel):
            verdict: str = "safe"
            confidence: str = "high"
            summary: str = "No breaking changes"
            breaking_changes: list = []

        key = ("PyPI", "pytest", "/r.txt")
        plan = _PlanEntry(
            ecosystem="PyPI", name="pytest",
            installed="7.0.0", target="9.0.3",
            manifest=Path("/r.txt"),
            advisory_ids=["GHSA-y"],
        )
        major_blocked = {key: plan}
        vuln_plans = {}

        mock_client = object()
        with patch("packages.sca.llm.get_llm_client", return_value=mock_client), \
             patch("packages.sca.llm.upgrade_impact_review.assess_upgrade_impact",
                   return_value=_SafeVerdict()):
            approved, verdicts = optimise._analyze_major_bumps(
                major_blocked, vuln_plans, Path("/project"),
                promote=True,       # the operator's --llm-approve-major
            )

        assert key in approved
        assert key in vuln_plans
        assert key not in major_blocked
        assert verdicts == {}

    def test_breaking_verdict_stays_blocked(self):
        from pydantic import BaseModel

        class _BreakingVerdict(BaseModel):
            verdict: str = "major_migration"
            confidence: str = "high"
            summary: str = "API removed"
            breaking_changes: list = []

        key = ("PyPI", "pytest", "/r.txt")
        plan = _PlanEntry(
            ecosystem="PyPI", name="pytest",
            installed="7.0.0", target="9.0.3",
            manifest=Path("/r.txt"),
            advisory_ids=["GHSA-y"],
        )
        major_blocked = {key: plan}
        vuln_plans = {}

        mock_client = object()
        with patch("packages.sca.llm.get_llm_client", return_value=mock_client), \
             patch("packages.sca.llm.upgrade_impact_review.assess_upgrade_impact",
                   return_value=_BreakingVerdict()):
            approved, verdicts = optimise._analyze_major_bumps(
                major_blocked, vuln_plans, Path("/project"),
            )

        assert approved == set()
        assert key not in vuln_plans
        assert key in major_blocked
        assert key in verdicts
        assert verdicts[key].verdict == "major_migration"

    def test_none_verdict_skipped(self):
        key = ("PyPI", "pytest", "/r.txt")
        major_blocked = {
            key: _PlanEntry(
                ecosystem="PyPI", name="pytest",
                installed="7.0.0", target="9.0.3",
                manifest=Path("/r.txt"),
                advisory_ids=["GHSA-y"],
            ),
        }
        vuln_plans = {}

        mock_client = object()
        with patch("packages.sca.llm.get_llm_client", return_value=mock_client), \
             patch("packages.sca.llm.upgrade_impact_review.assess_upgrade_impact",
                   return_value=None):
            approved, verdicts = optimise._analyze_major_bumps(
                major_blocked, vuln_plans, Path("/project"),
            )

        assert approved == set()
        assert verdicts == {}
        assert key in major_blocked

    def test_multi_dep_mixed_verdicts(self):
        """Two deps: one safe (moves), one breaking (stays blocked)."""
        from pydantic import BaseModel

        class _SafeVerdict(BaseModel):
            verdict: str = "safe"
            confidence: str = "high"
            summary: str = "No breaking changes"
            breaking_changes: list = []

        class _BreakingVerdict(BaseModel):
            verdict: str = "major_migration"
            confidence: str = "high"
            summary: str = "API removed"
            breaking_changes: list = []

        key_safe = ("PyPI", "requests", "/r.txt")
        key_break = ("npm", "lodash", "/package.json")

        major_blocked = {
            key_safe: _PlanEntry(
                ecosystem="PyPI", name="requests",
                installed="2.28.0", target="3.0.0",
                manifest=Path("/r.txt"),
                advisory_ids=["GHSA-a"],
            ),
            key_break: _PlanEntry(
                ecosystem="npm", name="lodash",
                installed="3.10.1", target="4.17.21",
                manifest=Path("/package.json"),
                advisory_ids=["GHSA-b"],
            ),
        }
        vuln_plans = {}

        verdict_map = {
            ("requests", "3.0.0"): _SafeVerdict(),
            ("lodash", "4.17.21"): _BreakingVerdict(),
        }

        def _fake_assess(client, dep, new_version, target):
            return verdict_map.get((dep.name, new_version))

        mock_client = object()
        with patch("packages.sca.llm.get_llm_client", return_value=mock_client), \
             patch("packages.sca.llm.upgrade_impact_review.assess_upgrade_impact",
                   side_effect=_fake_assess):
            approved, verdicts = optimise._analyze_major_bumps(
                major_blocked, vuln_plans, Path("/project"),
                promote=True,       # the operator's --llm-approve-major
            )

        assert key_safe in approved
        assert key_safe in vuln_plans
        assert key_safe not in major_blocked
        assert key_break not in approved
        assert key_break in major_blocked
        assert key_break in verdicts

    def test_llm_exception_isolated_per_dep(self):
        """An exception on one dep doesn't prevent processing of others."""
        from pydantic import BaseModel

        class _SafeVerdict(BaseModel):
            verdict: str = "safe"
            confidence: str = "high"
            summary: str = ""
            breaking_changes: list = []

        key_ok = ("PyPI", "ok", "/r.txt")
        key_err = ("npm", "boom", "/package.json")

        major_blocked = {
            key_err: _PlanEntry(
                ecosystem="npm", name="boom",
                installed="3.0.0", target="4.0.0",
                manifest=Path("/package.json"),
                advisory_ids=["GHSA-x"],
            ),
            key_ok: _PlanEntry(
                ecosystem="PyPI", name="ok",
                installed="1.0.0", target="2.0.0",
                manifest=Path("/r.txt"),
                advisory_ids=["GHSA-y"],
            ),
        }
        vuln_plans = {}

        def _fake_assess(client, dep, new_version, target):
            if dep.name == "boom":
                raise PermissionError("scratch dir unreadable")
            return _SafeVerdict()

        mock_client = object()
        with patch("packages.sca.llm.get_llm_client", return_value=mock_client), \
             patch("packages.sca.llm.upgrade_impact_review.assess_upgrade_impact",
                   side_effect=_fake_assess):
            approved, verdicts = optimise._analyze_major_bumps(
                major_blocked, vuln_plans, Path("/project"),
                promote=True,       # the operator's --llm-approve-major
            )

        # The successful dep should be approved despite the failure on the
        # other one.
        assert key_ok in approved
        assert key_ok in vuln_plans
        # The failing dep stays in major_blocked (treated as needs-review).
        assert key_err in major_blocked
        assert key_err not in approved


class TestVersionErrorResilience:
    def test_cross_manifest_propagation_survives_unparseable_version(self):
        """VersionError from cross-ecosystem version strings must not crash."""
        plan_a = _PlanEntry(
            ecosystem="npm", name="lodash", installed="4.17.19",
            target="BOGUS_RUBY_VERSION",
            manifest=Path("/a/package.json"), advisory_ids=["GHSA-1"],
        )
        plan_b = _PlanEntry(
            ecosystem="npm", name="lodash", installed="4.17.19",
            target="4.17.21",
            manifest=Path("/b/package.json"), advisory_ids=["GHSA-2"],
        )
        vuln_plans = {
            ("npm", "lodash", Path("/a/package.json")): plan_a,
            ("npm", "lodash", Path("/b/package.json")): plan_b,
        }
        with patch.object(optimise, "version_compare",
                          side_effect=VersionError("unparseable")):
            result = optimise._plan_hygiene_pins([], vuln_plans)
        assert isinstance(result, dict)


class TestExcludeGlobs:
    """--exclude on the default `fix` path (this module): write-set
    filtering shared with `fix --cve-only` via
    ``update._filter_excluded_plans``."""

    def test_parse_args_exclude_is_repeatable(self) -> None:
        args = optimise._parse_args(
            ["/tmp", "--exclude", "**/tests/**",
             "--exclude", "**/fixtures/**"])
        assert args.exclude == ["**/tests/**", "**/fixtures/**"]
        assert optimise._parse_args(["/tmp"]).exclude is None

    def test_filter_excluded_plans_drops_matching_manifests(
        self, tmp_path: Path,
    ) -> None:
        from packages.sca.update import _filter_excluded_plans

        prod = _PlanEntry(
            ecosystem="npm", name="lodash", installed="4.17.19",
            target="4.17.21",
            manifest=tmp_path / "package.json", advisory_ids=["GHSA-1"],
        )
        fixture = _PlanEntry(
            ecosystem="npm", name="lodash", installed="1.0.0",
            target="4.17.21",
            manifest=tmp_path / "tests" / "fixtures" / "package.json",
            advisory_ids=["GHSA-1"],
        )
        plans = {
            ("npm", "lodash", str(prod.manifest)): prod,
            ("npm", "lodash", str(fixture.manifest)): fixture,
        }
        kept, excluded = _filter_excluded_plans(
            plans, ["**/tests/**"], root=tmp_path,
        )
        assert list(kept.values()) == [prod]
        assert excluded == [str(fixture.manifest)]
        # No patterns → no filtering, nothing reported.
        kept2, excluded2 = _filter_excluded_plans(plans, None, root=tmp_path)
        assert kept2 == plans and excluded2 == []


class TestPinStagingAnchors:
    """Staged-copy anchoring for manifests outside the relative base."""

    def test_same_named_manifests_outside_base_stay_distinct(
        self, tmp_path: Path,
    ) -> None:
        """Two same-named manifests that live outside the staging base
        must not collapse onto one staged file (last writer wins) —
        each gets its own disambiguated anchor with its own content."""
        dir_a = tmp_path / "proj_a"
        dir_b = tmp_path / "proj_b"
        dir_a.mkdir()
        dir_b.mkdir()
        (dir_a / "requirements.txt").write_text("flask==2.3.0\n")
        (dir_b / "requirements.txt").write_text("django==3.2.0\n")
        target = tmp_path / "elsewhere"
        target.mkdir()
        proposed = tmp_path / "proposed"
        plans = {
            ("PyPI", "flask", str(dir_a / "requirements.txt")): _PlanEntry(
                ecosystem="PyPI", name="flask",
                installed="2.3.0", target="2.3.1",
                manifest=dir_a / "requirements.txt",
                advisory_ids=[],
            ),
            ("PyPI", "django", str(dir_b / "requirements.txt")): _PlanEntry(
                ecosystem="PyPI", name="django",
                installed="3.2.0", target="3.2.1",
                manifest=dir_b / "requirements.txt",
                advisory_ids=[],
            ),
        }
        changes = optimise._materialise_pin_changes(
            plans, proposed, target=target,
        )
        assert all(c.skipped_reason is None for c in changes)
        staged = sorted(p for p in proposed.rglob("*") if p.is_file())
        assert len(staged) == 2, (
            f"expected two distinct staged files, got {staged}"
        )
        texts = [p.read_text() for p in staged]
        assert any("flask==2.3.1" in t and "django" not in t for t in texts)
        assert any("django==3.2.1" in t and "flask" not in t for t in texts)

    def test_composes_with_cve_phase_copy_at_shared_anchor(
        self, tmp_path: Path,
    ) -> None:
        """When the CVE phase already staged a rewritten copy (at the
        shared out-of-cwd anchor), pin tightening must read THAT copy so
        both change sets compose."""
        from packages.sca.update import _proposed_rel_path

        proj = tmp_path / "proj"
        proj.mkdir()
        manifest = proj / "requirements.txt"
        manifest.write_text("flask==2.3.0\nrequests==2.0.0\n")
        target = tmp_path / "elsewhere"
        target.mkdir()
        proposed = tmp_path / "proposed"
        cve_copy = proposed / _proposed_rel_path(manifest)
        cve_copy.parent.mkdir(parents=True)
        cve_copy.write_text("flask==2.3.0\nrequests==2.31.0\n")
        plans = {
            ("PyPI", "flask", str(manifest)): _PlanEntry(
                ecosystem="PyPI", name="flask",
                installed="2.3.0", target="2.3.1",
                manifest=manifest,
                advisory_ids=[],
            ),
        }
        changes = optimise._materialise_pin_changes(
            plans, proposed, target=target,
        )
        assert all(c.skipped_reason is None for c in changes)
        final = cve_copy.read_text()
        assert "flask==2.3.1" in final
        assert "requests==2.31.0" in final, (
            "CVE-phase rewrite lost — pin staging did not compose"
        )


class TestDryRunTerminalEscaping:
    """Default dry-run output interpolates manifest-, OSV-, and
    LLM-derived strings: ANSI/OSC sequences in any of them must never
    reach the operator's terminal raw."""

    _ANSI = "\x1b]0;pwned\x07\x1b[31m"

    def _plan(self, **kw):
        base = dict(
            ecosystem="PyPI", name=f"evil{self._ANSI}pkg",
            installed="1.0.0", target=f"2.0.0{self._ANSI}",
            manifest=Path("/p/requirements.txt"),
            advisory_ids=[f"GHSA-{self._ANSI}x"],
        )
        base.update(kw)
        return _PlanEntry(**base)

    def test_plan_lines_escaped(self, capsys):
        key = ("PyPI", f"evil{self._ANSI}pkg", "/p/requirements.txt")
        optimise._print_dry_run({key: self._plan()}, {})
        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert "\x07" not in out

    def test_llm_verdict_text_escaped(self, capsys):
        from packages.sca.llm.schemas import BreakingChange, UpgradeImpactVerdict

        key = ("PyPI", "flask", "/p/requirements.txt")
        plan = self._plan(name="flask")
        verdict = UpgradeImpactVerdict(
            verdict="major_migration",
            confidence="low",
            breaking_changes=[BreakingChange(
                site=f"src/x.py:1{self._ANSI}",
                what_breaks=f"api gone{self._ANSI}",
            )],
            summary=f"looks fine{self._ANSI} ![b](https://evil.example/p)",
        )
        optimise._print_dry_run(
            {}, {}, {key: plan}, llm_verdicts={key: verdict},
        )
        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert "\x07" not in out
        # LLM free text also gets the markdown/autofetch defang.
        assert "![b](" not in out


class TestMaterialiseSymlinkRefusal:
    """The fix write path re-reads manifests AFTER the scan (TOCTOU
    window; `--findings <file>` takes operator-era paths at face
    value): a symlink swapped in must be refused, not followed —
    following it routed host-file content into proposed/ and the
    emitted patch context."""

    def test_pin_changes_refuse_symlinked_manifest(self, tmp_path):
        import os

        real = tmp_path / "outside.txt"
        real.write_text("flask==1.0.0\n")
        manifest = tmp_path / "requirements.txt"
        os.symlink(real, manifest)

        plans = {
            ("PyPI", "flask", str(manifest)): _PlanEntry(
                ecosystem="PyPI", name="flask",
                installed="1.0.0", target="1.0.0",
                manifest=manifest,
                advisory_ids=[],
            ),
        }
        changes = optimise._materialise_pin_changes(
            plans, tmp_path / "proposed",
        )
        assert len(changes) == 1
        assert changes[0].skipped_reason is not None
        assert "refused" in changes[0].skipped_reason

    def test_cve_changes_refuse_symlinked_manifest(self, tmp_path):
        import os

        from packages.sca.update import _materialise_changes

        real = tmp_path / "outside.txt"
        real.write_text("flask==1.0.0\n")
        manifest = tmp_path / "requirements.txt"
        os.symlink(real, manifest)

        plans = {
            ("PyPI", "flask", str(manifest)): _PlanEntry(
                ecosystem="PyPI", name="flask",
                installed="1.0.0", target="2.0.0",
                manifest=manifest,
                advisory_ids=["GHSA-x"],
            ),
        }
        changes = _materialise_changes(
            plans, [], tmp_path / "proposed", pin_only=False,
        )
        assert len(changes) == 1
        assert changes[0].skipped_reason is not None
        assert "refused" in changes[0].skipped_reason


class TestBarePinConfinement:
    """The bare-name pinners run exactly when the hardened
    (section-confined) rewriters declined — the fallback must carry
    the same decoy-section resistance, never splicing pins into
    non-dependency data."""

    def test_package_json_scripts_decoy_untouched(self):
        plan = _PlanEntry(
            ecosystem="npm", name="jest",
            installed="29.0.0", target="29.7.0",
            manifest=Path("/p/package.json"), advisory_ids=[],
        )
        text = (
            '{\n'
            '  "scripts": {\n    "jest": ""\n  },\n'
            '  "config": {\n    "jest": "*"\n  },\n'
            '  "devDependencies": {\n    "jest": "*"\n  }\n'
            '}'
        )
        new, applied, _ = optimise._pin_bare_package_json(text, plan)
        assert applied
        # Only the dependency-section entry is pinned.
        assert new.count('"jest": "29.7.0"') == 1
        assert '"scripts": {\n    "jest": ""\n  }' in new
        assert '"config": {\n    "jest": "*"\n  }' in new

    def test_package_json_no_dep_section_refuses(self):
        plan = _PlanEntry(
            ecosystem="npm", name="jest",
            installed="29.0.0", target="29.7.0",
            manifest=Path("/p/package.json"), advisory_ids=[],
        )
        text = '{"scripts": {"jest": "*"}}'
        new, applied, reason = optimise._pin_bare_package_json(text, plan)
        assert not applied
        assert new == text

    def test_pyproject_keywords_array_untouched(self):
        plan = _PlanEntry(
            ecosystem="PyPI", name="requests",
            installed="2.28.0", target="2.31.0",
            manifest=Path("/p/pyproject.toml"), advisory_ids=[],
        )
        text = (
            '[project]\n'
            'keywords = [\n    "requests",\n]\n'
            'dependencies = [\n    "requests",\n]\n'
        )
        new, applied, _ = optimise._pin_bare_pyproject(text, plan)
        assert applied
        assert 'keywords = [\n    "requests",\n]' in new
        assert '"requests==2.31.0",' in new

    def test_pyproject_tool_config_array_untouched(self):
        plan = _PlanEntry(
            ecosystem="PyPI", name="requests",
            installed="2.28.0", target="2.31.0",
            manifest=Path("/p/pyproject.toml"), advisory_ids=[],
        )
        text = (
            '[tool.mytool]\n'
            'packages = [\n    "requests",\n]\n'
        )
        new, applied, _ = optimise._pin_bare_pyproject(text, plan)
        assert not applied
        assert new == text

    def test_pyproject_optional_dependency_group_pinned(self):
        plan = _PlanEntry(
            ecosystem="PyPI", name="requests",
            installed="2.28.0", target="2.31.0",
            manifest=Path("/p/pyproject.toml"), advisory_ids=[],
        )
        text = (
            '[project.optional-dependencies]\n'
            'http = [\n    "requests",\n]\n'
        )
        new, applied, _ = optimise._pin_bare_pyproject(text, plan)
        assert applied
        assert '"requests==2.31.0",' in new

    def test_pyproject_build_system_requires_pinned(self):
        plan = _PlanEntry(
            ecosystem="PyPI", name="setuptools",
            installed="68.0.0", target="70.0.0",
            manifest=Path("/p/pyproject.toml"), advisory_ids=[],
        )
        text = (
            '[build-system]\n'
            'requires = [\n    "setuptools",\n]\n'
        )
        new, applied, _ = optimise._pin_bare_pyproject(text, plan)
        assert applied
        assert '"setuptools==70.0.0",' in new

    def test_pyproject_unbalanced_bracket_string_does_not_leak_context(self):
        """A dependency string carrying a net-positive bracket
        (``"foo[",``) must not keep the tracker "inside" the
        dependencies array past its real ``]`` — the stale array
        context silently rewrote a bare string in the FOLLOWING
        ``keywords`` array in the same section."""
        plan = _PlanEntry(
            ecosystem="PyPI", name="requests",
            installed="2.28.0", target="2.31.0",
            manifest=Path("/p/pyproject.toml"), advisory_ids=[],
        )
        text = (
            '[project]\n'
            'name = "demo"\n'
            'dependencies = [\n    "foo[",\n]\n'
            'keywords = [\n    "requests",\n]\n'
        )
        new, applied, reason = optimise._pin_bare_pyproject(text, plan)
        assert not applied
        assert new == text
        assert reason == "bare name not found in a dependency array"

    def test_pyproject_bracketed_extras_string_keeps_array_live(self):
        """Two-direction guard: brackets inside strings are ignored in
        BOTH directions — a balanced extras entry (``"foo[bar]",``)
        neither closes nor extends the array, so a real dependency
        later in the SAME array is still pinned."""
        plan = _PlanEntry(
            ecosystem="PyPI", name="requests",
            installed="2.28.0", target="2.31.0",
            manifest=Path("/p/pyproject.toml"), advisory_ids=[],
        )
        text = (
            '[project]\n'
            'dependencies = [\n'
            '    "foo[bar]",\n'
            '    "requests",\n'
            ']\n'
        )
        new, applied, _ = optimise._pin_bare_pyproject(text, plan)
        assert applied
        assert '"requests==2.31.0",' in new
        assert '"foo[bar]",' in new

    def test_pyproject_comment_brackets_ignored(self):
        """A ``]`` inside a comment must not close the array early —
        the real dependency below the comment is still in context."""
        plan = _PlanEntry(
            ecosystem="PyPI", name="requests",
            installed="2.28.0", target="2.31.0",
            manifest=Path("/p/pyproject.toml"), advisory_ids=[],
        )
        text = (
            '[project]\n'
            'dependencies = [\n'
            '    # see matrix ]\n'
            '    "requests",\n'
            ']\n'
        )
        new, applied, _ = optimise._pin_bare_pyproject(text, plan)
        assert applied
        assert '"requests==2.31.0",' in new


class TestSafeVerdictConfidenceFloor:
    """Only a HIGH-confidence "safe" verdict auto-promotes a
    mechanically-blocked major bump; a hedged "safe" stays in the
    review bucket with the verdict attached (both directions of the
    floor pinned)."""

    def _blocked(self):
        key = ("PyPI", "pytest", "/r.txt")
        plan = _PlanEntry(
            ecosystem="PyPI", name="pytest",
            installed="7.0.0", target="9.0.3",
            manifest=Path("/r.txt"),
            advisory_ids=["GHSA-y"],
        )
        return key, {key: plan}

    def _run(self, verdict):
        key, major_blocked = self._blocked()
        vuln_plans = {}
        with patch("packages.sca.llm.get_llm_client",
                   return_value=object()), \
             patch("packages.sca.llm.upgrade_impact_review."
                   "assess_upgrade_impact", return_value=verdict):
            approved, verdicts = optimise._analyze_major_bumps(
                major_blocked, vuln_plans, Path("/project"),
                promote=True,       # the operator's --llm-approve-major
            )
        return key, major_blocked, vuln_plans, approved, verdicts

    def test_low_confidence_safe_stays_blocked(self):
        from pydantic import BaseModel

        class _HedgedSafe(BaseModel):
            verdict: str = "safe"
            confidence: str = "low"
            summary: str = "probably fine"
            breaking_changes: list = []

        key, blocked, plans, approved, verdicts = self._run(_HedgedSafe())
        assert approved == set()
        assert key in blocked
        assert key not in plans
        # The verdict is retained so dry-run shows it for review.
        assert key in verdicts

    def test_medium_confidence_safe_stays_blocked(self):
        from pydantic import BaseModel

        class _MediumSafe(BaseModel):
            verdict: str = "safe"
            confidence: str = "medium"
            summary: str = "looks compatible"
            breaking_changes: list = []

        key, blocked, plans, approved, verdicts = self._run(_MediumSafe())
        assert approved == set()
        assert key in blocked
        assert key in verdicts

    def test_high_confidence_safe_promotes(self):
        from pydantic import BaseModel

        class _HighSafe(BaseModel):
            verdict: str = "safe"
            confidence: str = "high"
            summary: str = "no call sites affected"
            breaking_changes: list = []

        key, blocked, plans, approved, verdicts = self._run(_HighSafe())
        assert key in approved
        assert key in plans
        assert key not in blocked


class TestLlmMajorApprovalGate:
    def test_safe_verdict_is_annotation_only_without_opt_in(self):
        """LLM output is not operator consent: the documented opt-in
        for applying a major bump is --allow-major, and target-tree
        content can steer the classification of its own bump. Without
        the explicit --llm-approve-major opt-in a high-confidence
        \"safe\" verdict stays an ANNOTATION — the bump remains
        blocked."""
        from pydantic import BaseModel

        class _SafeVerdict(BaseModel):
            verdict: str = "safe"
            confidence: str = "high"
            summary: str = "No breaking changes"
            breaking_changes: list = []

        key = ("PyPI", "pytest", "/r.txt")
        plan = _PlanEntry(
            ecosystem="PyPI", name="pytest",
            installed="7.0.0", target="9.0.3",
            manifest=Path("/r.txt"),
            advisory_ids=["GHSA-y"],
        )
        major_blocked = {key: plan}
        vuln_plans = {}

        with patch("packages.sca.llm.get_llm_client",
                   return_value=object()), \
             patch("packages.sca.llm.upgrade_impact_review"
                   ".assess_upgrade_impact",
                   return_value=_SafeVerdict()):
            approved, verdicts = optimise._analyze_major_bumps(
                major_blocked, vuln_plans, Path("/project"),
            )

        assert approved == set()
        assert vuln_plans == {}
        assert key in major_blocked          # never applied
        assert key in verdicts               # ...but the verdict shows
        assert verdicts[key].verdict == "safe"

    def test_llm_approve_major_flag_exists_and_defaults_off(self):
        args = optimise._parse_args(["/x"])
        assert args.llm_approve_major is False
        args = optimise._parse_args(["/x", "--llm-approve-major"])
        assert args.llm_approve_major is True
