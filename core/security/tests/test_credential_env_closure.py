"""Closure oracle: every env-construction surface consumes the
canonical credential-env vocabulary.

This is the mechanical lock behind the single-homing claim: the test
walks the enumerated allowlist and blocklist surfaces and asserts, per
surface, that its EFFECTIVE set relates to the family the documented
way (allowlist lanes are family-disjoint; blocklist lanes are family-
superset; re-admit lanes re-admit exactly their documented members),
plus a source-level lock that consumer modules import the vocabulary
and that the family's most-drifted member name is spelled in exactly
one runtime location.

Surfaces walked (the env-credential matrix):
  1  RaptorConfig.SAFE_ENV_ALLOWLIST (+ prefixes)     — allowlist
  2  RaptorConfig.get_safe_env()                      — behavioral
  3  env_sanitisation.MINIMAL_ENV_KEEP fallback       — allowlist
  4  RaptorConfig.DANGEROUS_ENV_VARS                  — blocklist
  5  sandbox strict_env sweep                         — consumes 4
  6  get_llm_env re-admits (keys + routing)           — re-admit
  7  cc_adapter env-mode AWS passthrough / static trio — re-admit
  8  cc_adapter env-mode alternate-cloud pop          — pop set
  9  cc_adapter proxy-mode strip                      — blocklist
 10  cc_adapter proxy-mode belt sweep                 — behavioral
 11  cc_trust settings-env scan (+ standalone fallback) — blocklist
 12  cc_trust ⊇ core/config drift closure             — superset
 13  strip_llm_env_vars                               — behavioral
 14  codeql _filter_build_env_vars                    — behavioral
 15  container DOCKER_CHILD_ENV_VARS re-admit         — re-admit
 16  TARGET_ENV_STRIP_SET / fuzzing identity scrub    — session cred
     (the seatbelt-shim tuple mirrors TARGET_ENV_STRIP_SET and is
     table-driven off it by its own regression harness)

Plus the model-traffic-redirect shape tier (NOT family members — the
proxy dispatcher and the LLM routing re-admit legitimately carry
endpoint names): its two consumers (cc_trust settings scan, cc_adapter
proxy strip) are locked symmetric below.
"""

import re
from pathlib import Path

from core.config import RaptorConfig
from core.security.credential_env import (
    ANTHROPIC_FIRST_PARTY_AUTH_VARS,
    CREDENTIAL_BEARING_ENV_VARS,
    CREDENTIAL_ENV_FAMILY,
    CREDENTIAL_GENERAL_BLOCKLIST_VARS,
    GENERAL_BLOCKLIST_EXEMPT_VARS,
    is_credential_shaped,
    is_model_traffic_redirect_shaped,
)

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


# --- 1-3: allowlist lanes are family-disjoint -----------------------

class TestAllowlistLanes:
    def test_safe_env_allowlist_family_disjoint(self):
        assert not (RaptorConfig.SAFE_ENV_ALLOWLIST & CREDENTIAL_ENV_FAMILY)

    def test_safe_env_allowlist_shape_clean(self):
        # The one documented credential-shaped allowlist member is
        # RAPTOR's own session-registry credential (validated on every
        # read; target-bound envs strip it via TARGET_ENV_STRIP_SET).
        shaped = {
            n for n in RaptorConfig.SAFE_ENV_ALLOWLIST
            if is_credential_shaped(n)
        }
        assert shaped == {"RAPTOR_SESSION_TOKEN"}

    def test_safe_env_prefixes_admit_no_family_member(self):
        for member in CREDENTIAL_ENV_FAMILY:
            assert not member.startswith(RaptorConfig.SAFE_ENV_PREFIXES), (
                member
            )

    def test_get_safe_env_behavioral(self, monkeypatch):
        for name in CREDENTIAL_ENV_FAMILY:
            monkeypatch.setenv(name, "hostile")
        monkeypatch.setenv("FUTURE_VENDOR_API_TOKEN", "hostile")
        env = RaptorConfig.get_safe_env()
        survivors = {
            k for k, v in env.items()
            if (k in CREDENTIAL_ENV_FAMILY or is_credential_shaped(k))
            and k != "RAPTOR_SESSION_TOKEN"
        }
        # Only GIT_ENV_VARS pins may remain, at their pinned values.
        for k in survivors:
            assert env[k] == RaptorConfig.GIT_ENV_VARS.get(k), k

    def test_minimal_fallback_keep_family_disjoint(self):
        from core.security.env_sanitisation import MINIMAL_ENV_KEEP
        assert not (set(MINIMAL_ENV_KEEP) & CREDENTIAL_ENV_FAMILY)
        assert not any(is_credential_shaped(n) for n in MINIMAL_ENV_KEEP)


# --- 4-5: general blocklist lane ------------------------------------

class TestGeneralBlocklistLane:
    def test_dangerous_env_vars_superset(self):
        assert CREDENTIAL_GENERAL_BLOCKLIST_VARS <= (
            RaptorConfig.DANGEROUS_ENV_VARS
        )

    def test_exempt_members_not_in_dangerous(self):
        # Both directions: the documented runtime re-admits must stay
        # OUT (the sandbox strict_env sweep consumes this list against
        # trusted caller envs that legitimately carry them).
        assert not (
            GENERAL_BLOCKLIST_EXEMPT_VARS & RaptorConfig.DANGEROUS_ENV_VARS
        )

    def test_strict_env_lanes_consume_dangerous_vocabulary(self):
        # The three strict_env sweep sites filter through
        # RaptorConfig.is_dangerous_env_name (DANGEROUS_ENV_VARS plus
        # the credential-env name patterns) — with the family unioned
        # into the blocklist, they inherit it. Lock the consumption
        # edge on the CODE (comments stripped — prose containing the
        # token must never satisfy this), as the CALL expression. The
        # load-bearing oracles are the behavioral capture-spawn pins
        # in core/sandbox/tests/test_strict_env_pattern_pins.py; this
        # source lock is the belt for platforms the pins skip on.
        for rel in (
            "core/sandbox/context.py",
            "core/sandbox/_spawn.py",
            "core/sandbox/_macos_spawn.py",
        ):
            src = (_RAPTOR_ROOT / rel).read_text(encoding="utf-8")
            code_only = _COMMENT_RE.sub("", src)
            assert "RaptorConfig.is_dangerous_env_name(" in code_only, rel


# --- 6-8: documented re-admit lanes ---------------------------------

class TestReadmitLanes:
    def test_llm_lane_readmits_exactly_documented(self):
        readmits = (
            set(RaptorConfig.LLM_API_KEY_VARS)
            | set(RaptorConfig.LLM_ROUTING_ENV_VARS)
        ) & CREDENTIAL_ENV_FAMILY
        # Every family member the LLM lane re-admits is either a
        # general-blocklist exemption (carried by trusted lanes) or
        # GOOGLE_APPLICATION_CREDENTIALS (blocked for general lanes,
        # re-admitted post-strip by get_llm_env's documented overlay).
        assert readmits <= (
            GENERAL_BLOCKLIST_EXEMPT_VARS
            | {"GOOGLE_APPLICATION_CREDENTIALS"}
        ), readmits

    def test_cc_env_mode_aws_passthrough_documented(self):
        from core.llm.cc_adapter import (
            _CC_AWS_PASSTHROUGH_NAMES,
            _CC_AWS_STATIC_CREDENTIAL_NAMES,
        )
        overlap = (
            set(_CC_AWS_PASSTHROUGH_NAMES)
            | set(_CC_AWS_STATIC_CREDENTIAL_NAMES)
        ) & CREDENTIAL_ENV_FAMILY
        # Every family member the cc env-mode lane re-admits must be a
        # documented general-blocklist exemption — otherwise the
        # sandbox strict_env sweep strips it right back out and the
        # lane is silently broken.
        assert overlap <= GENERAL_BLOCKLIST_EXEMPT_VARS, overlap

    def test_docker_child_readmit_exactly_docker_config(self):
        from core.container.proc import DOCKER_CHILD_ENV_VARS
        overlap = set(DOCKER_CHILD_ENV_VARS) & CREDENTIAL_ENV_FAMILY
        # The docker CLI child lane re-admits exactly the docker
        # config dir (credsStore hazard accepted and documented at the
        # constant) — nothing else from the family.
        assert overlap == {"DOCKER_CONFIG"}

    def test_alternate_cloud_pop_covers_first_party_trio(self):
        assert set(ANTHROPIC_FIRST_PARTY_AUTH_VARS) <= (
            CREDENTIAL_BEARING_ENV_VARS
        )


# --- 9-10: proxy-mode lane ------------------------------------------

class TestProxyModeLane:
    def test_proxy_strip_covers_whole_family(self):
        from core.llm.cc_adapter import _cc_proxy_strip
        for member in CREDENTIAL_ENV_FAMILY:
            assert _cc_proxy_strip(member), member

    def test_proxy_strip_covers_shape(self):
        from core.llm.cc_adapter import _cc_proxy_strip
        assert _cc_proxy_strip("CLAUDE_CODE_FUTURE_TOKEN")
        assert _cc_proxy_strip("ANTHROPIC_NEW_SECRET")


# --- Model-traffic-redirect shape tier ------------------------------

class TestModelTrafficRedirectTier:
    def test_redirect_names_are_not_family_members(self):
        # By design: family membership would put endpoint names in the
        # general blocklists that the proxy dispatcher (which SETS
        # gateway base URLs on its children) and the LLM routing
        # re-admit (ANTHROPIC_BASE_URL) must carry them through.
        for name in CREDENTIAL_ENV_FAMILY:
            assert not is_model_traffic_redirect_shaped(name), name

    def test_llm_routing_readmit_is_exactly_base_url(self):
        # The one redirect-shaped name a trusted lane re-admits is the
        # primary base URL, carried for RAPTOR's OWN LLM children.
        shaped = {
            n for n in RaptorConfig.LLM_ROUTING_ENV_VARS
            if is_model_traffic_redirect_shaped(n)
        }
        assert shaped == {"ANTHROPIC_BASE_URL"}

    def test_safe_env_allowlist_redirect_clean(self):
        shaped = {
            n for n in RaptorConfig.SAFE_ENV_ALLOWLIST
            if is_model_traffic_redirect_shaped(n)
        }
        assert shaped == set()

    def test_proxy_strip_consumes_redirect_shape(self):
        from core.llm.cc_adapter import _cc_proxy_strip
        for name in (
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_BEDROCK_MANTLE_BASE_URL",
            "ANTHROPIC_VERTEX_BASE_URL",
            "CLAUDE_CODE_SKIP_MANTLE_AUTH",
            "AWS_ENDPOINT_URL_BEDROCK_RUNTIME",
        ):
            assert is_model_traffic_redirect_shaped(name), name
            assert _cc_proxy_strip(name), name

    def test_both_consumers_import_the_shape_rule(self):
        # Symmetry lock: cc_trust's settings scan and cc_adapter's
        # proxy strip block the SAME redirect shapes — each must
        # consume the vocabulary predicate, not a local pattern.
        for rel in (
            "core/security/cc_trust.py",
            "core/llm/cc_adapter.py",
        ):
            src = (_RAPTOR_ROOT / rel).read_text(encoding="utf-8")
            assert "is_model_traffic_redirect_shaped" in src, rel


# --- 11-12: trust-gate lane -----------------------------------------

class TestTrustGateLane:
    def test_cc_trust_blocklist_superset_of_family(self):
        from core.security.cc_trust import (
            _COMPREHENSIVE_DANGEROUS_ENV_VARS,
            _DANGEROUS_ENV_VARS,
        )
        assert CREDENTIAL_ENV_FAMILY <= _DANGEROUS_ENV_VARS
        # The standalone fallback (core.config unimportable) must
        # carry the family on its own.
        assert CREDENTIAL_ENV_FAMILY <= _COMPREHENSIVE_DANGEROUS_ENV_VARS

    def test_cc_trust_scan_carries_toolchain_home_class(self):
        """Settings-scan-only class: a repo-supplied JAVA_HOME/GOROOT
        redirects the operator session's next launcher invocation at
        a repo binary (PATH itself is blocked on this lane, so this
        is the surviving launcher-redirect primitive). The class must
        be in the scan set on BOTH import branches, and must stay OUT
        of the general blocklist (operators legitimately set these;
        the traced-build lane carries them by design)."""
        from core.security.cc_trust import (
            _COMPREHENSIVE_DANGEROUS_ENV_VARS,
        )
        from core.security.credential_env import TOOLCHAIN_HOME_ENV_VARS
        assert TOOLCHAIN_HOME_ENV_VARS <= _COMPREHENSIVE_DANGEROUS_ENV_VARS
        assert not (
            TOOLCHAIN_HOME_ENV_VARS & RaptorConfig.DANGEROUS_ENV_VARS
        )

    def test_cc_trust_superset_of_core_config(self):
        # Drift closure: the trust gate's effective set contains every
        # core/config DANGEROUS member (the two lists had already
        # drifted once before the vocabulary was single-homed).
        from core.security.cc_trust import _DANGEROUS_ENV_VARS
        assert frozenset(RaptorConfig.DANGEROUS_ENV_VARS) <= (
            _DANGEROUS_ENV_VARS
        )

    def test_cc_trust_standalone_fallback_superset_of_core_config(self):
        # The REAL direction: on a full install the effective set
        # unions core.config in, so the assertion above is true by
        # construction and structurally blind to fallback drift — a
        # degraded install (core.config unimportable) scans with
        # _COMPREHENSIVE_DANGEROUS_ENV_VARS ALONE, and that set had
        # silently lacked 27 members including exec-grade
        # GCONV_PATH/PHPRC. Every core/config member must be carried
        # by the standalone set itself; add new members to BOTH homes.
        from core.security.cc_trust import (
            _COMPREHENSIVE_DANGEROUS_ENV_VARS,
        )
        missing = (frozenset(RaptorConfig.DANGEROUS_ENV_VARS)
                   - _COMPREHENSIVE_DANGEROUS_ENV_VARS)
        assert not missing, (
            f"cc_trust standalone fallback lacks {sorted(missing)} — "
            "mirror the new DANGEROUS_ENV_VARS member(s) into "
            "_COMPREHENSIVE_DANGEROUS_ENV_VARS so degraded installs "
            "keep parity"
        )

    def test_degraded_install_scan_blocks_loader_members(self, tmp_path):
        # Behavioural half: with core.config blocked at import, the
        # settings scan must still flag members only the full list
        # used to carry.
        import json
        import subprocess
        import sys
        claude = tmp_path / ".claude"
        claude.mkdir()
        (claude / "settings.json").write_text(json.dumps({
            "env": {"GCONV_PATH": "/repo/g", "PHPRC": "/repo/php.ini"},
        }))
        code = (
            "import sys\n"
            "import importlib.abc\n"
            "class _Block(importlib.abc.MetaPathFinder):\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name == 'core.config'"
            " or name.startswith('core.config.'):\n"
            "            raise ImportError('blocked: degraded install')\n"
            "sys.meta_path.insert(0, _Block())\n"
            "from core.security.cc_trust import check_repo_claude_trust\n"
            "assert check_repo_claude_trust(sys.argv[1],"
            " trust_override=False)\n"
            "print('DEGRADED-BLOCKS')\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code, str(tmp_path)],
            capture_output=True, text=True, timeout=60,
            cwd=str(Path(__file__).resolve().parents[3]),
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        assert "DEGRADED-BLOCKS" in proc.stdout


# --- 13-14: remaining blocklist lanes (behavioral) ------------------

class TestStripLanes:
    def test_strip_llm_env_vars_drops_bearing_tier(self):
        env = {name: "v" for name in CREDENTIAL_BEARING_ENV_VARS}
        env["PATH"] = "/usr/bin"
        RaptorConfig.strip_llm_env_vars(env)
        assert not (set(env) & CREDENTIAL_BEARING_ENV_VARS)

    def test_codeql_build_env_gate_refuses_family(self):
        from packages.codeql.database_manager import _filter_build_env_vars
        hostile = dict.fromkeys(CREDENTIAL_ENV_FAMILY, "x")
        assert _filter_build_env_vars(hostile) == {}


# --- 16: session credential on the target-strip lane ----------------

class TestTargetStripLane:
    def test_session_credential_in_target_strip(self):
        assert "RAPTOR_SESSION_TOKEN" in RaptorConfig.TARGET_ENV_STRIP_SET
        assert "RAPTOR_SESSION_PID" in RaptorConfig.TARGET_ENV_STRIP_SET


# --- Source-level single-homing locks -------------------------------

_CONSUMER_MODULES = (
    # Every module that filters/blocks by credential-family names must
    # import the vocabulary — a local list reappearing here is the
    # multi-homing regression this program removed. Known bound: these
    # locks catch behavior-FLIPPING copies (an exempt member re-added
    # to a blocklist) and the pinned sentinel spelling below; a behavior-
    # IDENTICAL redundant hand-copy of a non-exempt member in a
    # consumer survives them — reviews, not this suite, catch that.
    "core/config/__init__.py",
    "core/security/cc_trust.py",
    "core/llm/cc_adapter.py",
    "packages/codeql/database_manager.py",
    "core/audit/dynamic_sweep.py",
)

_COMMENT_RE = re.compile(r"#.*$", re.MULTILINE)


def _runtime_python_files():
    for sub in ("core", "packages", "libexec", "bin"):
        base = _RAPTOR_ROOT / sub
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if "tests" in path.parts or path.name.startswith("test_"):
                continue
            if path.suffix and path.suffix != ".py":
                continue
            yield path
    yield from _RAPTOR_ROOT.glob("raptor*.py")


class TestSingleHoming:
    def test_consumers_import_the_vocabulary(self):
        for rel in _CONSUMER_MODULES:
            src = (_RAPTOR_ROOT / rel).read_text(encoding="utf-8")
            assert "core.security.credential_env" in src, rel

    def test_oauth_token_name_single_homed(self):
        """The family's most-drifted member is spelled in exactly one
        runtime location: the vocabulary module. Comments don't count;
        code does. A second code spelling means a consumer grew a
        local list again."""
        offenders = []
        for path in _runtime_python_files():
            try:
                src = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "CLAUDE_CODE_OAUTH_TOKEN" not in src:
                continue
            code_only = _COMMENT_RE.sub("", src)
            if "CLAUDE_CODE_OAUTH_TOKEN" in code_only:
                offenders.append(str(path.relative_to(_RAPTOR_ROOT)))
        assert offenders == ["core/security/credential_env.py"], offenders


# --- Ecosystem census + pattern-member lanes -------------------------

class TestEcosystemCensus:
    def test_every_build_system_has_an_adjudicated_surface(self):
        """Census closure: every build system the detector inventory
        can emit maps to an ecosystem surface that adjudicated its
        env family. Adding a build system without adjudicating its
        env surface fails HERE — ecosystem coverage is structural,
        not a per-name chase across sibling blocklists."""
        from core.build.build_detector import BuildDetector
        from core.security.credential_env import (
            BUILD_ECOSYSTEM_ENV_SURFACES,
            BUILD_SYSTEM_ECOSYSTEM_MAP,
        )
        declared = {s.ecosystem for s in BUILD_ECOSYSTEM_ENV_SURFACES}
        for language, systems in BuildDetector.BUILD_SYSTEMS.items():
            for build_system in systems:
                assert build_system in BUILD_SYSTEM_ECOSYSTEM_MAP, (
                    f"{language}/{build_system}: no env-family "
                    "adjudication — add the build system to "
                    "BUILD_SYSTEM_ECOSYSTEM_MAP and (if new) declare "
                    "its BuildEcosystemEnvSurface"
                )
                assert (
                    BUILD_SYSTEM_ECOSYSTEM_MAP[build_system] in declared
                ), build_system

    def test_census_map_has_no_stale_rows(self):
        """Both directions: every inventory build system is mapped
        (the test above) AND every map row names a live inventory
        build system — a build-system removal must take its
        adjudication row with it, or the census silently carries dead
        adjudications. Extras are ∅ today by design; a documented
        extra would join an explicit allowlist here, not slip by."""
        from core.build.build_detector import BuildDetector
        from core.security.credential_env import (
            BUILD_SYSTEM_ECOSYSTEM_MAP,
        )
        inventory = {
            build_system
            for systems in BuildDetector.BUILD_SYSTEMS.values()
            for build_system in systems
        }
        stale = set(BUILD_SYSTEM_ECOSYSTEM_MAP) - inventory
        assert stale == set(), stale

    def test_zero_member_surfaces_are_explicit(self):
        """A surface with no members in any tier must SAY so — the
        completeness prose is the adjudication record, and an
        accidental all-empty surface must not read like a decision.
        (No such surface exists today; this is the structural rail
        for the first one.)"""
        from core.security.credential_env import (
            BUILD_ECOSYSTEM_ENV_SURFACES,
        )
        for surface in BUILD_ECOSYSTEM_ENV_SURFACES:
            populated = (
                surface.credential_bearing
                or surface.config_redirect
                or surface.tool_override
                or surface.flags_injection
                or surface.tool_override_patterns
            )
            if not populated:
                assert "zero-member" in surface.completeness, (
                    surface.ecosystem
                )

    def test_env_detect_passthroughs_stay_out_of_the_family(self):
        """The traced-build lane deliberately auto-detects and
        CARRIES the toolchain-home names each build system declares
        (env_detect: JAVA_HOME / GOROOT / DOTNET_ROOT). Family
        membership would make the vocabulary strip the lane's own
        passthrough — the two mechanisms must stay disjoint."""
        from core.build.build_detector import BuildDetector
        from core.security.credential_env import TOOLCHAIN_HOME_ENV_VARS
        for systems in BuildDetector.BUILD_SYSTEMS.values():
            for config in systems.values():
                for name in config.get("env_detect", ()):
                    assert name not in CREDENTIAL_ENV_FAMILY, name
                    # ...but every passthrough must be ADJUDICATED in
                    # the toolchain-home class the settings scan
                    # blocks: repo-supplied spellings of these names
                    # are launcher redirects at operator power.
                    assert name in TOOLCHAIN_HOME_ENV_VARS, name
        # The class stays out of the family (and thus the general
        # blocklist) in the other direction too — the settings scan is
        # its only consumer by design.
        assert not (TOOLCHAIN_HOME_ENV_VARS & CREDENTIAL_ENV_FAMILY)


class TestPatternMemberLanes:
    """Pattern members (CARGO_TARGET_<triple>_RUNNER-shaped names)
    cannot live in any exact-name set — every lane must match them
    through the vocabulary predicates."""

    def _examples(self):
        from core.security.credential_env import (
            CREDENTIAL_ENV_NAME_PATTERNS,
        )
        assert CREDENTIAL_ENV_NAME_PATTERNS  # patterns exist at all
        return [p.example for p in CREDENTIAL_ENV_NAME_PATTERNS]

    def test_get_safe_env_strips_pattern_members(self, monkeypatch):
        for name in self._examples():
            monkeypatch.setenv(name, "hostile")
        env = RaptorConfig.get_safe_env()
        for name in self._examples():
            assert name not in env, name

    def test_codeql_build_env_gate_refuses_pattern_members(self):
        from packages.codeql.database_manager import _filter_build_env_vars
        hostile = dict.fromkeys(self._examples(), "x")
        assert _filter_build_env_vars(hostile) == {}

    def test_dangerous_name_predicate_covers_pattern_members(self):
        for name in self._examples():
            assert RaptorConfig.is_dangerous_env_name(name), name

    def test_strict_env_sweeps_filter_through_the_predicate_in_code(self):
        # Every FILTER comprehension at the three sweep sites must
        # consult the pattern-aware predicate: comments are stripped
        # before matching, and the match is the negated call shape the
        # rebuild filters use — a site whose detection list consults
        # the predicate while its rebuild filter regressed to bare set
        # membership no longer satisfies this. Behavioral proof lives
        # in core/sandbox/tests/test_strict_env_pattern_pins.py (a
        # real child per site); this is the mechanical belt.
        for rel in (
            "core/sandbox/context.py",
            "core/sandbox/_spawn.py",
            "core/sandbox/_macos_spawn.py",
        ):
            src = (_RAPTOR_ROOT / rel).read_text(encoding="utf-8")
            code_only = _COMMENT_RE.sub("", src)
            assert "not RaptorConfig.is_dangerous_env_name(" in code_only, rel
            # No sweep site may fall back to bare set membership for
            # its filter: the raw idiom must not reappear in code.
            assert "k not in RaptorConfig.DANGEROUS_ENV_VARS" not in (
                code_only
            ), rel

    def test_hostile_input_shape_rule_covers_pattern_members(self):
        # Both hostile-input belts (cc_trust settings scan, codeql
        # build-metadata gate) apply is_credential_redirect_shaped —
        # the pattern fold-in reaches them with no consumer change.
        from core.security.credential_env import (
            is_credential_redirect_shaped,
        )
        for name in self._examples():
            assert is_credential_redirect_shaped(name), name
