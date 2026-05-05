"""
The single orchestrator for the agentic-first discover pipeline.

Stages, with a disk-budget gate at every entry:

    agent_discover  →  acquire  →  resolve  →  diff  →  render

The `agent_discover` stage is an Anthropic-SDK tool-use loop (see
`cve_diff/agent/`). It replaces the deterministic 7-gate scorer chain
and the recovery-as-fallback layer. Agent output is type-checked by
three invariants only (``agent/invariants.py``):
  (1) ``is_valid_sha_format`` + ``PatchTuple`` construction
  (2) ``commit_exists(slug, sha)`` + minimal URL shape check
  (3) ``check_diff_shape`` — post-extract, via ``_check_shape``

No hardcoded slug / tracker / keyword list anywhere on this path.

Diff semantics unchanged: the diff body is always ``fix^..fix``; OSV's
``introduced`` marker is preserved for provenance only.

Failure modes surface as typed exceptions (``DiscoveryError``,
``AcquisitionError``, ``IdenticalCommitsError``, ``UnsupportedSource``,
``AnalysisError``) that the CLI maps to exit codes.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
import time
from typing import Any, Callable

from cve_diff.acquisition.layers import CascadingRepoAcquirer
from cve_diff.agent.invariants import check_diff_shape, discover_validator
from cve_diff.agent.loop import AgentConfig, AgentLoop
from cve_diff.agent.prompt import SYSTEM_PROMPT, build_user_message
from cve_diff.agent.tools import TOOLS
from cve_diff.agent.types import AgentContext, AgentOutput, AgentResult, AgentSurrender
from cve_diff.core.exceptions import (
    AcquisitionError,
    AnalysisError,
    DiscoveryError,
    IdenticalCommitsError,
    UnsupportedSource,
)
from cve_diff.core.models import CommitSha, DiffBundle, PatchTuple, RepoRef
from cve_diff.diffing.commit_resolver import CommitResolver
from cve_diff.diffing.extract_via_api import extract_via_api
from cve_diff.diffing.extractor import extract_diff
from cve_diff.infra import disk_budget


# Maximum number of post-submit retries (i.e. extra agent runs after
# stages 2-5 fail on the agent's first pick). One retry = two total
# attempts. Empirically (501-CVE OSS 2022-2024 bench, 2026-04-26)
# 96% of multi-candidate explorations succeed on the second try; a
# 3rd attempt is statistical noise + cost.
_MAX_POST_SUBMIT_RETRIES: int = 1


# Map every internal ``_emit`` stage name to one of the 5 canonical
# pipeline stages (discover/acquire/resolve/diff/render). The trace
# renderer needs this to draw all 5 stage headers correctly on FAIL
# paths — see ``cve_diff/report/markdown.py::render_flow``.
#
# Auxiliary steps (``extraction_agreement``, ``consensus``) are NOT
# in this map — their success/failure is informational, not a stage
# verdict. Stage status is populated only for the structural events
# that mark "the pipeline reached this stage and (succeeded | failed)
# decisively here". On a clean pipeline.run() return, render="ok" is
# stamped at the end (whether or not consensus / agreement ran).
_CANONICAL_STAGE_OF: dict[str, str] = {
    "agent_discover": "discover",
    "post_submit_retry": "discover",
    "acquire": "acquire",
    "resolve": "resolve",
    "diff": "diff",
    "diff_via_api": "diff",
}


@dataclass
class PipelineResult:
    cve_id: str
    bundle: DiffBundle
    agent_result: AgentResult
    acquirer: CascadingRepoAcquirer


@dataclass
class Pipeline:
    agent: AgentLoop = field(default_factory=AgentLoop)
    acquirer_factory: Any = field(default=CascadingRepoAcquirer)
    resolver: CommitResolver = field(default_factory=CommitResolver)
    disk_limit_pct: float = disk_budget.DEFAULT_LIMIT_PCT
    # Per-file source-blob cap for DiffBundle.files[*].before_source /
    # after_source. None = use extractor module default (currently 128 KB).
    max_file_bytes: int | None = None
    # Run 2-method pointer consensus (OSV refs + NVD Patch-tagged)
    # after extract_diff. Adds ~2-3s and 1-2 API calls per CVE,
    # surfaces in the per-CVE markdown + osv_schema.database_specific
    # .consensus. Disabled by default in bench mode (the bench writes
    # its own per-CVE OSV directly via osv_schema.render — see
    # `cli/bench.py::_run_one`).
    enable_consensus: bool = True
    # When clone-based extraction (acquire → extract_diff) raises
    # AcquisitionError, fall back to GitHub Commits API.
    # extract_via_api computes the same fix^..fix diff via
    # `GET /repos/{slug}/commits/{sha}` (no HEAD fallback — Bug #12
    # defended by SHA-format check at the boundary). Off-GitHub repos
    # propagate the original clone error. Default on; bench can flip
    # to False for predictable cost.
    api_extract_fallback: bool = True
    # When clone-based extraction succeeds AND the slug is on GitHub,
    # also run extract_via_api to compute a two-source agreement
    # signal (see cve_diff/diffing/extraction_agreement). Cache-shared
    # with the agent's gh_commit_detail; cost is ~free. Default on so
    # every per-CVE report can show "two sources agree on the diff".
    enable_extraction_agreement: bool = True
    # Multiplier applied to AgentConfig.budget_* and meta-retry
    # budgets. CLI's `cve-diff run` raises this on user request when
    # the first attempt hits a budget cap (interactive extend-on-cap
    # flow). Default 1.0 = use the AgentConfig defaults as shipped.
    agent_budget_multiplier: float = 1.0
    # When set, called at each stage transition with
    # (stage_name: str, status: str, info: dict). The CLI's --verbose
    # flag wires this to a stderr-printer; bench leaves it None.
    progress_callback: "Callable[[str, str, dict], None] | None" = None
    # Set true after _maybe_retry runs the second AgentLoop. Read by
    # the bench harness for retry-effectiveness telemetry.
    _last_meta_retry_attempted: bool = field(default=False, init=False, repr=False)
    # Set true after a *post-submit* retry fires (the agent is re-run
    # because acquire/resolve/diff failed on its first pick). Distinct
    # from `_last_meta_retry_attempted` (budget walks, fires inside
    # `_run_agent`).
    _last_post_submit_retry_attempted: bool = field(
        default=False, init=False, repr=False
    )
    # When the opportunistic API extraction (extraction_agreement step)
    # ran successfully, the resulting DiffBundle is stashed here so the
    # caller (cli/main.py or cli/bench.py) can write it to disk as a
    # ``<cve>.<forge>.patch`` file alongside the clone-extracted patch.
    # This gives users two independent diff files to compare manually
    # whenever extraction_agreement comes back ``partial`` or ``disagree``.
    _last_api_bundle: "DiffBundle | None" = field(
        default=None, init=False, repr=False
    )
    # ``_last_extra_bundles`` is the FULL list of second-source bundles
    # the agreement check produced — not just one. Today there can be
    # up to two (JSON API + patch URL); cgit yields just patch_url.
    # Each bundle gets persisted as ``<cve>.<method>.patch``.
    _last_extra_bundles: "list[tuple[str, DiffBundle]]" = field(
        default_factory=list, init=False, repr=False
    )
    # Per-canonical-stage status. Populated by ``_emit`` whenever an
    # internal ``_emit(stage, status, ...)`` call maps to one of the 5
    # canonical pipeline stages (discover/acquire/resolve/diff/render).
    # The CLI's ``_flow_from_pipeline`` reads this so the trace renderer
    # can ALWAYS render all 5 stage headers — including on FAIL paths,
    # where it's the only signal of "where in the pipeline did we
    # actually stop?". User-stated requirement (2026-05-01).
    _stage_status: "dict[str, dict]" = field(
        default_factory=dict, init=False, repr=False
    )

    def run(self, cve_id: str, work_dir: Path) -> PipelineResult:
        self._emit("disk_check", "start", {"path": str(work_dir)})
        self._assert_disk(work_dir)

        self._emit("agent_discover", "start", {})
        t0 = time.monotonic()
        agent_result = self._run_agent(cve_id)
        patch: PatchTuple = self._require_rescued(cve_id, agent_result)
        ref = _patch_to_repo_ref(patch)
        self._emit("agent_discover", "ok",
                   {"slug": ref.repository_url, "fix_commit": ref.fix_commit[:12],
                    "elapsed_s": round(time.monotonic() - t0, 1)})

        # Post-submit agentic retry loop: on AcquisitionError /
        # AnalysisError / IdenticalCommitsError from stages 2-5,
        # spawn a focused agent re-run with the failure as feedback so
        # the agent can pick a different verified candidate. Cap at
        # _MAX_POST_SUBMIT_RETRIES (default 1; 2 total acquire
        # attempts). Empirically 96% of multi-candidate explorations
        # succeed on the second try; a 3rd attempt is statistical
        # noise + cost.
        for attempt in range(_MAX_POST_SUBMIT_RETRIES + 1):
            try:
                return self._acquire_to_render(
                    cve_id, ref, agent_result, work_dir
                )
            # Also catch ValueError from commit_resolver (rev-parse failure
            # on stale SHA) and RuntimeError from transient mid-fetch git
            # errors — both are recoverable by re-running the agent with
            # a different candidate, so they belong in the post-submit
            # retry path rather than being a hard pipeline crash.
            except (
                AcquisitionError,
                AnalysisError,
                IdenticalCommitsError,
                ValueError,
                RuntimeError,
            ) as exc:
                if attempt == _MAX_POST_SUBMIT_RETRIES:
                    raise
                self._emit("post_submit_retry", "start", {
                    "failed_class": type(exc).__name__,
                    "failed_slug": ref.repository_url,
                    "failed_sha": ref.fix_commit[:12],
                    "reason": str(exc)[:120],
                })
                agent_result = self._post_submit_retry(
                    cve_id, ref, exc, agent_result
                )
                patch = self._require_rescued(cve_id, agent_result)
                ref = _patch_to_repo_ref(patch)
                self._last_post_submit_retry_attempted = True
                self._emit("post_submit_retry", "ok", {
                    "new_slug": ref.repository_url,
                    "new_sha": ref.fix_commit[:12],
                })
        # unreachable — the loop either returns or re-raises on the cap

    def _acquire_to_render(
        self, cve_id: str, ref: RepoRef, agent_result: AgentResult,
        work_dir: Path,
    ) -> PipelineResult:
        """Stages 2-5: acquire → resolve → diff → render.

        Extracted from `run` so the post-submit retry loop can call it
        once per agent pick. Side-effect: writes into a fresh
        ``work_dir/repo`` subdirectory each call so a second attempt
        doesn't race the first attempt's leftovers.
        """
        self._assert_disk(work_dir)
        # On retry, the previous attempt may have left a partial clone
        # behind — use a numbered subdir so each retry has a clean slate.
        attempt_dirs = sorted(work_dir.glob("repo*"))
        repo_path = work_dir / f"repo{len(attempt_dirs) if attempt_dirs else ''}"
        acquirer = self.acquirer_factory()
        bundle: DiffBundle | None = None
        clone_error: Exception | None = None

        try:
            self._emit("acquire", "start", {"slug": ref.repository_url})
            t0 = time.monotonic()
            acquirer.acquire(ref, repo_path)
            self._emit("acquire", "ok",
                       {"layer": next((r.name for r in acquirer.reports if r.ok), "?"),
                        "elapsed_s": round(time.monotonic() - t0, 1)})

            self._assert_disk(repo_path)
            self._emit("resolve", "start", {})
            commit_after = self.resolver.expand(repo_path, ref.fix_commit)
            commit_before = self.resolver.parent_of(repo_path, commit_after)
            self.resolver.validate_different(commit_before, commit_after)
            self._emit("resolve", "ok",
                       {"before": commit_before[:12], "after": commit_after[:12]})

            self._emit("diff", "start", {})
            t0 = time.monotonic()
            bundle = extract_diff(
                repo_path=repo_path,
                cve_id=cve_id,
                ref=ref,
                commit_before=CommitSha(commit_before),
                commit_after=CommitSha(commit_after),
                max_file_bytes=self.max_file_bytes,
            )
            self._check_shape(cve_id, bundle)
            self._emit("diff", "ok",
                       {"shape": bundle.shape, "files": bundle.files_changed,
                        "bytes": bundle.bytes_size,
                        "elapsed_s": round(time.monotonic() - t0, 1)})
        except AcquisitionError as exc:
            if not self.api_extract_fallback:
                raise
            clone_error = exc
            self._emit("acquire", "fail", {"reason": str(exc)[:80]})

        if bundle is None:
            self._emit("diff_via_api", "start", {"slug": ref.repository_url})
            t0 = time.monotonic()
            try:
                bundle = extract_via_api(cve_id, ref)
                self._check_shape(cve_id, bundle)
                self._emit("diff_via_api", "ok",
                           {"shape": bundle.shape, "files": bundle.files_changed,
                            "bytes": bundle.bytes_size,
                            "elapsed_s": round(time.monotonic() - t0, 1)})
            except AnalysisError as api_exc:
                self._emit("diff_via_api", "fail", {"reason": str(api_exc)[:80]})
                # Both paths failed — propagate original clone error per plan.
                if clone_error is not None:
                    raise clone_error from api_exc
                raise
        elif self.enable_extraction_agreement:
            # Clone path succeeded — opportunistically also extract via
            # API to record a two-source agreement signal. Cache shared
            # with the agent's `gh_commit_detail` calls; cost is ~free.
            self._emit("extraction_agreement", "start", {})
            t0 = time.monotonic()
            try:
                from cve_diff.diffing.extraction_agreement import (
                    compute_extraction_agreement,
                )
                result_pair = compute_extraction_agreement(cve_id, ref, bundle)
                if result_pair is not None:
                    agreement, extras = result_pair
                    bundle = replace(bundle, extraction_agreement=agreement)
                    # Stash ALL second-source bundles for the caller to
                    # persist as ``<cve>.<method>.patch`` (one per
                    # method). ``_last_api_bundle`` keeps a backward-
                    # compatible pointer at the JSON-API one when
                    # available — but the canonical full list is
                    # ``_last_extra_bundles``.
                    self._last_extra_bundles = list(extras)
                    self._last_api_bundle = next(
                        (b for n, b in extras if n in ("github_api", "gitlab_api")),
                        None,
                    )
                    self._emit("extraction_agreement", "ok",
                               {"verdict": agreement["verdict"],
                                "n_sources": len(agreement.get("sources") or []),
                                "elapsed_s": round(time.monotonic() - t0, 1)})
                else:
                    self._emit("extraction_agreement", "skipped",
                               {"reason": "no second source available"})
            except Exception as exc:  # noqa: BLE001 — never block on aux check
                self._emit("extraction_agreement", "error",
                           {"exc_type": type(exc).__name__, "reason": str(exc)[:80]})

        if self.enable_consensus:
            self._emit("consensus", "start", {})
            t0 = time.monotonic()
            from cve_diff.report.consensus import run_consensus
            try:
                consensus = run_consensus(cve_id)
                bundle = replace(bundle, consensus=consensus.to_dict())
                self._emit("consensus", "ok",
                           {"agreement": consensus.agreement_count,
                            "attempted": consensus.attempted_count,
                            "elapsed_s": round(time.monotonic() - t0, 1)})
            except Exception as exc:  # noqa: BLE001
                self._emit("consensus", "error",
                           {"exc_type": type(exc).__name__, "reason": str(exc)[:80]})
        # Pipeline reached the end cleanly → stage 5 (render) is "ok".
        # ``render`` doesn't have its own ``_emit`` event today (writing
        # the artifacts is the CLI's job, not the pipeline's), so we
        # stamp the status directly. The trace renderer reads this on
        # the PASS path to mark Stage 5 ✓.
        self._stage_status["render"] = {"status": "ok"}
        return PipelineResult(
            cve_id=cve_id,
            bundle=bundle,
            agent_result=agent_result,
            acquirer=acquirer,
        )

    def _emit(self, stage: str, status: str, info: dict) -> None:
        # Map internal stage names to one of the 5 canonical pipeline
        # stages (discover/acquire/resolve/diff/render). Multiple inner
        # events may map to the same canonical stage (e.g. ``diff`` and
        # ``diff_via_api`` are both Stage 4). Last write wins.
        canonical = _CANONICAL_STAGE_OF.get(stage)
        if canonical and status in ("ok", "fail"):
            self._stage_status[canonical] = {
                "status": status,
                "reason": (info or {}).get("reason"),
            }
        if self.progress_callback is not None:
            try:
                self.progress_callback(stage, status, info)
            except Exception:  # noqa: BLE001 — never break pipeline on bad callback
                pass

    def _run_agent(self, cve_id: str) -> AgentResult:
        self._last_meta_retry_attempted = False
        config = AgentConfig(
            system_prompt=SYSTEM_PROMPT,
            user_message=build_user_message(cve_id),
            tools=TOOLS,
            validator=discover_validator,
        )
        config = self._scale_budgets(config)
        ctx = AgentContext(cve_id=cve_id)
        result = self.agent.run(config, ctx)
        retry = self._maybe_retry(cve_id, result)
        if retry is not None:
            self._last_meta_retry_attempted = True
            return retry
        return result

    def _scale_budgets(self, config: AgentConfig) -> AgentConfig:
        """Apply ``agent_budget_multiplier`` to the AgentConfig budgets.

        Used by both the primary run (``_run_agent``) and the focused
        meta-retry (``_maybe_retry``) so an extended budget propagates
        consistently. No-op when multiplier is 1.0.
        """
        m = self.agent_budget_multiplier
        if m == 1.0:
            return config
        return replace(
            config,
            budget_tokens=int(config.budget_tokens * m),
            budget_cost_usd=config.budget_cost_usd * m,
            budget_s=config.budget_s * m,
            max_iterations=int(config.max_iterations * m),
        )

    def _focused_retry(self, cve_id: str, retry_msg: str) -> AgentResult:
        """Spawn a fresh AgentLoop with the focused retry-budget shape.

        Shared between `_maybe_retry` (budget walks) and
        `_post_submit_retry` (stage-2-5 failures). The only thing those
        two callers do differently is build a different `retry_msg`;
        the `AgentConfig` shape is the same: 3.00 USD / 600k tokens /
        720s / 44 iter (loose enough for a focused 1-3 tool-call run).
        Subject to `_scale_budgets` like the primary run.
        """
        retry_config = AgentConfig(
            system_prompt=SYSTEM_PROMPT,
            user_message=retry_msg,
            tools=TOOLS,
            validator=discover_validator,
            budget_cost_usd=3.00,
            budget_tokens=600_000,
            budget_s=720.0,
            max_iterations=44,
        )
        retry_config = self._scale_budgets(retry_config)
        return self.agent.run(retry_config, AgentContext(cve_id=cve_id))

    def _maybe_retry(self, cve_id: str, result: AgentResult) -> AgentResult | None:
        """Focused second pass when the first run ran out of budget after
        finding a verified candidate. Returns the retry's result, or
        ``None`` if no retry is warranted (in which case the caller keeps
        the original).

        Triggered when:
          * ``AgentSurrender`` reason in budget_* family
          * at least one ``gh_commit_detail``-confirmed (slug, sha) was
            captured during the first run

        Other surrender reasons (``UnsupportedSource``, ``no_evidence``,
        ``llm_error`` after retries, etc.) are not retried — the agent
        already concluded the right answer.
        """
        if not isinstance(result, AgentSurrender):
            return None
        # Retry-worthy: ran out of budget (focused submit pass may finish
        # the work) or transient LLM error after the in-loop 5s/15s
        # backoff exhausted (a fresh request from the orchestrator may
        # land in a quieter API window). Other reasons are conclusive:
        # UnsupportedSource = closed-source, no_evidence = exhausted
        # search, model_stopped_without_submit = bug, client_init_failed
        # = config error.
        # `budget_tokens` is documented but never emitted by the agent
        # loop (see AgentLoop.surrender — only cost / iterations / s).
        # Kept as an alias the loop *could* emit in a future change.
        if result.reason not in ("budget_cost_usd", "budget_iterations", "budget_s", "llm_error"):
            return None
        if not result.verified_candidates:
            return None

        candidates_str = "\n".join(
            f"  - {slug} @ {sha}" for slug, sha in result.verified_candidates[:5]
        )
        retry_msg = (
            f"Find the upstream fix commit for {cve_id}.\n\n"
            f"You hit the budget cap on a prior attempt after confirming "
            f"the following candidate(s) via gh_commit_detail:\n"
            f"{candidates_str}\n\n"
            f"Pick the most likely upstream candidate and submit_result. "
            f"Use ≤ 3 tool calls. If none look right, submit no_evidence."
        )
        return self._focused_retry(cve_id, retry_msg)

    def _post_submit_retry(
        self, cve_id: str, ref: RepoRef, exc: Exception,
        prior_result: AgentResult,
    ) -> AgentResult:
        """Spawn a focused second agent run after a stage-2-5 failure.

        Builds a retry user message that pins the agent on the failure:
        the (slug, sha) that failed, the failure class, and the
        verified candidates from the prior run (if any). Tells the
        agent to pick a *different* candidate or surrender. Same
        retry-budget shape as `_maybe_retry` via `_focused_retry`.
        """
        # Both AgentOutput and AgentSurrender carry verified_candidates
        # since 2026-05; the post-submit-retry path is reached when the
        # agent submitted (AgentOutput) but stages 2-5 failed, so the
        # prior_result is AgentOutput in this code path.
        prior_verified: tuple[tuple[str, str], ...] = (
            getattr(prior_result, "verified_candidates", ()) or ()
        )

        candidates_str = (
            "\n".join(f"  - {slug} @ {sha[:12]}" for slug, sha in prior_verified[:5])
            or "  (none — your prior run did not log any gh_commit_detail successes)"
        )
        retry_msg = (
            f"Find the upstream fix commit for {cve_id}.\n\n"
            f"You previously submitted ({ref.repository_url}, "
            f"{ref.fix_commit[:12]}) but the pipeline failed at the "
            f"{type(exc).__name__} stage:\n"
            f"  {str(exc)[:200]}\n\n"
            f"Verified candidates from your prior run:\n"
            f"{candidates_str}\n\n"
            f"Pick a *different* candidate (or one of the verified "
            f"pairs above), verify it via gh_commit_detail if you "
            f"haven't already, and submit_result. Use ≤ 3 tool calls. "
            f"If no other candidate looks right, submit no_evidence."
        )
        return self._focused_retry(cve_id, retry_msg)

    @staticmethod
    def _require_rescued(cve_id: str, result: AgentResult) -> PatchTuple:
        if isinstance(result, AgentSurrender):
            if result.reason == "unsupported_source":
                raise UnsupportedSource(f"{cve_id}: {result.detail}")
            raise DiscoveryError(f"{cve_id}: agent surrendered ({result.reason}): {result.detail}")
        assert isinstance(result, AgentOutput)
        value = result.value
        if not isinstance(value, PatchTuple):
            raise DiscoveryError(f"{cve_id}: agent returned non-PatchTuple value: {type(value).__name__}")
        return value

    @staticmethod
    def _check_shape(cve_id: str, bundle: DiffBundle) -> None:
        reason = check_diff_shape(bundle.shape)
        if reason is not None:
            raise AnalysisError(
                f"{cve_id}: diff shape {bundle.shape!r} rejected ({reason}) — "
                f"likely downstream mirror not upstream fix"
            )

    def _assert_disk(self, path: Path) -> None:
        target = path.parent if (isinstance(path, Path) and path.exists()) else "/"
        disk_budget.assert_ok(target, self.disk_limit_pct)


def _patch_to_repo_ref(patch: PatchTuple) -> RepoRef:
    """Promote a validator-blessed ``PatchTuple`` to a ``RepoRef``.

    ``canonical_score`` is a legacy field on ``RepoRef`` whose original
    meaning (tracker-slug probability) was list-driven and is no longer
    gated on. We pass a fixed positive value to satisfy the frozen-
    dataclass ``canonical_score >= 0`` post-init; no scoring occurs.
    """
    return RepoRef(
        repository_url=patch.repository_url,
        fix_commit=patch.fix_commit,
        introduced=patch.introduced,
        canonical_score=100,
    )
