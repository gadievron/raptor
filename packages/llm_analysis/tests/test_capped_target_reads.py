"""Target-repo reads in the patch lane are byte-bounded.

`generate_patch` reads the finding's source file from the scanned
(hostile) repo for prompt context. The prompt layer keeps only the
first 5000 characters, so an uncapped read of a giant mislabeled
"source" file materialises hundreds of megabytes for nothing — the
same OOM class `read_vulnerable_code` already routes through
`read_text_capped`.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.source import DEFAULT_MAX_SOURCE_CHARS  # noqa: E402
from packages.llm_analysis.agent import AutonomousSecurityAgentV2  # noqa: E402


class _StubVuln:
    rule_id = "x.y.z"
    file_path = "huge.c"
    start_line = 1
    end_line = 2
    message = "m"
    analysis: dict = {}
    full_code = "int x;"
    feasibility = None
    attack_path_ref = None
    metadata: dict = {}

    def __init__(self, repo: Path, target: Path) -> None:
        self.repo_path = str(repo)
        self._target = target

    def get_full_file_path(self) -> Path:
        return self._target


class _StubAgent:
    _load_attack_path = staticmethod(lambda ref: None)


def test_generate_patch_source_read_is_capped(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    big = repo / "huge.c"
    # A single giant line just over the shared source cap — the
    # hostile-repo "mislabeled source" shape.
    big.write_text("x" * (DEFAULT_MAX_SOURCE_CHARS + 4096))

    import packages.llm_analysis.prompts.patch as patchmod

    seen: dict[str, int] = {}

    def spy_bundle(**kw):
        seen["full_file_content_len"] = len(kw.get("full_file_content") or "")
        raise RuntimeError("stop-after-read")

    with mock.patch.object(patchmod, "build_patch_prompt_bundle", spy_bundle):
        try:
            AutonomousSecurityAgentV2.generate_patch(
                _StubAgent(), _StubVuln(repo, big),
            )
        except RuntimeError:
            pass

    assert "full_file_content_len" in seen, "prompt build never reached"
    assert seen["full_file_content_len"] <= DEFAULT_MAX_SOURCE_CHARS
