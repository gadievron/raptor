"""Detector-correctness tests for the workflow pipeline/pipefail lint."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "check_workflow_pipefail.py"
REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def lint():
    spec = importlib.util.spec_from_file_location(
        "check_workflow_pipefail", _SCRIPT,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tree(tmp_path: Path, body: str, name: str = "wf.yml") -> Path:
    wf = tmp_path / ".github" / "workflows" / name
    wf.parent.mkdir(parents=True, exist_ok=True)
    wf.write_text(body, encoding="utf-8")
    return tmp_path


def _wf(step_lines: str) -> str:
    return (
        "name: Fixture\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        + step_lines
    )


UNPROTECTED_TEE = _wf(
    "      - name: Run gate\n"
    "        run: |\n"
    "          python3 gate.py | tee gate.log\n"
)


class TestDetection:
    def test_unprotected_tee_flagged(self, lint, tmp_path):
        root = _tree(tmp_path, UNPROTECTED_TEE)
        findings = lint.scan_tree(root)
        assert [f.key for f in findings] == ["wf.yml::build::Run gate"]

    def test_shell_bash_keyword_protects(self, lint, tmp_path):
        root = _tree(tmp_path, _wf(
            "      - name: Run gate\n"
            "        shell: bash\n"
            "        run: |\n"
            "          python3 gate.py | tee gate.log\n"
        ))
        assert lint.scan_tree(root) == []

    def test_custom_bash_template_does_not_protect(self, lint, tmp_path):
        # Only the built-in `bash` keyword gets the implicit
        # -eo pipefail; a custom template does not.
        root = _tree(tmp_path, _wf(
            "      - name: Run gate\n"
            "        shell: bash -e {0}\n"
            "        run: |\n"
            "          python3 gate.py | tee gate.log\n"
        ))
        assert len(lint.scan_tree(root)) == 1

    @pytest.mark.parametrize("set_line", [
        "set -o pipefail",
        "set -eo pipefail",
        "set -euo pipefail",
    ])
    def test_set_pipefail_protects(self, lint, tmp_path, set_line):
        root = _tree(tmp_path, _wf(
            "      - name: Run gate\n"
            "        run: |\n"
            f"          {set_line}\n"
            "          python3 gate.py | tee gate.log\n"
        ))
        assert lint.scan_tree(root) == []

    def test_set_without_pipefail_does_not_protect(self, lint, tmp_path):
        root = _tree(tmp_path, _wf(
            "      - name: Run gate\n"
            "        run: |\n"
            "          set -eu\n"
            "          python3 gate.py | tee gate.log\n"
        ))
        assert len(lint.scan_tree(root)) == 1

    def test_pipefail_after_the_pipe_does_not_protect(self, lint, tmp_path):
        # The credit is line-ordered: protection must be in effect
        # WHEN the pipe runs.
        root = _tree(tmp_path, _wf(
            "      - name: Run gate\n"
            "        run: |\n"
            "          python3 gate.py | tee gate.log\n"
            "          set -o pipefail\n"
        ))
        assert len(lint.scan_tree(root)) == 1

    def test_revoked_pipefail_does_not_protect(self, lint, tmp_path):
        root = _tree(tmp_path, _wf(
            "      - name: Run gate\n"
            "        run: |\n"
            "          set -euo pipefail\n"
            "          set +o pipefail\n"
            "          python3 gate.py | tee gate.log\n"
        ))
        assert len(lint.scan_tree(root)) == 1

    def test_revocation_after_the_pipe_keeps_the_credit(
        self, lint, tmp_path,
    ):
        root = _tree(tmp_path, _wf(
            "      - name: Run gate\n"
            "        run: |\n"
            "          set -o pipefail\n"
            "          python3 gate.py | tee gate.log\n"
            "          set +o pipefail\n"
            "          echo unpiped\n"
        ))
        assert lint.scan_tree(root) == []

    def test_pipestatus_inspection_protects(self, lint, tmp_path):
        root = _tree(tmp_path, _wf(
            "      - name: Run gate\n"
            "        run: |\n"
            "          python3 gate.py | tee gate.log\n"
            '          rc="${PIPESTATUS[0]}"; exit "$rc"\n'
        ))
        assert lint.scan_tree(root) == []

    def test_single_line_run_value_scanned(self, lint, tmp_path):
        root = _tree(tmp_path, _wf(
            "      - name: Run gate\n"
            "        run: python3 gate.py | tee gate.log\n"
        ))
        assert len(lint.scan_tree(root)) == 1

    def test_continuation_line_pipe_detected(self, lint, tmp_path):
        root = _tree(tmp_path, _wf(
            "      - name: Login\n"
            "        run: |\n"
            '          echo "$TOKEN" \\\n'
            "            | docker login --password-stdin\n"
        ))
        assert len(lint.scan_tree(root)) == 1


class TestNonPipes:
    def test_or_operator_not_a_pipe(self, lint, tmp_path):
        root = _tree(tmp_path, _wf(
            "      - name: Best effort\n"
            "        run: |\n"
            "          git fetch origin main || true\n"
        ))
        assert lint.scan_tree(root) == []

    def test_quoted_jq_filter_not_a_pipe(self, lint, tmp_path):
        root = _tree(tmp_path, _wf(
            "      - name: Query\n"
            "        run: |\n"
            "          gh api runs --jq '.runs[] | select(.ok) | .id'\n"
            '          gh api x --jq ".files[]? | .name"\n'
        ))
        assert lint.scan_tree(root) == []

    def test_comment_mentioning_tee_not_a_pipe(self, lint, tmp_path):
        root = _tree(tmp_path, _wf(
            "      - name: Documented\n"
            "        run: |\n"
            "          # a `| tee` here would swallow the exit code\n"
            "          python3 gate.py  # not piped | anywhere\n"
        ))
        assert lint.scan_tree(root) == []

    def test_mid_word_hash_is_not_a_comment(self, lint, tmp_path):
        # ``#`` opens a comment only at line start / after whitespace;
        # ``${FILE#./}`` is parameter expansion and a URL fragment is
        # data — truncating at either hid the real pipe after it.
        root = _tree(tmp_path, _wf(
            "      - name: Expansion\n"
            "        run: |\n"
            "          echo ${FILE#./} | tee gate.log\n"
        ))
        assert len(lint.scan_tree(root)) == 1
        root2 = _tree(tmp_path, _wf(
            "      - name: Fragment\n"
            "        run: |\n"
            "          curl -s https://host/page#frag | tee page.html\n"
        ), name="wf2.yml")
        findings = {f.key for f in lint.scan_tree(root2)}
        assert "wf2.yml::build::Fragment" in findings

    def test_gha_expression_pipe_not_a_pipe(self, lint, tmp_path):
        root = _tree(tmp_path, _wf(
            "      - name: Expr\n"
            "        run: |\n"
            "          echo ${{ github.ref || github.sha }}\n"
        ))
        assert lint.scan_tree(root) == []

    def test_uses_steps_ignored(self, lint, tmp_path):
        root = _tree(tmp_path, _wf(
            "      - name: Checkout\n"
            "        uses: actions/checkout@abc\n"
            "        with:\n"
            "          persist-credentials: false\n"
        ))
        assert lint.scan_tree(root) == []

    def test_unnamed_step_keyed_by_index(self, lint, tmp_path):
        root = _tree(tmp_path, _wf(
            "      - run: |\n"
            "          python3 gate.py | tee gate.log\n"
        ))
        findings = lint.scan_tree(root)
        assert [f.key for f in findings] == ["wf.yml::build::step-0"]


class TestBaselineSemantics:
    def _main(self, lint, monkeypatch, root, baseline) -> int:
        monkeypatch.setattr("sys.argv", [
            "check_workflow_pipefail.py",
            "--root", str(root), "--baseline", str(baseline),
        ])
        return lint.main()

    def test_new_finding_fails(self, lint, tmp_path, monkeypatch, capsys):
        root = _tree(tmp_path, UNPROTECTED_TEE)
        baseline = tmp_path / "b.json"
        baseline.write_text("{}", encoding="utf-8")
        assert self._main(lint, monkeypatch, root, baseline) == 1
        assert "wf.yml::build::Run gate" in capsys.readouterr().out

    def test_baselined_finding_passes(
        self, lint, tmp_path, monkeypatch, capsys,
    ):
        root = _tree(tmp_path, UNPROTECTED_TEE)
        baseline = tmp_path / "b.json"
        baseline.write_text(
            json.dumps({"wf.yml::build::Run gate": {"note": "reviewed"}}),
            encoding="utf-8",
        )
        assert self._main(lint, monkeypatch, root, baseline) == 0

    def test_stale_entry_warns_but_passes(
        self, lint, tmp_path, monkeypatch, capsys,
    ):
        root = _tree(tmp_path, _wf(
            "      - name: No pipes here\n"
            "        run: echo done\n"
        ))
        baseline = tmp_path / "b.json"
        baseline.write_text(
            json.dumps({"wf.yml::build::Gone": {"note": "old"}}),
            encoding="utf-8",
        )
        assert self._main(lint, monkeypatch, root, baseline) == 0
        assert "stale" in capsys.readouterr().out

    def test_write_baseline_preserves_notes(
        self, lint, tmp_path, monkeypatch, capsys,
    ):
        root = _tree(tmp_path, UNPROTECTED_TEE)
        baseline = tmp_path / "b.json"
        baseline.write_text(
            json.dumps({"wf.yml::build::Run gate": {"note": "reviewed"}}),
            encoding="utf-8",
        )
        monkeypatch.setattr("sys.argv", [
            "check_workflow_pipefail.py", "--root", str(root),
            "--baseline", str(baseline), "--write-baseline",
        ])
        assert lint.main() == 0
        data = json.loads(baseline.read_text(encoding="utf-8"))
        assert data == {"wf.yml::build::Run gate": {"note": "reviewed"}}


class TestRealRepoProtectedSites:
    """Regression pins against the live tree: the protected `| tee`
    sites must be recognised as protected (no finding), and the shipped
    baseline must stay in sync with the tree (gate exits 0, no stale
    rows)."""

    def test_known_protected_tee_sites_do_not_fire(self, lint):
        findings = {f.key for f in lint.scan_tree(REPO_ROOT)}
        for protected in (
            # shell: bash steps
            "corpus-labels.yml::pin-lint-pr::Pin-lint changed labels",
            "corpus-labels.yml::pin-lint-sweep::Pin-lint all labels",
            "refresh-sca-calibration.yml::refresh::Refresh corpus",
            # set -o pipefail in the script body
            "ubuntu26-canary.yml::canary::Probe kernel features (stock image)",
        ):
            assert protected not in findings, protected

    def test_live_tree_matches_shipped_baseline(self, lint):
        findings = {f.key for f in lint.scan_tree(REPO_ROOT)}
        baseline = set(lint.load_baseline(lint.DEFAULT_BASELINE))
        assert findings - baseline == set(), (
            "unbaselined pipeline step(s) — protect them or baseline "
            "with a note"
        )
        assert baseline - findings == set(), (
            "stale baseline row(s) — refresh workflow_pipefail_baseline.json"
        )
