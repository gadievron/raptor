# Stage 5 — dry-run preview

## File: `cve_diff/acquisition/layers.py` (221 LOC, 87% covered)

3 acquisition layers + cascade. Each does git subprocess work with timeouts and `LayerReport` returns. Coverage gap is in the per-layer error/timeout branches (lines 47-48, 95-96, 128-130, 171-172, 189-190, 192).

## Candidate identified

**Extract `_clean_dest(dest: Path)` helper.** The `subprocess.run(["rm", "-rf", ...], capture_output=True, check=False, timeout=60)` pattern appears in **3 places**:

| Where | Pre-condition |
|---|---|
| `ShallowCloneLayer.acquire` line 116 | `if dest.exists() and any(dest.iterdir()):` |
| `FullCloneLayer.acquire` line 180 | `if dest.exists() and any(dest.iterdir()):` |
| `CascadingRepoAcquirer.acquire` line 213 | `if layer_dest.exists():` (slightly different — no empty-dir check) |

Unifying via `_clean_dest(dest)` with the stricter precondition (`exists() AND any(iterdir())`) preserves behavior:
- Non-existent dest: both old and new skip
- Existent + empty: old cascade ran an effectively no-op rm-rf; new skips. **Observable difference: zero** (rm-rf on empty dir is the same as no-op).
- Existent + non-empty: both run rm-rf

The pre-condition-different cascade callsite is the one I worried about, but its behavior is identical post-unification (rm -rf on an existing-but-empty dir is a no-op anyway).

```python
def _clean_dest(dest: Path) -> None:
    """Remove ``dest`` if it exists and has content. No-op otherwise.

    Defensive: 60s timeout protects against pathological filesystems
    (broken NFS, dying disk); failures are silently ignored — the next
    acquire attempt will surface a real error if rm-rf actually didn't
    work."""
    if dest.exists() and any(dest.iterdir()):
        subprocess.run(
            ["rm", "-rf", str(dest)],
            capture_output=True, check=False, timeout=60,
        )
```

Then 3 callsites collapse to `_clean_dest(layer_dest)` / `_clean_dest(dest)`.

**Net LOC**: rough wash (helper docstring offsets the dedup), but cohesion is materially better.

## Other patterns considered, NOT extracted

- **`subprocess.TimeoutExpired` handling** in 3 layer.acquire methods. Each has different post-timeout behavior (return LayerReport vs continue with last_err). Abstraction loses clarity.
- **`if result.returncode != 0: return LayerReport(self.name, False, ...)`** with different error-message formats per layer. Low-value dedup at high-noise cost.
- **`_commit_exists` after-fetch check** in TargetedFetchLayer + ShallowCloneLayer + FullCloneLayer. The surrounding context differs (Targeted has multi-step setup; Shallow loops over depths; Full has a size guardrail). Not cleanly extractable.

## Stage 5 verdict

**One simplification to apply:** extract `_clean_dest(dest)` from `acquisition/layers.py`. Risk: low. Value: medium (DRY win on 3 callsites). Behavior preserved.

Smoke CVE: reuse Stage 1 baseline (CVE-2023-38545) — every CVE exercises the cascade. Stage 5's spec'd CVE (CVE-2014-6271 Shellshock) is too slow ($1.60+, 3min) for a quick smoke; the 4-CVE bench in V5 exercises multiple acquire paths.
