# Live WSL verification

The claims in the [WSL guide](../../docs/wsl.md) that only a real WSL kernel can confirm — the 9p
magic on the automount, Landlock availability on the stock kernel,
flock/rename client-locality, the consent ceremony, the sandbox
masks, the WSL1 refusal — are exercised nightly by
[`wsl.yml`](../workflows/wsl.yml) on a `windows-2022` runner
(WSL2 via the repo-local `.github/actions/wsl-setup` composite —
first-party, sha256-pinned rootfs; a probe job gates the leg and
reports a detected skip when the runner image cannot host WSL2).

What the leg verifies:

* **verify-live** — `.github/scripts/wsl_verify_live.py --section
  facts`: environment facts (kernel identity, LSM list, folding
  samples, perf surface) are recorded; expected values (V9FS magic on
  `/mnt/c`, Landlock absent on the stock kernel, flock double-acquire
  across two distros, mkfifo failure and the TMPDIR advisory latch on
  drvfs) are asserted — a mismatch fails the job.
* **wsl-tests** — `pytest -m wsl` plus the CRLF fixture set on three
  checkouts of the same tree: an ext4 LF clone, a git-materialized
  `core.autocrlf=true` twin, and the drvfs workspace view (which also
  runs the CRLF census on a case-insensitive mount and the
  nosemgrep/dead-scope suites over 9p).
* **sandbox-live** — the WSL sandbox/consent test files with the real
  kernel underneath, then the checklist `consent` section and
  `sandbox` section (mount-ns masks, PE-exec / interop-socket /
  binfmt-write probes, the nested-unshare mask-strip attempt, the
  `/run/WSL` re-grant refusal in both spellings, the `/mnt` target
  exemption).

  The consent ceremony is verified on BOTH sides of its TTY gate.
  The non-TTY refusal (exit 3, nothing written, the message naming
  the terminal requirement) is asserted directly — that is the
  load-bearing, CI-assertable path. The grant path is additionally
  driven through a pty the CI harness allocates, with the full
  transcript recorded (escaped) into the artifact. This does not
  undermine the gate: the gate is `sys.stdin.isatty()` by design,
  and its purpose is blocking accidental or scripted agent
  self-grants — an agent runs the CLI with a pipe or devnull stdin
  and stops at the refusal. A test harness allocating a pty on our
  own CI runner is exercising the grant path, not defeating the
  control; driving the ceremony programmatically anywhere else is
  exactly the behaviour the gate exists to stop.
* **wsl1-capture** — a `wsl-version 1` job recording WSL1 identity
  strings and `statfs` f_type words (the drvfs constant deliberately
  unmatched in code until captured here) and asserting the sandboxed
  execution refusal plus the `--sandbox none` escape.

Artifacts: each checklist section uploads a JSON artifact
(`wsl-verify-facts` / `wsl-verify-sandbox` / `wsl-verify-wsl1`,
14-day retention) with per-item status, values, and — for the grant
ceremony — the escaped pty transcript. The cross-client probes need a
second distro; the workflow installs one and names it through the
CI-only `RAPTOR_WSL_SECOND_DISTRO` knob (unset, those probes report
skipped-with-reason).
